package staging

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// sealChunk seals plaintext exactly as the capture session does.
func sealChunk(t *testing.T, cipher security.Cipher, auditID, stage string, seq, offset int64, plaintext []byte) storage.BodyChunk {
	t.Helper()
	compression, encoded, err := (&bodycodec.Encoder{}).Encode(plaintext, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "body_chunk_v2", stage, strconv.FormatInt(seq, 10), compression)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return storage.BodyChunk{AuditID: auditID, Stage: stage, Seq: seq, Offset: offset, PlaintextLength: len(plaintext),
		EncodedLength: len(encoded), ObservedAtNS: 1_700_000_000_000_000_000 + seq, Compression: compression, DataEnc: encrypted}
}

func stagingDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "staging")
}

type countingBudget struct{ used atomic.Int64 }

func (budget *countingBudget) Add(size int64)     { budget.used.Add(size) }
func (budget *countingBudget) Release(size int64) { budget.used.Add(-size) }

func openStager(t *testing.T, dir string, options Options) *Stager {
	t.Helper()
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	stager, err := Open(dir, testCipher(t), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stager.Close() })
	return stager
}

// The header and a record are pinned byte for byte.
func TestFormatVectors(t *testing.T) {
	if got := hex.EncodeToString(encodeHeader("apx_test")); got != "4c4c53544700020000000008"+"6170785f74657374" {
		t.Fatalf("header %s", got)
	}
	chunk := storage.BodyChunk{AuditID: "apx_test", Stage: storage.StageResponseReceived, Seq: 2, Offset: 2 << 20,
		PlaintextLength: 1 << 20, EncodedLength: 4, ObservedAtNS: 0x0102030405060708, Compression: bodycodec.CompressionGZIP,
		DataEnc: []byte{0xde, 0xad, 0xbe, 0xef}}
	head, err := encodeRecordHead(chunk)
	if err != nil {
		t.Fatal(err)
	}
	record := append(head, chunk.DataEnc...)
	want := "00000026" + // body length 38
		hex.EncodeToString(crc32Bytes(record[8:])) +
		"03" + "0000000000000002" + "0000000000200000" + "00100000" + "00000004" + "0102030405060708" + "01" + "deadbeef"
	if got := hex.EncodeToString(record); got != want {
		t.Fatalf("record\n got %s\nwant %s", got, want)
	}
	if got := hex.EncodeToString(record[4:8]); got != "8d70da14" {
		t.Fatalf("record CRC-32C %s", got)
	}
	decoded, err := checkRecord("apx_test", record)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(decoded) != fmt.Sprint(chunk) {
		t.Fatalf("decoded %+v", decoded)
	}
	for stage, code := range map[string]string{storage.StageRequestReceived: "01", storage.StageRequestSent: "02", storage.StageResponseSent: "04"} {
		chunk.Stage = stage
		chunk.Compression = bodycodec.CompressionNone
		head, err := encodeRecordHead(chunk)
		if err != nil || hex.EncodeToString(head[8:9]) != code || head[recordPrefix+recordMeta-1] != 0 {
			t.Fatalf("%s: head %x, %v", stage, head, err)
		}
	}
}

func crc32Bytes(data []byte) []byte {
	sum := crc32Of(data)
	return []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
}

func TestStageRoundTripAndGroupSync(t *testing.T) {
	cipher := testCipher(t)
	budget := &countingBudget{}
	stager := openStager(t, stagingDir(t), Options{BatchDelay: 20 * time.Millisecond})
	stager.SetBudget(budget)
	plaintexts := map[string][][]byte{}
	var refs []*Ref
	for index := range 6 {
		for _, stage := range []string{storage.StageRequestReceived, storage.StageResponseReceived} {
			plaintext := bytes.Repeat([]byte(fmt.Sprintf(`{"n":%d,"s":%q}`, index, stage)), 3000)
			chunk := sealChunk(t, cipher, "apx_round", stage, int64(index), int64(index*len(plaintext)), plaintext)
			ref, err := stager.Stage(chunk)
			if err != nil {
				t.Fatal(err)
			}
			refs = append(refs, ref)
			plaintexts[stage] = append(plaintexts[stage], plaintext)
		}
	}
	// Queued records are read from memory.
	if got, err := refs[0].Plaintext(); err != nil || !bytes.Equal(got, plaintexts[storage.StageRequestReceived][0]) {
		t.Fatalf("queued read: %v", err)
	}
	stager.Flush()
	if budget.used.Load() != 0 {
		t.Fatalf("budget still holds %d bytes after the writes", budget.used.Load())
	}
	stats := stager.Stats()
	if stats.Records != 12 || stats.Fsyncs != 1 {
		t.Fatalf("stats %+v: one batch must sync the file once", stats)
	}
	info, err := os.Stat(filepath.Join(stager.Dir(), "apx_round.stg"))
	if err != nil || info.Size() != stats.BytesWritten || stats.UsedBytes != info.Size() {
		t.Fatalf("file %v %v, stats %+v", info, err, stats)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %#o", info.Mode().Perm())
	}
	for index, ref := range refs {
		stage := ref.Metadata().Stage
		got, err := ref.Plaintext()
		if err != nil || !bytes.Equal(got, plaintexts[stage][index/2]) {
			t.Fatalf("ref %d: %v", index, err)
		}
	}
	scan, err := ScanFile(cipher, "apx_round", filepath.Join(stager.Dir(), "apx_round.stg"))
	if err != nil || len(scan.Records) != 12 || scan.Damage != "" || scan.TornTail || scan.Foreign {
		t.Fatalf("scan %+v, %v", scan, err)
	}
	stager.Discard("apx_round")
	if _, err := os.Stat(filepath.Join(stager.Dir(), "apx_round.stg")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file not removed: %v", err)
	}
	if _, err := refs[0].Chunk(); !errors.Is(err, ErrRemoved) {
		t.Fatalf("read after discard: %v", err)
	}
	if stager.Stats().UsedBytes != 0 {
		t.Fatalf("used %d after discard", stager.Stats().UsedBytes)
	}
	stager.Discard("apx_round")
}

func TestStageRefusesWhenFull(t *testing.T) {
	cipher := testCipher(t)
	chunk := sealChunk(t, cipher, "apx_full", storage.StageRequestReceived, 0, 0, bytes.Repeat([]byte("x"), 4096))
	stager := openStager(t, stagingDir(t), Options{MaxBytes: int64(len(chunk.DataEnc)) + 100})
	if _, err := stager.Stage(chunk); err != nil {
		t.Fatal(err)
	}
	next := sealChunk(t, cipher, "apx_full", storage.StageRequestReceived, 1, 4096, bytes.Repeat([]byte("y"), 4096))
	if _, err := stager.Stage(next); !errors.Is(err, ErrFull) {
		t.Fatalf("over max_bytes: %v", err)
	}
	queue := openStager(t, stagingDir(t), Options{QueueLimit: 1, BatchDelay: time.Hour})
	if _, err := queue.Stage(chunk); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Stage(next); !errors.Is(err, ErrFull) {
		t.Fatalf("queue limit: %v", err)
	}
}

// A failed write keeps the accepted chunk readable from memory and refuses
// the next one: no space is ErrFull, anything else ErrWriteFailed.
func TestWriteFailures(t *testing.T) {
	cipher := testCipher(t)
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"no space", syscall.ENOSPC, ErrFull},
		{"I/O error", syscall.EIO, ErrWriteFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			budget := &countingBudget{}
			stager := openStager(t, stagingDir(t), Options{Fault: func(operation, auditID string) error {
				if operation == "write" && auditID == "apx_fail" {
					return test.err
				}
				return nil
			}})
			stager.SetBudget(budget)
			plaintext := bytes.Repeat([]byte("data "), 1000)
			ref, err := stager.Stage(sealChunk(t, cipher, "apx_fail", storage.StageRequestReceived, 0, 0, plaintext))
			if err != nil {
				t.Fatal(err)
			}
			stager.Flush()
			if got, err := ref.Plaintext(); err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("accepted chunk lost: %v", err)
			}
			if _, err := stager.Stage(sealChunk(t, cipher, "apx_fail", storage.StageRequestReceived, 1, 5000, plaintext)); !errors.Is(err, test.want) {
				t.Fatalf("next chunk: %v, want %v", err, test.want)
			}
			_, err = stager.Stage(sealChunk(t, cipher, "apx_other", storage.StageRequestReceived, 0, 0, plaintext))
			if test.want == ErrFull && !errors.Is(err, ErrFull) || test.want != ErrFull && err != nil {
				t.Fatalf("other audit after %s: %v", test.name, err)
			}
			stager.Discard("apx_fail")
			stager.Discard("apx_other")
			stager.Flush()
			if budget.used.Load() != 0 {
				t.Fatalf("budget holds %d bytes", budget.used.Load())
			}
			if _, err := stager.Stage(sealChunk(t, cipher, "apx_after", storage.StageRequestReceived, 0, 0, plaintext)); err != nil {
				t.Fatalf("after the space was freed: %v", err)
			}
		})
	}
}

func TestKeepLeavesTheFile(t *testing.T) {
	cipher := testCipher(t)
	stager := openStager(t, stagingDir(t), Options{})
	if _, err := stager.Stage(sealChunk(t, cipher, "apx_keep", storage.StageRequestReceived, 0, 0, []byte("kept"))); err != nil {
		t.Fatal(err)
	}
	stager.Keep("apx_keep")
	stager.Flush()
	if err := stager.Close(); err != nil {
		t.Fatal(err)
	}
	scan, err := ScanFile(cipher, "apx_keep", filepath.Join(stager.Dir(), "apx_keep.stg"))
	if err != nil || len(scan.Records) != 1 {
		t.Fatalf("kept file: %+v %v", scan, err)
	}
	if err := os.Remove(filepath.Join(stager.Dir(), "apx_keep.stg")); err != nil {
		t.Fatalf("file still open after Keep and Close: %v", err)
	}
}

func TestPrepareDirectory(t *testing.T) {
	if err := PrepareDirectory("relative/staging"); err == nil {
		t.Fatal("relative path accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareDirectory(file); err == nil {
		t.Fatal("a file accepted as directory")
	}
	dir := filepath.Join(t.TempDir(), "a", "staging")
	if err := PrepareDirectory(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("probe left %v", entries)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("created with %#o", info.Mode().Perm())
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := PrepareDirectory(dir); err == nil {
		t.Fatal("group-readable directory accepted")
	}
}

// fakeRestorer applies the store's rules to an in-memory table.
type fakeRestorer struct {
	audits  map[string]bool // id → finalized
	bodies  map[string]map[string]string
	stored  map[string]map[string][]storage.BodyChunk
	failErr error
	calls   int
}

func newFakeRestorer() *fakeRestorer {
	return &fakeRestorer{audits: map[string]bool{}, bodies: map[string]map[string]string{}, stored: map[string]map[string][]storage.BodyChunk{}}
}

func (store *fakeRestorer) open(id string, stages ...string) {
	store.audits[id] = false
	store.bodies[id] = map[string]string{}
	store.stored[id] = map[string][]storage.BodyChunk{}
	for _, stage := range stages {
		store.bodies[id][stage] = stage
	}
}

func (store *fakeRestorer) RestoreStagedChunks(_ context.Context, restore storage.StagedChunkRestore) (storage.StagedChunkRestoreResult, error) {
	store.calls++
	if store.failErr != nil {
		return storage.StagedChunkRestoreResult{}, store.failErr
	}
	finalized, ok := store.audits[restore.AuditID]
	if !ok {
		return storage.StagedChunkRestoreResult{Outcome: storage.StagedRestoreNoAudit}, nil
	}
	if finalized {
		return storage.StagedChunkRestoreResult{Outcome: storage.StagedRestoreFinalized}, nil
	}
	runs := map[string]storage.StoredChunkRun{}
	for stage, chunks := range store.stored[restore.AuditID] {
		var end int64
		for _, chunk := range chunks {
			end += int64(chunk.PlaintextLength)
		}
		runs[stage] = storage.StoredChunkRun{Next: int64(len(chunks)), End: end}
	}
	plan := storage.NewStagedRestorePlan(store.bodies[restore.AuditID], runs)
	var inserted []storage.BodyChunk
	if err := plan.Filter(restore.Chunks).Each(func(chunk storage.BodyChunk) error {
		chunk.DataEnc = bytes.Clone(chunk.DataEnc)
		inserted = append(inserted, chunk)
		return nil
	}); err != nil {
		return storage.StagedChunkRestoreResult{}, err
	}
	for _, chunk := range inserted {
		store.stored[restore.AuditID][chunk.Stage] = append(store.stored[restore.AuditID][chunk.Stage], chunk)
	}
	return plan.Result(), nil
}

// writeFile writes a staging file from records, with an optional change.
func writeFile(t *testing.T, dir, name, headerID string, chunks []storage.BodyChunk, change func([]byte) []byte) string {
	t.Helper()
	data := encodeHeader(headerID)
	for _, chunk := range chunks {
		head, err := encodeRecordHead(chunk)
		if err != nil {
			t.Fatal(err)
		}
		data = append(append(data, head...), chunk.DataEnc...)
	}
	if change != nil {
		data = change(data)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func threeChunks(t *testing.T, cipher security.Cipher, id, stage string) []storage.BodyChunk {
	var chunks []storage.BodyChunk
	for seq := range 3 {
		chunks = append(chunks, sealChunk(t, cipher, id, stage, int64(seq), int64(seq*2000), bytes.Repeat([]byte{byte('a' + seq)}, 2000)))
	}
	return chunks
}

func recordOffset(id string, chunks []storage.BodyChunk, index int) int {
	offset := len(encodeHeader(id))
	for _, chunk := range chunks[:index] {
		offset += recordPrefix + recordMeta + len(chunk.DataEnc)
	}
	return offset
}

// Every row of F.7, the damaged-file cases of I.3 among them.
func TestImportCases(t *testing.T) {
	cipher := testCipher(t)
	stage := storage.StageRequestReceived
	for _, test := range []struct {
		name     string
		setup    func(store *fakeRestorer, id string)
		header   string
		change   func(id string, chunks []storage.BodyChunk) func([]byte) []byte
		inserted int
		kept     string // "", ".orphan" or ".corrupt"
	}{
		{name: "imported in full", setup: func(store *fakeRestorer, id string) { store.open(id, stage) }, inserted: 3},
		{name: "some chunks already stored", setup: func(store *fakeRestorer, id string) {
			store.open(id, stage)
			store.stored[id][stage] = threeChunks(t, cipher, id, stage)[:2]
		}, inserted: 1},
		{name: "audit finalized", setup: func(store *fakeRestorer, id string) { store.open(id, stage); store.audits[id] = true }},
		{name: "no audit row", setup: func(*fakeRestorer, string) {}, kept: OrphanSuffix},
		{name: "no body row", setup: func(store *fakeRestorer, id string) { store.open(id) }, kept: OrphanSuffix},
		{name: "torn tail: half a record", setup: func(store *fakeRestorer, id string) { store.open(id, stage) },
			change: func(string, []storage.BodyChunk) func([]byte) []byte {
				return func(data []byte) []byte { return data[:len(data)-7] }
			}, inserted: 2},
		{name: "torn tail: CRC of the last record", setup: func(store *fakeRestorer, id string) { store.open(id, stage) },
			change: func(string, []storage.BodyChunk) func([]byte) []byte {
				return func(data []byte) []byte { data[len(data)-1] ^= 1; return data }
			}, inserted: 2},
		{name: "torn tail: header only", setup: func(store *fakeRestorer, id string) { store.open(id, stage) },
			change: func(id string, _ []storage.BodyChunk) func([]byte) []byte {
				return func(data []byte) []byte { return data[:len(encodeHeader(id))-3] }
			}},
		{name: "CRC error in the middle", setup: func(store *fakeRestorer, id string) { store.open(id, stage) },
			change: func(id string, chunks []storage.BodyChunk) func([]byte) []byte {
				return func(data []byte) []byte { data[recordOffset(id, chunks, 1)+20] ^= 1; return data }
			}, inserted: 1, kept: CorruptSuffix},
		{name: "authentication fails in the middle", setup: func(store *fakeRestorer, id string) { store.open(id, stage) },
			change: func(id string, chunks []storage.BodyChunk) func([]byte) []byte {
				return func(data []byte) []byte {
					at := recordOffset(id, chunks, 1)
					data[at+recordPrefix+recordMeta+3] ^= 1
					body := data[at+recordPrefix : recordOffset(id, chunks, 2)]
					copy(data[at+4:at+8], crc32Bytes(body))
					return data
				}
			}, inserted: 1, kept: CorruptSuffix},
		{name: "header names another audit", header: "apx_someone_else", setup: func(store *fakeRestorer, id string) { store.open(id, stage) }, kept: CorruptSuffix},
		{name: "chunks do not continue the stored ones", setup: func(store *fakeRestorer, id string) {
			store.open(id, stage)
			store.stored[id][stage] = []storage.BodyChunk{{Stage: stage, PlaintextLength: 10}}
		}, kept: CorruptSuffix},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := stagingDir(t)
			stager := openStager(t, dir, Options{})
			id := "apx_import"
			store := newFakeRestorer()
			test.setup(store, id)
			chunks := threeChunks(t, cipher, id, stage)
			header := id
			if test.header != "" {
				header = test.header
			}
			var change func([]byte) []byte
			if test.change != nil {
				change = test.change(id, chunks)
			}
			path := writeFile(t, dir, id+Suffix, header, chunks, change)
			if err := os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, "lost+found"), 0o700); err != nil {
				t.Fatal(err)
			}
			report, err := stager.Import(context.Background(), store)
			if err != nil {
				t.Fatal(err)
			}
			if report.Inserted != test.inserted || report.Files != 1 || report.Ignored != 2 {
				t.Fatalf("report %+v, want %d inserted", report, test.inserted)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging file still there: %v", err)
			}
			_, err = os.Stat(filepath.Join(dir, id+test.kept))
			if test.kept != "" && err != nil {
				t.Fatalf("file not kept as %s: %v", test.kept, err)
			}
			for index, chunk := range store.stored[id][stage] {
				if chunk.DataEnc == nil {
					continue
				}
				got, err := OpenChunk(cipher, chunk)
				want, _ := OpenChunk(cipher, chunks[index])
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("chunk %d stored differently: %v", index, err)
				}
			}
			// A second run (a crash after the first) changes nothing.
			before := fmt.Sprint(store.stored)
			again, err := stager.Import(context.Background(), store)
			if err != nil || again.Inserted != 0 || again.Files != 0 || fmt.Sprint(store.stored) != before {
				t.Fatalf("second import %+v, %v", again, err)
			}
		})
	}
}

// The import is idempotent at each of its crash points: before the store
// operation commits (the store failed), after it committed and before the
// file was removed (the file is imported again), and after.
func TestImportIdempotentAtCrashPoints(t *testing.T) {
	cipher := testCipher(t)
	stage := storage.StageResponseReceived
	dir := stagingDir(t)
	id := "apx_crash"
	chunks := threeChunks(t, cipher, id, stage)
	store := newFakeRestorer()
	store.open(id, stage)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, id+Suffix, id, chunks, nil)

	// The store operation fails: nothing changes, the file stays, and the
	// error stops the import.
	store.failErr = errors.New("database unavailable")
	stager := openStager(t, dir, Options{})
	if _, err := stager.Import(context.Background(), store); err == nil {
		t.Fatal("store error not returned")
	}
	if len(store.stored[id][stage]) != 0 {
		t.Fatal("chunks stored by a failed operation")
	}
	// The operation committed, then the process stopped before removing the
	// file: a copy of the file plays the second start.
	store.failErr = nil
	raw, err := os.ReadFile(filepath.Join(dir, id+Suffix))
	if err != nil {
		t.Fatal(err)
	}
	if report, err := openStager(t, dir, Options{}).Import(context.Background(), store); err != nil || report.Inserted != 3 {
		t.Fatalf("first import %+v, %v", report, err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+Suffix), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := openStager(t, dir, Options{}).Import(context.Background(), store)
	if err != nil || report.Inserted != 0 || report.Removed != 1 || len(store.stored[id][stage]) != 3 {
		t.Fatalf("repeated import %+v, %v, %d stored", report, err, len(store.stored[id][stage]))
	}
	// After recovery finalized the audit, a file left again is only removed.
	store.audits[id] = true
	if err := os.WriteFile(filepath.Join(dir, id+Suffix), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = openStager(t, dir, Options{}).Import(context.Background(), store)
	if err != nil || report.Removed != 1 || len(store.stored[id][stage]) != 3 {
		t.Fatalf("import after finalization %+v, %v", report, err)
	}
}

func TestImportMustPrecedeStaging(t *testing.T) {
	cipher := testCipher(t)
	stager := openStager(t, stagingDir(t), Options{})
	if _, err := stager.Stage(sealChunk(t, cipher, "apx_live", storage.StageRequestReceived, 0, 0, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Import(context.Background(), newFakeRestorer()); err == nil {
		t.Fatal("import ran over live files")
	}
}

// A duplicate's chunks whose body row points at its source are not inserted.
func TestRestorePlanSkipsBorrowedStage(t *testing.T) {
	cipher := testCipher(t)
	chunks := threeChunks(t, cipher, "apx_pair", storage.StageRequestSent)
	plan := storage.NewStagedRestorePlan(map[string]string{storage.StageRequestSent: storage.StageRequestReceived}, nil)
	count := 0
	if err := plan.Filter(storage.ChunkList(chunks)).Each(func(storage.BodyChunk) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if result := plan.Result(); count != 0 || result.Borrowed != 3 || len(result.NoBody) != 0 {
		t.Fatalf("inserted %d, result %+v", count, result)
	}
}
