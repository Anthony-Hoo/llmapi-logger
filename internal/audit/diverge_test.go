package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// pieceReader returns at most size bytes per Read.
type pieceReader struct {
	data []byte
	size int
}

func (reader *pieceReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer[:min(len(buffer), reader.size)], reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

// divergeDrive feeds each stage its own bytes, so a duplicate can differ
// from its source. The request stages are read in alternation as the
// Transport does; the response is written in pieces as ReverseProxy does.
type divergeDrive struct {
	inbound, outbound []byte
	received, sent    []byte
	piece             int
}

func runDiverge(t *testing.T, writePath string, drive divergeDrive) (storage.AuditFinish, sqlite.Snapshot) {
	t.Helper()
	return runDivergeWith(t, Options{WritePath: writePath}, drive)
}

// runDivergeWith is runDiverge with the manager's options, the clock and the
// id source excepted.
func runDivergeWith(t *testing.T, options Options, drive divergeDrive) (storage.AuditFinish, sqlite.Snapshot) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{9}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	clock := int64(1_700_000_000_000_000_000)
	options.Now = func() time.Time { clock++; return time.Unix(0, clock) }
	options.Random = rand.NewChaCha8([32]byte{1})
	manager, err := NewManagerWithOptions(store, cipher, nil, ModeAvailable, nil, options)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", &pieceReader{data: drive.inbound, size: drive.piece})
	request.ContentLength = int64(len(drive.inbound))
	request.Header.Set("Content-Type", "application/json")
	session, err := manager.Begin(ctx, request, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	outbound := request.Clone(ctx)
	outbound.Host = "newapi.example.com"
	outbound.Body = io.NopCloser(&pieceReader{data: drive.outbound, size: drive.piece})
	session.WrapRequestSent(outbound)
	buffer := make([]byte, drive.piece)
	inDone, outDone := false, false
	for !inDone || !outDone {
		if !inDone {
			if _, err := request.Body.Read(buffer); err != nil {
				inDone = true
			}
		}
		if !outDone {
			if _, err := outbound.Body.Read(buffer); err != nil {
				outDone = true
			}
		}
	}
	_ = request.Body.Close()
	_ = outbound.Body.Close()
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ContentLength: -1, Request: outbound,
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(&pieceReader{data: drive.received, size: drive.piece})}
	session.WrapResponseReceived(response)
	writer := session.WrapResponseWriter(httptest.NewRecorder(), request)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(200)
	sent := drive.sent
	for {
		count, err := response.Body.Read(buffer)
		if count > 0 {
			piece := sent[:min(len(sent), count)]
			sent = sent[len(piece):]
			_, _ = writer.Write(piece)
		}
		if err != nil {
			break
		}
	}
	if len(sent) > 0 {
		_, _ = writer.Write(sent)
	}
	writer.CaptureTrailers()
	_ = session.Finish()
	snapshot, err := store.Snapshot(ctx, session.ID())
	if err != nil {
		t.Fatal(err)
	}
	terminal, _ := session.Terminal()
	return storage.AuditFinish{CaptureStatus: terminal.CaptureStatus, ForwardStatus: terminal.ForwardStatus}, openSnapshot(t, cipher, snapshot)
}

// openSnapshot replaces ciphertext by the decoded plaintext, so two runs
// with different nonces compare equal when their content is.
func openSnapshot(t *testing.T, cipher security.Cipher, snapshot sqlite.Snapshot) sqlite.Snapshot {
	t.Helper()
	snapshot.Audit.RequestURIEnc = nil
	for index, header := range snapshot.Headers {
		aad, _ := security.AAD(header.AuditID, "header", header.Stage, header.Kind, header.Name, strconv.Itoa(header.ValueIndex))
		plaintext, err := cipher.Decrypt(aad, header.ValueEnc)
		if err != nil {
			t.Fatalf("header %s/%s does not open", header.Stage, header.Name)
		}
		snapshot.Headers[index].ValueEnc = plaintext
	}
	for index, chunk := range snapshot.Chunks {
		aad, _ := security.AAD(chunk.AuditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), chunk.Compression)
		encoded, err := cipher.Decrypt(aad, chunk.DataEnc)
		if err != nil {
			t.Fatalf("chunk %s/%d does not open", chunk.Stage, chunk.Seq)
		}
		plaintext, err := bodycodec.Decode(encoded, chunk.Compression, chunk.PlaintextLength)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Chunks[index].DataEnc = plaintext
	}
	return snapshot
}

func noise(size int, seed uint64) []byte {
	random := rand.New(rand.NewPCG(seed, seed))
	data := make([]byte, size)
	for index := range data {
		data[index] = byte('a' + random.IntN(26))
	}
	return data
}

func withChange(data []byte, at int) []byte {
	changed := bytes.Clone(data)
	changed[at] ^= 0x20
	return changed
}

// A duplicate that stops matching its source keeps the matched prefix
// borrowed and owns the rest; its chunks, cut on its own grid and sealed
// from both parts, are those legacy writes from its own copy.
func TestDivergingDuplicatesMatchLegacy(t *testing.T) {
	request := noise(3<<19, 1)
	response := noise(5<<19, 2)
	for _, test := range []struct {
		name  string
		drive divergeDrive
	}{
		{"request differs mid-chunk after 1.5 MiB", divergeDrive{inbound: request, outbound: withChange(request, 3<<19-100), received: response, sent: response, piece: 48 << 10}},
		{"request differs at byte 100", divergeDrive{inbound: request, outbound: withChange(request, 100), received: response, sent: response, piece: 48 << 10}},
		{"outbound longer than inbound", divergeDrive{inbound: request, outbound: append(bytes.Clone(request), noise(700<<10, 3)...), received: response, sent: response, piece: 48 << 10}},
		{"outbound shorter than inbound", divergeDrive{inbound: request, outbound: request[:1<<20+5], received: response, sent: response, piece: 48 << 10}},
		{"response differs after two MiB", divergeDrive{inbound: request, outbound: request, received: response, sent: withChange(response, 2<<20+77), piece: 32 << 10}},
		{"response written longer", divergeDrive{inbound: request, outbound: request, received: response, sent: append(bytes.Clone(response), noise(1<<20, 4)...), piece: 32 << 10}},
	} {
		t.Run(test.name, func(t *testing.T) {
			legacyOutcome, legacy := runDiverge(t, WritePathLegacy, test.drive)
			unifiedOutcome, unified := runDiverge(t, WritePathUnified, test.drive)
			if legacyOutcome != unifiedOutcome {
				t.Fatalf("outcome %+v, unified %+v", legacyOutcome, unifiedOutcome)
			}
			for _, part := range []struct {
				name            string
				legacy, unified any
			}{
				{"audit", legacy.Audit, unified.Audit},
				{"stages", legacy.Stages, unified.Stages},
				{"headers", legacy.Headers, unified.Headers},
				{"bodies", legacy.Bodies, unified.Bodies},
				{"chunks", chunkSummary(legacy.Chunks), chunkSummary(unified.Chunks)},
			} {
				if !reflect.DeepEqual(part.legacy, part.unified) {
					t.Fatalf("%s differ:\n legacy  %+v\n unified %+v", part.name, part.legacy, part.unified)
				}
			}
			owned := map[string]int{}
			for _, chunk := range unified.Chunks {
				owned[chunk.Stage]++
			}
			if owned[storage.StageRequestSent] == 0 && owned[storage.StageResponseSent] == 0 {
				t.Fatalf("no duplicate wrote its own chunks: %v", owned)
			}
		})
	}
}

func chunkSummary(chunks []storage.BodyChunk) []string {
	out := make([]string, len(chunks))
	for index, chunk := range chunks {
		out[index] = fmt.Sprintf("%s seq=%d offset=%d length=%d encoded=%d %s at=%d sum=%x", chunk.Stage, chunk.Seq, chunk.Offset,
			chunk.PlaintextLength, chunk.EncodedLength, chunk.Compression, chunk.ObservedAtNS, sumOf(chunk.DataEnc))
	}
	return out
}

func sumOf(data []byte) []byte {
	sum := sha256Sum(data)
	return sum[:8]
}

func sha256Sum(data []byte) [32]byte { return sha256.Sum256(data) }
