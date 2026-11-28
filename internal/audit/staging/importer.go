package staging

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Restorer is the store operation the import uses (F.7). It inserts, in one
// writer operation, the chunks the database does not have yet and says what
// it found.
type Restorer interface {
	RestoreStagedChunks(context.Context, storage.StagedChunkRestore) (storage.StagedChunkRestoreResult, error)
}

// Suffixes of the files the import keeps instead of removing.
const (
	OrphanSuffix  = ".orphan"
	CorruptSuffix = ".corrupt"
)

// ImportReport counts what Import did, by file.
type ImportReport struct {
	// Files is the number of staging files found.
	Files int
	// Removed files were imported in full, or belonged to an audit already
	// finalized.
	Removed int
	// Orphaned files were renamed .orphan: no audit row, or a stage without a
	// body row.
	Orphaned int
	// Corrupt files were renamed .corrupt after importing the part before
	// the damage.
	Corrupt int
	// Unreadable files could not be read and were left in place.
	Unreadable int
	// Inserted counts the chunks written into the database.
	Inserted int
	// Ignored counts other directory entries, which are left alone.
	Ignored int
}

// Import puts every staging file in the directory back into the store (F.7).
// It runs at start-up, before RecoverInterruptedAudits and before any chunk
// is staged. Each file is handled on its own:
//
//   - audit finalized with every chunk stored (stopped after its commit, or
//     after recovery stored the chunks of a failed commit, before cleanup):
//     removed; finalized without some of them: renamed .orphan, as a
//     finalized audit is never changed;
//   - no audit row: renamed .orphan;
//   - a stage whose body row is missing (the checkpoint written when the
//     stage first spilled was lost): the other stages are imported and the
//     file is renamed .orphan;
//   - otherwise every record is verified (CRC, AEAD, seq and offset
//     continuity) and the chunks the database does not have are inserted,
//     then the file is removed;
//   - an incomplete last record is where the process stopped and is dropped;
//   - a record in the middle that fails verification, a header that names
//     another audit, or chunks that do not continue the stored ones: what
//     comes before is imported and the file is renamed .corrupt.
//
// A damaged file is never removed. A file that cannot be read stops the
// import with an error, like a store error. The import is idempotent: chunks already
// stored are skipped, so a crash at any point only repeats work. A store
// error stops the import and is returned; the caller must not recover
// interrupted audits then, or a later start would find them finalized and
// drop the staged chunks.
func (stager *Stager) Import(ctx context.Context, store Restorer) (ImportReport, error) {
	var report ImportReport
	if store == nil {
		return report, errors.New("staging: nil store")
	}
	stager.mu.Lock()
	if len(stager.files) != 0 || stager.started {
		stager.mu.Unlock()
		return report, errors.New("staging: import must run before staging starts")
	}
	stager.imported = true
	stager.mu.Unlock()
	entries, err := os.ReadDir(stager.dir)
	if err != nil {
		return report, fmt.Errorf("staging: list directory: %w", err)
	}
	changed := false
	for _, entry := range entries {
		id, ok := auditIDOf(entry.Name())
		if !ok || !entry.Type().IsRegular() {
			if !strings.HasPrefix(entry.Name(), ".probe-") {
				report.Ignored++
			}
			continue
		}
		report.Files++
		outcome, inserted, err := stager.importFile(ctx, store, id, filepath.Join(stager.dir, entry.Name()))
		if err != nil {
			return report, err
		}
		report.Inserted += inserted
		switch outcome {
		case outcomeRemoved:
			report.Removed++
			changed = true
		case outcomeOrphaned:
			report.Orphaned++
			changed = true
		case outcomeCorrupt:
			report.Corrupt++
			changed = true
		case outcomeUnreadable:
			report.Unreadable++
		}
	}
	if changed {
		if err := syncDirectory(stager.dir); err == nil {
			stager.dirSyncs.Add(1)
		}
	}
	used, err := directoryUsage(stager.dir)
	if err == nil {
		stager.mu.Lock()
		stager.used = used
		stager.mu.Unlock()
	}
	if report.Files > 0 || report.Ignored > 0 {
		stager.logger.Info("audit staging import completed", "files", report.Files, "removed", report.Removed,
			"orphaned", report.Orphaned, "corrupt", report.Corrupt, "unreadable", report.Unreadable,
			"inserted_chunks", report.Inserted, "ignored_entries", report.Ignored)
	}
	return report, nil
}

type importOutcome int

const (
	outcomeRemoved importOutcome = iota + 1
	outcomeOrphaned
	outcomeCorrupt
	outcomeUnreadable
)

func (stager *Stager) importFile(ctx context.Context, store Restorer, auditID, path string) (importOutcome, int, error) {
	scan, err := ScanFile(stager.cipher, auditID, path)
	if err != nil {
		// A file that cannot be read now may be intact: recovering its audit
		// without it would make the next start drop it as finalized.
		return 0, 0, fmt.Errorf("staging: read %s: %w", auditID, err)
	}
	if scan.Foreign {
		return stager.keepFile(auditID, path, CorruptSuffix, "foreign_header", 0)
	}
	result, err := store.RestoreStagedChunks(ctx, storage.StagedChunkRestore{AuditID: auditID, Chunks: scan.Source()})
	if err != nil {
		return 0, 0, fmt.Errorf("staging: restore %s: %w", auditID, err)
	}
	damage := scan.Damage
	switch {
	case damage != "":
	case result.Outcome == storage.StagedRestoreImported && len(result.Discontinuous) != 0:
		damage = "discontinuous_chunks"
	}
	switch {
	case damage != "":
		return stager.keepFile(auditID, path, CorruptSuffix, damage, result.Inserted)
	case result.Outcome == storage.StagedRestoreNoAudit:
		return stager.keepFile(auditID, path, OrphanSuffix, "no_audit", 0)
	case result.Outcome == storage.StagedRestoreFinalized && (result.Missing != 0 || len(result.NoBody) != 0 || len(result.Discontinuous) != 0):
		// The audit was finalized without some of these chunks (their
		// insertion at recovery was rejected). A finalized audit is never
		// changed, so the file is the only copy: keep it.
		return stager.keepFile(auditID, path, OrphanSuffix, "finalized_without_chunks", 0)
	case result.Outcome == storage.StagedRestoreImported && len(result.NoBody) != 0:
		return stager.keepFile(auditID, path, OrphanSuffix, "no_body_row", result.Inserted)
	}
	if err := stager.removeFile(path); err != nil {
		stager.logger.Warn("audit staging file not removed", "audit_id", auditID, "error_category", "staging_remove_failed", "reason", fileErrorReason(err))
		return outcomeUnreadable, result.Inserted, nil
	}
	stager.logger.Info("audit staging file imported", "audit_id", auditID, "outcome", result.Outcome,
		"inserted_chunks", result.Inserted, "present_chunks", result.Present, "torn_tail", scan.TornTail)
	return outcomeRemoved, result.Inserted, nil
}

// keepFile renames a file the import must not remove.
func (stager *Stager) keepFile(auditID, path, suffix, reason string, inserted int) (importOutcome, int, error) {
	base := strings.TrimSuffix(path, Suffix) + suffix
	target := base
	for index := 1; ; index++ {
		if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
			break
		}
		target = base + "." + strconv.Itoa(index)
	}
	if err := stager.renameFile(path, target); err != nil {
		stager.logger.Warn("audit staging file not renamed", "audit_id", auditID, "kept_reason", reason, "error_category", "staging_rename_failed", "reason", fileErrorReason(err))
		return outcomeUnreadable, inserted, nil
	}
	stager.logger.Warn("audit staging file kept", "audit_id", auditID, "reason", reason,
		"kept_as", filepath.Base(target), "inserted_chunks", inserted)
	if suffix == OrphanSuffix {
		return outcomeOrphaned, inserted, nil
	}
	return outcomeCorrupt, inserted, nil
}

// FileScan is the verified content of one staging file.
type FileScan struct {
	AuditID string
	Path    string
	// Records are the verified records, in file order.
	Records []ScannedRecord
	// TornTail: the last record was incomplete and is dropped.
	TornTail bool
	// Damage names why verification stopped before the end, or is empty.
	Damage string
	// Foreign: the header names another audit; nothing is trusted.
	Foreign bool
}

// ScannedRecord is where one verified record is.
type ScannedRecord struct {
	Chunk    storage.BodyChunk // without DataEnc
	Position int64
	Length   int64
}

// ScanFile reads a staging file and verifies every record: the CRC, the
// chunk metadata, the AEAD and length of its ciphertext under the audit's
// AAD, and that each stage's chunks go forward (seq up, offset at or past the
// previous chunk's end). A stage may skip chunks a checkpoint wrote and
// released while others were staged; the store checks that the file
// continues what the database holds. It stops at the first record that fails. A failing last record
// whose bytes end the file is a torn tail; anything else is damage.
// Opening every chunk costs one decryption per chunk, once per start.
func ScanFile(cipher security.Cipher, auditID, path string) (FileScan, error) {
	if cipher == nil {
		return FileScan{}, errors.New("staging: nil cipher")
	}
	scan := FileScan{AuditID: auditID, Path: path}
	handle, err := os.Open(path)
	if err != nil {
		return scan, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return scan, err
	}
	size := info.Size()
	reader := bufio.NewReaderSize(handle, 1<<20)
	prefix := make([]byte, len(magic)+4)
	read, err := io.ReadFull(reader, prefix)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			if read == 0 || string(prefix[:min(read, len(magic))]) == magic[:min(read, len(magic))] {
				scan.TornTail = true
				return scan, nil
			}
			scan.Foreign = true
			return scan, nil
		}
		return scan, err
	}
	if string(prefix[:len(magic)]) != magic {
		scan.Foreign = true
		return scan, nil
	}
	idLength := int(binary.BigEndian.Uint32(prefix[len(magic):]))
	if idLength == 0 || idLength > maxAuditID {
		scan.Foreign = true
		return scan, nil
	}
	idBytes := make([]byte, idLength)
	if _, err := io.ReadFull(reader, idBytes); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			scan.TornTail = true
			return scan, nil
		}
		return scan, err
	}
	if string(idBytes) != auditID {
		scan.Foreign = true
		return scan, nil
	}
	position := int64(len(prefix) + idLength)
	type next struct{ seq, offset int64 }
	expected := map[string]next{}
	head := make([]byte, recordPrefix)
	var body []byte
	for position < size {
		if size-position < recordPrefix {
			scan.TornTail = true
			return scan, nil
		}
		if _, err := io.ReadFull(reader, head); err != nil {
			return scan, err
		}
		length := int64(binary.BigEndian.Uint32(head[0:4]))
		crc := binary.BigEndian.Uint32(head[4:8])
		end := position + recordPrefix + length
		if end > size {
			scan.TornTail = true
			return scan, nil
		}
		last := end == size
		if length <= recordMeta || length > maxRecordBody {
			scan.Damage = "record_length"
			return scan, nil
		}
		if int64(cap(body)) < length {
			body = make([]byte, length)
		}
		body = body[:length]
		if _, err := io.ReadFull(reader, body); err != nil {
			return scan, err
		}
		if crc32Of(body) != crc {
			if last {
				scan.TornTail = true
			} else {
				scan.Damage = "record_crc"
			}
			return scan, nil
		}
		chunk, err := decodeRecordBody(auditID, body)
		if err == nil {
			err = storage.ValidateOwnedChunk(auditID, chunk)
		}
		if err != nil {
			scan.Damage = "record_metadata"
			return scan, nil
		}
		if want, seen := expected[chunk.Stage]; seen && (chunk.Seq < want.seq || chunk.Offset < want.offset || chunk.Seq == want.seq && chunk.Offset != want.offset) {
			scan.Damage = "record_sequence"
			return scan, nil
		}
		plaintext, err := OpenChunk(cipher, chunk)
		if err != nil {
			scan.Damage = "record_authentication"
			return scan, nil
		}
		clear(plaintext)
		expected[chunk.Stage] = next{seq: chunk.Seq + 1, offset: chunk.Offset + int64(chunk.PlaintextLength)}
		chunk.DataEnc = nil
		scan.Records = append(scan.Records, ScannedRecord{Chunk: chunk, Position: position, Length: recordPrefix + length})
		position = end
	}
	return scan, nil
}

// Source returns a repeatable chunk source over the verified records, read
// from the file on every pass.
func (scan FileScan) Source() storage.ChunkSource {
	return fileSource{scan: scan}
}

type fileSource struct{ scan FileScan }

func (source fileSource) Each(visit func(storage.BodyChunk) error) error {
	if len(source.scan.Records) == 0 {
		return nil
	}
	handle, err := os.Open(source.scan.Path)
	if err != nil {
		return fmt.Errorf("staging: open %s: %w", source.scan.AuditID, err)
	}
	defer handle.Close()
	var buffer []byte
	for _, scanned := range source.scan.Records {
		if int64(cap(buffer)) < scanned.Length {
			buffer = make([]byte, scanned.Length)
		}
		buffer = buffer[:scanned.Length]
		if _, err := handle.ReadAt(buffer, scanned.Position); err != nil {
			return fmt.Errorf("staging: read %s: %w", source.scan.AuditID, err)
		}
		chunk, err := checkRecord(source.scan.AuditID, buffer)
		if err != nil {
			return err
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return nil
}

// EachMetadata yields the chunks without reading their ciphertext, for the
// stores' failure bookkeeping.
func (source fileSource) EachMetadata(visit func(storage.BodyChunk) error) error {
	for _, scanned := range source.scan.Records {
		if err := visit(scanned.Chunk); err != nil {
			return err
		}
	}
	return nil
}
