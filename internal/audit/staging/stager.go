package staging

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// Errors a Stager returns when it cannot take a chunk. The capture session
// stops retaining the stage then (design F.6): ErrFull and ErrClosed give
// capture_budget_exhausted, ErrWriteFailed gives staging_write_failed.
var (
	// ErrFull: audit.staging.max_bytes is reached, the write queue is full, or
	// the file system has no space left.
	ErrFull = errors.New("staging: full")
	// ErrWriteFailed: an earlier write or sync of this audit's file failed.
	ErrWriteFailed = errors.New("staging: write failed")
	// ErrClosed: the stager is closed.
	ErrClosed = errors.New("staging: closed")
	// ErrRemoved: the chunk's file was discarded after its commit.
	ErrRemoved = errors.New("staging: staged chunk removed")
)

// Defaults of Options.
const (
	DefaultMaxBytes   = 4 << 30
	DefaultBatchDelay = 5 * time.Millisecond
	DefaultQueueLimit = 4096
)

// Budget is the process-wide memory budget the write queue counts against
// (F.5). Add never refuses: the plaintext a staged chunk releases is larger
// than or about as large as its ciphertext, so the queue may push the budget
// over its limit only by the AEAD overhead.
type Budget interface {
	Add(bytes int64)
	Release(bytes int64)
}

// Options configures a Stager. The zero value takes the defaults.
type Options struct {
	// MaxBytes bounds the bytes of every file in the directory, including the
	// ones the import renamed and kept.
	MaxBytes int64
	// BatchDelay is how long the writer collects records before it writes
	// them and syncs each file once.
	BatchDelay time.Duration
	// QueueLimit bounds the records waiting for the writer.
	QueueLimit int
	Logger     *slog.Logger
	// Fault, when set, is called before each create, write and sync of a
	// staging file with the operation ("create", "write", "sync") and the
	// audit id; a non-nil result is that operation's error. Tests use it to
	// simulate a full disk or an I/O error.
	Fault func(operation, auditID string) error
}

// Stats are the counters of a Stager, for metrics and measurements.
type Stats struct {
	// BytesWritten counts the file bytes written, headers included.
	BytesWritten int64
	// Fsyncs counts file syncs; directory syncs are DirSyncs.
	Fsyncs   int64
	DirSyncs int64
	Records  int64
	// UsedBytes is what counts against MaxBytes now.
	UsedBytes int64
}

// Stager writes sealed chunks to one file per audit with a background writer
// that groups records for up to BatchDelay and syncs every file it wrote once
// per batch. Staging never blocks the caller: a full queue, a full directory
// or a failed write refuse the next chunk instead.
type Stager struct {
	dir     string
	cipher  security.Cipher
	options Options
	logger  *slog.Logger

	mu       sync.Mutex
	files    map[string]*stagedFile
	queue    []*record
	used     int64
	closed   bool
	busy     bool
	started  bool
	budget   atomic.Value // budgetBox
	noSpace  atomic.Bool
	wake     chan struct{}
	stop     chan struct{}
	done     chan struct{}
	imported bool
	// removeFile and renameFile are os.Remove and os.Rename; tests replace
	// them to make the file system fail.
	removeFile func(string) error
	renameFile func(string, string) error

	bytesWritten atomic.Int64
	fsyncs       atomic.Int64
	dirSyncs     atomic.Int64
	records      atomic.Int64
}

type stagedFile struct {
	stager  *Stager
	auditID string
	path    string

	mu     sync.Mutex
	handle *os.File
	// created: the file exists on disk (it may have failed afterwards).
	created bool
	// size is the end of the last accepted record; reserved is what the file
	// counts against MaxBytes.
	size     int64
	reserved int64
	// held is the ciphertext of this file's records still in memory: queued,
	// or kept because their write failed.
	held    int64
	pending int
	failure error
	removed bool
	// detached: the session is done with the file but keeps it on disk.
	detached bool
}

type record struct {
	file     *stagedFile
	position int64
	length   int64
	head     []byte
	// data is the chunk ciphertext while the record is in memory.
	data []byte
}

// Ref is the index entry of one staged chunk: its metadata and where its
// ciphertext is. The ciphertext stays in memory until the writer has written
// it, so a chunk whose write failed is still readable.
type Ref struct {
	meta   storage.BodyChunk
	record *record
}

// Metadata returns the chunk without its ciphertext.
func (ref *Ref) Metadata() storage.BodyChunk { return ref.meta }

// Size is the bytes the chunk occupies in its file.
func (ref *Ref) Size() int64 { return ref.record.length }

// Chunk returns the sealed chunk, from memory or from its file. It never
// waits for the writer.
func (ref *Ref) Chunk() (storage.BodyChunk, error) {
	file := ref.record.file
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.removed {
		return storage.BodyChunk{}, ErrRemoved
	}
	chunk := ref.meta
	if data := ref.record.data; data != nil {
		chunk.DataEnc = data
		return chunk, nil
	}
	handle, err := os.Open(file.path)
	if err != nil {
		return storage.BodyChunk{}, fmt.Errorf("staging: open %s: %w", file.auditID, err)
	}
	defer handle.Close()
	buffer := make([]byte, ref.record.length)
	if _, err := handle.ReadAt(buffer, ref.record.position); err != nil {
		return storage.BodyChunk{}, fmt.Errorf("staging: read %s: %w", file.auditID, err)
	}
	read, err := checkRecord(file.auditID, buffer)
	if err != nil {
		return storage.BodyChunk{}, err
	}
	if read.Stage != chunk.Stage || read.Seq != chunk.Seq || read.Offset != chunk.Offset ||
		read.PlaintextLength != chunk.PlaintextLength || read.EncodedLength != chunk.EncodedLength ||
		read.ObservedAtNS != chunk.ObservedAtNS || read.Compression != chunk.Compression {
		return storage.BodyChunk{}, fmt.Errorf("staging: record of %s/%d does not match its index", chunk.Stage, chunk.Seq)
	}
	return read, nil
}

// Plaintext opens the staged chunk with the stager's cipher. The finalizer
// and a duplicate stage that borrowed the bytes use it to read staged
// plaintext back.
func (ref *Ref) Plaintext() ([]byte, error) {
	chunk, err := ref.Chunk()
	if err != nil {
		return nil, err
	}
	return OpenChunk(ref.record.file.stager.cipher, chunk)
}

// checkRecord verifies the CRC of one whole record and decodes it.
func checkRecord(auditID string, buffer []byte) (storage.BodyChunk, error) {
	if len(buffer) < recordPrefix {
		return storage.BodyChunk{}, errTruncated
	}
	length := int(uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3]))
	if length != len(buffer)-recordPrefix {
		return storage.BodyChunk{}, errors.New("staging: record length mismatch")
	}
	crc := uint32(buffer[4])<<24 | uint32(buffer[5])<<16 | uint32(buffer[6])<<8 | uint32(buffer[7])
	if crc32Of(buffer[recordPrefix:]) != crc {
		return storage.BodyChunk{}, errCRC
	}
	return decodeRecordBody(auditID, buffer[recordPrefix:])
}

var errCRC = errors.New("staging: record CRC mismatch")

// Open prepares dir for staging and returns a stager over it. dir must be an
// absolute path; it is created with mode 0700 when missing. On Unix an
// existing directory must belong to the process's user and grant nothing to
// group or others; on Windows access is left to the directory's ACL, as for
// the key file. A probe file is created and removed to prove the directory is
// writable. The writer goroutine starts with the first staged chunk.
func Open(dir string, cipher security.Cipher, options Options) (*Stager, error) {
	if cipher == nil {
		return nil, errors.New("staging: nil cipher")
	}
	if err := PrepareDirectory(dir); err != nil {
		return nil, err
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.BatchDelay <= 0 {
		options.BatchDelay = DefaultBatchDelay
	}
	if options.QueueLimit <= 0 {
		options.QueueLimit = DefaultQueueLimit
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	stager := &Stager{
		dir:        filepath.Clean(dir),
		cipher:     cipher,
		options:    options,
		logger:     logger,
		files:      make(map[string]*stagedFile),
		removeFile: os.Remove,
		renameFile: os.Rename,
		wake:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	used, err := directoryUsage(stager.dir)
	if err != nil {
		return nil, err
	}
	stager.used = used
	return stager, nil
}

// PrepareDirectory runs Open's checks on dir: absolute, created 0700 when
// missing, owned by the process's user with no group or other permissions
// (Unix only), and writable.
func PrepareDirectory(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return &DirectoryError{Reason: "not_absolute", Err: fmt.Errorf("staging: directory %q must be an absolute path", dir)}
	}
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return &DirectoryError{Reason: "create_failed", Err: fmt.Errorf("staging: create directory: %w", err)}
		}
		info, err = os.Stat(dir)
	}
	if err != nil {
		return &DirectoryError{Reason: "inspect_failed", Err: fmt.Errorf("staging: inspect directory: %w", err)}
	}
	if !info.IsDir() {
		return &DirectoryError{Reason: "not_directory", Err: fmt.Errorf("staging: %s is not a directory", dir)}
	}
	if err := checkDirectoryAccess(info); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return &DirectoryError{Reason: "not_writable", Err: fmt.Errorf("staging: probe name: %w", err)}
	}
	probe := filepath.Join(dir, ".probe-"+hex.EncodeToString(suffix))
	handle, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return &DirectoryError{Reason: "not_writable", Err: fmt.Errorf("staging: directory is not writable: %w", err)}
	}
	_, writeErr := handle.Write([]byte{0})
	closeErr := handle.Close()
	removeErr := os.Remove(probe)
	if err := errors.Join(writeErr, closeErr, removeErr); err != nil {
		return &DirectoryError{Reason: "not_writable", Err: fmt.Errorf("staging: directory probe failed: %w", err)}
	}
	return nil
}

// DirectoryError is why a staging directory cannot be used. Reason is a
// stable code for logs (not_absolute, create_failed, inspect_failed,
// not_directory, wrong_owner, open_permissions, not_writable); Err carries
// the detail, which may name the path.
type DirectoryError struct {
	Reason string
	Err    error
}

func (err *DirectoryError) Error() string { return err.Err.Error() }
func (err *DirectoryError) Unwrap() error { return err.Err }

// Reason returns the stable code of a staging directory error, or
// "staging_unavailable" for any other error.
func Reason(err error) string {
	var directory *DirectoryError
	if errors.As(err, &directory) {
		return directory.Reason
	}
	return "staging_unavailable"
}

// directoryUsage sums the regular files of dir, all of which count against
// MaxBytes: staging files, and the orphaned and damaged ones the import kept.
func directoryUsage(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("staging: list directory: %w", err)
	}
	var used int64
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if info, err := entry.Info(); err == nil {
			used += info.Size()
		}
	}
	return used, nil
}

// SetBudget makes the write queue count against budget (F.5). Call it before
// the first chunk is staged.
func (stager *Stager) SetBudget(budget Budget) {
	stager.budget.Store(budgetBox{budget})
}

type budgetBox struct{ Budget }

func (stager *Stager) currentBudget() Budget {
	box, _ := stager.budget.Load().(budgetBox)
	return box.Budget
}

// Dir returns the staging directory.
func (stager *Stager) Dir() string { return stager.dir }

// Stage queues one sealed chunk for its audit's file and returns its index
// entry. It takes ownership of chunk.DataEnc, which must not change
// afterwards. It does not block: it refuses with ErrFull when MaxBytes or the
// queue limit would be exceeded or the disk is full, with ErrWriteFailed when
// this audit's file failed, and with ErrClosed after Close.
func (stager *Stager) Stage(chunk storage.BodyChunk) (*Ref, error) {
	if err := storage.ValidateOwnedChunk(chunk.AuditID, chunk); err != nil || chunk.AuditID == "" {
		return nil, fmt.Errorf("%w: invalid chunk: %v", ErrWriteFailed, err)
	}
	head, err := encodeRecordHead(chunk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	length := int64(len(head) + len(chunk.DataEnc))
	stager.mu.Lock()
	defer stager.mu.Unlock()
	if stager.closed {
		return nil, ErrClosed
	}
	file := stager.files[chunk.AuditID]
	needed := length
	if file == nil {
		file = &stagedFile{stager: stager, auditID: chunk.AuditID, path: filepath.Join(stager.dir, chunk.AuditID+Suffix)}
		file.size = int64(len(encodeHeader(chunk.AuditID)))
		needed += file.size
	} else {
		file.mu.Lock()
		failure := file.failure
		file.mu.Unlock()
		if failure != nil {
			return nil, failure
		}
	}
	switch {
	case stager.noSpace.Load():
		return nil, fmt.Errorf("%w: no space left on the staging file system", ErrFull)
	case stager.used+needed > stager.options.MaxBytes:
		return nil, fmt.Errorf("%w: audit.staging.max_bytes reached", ErrFull)
	case len(stager.queue) >= stager.options.QueueLimit:
		return nil, fmt.Errorf("%w: write queue full", ErrFull)
	}
	stager.files[chunk.AuditID] = file
	stager.used += needed
	file.mu.Lock()
	file.reserved += needed
	entry := &record{file: file, position: file.size, length: length, head: head, data: chunk.DataEnc}
	file.size += length
	file.pending++
	file.held += int64(len(chunk.DataEnc))
	file.mu.Unlock()
	stager.queue = append(stager.queue, entry)
	if budget := stager.currentBudget(); budget != nil {
		budget.Add(int64(len(chunk.DataEnc)))
	}
	if !stager.started {
		stager.started = true
		go stager.run()
	}
	select {
	case stager.wake <- struct{}{}:
	default:
	}
	meta := chunk
	meta.DataEnc = nil
	return &Ref{meta: meta, record: entry}, nil
}

// Discard drops what is staged for an audit and removes its file. The
// session calls it once its commit is acknowledged; records still queued are
// not written. It is idempotent.
func (stager *Stager) Discard(auditID string) {
	stager.mu.Lock()
	file := stager.files[auditID]
	delete(stager.files, auditID)
	if file == nil {
		stager.mu.Unlock()
		return
	}
	file.mu.Lock()
	file.removed = true
	if file.handle != nil {
		_ = file.handle.Close()
		file.handle = nil
	}
	held := file.held
	file.held = 0
	removeErr := error(nil)
	if file.created {
		removeErr = stager.removeFile(file.path)
	}
	file.mu.Unlock()
	stager.used -= file.reserved
	stager.noSpace.Store(false)
	budget := stager.currentBudget()
	stager.mu.Unlock()
	if budget != nil {
		budget.Release(held)
	}
	if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		stager.logger.Warn("audit staging file not removed", "audit_id", auditID, "error_category", "staging_remove_failed", "reason", fileErrorReason(removeErr))
	}
}

// Keep ends the session's use of an audit's file but leaves it on disk: the
// commit did not succeed. The store that remembered the failure inserts the
// staged chunks when it finalizes the audit and then calls Discard; if the
// process stops first, the next start imports them. Queued records are still
// written, and records whose write failed keep their ciphertext in memory, so
// every staged chunk stays readable until Discard. The file keeps counting
// against MaxBytes. It is idempotent.
func (stager *Stager) Keep(auditID string) {
	stager.mu.Lock()
	file := stager.files[auditID]
	stager.mu.Unlock()
	if file == nil {
		return
	}
	file.mu.Lock()
	file.detached = true
	if file.pending == 0 && file.handle != nil {
		_ = file.handle.Close()
		file.handle = nil
	}
	file.mu.Unlock()
}

// Flush waits until every record staged before the call is written and
// synced, or its write failed.
func (stager *Stager) Flush() {
	for {
		stager.mu.Lock()
		idle := len(stager.queue) == 0 && !stager.busy
		stager.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Close writes and syncs what is queued, stops the writer and closes every
// file. Files stay on disk for the next start to import.
func (stager *Stager) Close() error {
	stager.mu.Lock()
	if stager.closed {
		stager.mu.Unlock()
		return nil
	}
	stager.closed = true
	started := stager.started
	stager.mu.Unlock()
	if started {
		close(stager.stop)
		<-stager.done
	}
	stager.mu.Lock()
	defer stager.mu.Unlock()
	for _, file := range stager.files {
		file.mu.Lock()
		if file.handle != nil {
			_ = file.handle.Close()
			file.handle = nil
		}
		file.mu.Unlock()
	}
	return nil
}

// processTotals add up the counters of every Stager in the process, so a
// measurement that runs the application in its own process (cmd/audit-bench)
// can read them without a handle on the Stager the application opened.
var processTotals struct {
	bytesWritten, fsyncs, dirSyncs, records atomic.Int64
}

// ProcessStats returns the counters of every Stager this process opened,
// added up; UsedBytes is zero.
func ProcessStats() Stats {
	return Stats{
		BytesWritten: processTotals.bytesWritten.Load(),
		Fsyncs:       processTotals.fsyncs.Load(),
		DirSyncs:     processTotals.dirSyncs.Load(),
		Records:      processTotals.records.Load(),
	}
}

func (stager *Stager) countBytes(bytes int64) {
	stager.bytesWritten.Add(bytes)
	processTotals.bytesWritten.Add(bytes)
}

// Stats returns the stager's counters.
func (stager *Stager) Stats() Stats {
	stager.mu.Lock()
	used := stager.used
	stager.mu.Unlock()
	return Stats{
		BytesWritten: stager.bytesWritten.Load(),
		Fsyncs:       stager.fsyncs.Load(),
		DirSyncs:     stager.dirSyncs.Load(),
		Records:      stager.records.Load(),
		UsedBytes:    used,
	}
}

func (stager *Stager) run() {
	defer close(stager.done)
	for {
		stopping := false
		select {
		case <-stager.wake:
			timer := time.NewTimer(stager.options.BatchDelay)
			select {
			case <-timer.C:
			case <-stager.stop:
				timer.Stop()
				stopping = true
			}
		case <-stager.stop:
			stopping = true
		}
		stager.mu.Lock()
		batch := stager.queue
		stager.queue = nil
		stager.busy = len(batch) > 0
		stager.mu.Unlock()
		if len(batch) > 0 {
			stager.writeBatch(batch)
			stager.mu.Lock()
			stager.busy = false
			stager.mu.Unlock()
		}
		if stopping {
			stager.mu.Lock()
			rest := stager.queue
			stager.queue = nil
			stager.mu.Unlock()
			if len(rest) > 0 {
				stager.writeBatch(rest)
			}
			return
		}
	}
}

// writeBatch writes the records in order, then syncs each file it wrote once
// and, when it created files, the directory.
func (stager *Stager) writeBatch(batch []*record) {
	touched := make([]*stagedFile, 0, 4)
	seen := make(map[*stagedFile]bool, 4)
	created := false
	for _, entry := range batch {
		file := entry.file
		wrote, made := stager.writeRecord(entry)
		created = created || made
		if wrote && !seen[file] {
			seen[file] = true
			touched = append(touched, file)
		}
	}
	for _, file := range touched {
		stager.syncFile(file)
	}
	if created {
		if err := syncDirectory(stager.dir); err == nil {
			stager.dirSyncs.Add(1)
			processTotals.dirSyncs.Add(1)
		}
	}
}

func (stager *Stager) writeRecord(entry *record) (wrote, created bool) {
	file := entry.file
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.removed {
		return false, false
	}
	file.pending--
	if file.failure != nil {
		return false, false
	}
	if file.handle == nil {
		if file.created {
			// Kept after an earlier batch closed it: append to it again.
			handle, err := os.OpenFile(file.path, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				stager.fail(file, err)
				return false, false
			}
			file.handle = handle
		} else {
			if err := stager.fault("create", file.auditID); err != nil {
				stager.fail(file, err)
				return false, false
			}
			handle, err := os.OpenFile(file.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				stager.fail(file, err)
				return false, false
			}
			file.handle, file.created, created = handle, true, true
			header := encodeHeader(file.auditID)
			if err := writeAll(file.handle, header); err != nil {
				stager.fail(file, err)
				return false, created
			}
			stager.countBytes(int64(len(header)))
		}
	}
	if err := stager.fault("write", file.auditID); err != nil {
		stager.fail(file, err)
		return false, created
	}
	if err := writeAll(file.handle, entry.head); err != nil {
		stager.fail(file, err)
		return false, created
	}
	if err := writeAll(file.handle, entry.data); err != nil {
		stager.fail(file, err)
		return false, created
	}
	stager.countBytes(entry.length)
	stager.records.Add(1)
	processTotals.records.Add(1)
	size := int64(len(entry.data))
	entry.data = nil
	file.held -= size
	stager.release(size)
	return true, created
}

func (stager *Stager) syncFile(file *stagedFile) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.removed || file.handle == nil {
		return
	}
	err := stager.fault("sync", file.auditID)
	if err == nil {
		err = file.handle.Sync()
	}
	stager.fsyncs.Add(1)
	processTotals.fsyncs.Add(1)
	if err != nil {
		stager.fail(file, err)
		return
	}
	if file.detached && file.pending == 0 {
		_ = file.handle.Close()
		file.handle = nil
	}
}

// fail records a write failure on a file, under its lock. The records it did
// not write keep their ciphertext in memory, so what was staged is still
// readable; the next chunk for this audit is refused.
func (stager *Stager) fail(file *stagedFile, err error) {
	if noSpace(err) {
		file.failure = fmt.Errorf("%w: no space left on the staging file system", ErrFull)
		stager.noSpace.Store(true)
	} else {
		file.failure = fmt.Errorf("%w: %v", ErrWriteFailed, err)
	}
	if file.handle != nil {
		_ = file.handle.Close()
		file.handle = nil
	}
	stager.logger.Warn("audit staging write failed", "audit_id", file.auditID, "error_code", stagingErrorCode(file.failure))
}

// stagingErrorCode names a file failure with the stage error code it leads
// to (design F.6), so the writer's log and the stage agree: a full directory
// or disk is capture_budget_exhausted, anything else staging_write_failed.
func stagingErrorCode(err error) string {
	if errors.Is(err, ErrFull) {
		return "capture_budget_exhausted"
	}
	return "staging_write_failed"
}

// fileErrorReason is a stable code for a file system error, for logs, which
// never carry the error text: it may name paths.
func fileErrorReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not_found"
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case noSpace(err):
		return "no_space"
	default:
		return "io_error"
	}
}

func (stager *Stager) release(size int64) {
	if budget := stager.currentBudget(); budget != nil && size > 0 {
		budget.Release(size)
	}
}

func (stager *Stager) fault(operation, auditID string) error {
	if stager.options.Fault == nil {
		return nil
	}
	return stager.options.Fault(operation, auditID)
}

func writeAll(handle *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := handle.Write(data)
		if err != nil {
			return err
		}
		data = data[written:]
	}
	return nil
}

// auditIDOf returns the audit id a staging file name stands for.
func auditIDOf(name string) (string, bool) {
	id, ok := strings.CutSuffix(name, Suffix)
	if !ok || id == "" || len(id) > maxAuditID || strings.ContainsAny(id, `/\.`) {
		return "", false
	}
	return id, true
}
