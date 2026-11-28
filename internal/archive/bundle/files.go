package bundle

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"llmapi-logger/internal/archive/stream"
)

// Fault operations: Options.Fault is called with one of these and the path
// before the operation; a non-nil result is that operation's error. Tests
// use it to simulate a full disk or an I/O error at every step.
const (
	FaultMkdir   = "mkdir"
	FaultCreate  = "create"
	FaultWrite   = "write"
	FaultSync    = "sync"
	FaultClose   = "close"
	FaultLink    = "link"
	FaultDirSync = "dirsync"
)

// MaxEntryBytes bounds one line of any data file. The writer refuses a longer
// entry and the reader stops at it, so a damaged file without newlines cannot
// make the reader buffer the whole stream.
const MaxEntryBytes = 1 << 30

const ioBufferSize = 64 << 10

type faults func(operation, path string) error

func (f faults) check(operation, path string) error {
	if f == nil {
		return nil
	}
	return f(operation, path)
}

func writeReason(err error) string {
	if noSpace(err) {
		return ReasonDiskFull
	}
	return ReasonWriteFailed
}

func randomHex(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fail(ReasonRandomFailed, err)
	}
	return hex.EncodeToString(buffer), nil
}

// outFile is a temporary file being written: every write goes through the
// fault hook and into the SHA-256 of the stored bytes.
type outFile struct {
	faults faults
	path   string
	file   *os.File
	digest hash.Hash
	size   int64
	closed bool
}

func createTemp(f faults, dir, segmentID, role string) (*outFile, error) {
	random, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, tempName(segmentID, role, random))
	if err := f.check(FaultCreate, path); err != nil {
		return nil, fail(ReasonCreateFailed, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if noSpace(err) {
			return nil, fail(ReasonDiskFull, err)
		}
		return nil, fail(ReasonCreateFailed, err)
	}
	return &outFile{faults: f, path: path, file: file, digest: sha256.New()}, nil
}

func (out *outFile) Write(p []byte) (int, error) {
	if err := out.faults.check(FaultWrite, out.path); err != nil {
		return 0, err
	}
	n, err := out.file.Write(p)
	_, _ = out.digest.Write(p[:n])
	out.size += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// finish syncs and closes the file.
func (out *outFile) finish() error {
	if err := out.faults.check(FaultSync, out.path); err != nil {
		return fail(ReasonSyncFailed, err)
	}
	if err := out.file.Sync(); err != nil {
		return fail(ReasonSyncFailed, err)
	}
	if err := out.faults.check(FaultClose, out.path); err != nil {
		return fail(ReasonCloseFailed, err)
	}
	out.closed = true
	if err := out.file.Close(); err != nil {
		return fail(ReasonCloseFailed, err)
	}
	return nil
}

func (out *outFile) sum() [32]byte {
	var sum [32]byte
	copy(sum[:], out.digest.Sum(nil))
	return sum
}

// discard closes the file if needed and removes it. It is the only removal
// the writer does, and only of a file it created under the temporary naming.
func (out *outFile) discard() {
	if out == nil {
		return
	}
	if !out.closed {
		out.closed = true
		_ = out.file.Close()
	}
	_ = os.Remove(out.path)
}

// encodedFile is the JSONL → gzip → (stream) → outFile pipeline of one data
// file. Plain counts the uncompressed bytes for rolling (B.4).
type encodedFile struct {
	out       *outFile
	buffer    *bufio.Writer
	encrypter *stream.Writer
	gzip      *gzip.Writer
	plain     int64
	entries   int64
}

func newEncodedFile(f faults, dir, segmentID, role string, key []byte) (*encodedFile, error) {
	out, err := createTemp(f, dir, segmentID, role)
	if err != nil {
		return nil, err
	}
	encoded := &encodedFile{out: out, buffer: bufio.NewWriterSize(out, ioBufferSize)}
	var sink io.Writer = encoded.buffer
	if key != nil {
		encrypter, err := stream.NewWriter(encoded.buffer, key)
		if err != nil {
			out.discard()
			return nil, fail(writeReason(err), err)
		}
		encoded.encrypter, sink = encrypter, encrypter
	}
	encoded.gzip = gzip.NewWriter(sink)
	return encoded, nil
}

func (encoded *encodedFile) writeEntry(entry []byte) error {
	if len(entry) > MaxEntryBytes {
		return fail(ReasonEntryTooLarge, fmt.Errorf("entry of %d bytes", len(entry)))
	}
	if _, err := encoded.gzip.Write(entry); err != nil {
		return fail(writeReason(err), err)
	}
	if _, err := encoded.gzip.Write([]byte{'\n'}); err != nil {
		return fail(writeReason(err), err)
	}
	encoded.plain += int64(len(entry)) + 1
	encoded.entries++
	return nil
}

// close finishes the gzip stream, seals the last frame, flushes, syncs and
// closes the file.
func (encoded *encodedFile) close() error {
	if err := encoded.gzip.Close(); err != nil {
		return fail(writeReason(err), err)
	}
	if encoded.encrypter != nil {
		if err := encoded.encrypter.Close(); err != nil {
			return fail(writeReason(err), err)
		}
	}
	if err := encoded.buffer.Flush(); err != nil {
		return fail(writeReason(err), err)
	}
	return encoded.out.finish()
}

func (encoded *encodedFile) discard() {
	if encoded != nil {
		encoded.out.discard()
	}
}

// writeWhole writes data as a temporary file, syncs and closes it.
func writeWhole(f faults, dir, segmentID, role string, data []byte) (*outFile, error) {
	out, err := createTemp(f, dir, segmentID, role)
	if err != nil {
		return nil, err
	}
	buffer := bufio.NewWriterSize(out, ioBufferSize)
	if _, err := buffer.Write(data); err != nil {
		out.discard()
		return nil, fail(writeReason(err), err)
	}
	if err := buffer.Flush(); err != nil {
		out.discard()
		return nil, fail(writeReason(err), err)
	}
	if err := out.finish(); err != nil {
		out.discard()
		return nil, err
	}
	return out, nil
}

// syncDir runs the fault hook and the platform directory sync.
func syncDir(f faults, dir string) error {
	if err := f.check(FaultDirSync, dir); err != nil {
		return fail(ReasonDirSyncFailed, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fail(ReasonDirSyncFailed, err)
	}
	return nil
}

// makeDirs creates dir and its missing parents up to (not including) root
// with 0700 and syncs the parent of every directory it created.
func makeDirs(f faults, root, dir string) error {
	relative, err := filepath.Rel(root, dir)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 2 && relative[:2] == ".." {
		return fail(ReasonInvalidOptions, errors.New("directory outside the archive root"))
	}
	var missing []string
	for current := dir; current != root; current = filepath.Dir(current) {
		if _, err := os.Stat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fail(ReasonMkdirFailed, err)
		}
		missing = append(missing, current)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		current := missing[index]
		if err := f.check(FaultMkdir, current); err != nil {
			return fail(ReasonMkdirFailed, err)
		}
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			if noSpace(err) {
				return fail(ReasonDiskFull, err)
			}
			return fail(ReasonMkdirFailed, err)
		}
		if err := syncDir(f, filepath.Dir(current)); err != nil {
			return err
		}
	}
	return nil
}

// linkNew publishes source under target without ever replacing target: a
// hard link fails when target exists (as security/key.go publishes keys).
func linkNew(f faults, source, target string) error {
	if err := f.check(FaultLink, target); err != nil {
		return fail(ReasonLinkFailed, err)
	}
	if err := os.Link(source, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fail(ReasonNameExists, err)
		}
		return fail(ReasonLinkFailed, err)
	}
	return nil
}

// renameAside gives path a new name ending in suffix without replacing any
// file: path + suffix, or path + ".<n>" + suffix when that exists. The new
// name is linked first and the old one removed, so the file is never lost.
func renameAside(path, suffix string) (string, error) {
	for attempt := 1; attempt <= 100; attempt++ {
		target := path + suffix
		if attempt > 1 {
			target = fmt.Sprintf("%s.%d%s", path, attempt, suffix)
		}
		err := os.Link(path, target)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", fail(ReasonRenameFailed, err)
		}
		if err := os.Remove(path); err != nil {
			return target, fail(ReasonRenameFailed, err)
		}
		return target, nil
	}
	return "", fail(ReasonRenameFailed, errors.New("no free name"))
}
