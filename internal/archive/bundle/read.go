package bundle

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/stream"
)

// hashingReader hashes and counts the stored bytes as they are read. Its
// errors are read_failed.
type hashingReader struct {
	file   *os.File
	digest hash.Hash
	size   int64
}

func (reader *hashingReader) Read(p []byte) (int, error) {
	n, err := reader.file.Read(p)
	_, _ = reader.digest.Write(p[:n])
	reader.size += int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		err = fail(ReasonReadFailed, err)
	}
	return n, err
}

// markReader turns every error of the layer below except io.EOF into a
// *Error with reason, unless it already is one.
type markReader struct {
	source io.Reader
	reason string
}

func (reader markReader) Read(p []byte) (int, error) {
	n, err := reader.source.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = keep(reader.reason, err)
	}
	return n, err
}

// dataReader reads the entries of one data file: stored bytes → SHA-256 →
// (stream decryption) → gunzip → lines. Each next returns one entry; finish,
// after io.EOF, checks that nothing follows the gzip member and that the
// stored size and SHA-256 equal the manifest's. Any error voids the file
// (G.3): callers stop at the first one.
type dataReader struct {
	file     *os.File
	hashing  *hashingReader
	source   *bufio.Reader // what gzip reads; checked for trailing bytes
	gzip     *gzip.Reader
	lines    *bufio.Reader
	expected archive.ManifestFile
}

func openData(path string, expected archive.ManifestFile, key []byte) (*dataReader, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fail(ReasonFileMissing, err)
	}
	if err != nil {
		return nil, fail(ReasonReadFailed, err)
	}
	reader := &dataReader{file: file, hashing: &hashingReader{file: file, digest: sha256.New()}, expected: expected}
	var plain io.Reader = bufio.NewReaderSize(reader.hashing, ioBufferSize)
	if key != nil {
		decrypter, err := stream.NewReader(plain, key)
		if err != nil {
			_ = file.Close()
			return nil, keep(ReasonDecryptFailed, err)
		}
		plain = markReader{source: decrypter, reason: ReasonDecryptFailed}
	}
	reader.source = bufio.NewReaderSize(plain, ioBufferSize)
	decompressor, err := gzip.NewReader(reader.source)
	if err != nil {
		_ = file.Close()
		return nil, keep(ReasonDecompressFailed, err)
	}
	decompressor.Multistream(false)
	reader.gzip = decompressor
	reader.lines = bufio.NewReaderSize(markReader{source: decompressor, reason: ReasonDecompressFailed}, ioBufferSize)
	return reader, nil
}

// next returns the next entry without its newline, or io.EOF at the end.
// The returned slice is only valid until the next call.
func (reader *dataReader) next() ([]byte, error) {
	var line []byte
	for {
		fragment, err := reader.lines.ReadSlice('\n')
		if len(line)+len(fragment) > MaxEntryBytes+1 {
			return nil, fail(ReasonLineInvalid, errors.New("entry too long"))
		}
		switch {
		case err == nil:
			if line == nil {
				return fragment[:len(fragment)-1], nil
			}
			line = append(line, fragment...)
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			line = append(line, fragment...)
		case errors.Is(err, io.EOF):
			if len(line)+len(fragment) > 0 {
				return nil, fail(ReasonLineInvalid, errors.New("last entry without a newline"))
			}
			return nil, io.EOF
		default:
			return nil, keep(ReasonDecompressFailed, err)
		}
	}
}

func (reader *dataReader) finish() error {
	if _, err := reader.source.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fail(ReasonDecompressFailed, errors.New("data after the gzip member"))
		}
		return keep(ReasonDecompressFailed, err)
	}
	if reader.hashing.size != reader.expected.Bytes || [32]byte(reader.hashing.digest.Sum(nil)) != reader.expected.SHA256 {
		return fail(ReasonFileMismatch, errors.New("stored bytes differ from the manifest"))
	}
	return nil
}

func (reader *dataReader) close() { _ = reader.file.Close() }

// eachEntry calls visit for every entry of a data file and then checks the
// file's end, size and SHA-256.
func eachEntry(ctx context.Context, path string, expected archive.ManifestFile, key []byte, visit func([]byte) error) error {
	reader, err := openData(path, expected, key)
	if err != nil {
		return err
	}
	defer reader.close()
	for count := 0; ; count++ {
		if count%256 == 0 {
			if err := checkContext(ctx); err != nil {
				return err
			}
		}
		entry, err := reader.next()
		if errors.Is(err, io.EOF) {
			return reader.finish()
		}
		if err != nil {
			return err
		}
		if err := visit(entry); err != nil {
			return err
		}
	}
}

// hashFile checks one file's stored size and SHA-256 against the manifest,
// without any key.
func hashFile(ctx context.Context, path string, expected archive.ManifestFile) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return fail(ReasonFileMissing, err)
	}
	if err != nil {
		return fail(ReasonReadFailed, err)
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return fail(ReasonReadFailed, err)
	}
	if size != expected.Bytes || [32]byte(digest.Sum(nil)) != expected.SHA256 {
		return fail(ReasonFileMismatch, fmt.Errorf("%s differs from the manifest", expected.Role))
	}
	return nil
}
