// Package stream implements the framed authenticated encryption of cold-archive
// bundle files (doc/design/issue-59-stage4-cold-archive.md G.2).
//
// Construction. This is the STREAM construction of Hoang, Reyhanitabar,
// Rogaway and Vizár (2015) over AES-256-GCM, as used by age and Tink:
//
//	header  = "LLAR" || 0x01 || 0x10 || 0x00 0x00 || salt[32]        (40 bytes)
//	K_file  = HMAC-SHA-256(K_enc, "llmapi-logger/archive-file-key/v1\x00" || header)
//	nonce_i = uint88_be(i) || (0x01 if frame i is the last frame else 0x00)
//	C_i     = AES-256-GCM-Seal(K_file, nonce_i, P_i, AAD = empty)
//	file    = header || C_0 || ... || C_n
//
// The plaintext is cut into 65,536-byte frames. Every frame but the last is
// exactly that size; the last holds 0 to 65,536 bytes and is empty only when
// the whole plaintext is empty. There are no length fields: every non-final
// sealed frame is 65,552 bytes, and the frame that reaches end of file is the
// last one.
//
// Security argument. The salt is 32 random bytes per file, so each file gets
// its own key and a (key, nonce) pair never repeats across files; within a
// file the counter never repeats. GCM authenticates each frame on its own, so
// a reader releases a frame's plaintext only after its tag verifies. The
// counter in the nonce binds each frame to its position (reordering, dropping
// or duplicating frames fails), the last-frame byte binds the end of the
// stream (cutting at a frame boundary leaves a last frame that was sealed as
// non-final, and appending bytes moves the real last frame to a non-final
// position), the salt binds frames to their file (splicing from another file
// under the same K_enc fails), and every header byte feeds K_file (a changed
// header changes the key, so frame 0 fails). A wrong K_enc fails at frame 0.
//
// A reader that fails part-way has already returned the earlier, authentic
// frames. Callers must treat any read error as voiding the whole file.
package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	// KeySize is the length of K_enc.
	KeySize = 32
	// HeaderSize is the length of the file header.
	HeaderSize = 40
	// FrameSize is the plaintext length of every frame but the last.
	FrameSize = 1 << frameSizeLog2
	// Overhead is the GCM tag added to every frame.
	Overhead = 16
	// SealedFrameSize is the on-disk length of every frame but the last.
	SealedFrameSize = FrameSize + Overhead

	formatVersion = 0x01
	frameSizeLog2 = 16
	saltSize      = 32
	nonceSize     = 12
	fileKeyDomain = "llmapi-logger/archive-file-key/v1\x00"
)

var magic = [4]byte{'L', 'L', 'A', 'R'}

var (
	// ErrFormat reports a header with a wrong magic, version, frame size or
	// reserved bytes, or a non-canonical empty last frame after other frames.
	ErrFormat = errors.New("stream: invalid archive stream format")
	// ErrTruncated reports a file that ends inside the header or before a
	// complete last frame.
	ErrTruncated = errors.New("stream: truncated archive stream")
	// ErrAuthentication reports a frame whose tag does not verify: a wrong
	// key, a modified byte, or frames that were cut, reordered, duplicated,
	// spliced or followed by extra bytes.
	ErrAuthentication = errors.New("stream: archive frame failed authentication")

	errClosed  = errors.New("stream: write after close")
	errTooLong = errors.New("stream: frame counter exhausted")
)

// Writer encrypts as it is written. Close seals the last frame; a file whose
// writer was never closed has no last frame and every reader rejects it.
// Close does not close the destination.
type Writer struct {
	dst     io.Writer
	aead    cipher.AEAD
	buffer  []byte
	sealed  []byte
	counter uint64
	closed  bool
	err     error
}

// NewWriter writes a header with a fresh random salt to dst and returns a
// writer that encrypts under key (K_enc, KeySize bytes). The key is not
// retained.
func NewWriter(dst io.Writer, key []byte) (*Writer, error) {
	var salt [saltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("stream: generate salt: %w", err)
	}
	return newWriterWithSalt(dst, key, salt)
}

func newWriterWithSalt(dst io.Writer, key []byte, salt [saltSize]byte) (*Writer, error) {
	header := encodeHeader(salt)
	aead, err := fileCipher(key, header[:])
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(header[:]); err != nil {
		return nil, err
	}
	return &Writer{
		dst:    dst,
		aead:   aead,
		buffer: make([]byte, 0, FrameSize),
		sealed: make([]byte, 0, SealedFrameSize),
	}, nil
}

// Write buffers p and emits a non-final frame each time a full frame is
// buffered and more data follows. A full buffer is held until then, because
// it may still become the last frame.
func (writer *Writer) Write(p []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}
	if writer.closed {
		return 0, errClosed
	}
	written := 0
	for len(p) > 0 {
		if len(writer.buffer) == FrameSize {
			if err := writer.seal(false); err != nil {
				return written, err
			}
		}
		n := min(FrameSize-len(writer.buffer), len(p))
		writer.buffer = append(writer.buffer, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

// Close seals whatever is buffered, possibly nothing or a full frame, as the
// last frame. After an earlier error it writes nothing and returns that error.
// Calling Close again returns the first result.
func (writer *Writer) Close() error {
	if writer.closed {
		return writer.err
	}
	writer.closed = true
	if writer.err != nil {
		return writer.err
	}
	return writer.seal(true)
}

func (writer *Writer) seal(final bool) error {
	if writer.counter == math.MaxUint64 {
		writer.err = errTooLong
		return writer.err
	}
	nonce := frameNonce(writer.counter, final)
	writer.sealed = writer.aead.Seal(writer.sealed[:0], nonce[:], writer.buffer, nil)
	writer.buffer = writer.buffer[:0]
	writer.counter++
	if _, err := writer.dst.Write(writer.sealed); err != nil {
		writer.err = err
		return err
	}
	return nil
}

// Reader decrypts a stream written by Writer. It authenticates each frame
// before returning any of its plaintext and holds at most one sealed frame
// plus one byte of lookahead in memory. Errors are sticky.
type Reader struct {
	src       io.Reader
	aead      cipher.AEAD
	frame     []byte
	plain     []byte
	lookahead [1]byte
	hasAhead  bool
	counter   uint64
	done      bool
	err       error
}

// NewReader reads and checks the header from src and returns a reader that
// decrypts under key (K_enc, KeySize bytes). The key is not retained.
func NewReader(src io.Reader, key []byte) (*Reader, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("stream: key must be exactly %d bytes", KeySize)
	}
	var header [HeaderSize]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: header", ErrTruncated)
		}
		return nil, err
	}
	if [4]byte(header[0:4]) != magic || header[4] != formatVersion || header[5] != frameSizeLog2 ||
		header[6] != 0 || header[7] != 0 {
		return nil, fmt.Errorf("%w: header", ErrFormat)
	}
	aead, err := fileCipher(key, header[:])
	if err != nil {
		return nil, err
	}
	return &Reader{src: src, aead: aead, frame: make([]byte, 0, SealedFrameSize)}, nil
}

// Read returns authenticated plaintext. It returns io.EOF only after the last
// frame has verified.
func (reader *Reader) Read(p []byte) (int, error) {
	for len(reader.plain) == 0 {
		if reader.err != nil {
			return 0, reader.err
		}
		if reader.done {
			return 0, io.EOF
		}
		if err := reader.next(); err != nil {
			reader.plain = nil
			reader.err = err
			return 0, err
		}
	}
	n := copy(p, reader.plain)
	reader.plain = reader.plain[n:]
	return n, nil
}

// next reads up to one sealed frame plus one byte. A full frame followed by at
// least one more byte is non-final; whatever reaches end of file is the last
// frame.
func (reader *Reader) next() error {
	frame := reader.frame[:SealedFrameSize]
	start := 0
	if reader.hasAhead {
		frame[0] = reader.lookahead[0]
		start = 1
		reader.hasAhead = false
	}
	n, err := io.ReadFull(reader.src, frame[start:])
	length := start + n
	final := false
	switch {
	case err == nil:
		_, err = io.ReadFull(reader.src, reader.lookahead[:])
		switch {
		case err == nil:
			reader.hasAhead = true
		case errors.Is(err, io.EOF):
			final = true
		default:
			return err
		}
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		final = true
	default:
		return err
	}
	frame = frame[:length]
	if length < Overhead {
		return fmt.Errorf("%w: frame %d", ErrTruncated, reader.counter)
	}
	if final && length == Overhead && reader.counter > 0 {
		// Writer never emits an empty last frame after another frame.
		return fmt.Errorf("%w: empty last frame %d", ErrFormat, reader.counter)
	}
	if reader.counter == math.MaxUint64 {
		return errTooLong
	}
	nonce := frameNonce(reader.counter, final)
	plain, err := reader.aead.Open(frame[:0], nonce[:], frame, nil)
	if err != nil {
		return fmt.Errorf("%w: frame %d", ErrAuthentication, reader.counter)
	}
	reader.counter++
	reader.plain = plain
	reader.done = final
	return nil
}

func encodeHeader(salt [saltSize]byte) [HeaderSize]byte {
	var header [HeaderSize]byte
	copy(header[0:4], magic[:])
	header[4] = formatVersion
	header[5] = frameSizeLog2
	copy(header[8:], salt[:])
	return header
}

// fileCipher derives K_file from K_enc and the whole header and returns the
// AES-256-GCM instance keyed with it. Neither key is kept outside the cipher.
func fileCipher(key, header []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("stream: key must be exactly %d bytes", KeySize)
	}
	derivation := hmac.New(sha256.New, key)
	_, _ = derivation.Write([]byte(fileKeyDomain))
	_, _ = derivation.Write(header)
	fileKey := derivation.Sum(nil)
	defer clear(fileKey)
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// frameNonce is the 11-byte big-endian frame counter followed by the
// last-frame flag. The counter is a uint64, so the top three bytes are zero.
func frameNonce(counter uint64, final bool) [nonceSize]byte {
	var nonce [nonceSize]byte
	for i := 10; i >= 3; i-- {
		nonce[i] = byte(counter)
		counter >>= 8
	}
	if final {
		nonce[11] = 0x01
	}
	return nonce
}
