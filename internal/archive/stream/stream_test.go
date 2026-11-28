package stream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

// The vectors in testdata/vectors.json pin the G.3 byte layout. They are
// checked against both Writer and the straight-line reference encoder below,
// so a change to either one fails. Regenerate with:
// go test ./internal/archive/stream -run Vectors -update
var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

const plaintextDomain = "llmapi-logger/archive-stream-test-plaintext\x00"

// testKey and testSalt are synthetic constants, not real keys.
func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func testSalt(seed byte) [saltSize]byte {
	var salt [saltSize]byte
	for i := range salt {
		salt[i] = seed + byte(i)
	}
	return salt
}

// testPlaintext is block j = SHA-256(plaintextDomain || uint64_be(j)),
// concatenated and cut to length.
func testPlaintext(length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	var counter [8]byte
	for j := uint64(0); len(out) < length; j++ {
		binary.BigEndian.PutUint64(counter[:], j)
		block := sha256.Sum256(append([]byte(plaintextDomain), counter[:]...))
		out = append(out, block[:]...)
	}
	return out[:length]
}

// referenceFileKey and referenceEncrypt restate G.2 without any streaming
// logic, independently of the package code.
func referenceFileKey(key []byte, salt [saltSize]byte) []byte {
	header := append([]byte{'L', 'L', 'A', 'R', 0x01, 0x10, 0x00, 0x00}, salt[:]...)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("llmapi-logger/archive-file-key/v1\x00"))
	mac.Write(header)
	return mac.Sum(nil)
}

func referenceSeal(fileKey []byte, index uint64, final bool, plain []byte) []byte {
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[3:11], index)
	if final {
		nonce[11] = 1
	}
	return aead.Seal(nil, nonce, plain, nil)
}

func referenceEncrypt(key []byte, salt [saltSize]byte, plain []byte) []byte {
	fileKey := referenceFileKey(key, salt)
	out := append([]byte{'L', 'L', 'A', 'R', 0x01, 0x10, 0x00, 0x00}, salt[:]...)
	index := uint64(0)
	for len(plain) > 65536 {
		out = append(out, referenceSeal(fileKey, index, false, plain[:65536])...)
		plain = plain[65536:]
		index++
	}
	return append(out, referenceSeal(fileKey, index, true, plain)...)
}

func encrypt(t *testing.T, key []byte, salt [saltSize]byte, plain []byte, chunk int) []byte {
	t.Helper()
	var out bytes.Buffer
	writer, err := newWriterWithSalt(&out, key, salt)
	if err != nil {
		t.Fatal(err)
	}
	for rest := plain; len(rest) > 0; {
		n := min(chunk, len(rest))
		if written, err := writer.Write(rest[:n]); err != nil || written != n {
			t.Fatalf("write %d: %d, %v", n, written, err)
		}
		rest = rest[n:]
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// decrypt reads the whole stream and returns what the reader released before
// any error, wherever the error surfaced.
func decrypt(src io.Reader, key []byte) ([]byte, error) {
	reader, err := NewReader(src, key)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

type vectorFile struct {
	Description string       `json:"description"`
	KeyHex      string       `json:"key_hex"`
	SaltHex     string       `json:"salt_hex"`
	FileKeyHex  string       `json:"file_key_hex"`
	Cases       []vectorCase `json:"cases"`
}

type vectorCase struct {
	PlaintextLength int    `json:"plaintext_length"`
	FileLength      int    `json:"file_length"`
	SHA256          string `json:"sha256"`
	First64Hex      string `json:"first_64_hex"`
	CiphertextHex   string `json:"ciphertext_hex,omitempty"`
}

var vectorLengths = []int{0, 1, FrameSize - 1, FrameSize, FrameSize + 1, 200000}

func TestVectors(t *testing.T) {
	key, salt := testKey(), testSalt(0xa0)
	built := vectorFile{
		Description: "Test vectors for internal/archive/stream (stage 4 design G.2, G.3). Key and salt are synthetic. " +
			"The plaintext of length n is block j = SHA-256(\"llmapi-logger/archive-stream-test-plaintext\\x00\" || uint64_be(j)) " +
			"for j = 0, 1, ..., concatenated and cut to n bytes. file_key_hex is K_file for this key and salt. " +
			"ciphertext_hex is the whole file when it is short. All hex is lower case.",
		KeyHex:     hex.EncodeToString(key),
		SaltHex:    hex.EncodeToString(salt[:]),
		FileKeyHex: hex.EncodeToString(referenceFileKey(key, salt)),
	}
	for _, length := range vectorLengths {
		plain := testPlaintext(length)
		file := encrypt(t, key, salt, plain, 4093)
		if want := referenceEncrypt(key, salt, plain); !bytes.Equal(file, want) {
			t.Fatalf("length %d: Writer output differs from the reference encoder", length)
		}
		sum := sha256.Sum256(file)
		entry := vectorCase{
			PlaintextLength: length,
			FileLength:      len(file),
			SHA256:          hex.EncodeToString(sum[:]),
			First64Hex:      hex.EncodeToString(file[:min(64, len(file))]),
		}
		if len(file) <= 128 {
			entry.CiphertextHex = hex.EncodeToString(file)
		}
		built.Cases = append(built.Cases, entry)
		got, err := decrypt(bytes.NewReader(file), key)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("length %d: round trip failed: %v", length, err)
		}
	}
	encoded, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "vectors.json")
	if *updateVectors {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pinned, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored vectorFile
	if err := json.Unmarshal(pinned, &stored); err != nil {
		t.Fatal(err)
	}
	storedJSON, _ := json.Marshal(stored)
	builtJSON, _ := json.Marshal(built)
	if !bytes.Equal(storedJSON, builtJSON) {
		t.Fatalf("testdata/vectors.json does not match the encoder:\n%s", encoded)
	}
}

func TestRoundTripAroundFrameBoundaries(t *testing.T) {
	t.Parallel()
	key := testKey()
	for _, length := range []int{0, 1, FrameSize - 1, FrameSize, FrameSize + 1, 2*FrameSize - 1, 2 * FrameSize,
		2*FrameSize + 1, 3*FrameSize + 5} {
		plain := testPlaintext(length)
		file := encrypt(t, key, testSalt(1), plain, FrameSize)
		frames := (max(length, 1) + FrameSize - 1) / FrameSize
		if want := HeaderSize + length + frames*Overhead; len(file) != want {
			t.Errorf("length %d: file is %d bytes, want %d", length, len(file), want)
		}
		for name, wrap := range map[string]func(io.Reader) io.Reader{
			"plain":    func(r io.Reader) io.Reader { return r },
			"one-byte": iotest.OneByteReader,
			"half":     iotest.HalfReader,
			"data-err": iotest.DataErrReader,
		} {
			got, err := decrypt(wrap(bytes.NewReader(file)), key)
			if err != nil || !bytes.Equal(got, plain) {
				t.Errorf("length %d, %s reader: %v", length, name, err)
			}
		}
	}
}

func TestLargeStreamInOddChunks(t *testing.T) {
	t.Parallel()
	key, salt := testKey(), testSalt(2)
	plain := testPlaintext(5*FrameSize + 12345)
	var out bytes.Buffer
	writer, err := newWriterWithSalt(&out, key, salt)
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{1, 0, 7, 4093, 65537, 3, 65535, 0, 100003}
	for rest, i := plain, 0; len(rest) > 0; i++ {
		n := min(sizes[i%len(sizes)], len(rest))
		if _, err := writer.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), referenceEncrypt(key, salt, plain)) {
		t.Fatal("chunked Writer output differs from the reference encoder")
	}
	reader, err := NewReader(bytes.NewReader(out.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	buffer := make([]byte, 777)
	for {
		n, err := reader.Read(buffer)
		got.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), plain) {
		t.Fatal("chunked round trip differs")
	}
}

func TestRandomSizesMatchReference(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(59, 4))
	key := testKey()
	for range 40 {
		length := random.IntN(4*FrameSize + 2)
		if random.IntN(4) == 0 {
			length = random.IntN(4)*FrameSize + random.IntN(3) - 1
			length = max(length, 0)
		}
		var salt [saltSize]byte
		for i := range salt {
			salt[i] = byte(random.Uint32())
		}
		plain := testPlaintext(length)
		file := encrypt(t, key, salt, plain, 1+random.IntN(2*FrameSize))
		if !bytes.Equal(file, referenceEncrypt(key, salt, plain)) {
			t.Fatalf("length %d: Writer output differs from the reference encoder", length)
		}
		got, err := decrypt(iotest.HalfReader(bytes.NewReader(file)), key)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("length %d: round trip failed: %v", length, err)
		}
	}
}

func TestEmptyWritesDoNotFlushAFullFrame(t *testing.T) {
	t.Parallel()
	key, salt := testKey(), testSalt(3)
	plain := testPlaintext(FrameSize)
	var out bytes.Buffer
	writer, err := newWriterWithSalt(&out, key, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if n, err := writer.Write(nil); n != 0 || err != nil {
			t.Fatalf("empty write: %d, %v", n, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != HeaderSize+SealedFrameSize || !bytes.Equal(out.Bytes(), referenceEncrypt(key, salt, plain)) {
		t.Fatalf("one full frame produced %d bytes, want one last frame", out.Len())
	}
}

func TestWriterAfterClose(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	writer, err := NewWriter(&out, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	length := out.Len()
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("write after close succeeded")
	}
	if err := writer.Close(); err != nil || out.Len() != length {
		t.Fatalf("second close: %v, %d bytes written", err, out.Len()-length)
	}
}

func TestRandomSaltDiffersPerFile(t *testing.T) {
	t.Parallel()
	var first, second bytes.Buffer
	for _, out := range []*bytes.Buffer{&first, &second} {
		writer, err := NewWriter(out, testKey())
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(first.Bytes()[8:HeaderSize], second.Bytes()[8:HeaderSize]) {
		t.Fatal("two files share a salt")
	}
}

func TestUnclosedWriterIsRejected(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 100, FrameSize, 2*FrameSize + 9} {
		var out bytes.Buffer
		writer, err := newWriterWithSalt(&out, testKey(), testSalt(4))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(testPlaintext(length)); err != nil {
			t.Fatal(err)
		}
		if _, err := decrypt(bytes.NewReader(out.Bytes()), testKey()); err == nil {
			t.Errorf("unclosed writer after %d bytes left a readable file", length)
		}
	}
}

func TestInvalidKeyLength(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 16, 31, 33} {
		if _, err := NewWriter(io.Discard, make([]byte, length)); err == nil {
			t.Errorf("writer accepted a %d-byte key", length)
		}
		file := encrypt(t, testKey(), testSalt(5), nil, 1)
		if _, err := NewReader(bytes.NewReader(file), make([]byte, length)); err == nil {
			t.Errorf("reader accepted a %d-byte key", length)
		}
	}
}

// tamperFixture is the 200,000-byte G.3 case: frames 0 to 2 are full and
// frame 3 is the 3,392-byte last frame.
type tamperFixture struct {
	key    []byte
	plain  []byte
	file   []byte
	frames [][]byte
	other  [][]byte

	otherHeader []byte
}

func newTamperFixture(t *testing.T) tamperFixture {
	t.Helper()
	fixture := tamperFixture{key: testKey(), plain: testPlaintext(200000)}
	fixture.file = encrypt(t, fixture.key, testSalt(0xa0), fixture.plain, 9999)
	fixture.frames = splitFrames(fixture.file)
	otherFile := encrypt(t, fixture.key, testSalt(0x50), fixture.plain, 9999)
	fixture.other = splitFrames(otherFile)
	fixture.otherHeader = otherFile[:HeaderSize]
	if len(fixture.frames) != 4 {
		t.Fatalf("fixture has %d frames", len(fixture.frames))
	}
	return fixture
}

func splitFrames(file []byte) [][]byte {
	var frames [][]byte
	for rest := file[HeaderSize:]; len(rest) > 0; {
		n := min(SealedFrameSize, len(rest))
		frames = append(frames, rest[:n])
		rest = rest[n:]
	}
	return frames
}

func join(header []byte, frames ...[]byte) []byte {
	out := append([]byte(nil), header...)
	for _, frame := range frames {
		out = append(out, frame...)
	}
	return out
}

// expectRejected requires a read failure and checks that the reader released
// only whole authentic frames from the start of the plaintext.
func expectRejected(t *testing.T, name string, file, key, plain []byte) {
	t.Helper()
	got, err := decrypt(bytes.NewReader(file), key)
	if err == nil {
		t.Errorf("%s: tampered file was accepted", name)
		return
	}
	if len(got)%FrameSize != 0 || len(got) > len(plain) || !bytes.Equal(got, plain[:len(got)]) {
		t.Errorf("%s: reader released %d bytes that are not whole authentic frames", name, len(got))
	}
}

func TestTamperedStreamsAreRejected(t *testing.T) {
	t.Parallel()
	fixture := newTamperFixture(t)
	file, frames, header := fixture.file, fixture.frames, fixture.file[:HeaderSize]
	cases := map[string][]byte{
		"empty file":              nil,
		"half header":             file[:HeaderSize/2],
		"header only":             file[:HeaderSize],
		"swap frames 0 and 1":     join(header, frames[1], frames[0], frames[2], frames[3]),
		"drop frame 1":            join(header, frames[0], frames[2], frames[3]),
		"duplicate frame 0":       join(header, frames[0], frames[0], frames[1], frames[2], frames[3]),
		"duplicate last frame":    join(header, frames[0], frames[1], frames[2], frames[3], frames[3]),
		"splice frame 1":          join(header, frames[0], fixture.other[1], frames[2], frames[3]),
		"splice last frame":       join(header, frames[0], frames[1], frames[2], fixture.other[3]),
		"other header":            join(fixture.otherHeader, frames...),
		"append one byte":         append(append([]byte(nil), file...), 0),
		"append sixteen bytes":    append(append([]byte(nil), file...), make([]byte, 16)...),
		"append a frame":          join(header, frames[0], frames[1], frames[2], frames[3], frames[0]),
		"cut inside last frame":   file[:len(file)-1],
		"cut to last frame's tag": file[:len(file)-len(frames[3])+15],
		"cut inside frame 1":      file[:HeaderSize+SealedFrameSize+1000],
	}
	for boundary := 1; boundary < len(frames); boundary++ {
		cases[fmt.Sprintf("cut at frame boundary %d", boundary)] = file[:HeaderSize+boundary*SealedFrameSize]
	}
	for index, frame := range frames {
		for _, position := range []int{0, len(frame) / 2, len(frame) - Overhead, len(frame) - 1} {
			tampered := append([]byte(nil), file...)
			tampered[HeaderSize+index*SealedFrameSize+position] ^= 0x01
			cases[fmt.Sprintf("flip frame %d byte %d", index, position)] = tampered
		}
	}
	for name, tampered := range cases {
		expectRejected(t, name, tampered, fixture.key, fixture.plain)
	}
}

func TestFlippedHeaderBitsAreRejected(t *testing.T) {
	t.Parallel()
	key := testKey()
	for _, length := range []int{0, 200000} {
		plain := testPlaintext(length)
		file := encrypt(t, key, testSalt(0xa0), plain, 4096)
		for bit := range HeaderSize * 8 {
			tampered := append([]byte(nil), file...)
			tampered[bit/8] ^= 1 << (bit % 8)
			got, err := decrypt(bytes.NewReader(tampered), key)
			if err == nil || len(got) != 0 {
				t.Fatalf("length %d: header bit %d flipped: %d bytes, err %v", length, bit, len(got), err)
			}
			if bit < 64 && !errors.Is(err, ErrFormat) || bit >= 64 && !errors.Is(err, ErrAuthentication) {
				t.Fatalf("length %d: header bit %d flipped: unexpected error %v", length, bit, err)
			}
		}
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	t.Parallel()
	for _, length := range []int{0, 1, 200000} {
		plain := testPlaintext(length)
		file := encrypt(t, testKey(), testSalt(6), plain, 4096)
		wrong := testKey()
		wrong[0] ^= 0x80
		got, err := decrypt(bytes.NewReader(file), wrong)
		if !errors.Is(err, ErrAuthentication) || len(got) != 0 {
			t.Errorf("length %d: wrong key: %d bytes, err %v", length, len(got), err)
		}
	}
}

func TestFailingFrameReleasesNoPlaintext(t *testing.T) {
	t.Parallel()
	fixture := newTamperFixture(t)
	tampered := append([]byte(nil), fixture.file...)
	tampered[HeaderSize+SealedFrameSize+SealedFrameSize-1] ^= 0x01 // last byte of frame 1
	got, err := decrypt(bytes.NewReader(tampered), fixture.key)
	if !errors.Is(err, ErrAuthentication) || !bytes.Equal(got, fixture.plain[:FrameSize]) {
		t.Fatalf("got %d bytes, err %v; want exactly frame 0 and an authentication error", len(got), err)
	}
	reader, err := NewReader(bytes.NewReader(tampered), fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("no error")
	}
	if n, err := reader.Read(make([]byte, 10)); n != 0 || !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error is not sticky: %d, %v", n, err)
	}
}

func TestEmptyLastFrameAfterFramesIsRejected(t *testing.T) {
	t.Parallel()
	key, salt := testKey(), testSalt(7)
	plain := testPlaintext(FrameSize)
	fileKey := referenceFileKey(key, salt)
	// Authentic but non-canonical: a full non-final frame, then an empty
	// last frame. Writer never produces this.
	header := encodeHeader(salt)
	file := join(header[:], referenceSeal(fileKey, 0, false, plain), referenceSeal(fileKey, 1, true, nil))
	got, err := decrypt(bytes.NewReader(file), key)
	if !errors.Is(err, ErrFormat) || !bytes.Equal(got, plain) {
		t.Fatalf("got %d bytes, err %v", len(got), err)
	}
}

func TestSourceErrorsPropagate(t *testing.T) {
	t.Parallel()
	fixture := newTamperFixture(t)
	failure := errors.New("disk failure")
	for _, cut := range []int{10, HeaderSize, HeaderSize + 100, HeaderSize + SealedFrameSize, HeaderSize + SealedFrameSize + 1} {
		source := io.MultiReader(bytes.NewReader(fixture.file[:cut]), iotest.ErrReader(failure))
		if _, err := decrypt(source, fixture.key); !errors.Is(err, failure) {
			t.Errorf("cut %d: got %v, want the source error", cut, err)
		}
	}
	short := &failingWriter{limit: HeaderSize + 10}
	writer, err := newWriterWithSalt(short, fixture.key, testSalt(8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(fixture.plain); !errors.Is(err, errShortWrite) {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); !errors.Is(err, errShortWrite) || short.written != HeaderSize {
		t.Fatalf("close after a failed write: %v, %d bytes", err, short.written)
	}
}

var errShortWrite = errors.New("destination full")

type failingWriter struct {
	limit, written int
}

func (writer *failingWriter) Write(p []byte) (int, error) {
	if writer.written+len(p) > writer.limit {
		return 0, errShortWrite
	}
	writer.written += len(p)
	return len(p), nil
}

func TestFrameNonceLayout(t *testing.T) {
	t.Parallel()
	nonce := frameNonce(0x0102030405060708, true)
	if got := hex.EncodeToString(nonce[:]); got != "000000010203040506070801" {
		t.Fatalf("nonce = %s", got)
	}
	nonce = frameNonce(1, false)
	if got := hex.EncodeToString(nonce[:]); got != "000000000000000000000100" {
		t.Fatalf("nonce = %s", got)
	}
}
