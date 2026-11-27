package auditmodel

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
)

const (
	testParsedAuditID = "audit-parsed-result"
	testParsedParser  = "openai.chat_completions"
)

func parsedResultTestCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x37}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// sealLegacyParsedResult builds parsed_json_enc exactly as rows written
// before compression: the JSON encrypted directly.
func sealLegacyParsedResult(t *testing.T, cipher security.Cipher, plaintext []byte) []byte {
	t.Helper()
	aad, err := security.AAD(testParsedAuditID, "parsed_json", testParsedParser)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func decryptParsedPayload(t *testing.T, cipher security.Cipher, sealed []byte) []byte {
	t.Helper()
	aad, err := security.AAD(testParsedAuditID, "parsed_json", testParsedParser)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cipher.Decrypt(aad, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// fallbackConversationJSON mimics the envelope parsedResultPlaintext writes
// when no verified turn exists: a compact summary plus the whole
// conversation. Text is drawn from a seeded vocabulary so the fixture is not
// trivially repetitive; tool calls carry JSON arguments as real traffic does.
func fallbackConversationJSON(t *testing.T, targetBytes int) []byte {
	t.Helper()
	random := rand.New(rand.NewSource(59))
	vocabulary := make([]string, 4000)
	for index := range vocabulary {
		length := 2 + random.Intn(10)
		word := make([]byte, length)
		for position := range word {
			word[position] = byte('a' + random.Intn(26))
		}
		vocabulary[index] = string(word)
	}
	// Word frequencies follow a Zipf law, as in natural text; the words
	// themselves are random letters, which keeps the fixture pessimistic
	// compared with real prose or code.
	zipf := rand.NewZipf(random, 1.1, 1, uint64(len(vocabulary)-1))
	sentence := func(words int) string {
		parts := make([]string, words)
		for index := range parts {
			parts[index] = vocabulary[zipf.Uint64()]
		}
		return strings.Join(parts, " ") + "."
	}
	type part struct {
		Index     int    `json:"index"`
		Type      string `json:"type"`
		Text      string `json:"text,omitempty"`
		ID        string `json:"id,omitempty"`
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	}
	type message struct {
		Index     int    `json:"index"`
		Role      string `json:"role"`
		Phase     string `json:"phase"`
		Direction string `json:"direction"`
		Content   []part `json:"content"`
	}
	messages := make([]message, 0)
	size := 0
	for index := 0; size < targetBytes; index++ {
		item := message{Index: index, Role: "user", Phase: "request", Direction: "client_to_upstream"}
		switch index % 3 {
		case 0:
			item.Content = []part{{Type: "text", Text: sentence(80 + random.Intn(400))}}
		case 1:
			item.Role = "assistant"
			arguments, _ := json.Marshal(map[string]any{"path": "/workspace/" + vocabulary[random.Intn(len(vocabulary))] + ".go", "query": sentence(12)})
			item.Content = []part{{Type: "text", Text: sentence(40 + random.Intn(120))}, {Index: 1, Type: "tool_call", ID: fmt.Sprintf("call-%d", index), Name: "read_file", Arguments: string(arguments)}}
		default:
			item.Role = "tool"
			item.Content = []part{{Type: "text", Text: sentence(200 + random.Intn(600))}}
		}
		encoded, _ := json.Marshal(item)
		size += len(encoded)
		messages = append(messages, item)
	}
	plaintext, err := json.Marshal(map[string]any{
		"status": "partial", "model": "model-example", "error_code": "stream_incomplete",
		"conversation": map[string]any{"schema_version": 1, "messages": messages},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func TestOpenParsedResultReadsLegacyPlainRowsUnchanged(t *testing.T) {
	t.Parallel()
	cipher := parsedResultTestCipher(t)
	for _, plaintext := range [][]byte{
		[]byte(`{"status":"ok","model":"model-example"}`),
		// Rows before compression could be any size; they stay plain and are
		// returned byte for byte, without the decompression bound.
		fallbackConversationJSON(t, 64<<10),
	} {
		got, err := OpenParsedResult(cipher, testParsedAuditID, testParsedParser, sealLegacyParsedResult(t, cipher, plaintext))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("legacy row read back %d bytes, want %d identical bytes", len(got), len(plaintext))
		}
	}
}

func TestSealParsedResultKeepsSmallResultsPlain(t *testing.T) {
	t.Parallel()
	cipher := parsedResultTestCipher(t)
	for _, plaintext := range [][]byte{
		[]byte(`{"status":"ok","model":"model-example"}`),
		// Compressible, but below the size where gzip is worth a writer.
		[]byte(`{"text":"` + strings.Repeat("a", minCompressedParsedResult-20) + `"}`),
	} {
		sealed, err := SealParsedResult(cipher, testParsedAuditID, testParsedParser, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		// Byte-identical to what the base commit stored after decryption.
		if payload := decryptParsedPayload(t, cipher, sealed); !bytes.Equal(payload, plaintext) {
			t.Fatalf("small result stored as %q, want the plain JSON", payload[:min(len(payload), 32)])
		}
		got, err := OpenParsedResult(cipher, testParsedAuditID, testParsedParser, sealed)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("small result round trip = %v", err)
		}
	}
}

func TestSealParsedResultCompressesFallbackConversation(t *testing.T) {
	t.Parallel()
	cipher := parsedResultTestCipher(t)
	// About the 1.2 MB average measured for fallback conversations.
	plaintext := fallbackConversationJSON(t, 1200<<10)
	legacy := sealLegacyParsedResult(t, cipher, plaintext)
	sealed, err := SealParsedResult(cipher, testParsedAuditID, testParsedParser, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if payload := decryptParsedPayload(t, cipher, sealed); !bytes.HasPrefix(payload, gzipMagic) {
		t.Fatal("large result was not stored compressed")
	}
	got, err := OpenParsedResult(cipher, testParsedAuditID, testParsedParser, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("compressed result did not round-trip")
	}
	factor := float64(len(legacy)) / float64(len(sealed))
	t.Logf("fallback conversation: plaintext %d bytes, legacy ciphertext %d bytes, compressed ciphertext %d bytes, factor %.2f", len(plaintext), len(legacy), len(sealed), factor)
	if factor < 2.5 {
		t.Fatalf("compression factor %.2f, want at least 2.5", factor)
	}
}

func TestSealParsedResultRejectsValuesThatLookCompressed(t *testing.T) {
	t.Parallel()
	_, err := SealParsedResult(parsedResultTestCipher(t), testParsedAuditID, testParsedParser, []byte("\x1f\x8bnot json"))
	if err == nil {
		t.Fatal("a plaintext starting with the gzip magic would be misread as compressed")
	}
}

func TestParsedResultAADFailure(t *testing.T) {
	t.Parallel()
	cipher := parsedResultTestCipher(t)
	if _, err := SealParsedResult(cipher, "audit\x00bad", testParsedParser, []byte(`{}`)); !errors.Is(err, ErrParsedResultAAD) {
		t.Fatalf("seal AAD error = %v", err)
	}
	if _, err := OpenParsedResult(cipher, "audit\x00bad", testParsedParser, []byte{1}); !errors.Is(err, ErrParsedResultAAD) {
		t.Fatalf("open AAD error = %v", err)
	}
}

func gzipParsedPayload(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

// gzipZeros builds an over-limit stream without holding its plaintext.
func gzipZeros(t *testing.T, length int64) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1<<20)
	for remaining := length; remaining > 0; {
		n := min(remaining, int64(len(buffer)))
		if _, err := writer.Write(buffer[:n]); err != nil {
			t.Fatal(err)
		}
		remaining -= n
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

// Not parallel: the allocation check reads process-wide counters, and
// sequential tests run while every parallel test is still paused.
func TestOpenParsedResultRejectsBadCompressedPayloads(t *testing.T) {
	cipher := parsedResultTestCipher(t)
	valid := gzipParsedPayload(t, fallbackConversationJSON(t, 32<<10))
	withISIZE := func(payload []byte, size uint32) []byte {
		patched := append([]byte(nil), payload...)
		binary.LittleEndian.PutUint32(patched[len(patched)-4:], size)
		return patched
	}
	flipped := append([]byte(nil), valid...)
	flipped[len(flipped)/2] ^= 0x40
	overLimit := gzipZeros(t, MaxParsedResultBytes+1)

	for _, test := range []struct {
		name    string
		payload []byte
		// maxAlloc bounds what a rejection may allocate; 0 skips the check.
		maxAlloc uint64
	}{
		{name: "magic only", payload: []byte{0x1f, 0x8b, 0x08}},
		{name: "truncated", payload: valid[:len(valid)-12]},
		{name: "bit flipped", payload: flipped},
		{name: "trailing garbage", payload: append(append([]byte(nil), valid...), []byte("garbage-after-stream")...)},
		{name: "declared size too small", payload: withISIZE(valid, 100)},
		{name: "declared size too large", payload: withISIZE(valid, uint32(len(valid))*1000)},
		// ISIZE says more than the bound: rejected before inflating anything.
		{name: "over limit", payload: overLimit, maxAlloc: 1 << 20},
		// ISIZE lies small for a stream that inflates past the bound: reading
		// stops at the declared size, so this cannot balloon either.
		{name: "over limit with small declared size", payload: withISIZE(overLimit, 4096), maxAlloc: 4 << 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			aad, err := security.AAD(testParsedAuditID, "parsed_json", testParsedParser)
			if err != nil {
				t.Fatal(err)
			}
			// Encrypted under the right key and AAD, so only the payload is bad.
			sealed, err := cipher.Encrypt(aad, test.payload)
			if err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			got, err := OpenParsedResult(cipher, testParsedAuditID, testParsedParser, sealed)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, ErrParsedResult) || got != nil {
				t.Fatalf("OpenParsedResult = %d bytes, %v; want ErrParsedResult", len(got), err)
			}
			// TotalAlloc is process-wide and includes the decrypted payload, so
			// this is a coarse bound, far below what the stream would inflate to.
			if allocated := after.TotalAlloc - before.TotalAlloc; test.maxAlloc != 0 && allocated > test.maxAlloc+uint64(len(sealed))*2 {
				t.Fatalf("rejection allocated %d bytes", allocated)
			}
		})
	}
}

func TestOpenParsedResultRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	cipher := parsedResultTestCipher(t)
	sealed, err := SealParsedResult(cipher, testParsedAuditID, testParsedParser, fallbackConversationJSON(t, 32<<10))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := OpenParsedResult(cipher, testParsedAuditID, testParsedParser, sealed); !errors.Is(err, ErrParsedResult) {
		t.Fatalf("tampered ciphertext error = %v", err)
	}
	if _, err := OpenParsedResult(cipher, testParsedAuditID, "other.parser", sealLegacyParsedResult(t, cipher, []byte(`{}`))); !errors.Is(err, ErrParsedResult) {
		t.Fatalf("wrong AAD error = %v", err)
	}
}
