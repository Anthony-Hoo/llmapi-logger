package auditmodel

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"llmapi-logger/internal/security"
)

type countingCipher struct {
	security.Cipher
	encryptions int
}

func (c *countingCipher) Encrypt(aad, plain []byte) ([]byte, error) {
	c.encryptions++
	return c.Cipher.Encrypt(aad, plain)
}

func TestPrepareItemsDeduplicatesBeforeSeal(t *testing.T) {
	cipher := &countingCipher{Cipher: testCipher(t)}
	encoder := &contentEncoder{}
	defer encoder.release()
	objects := make(map[string]plainContentCandidate)
	value := map[string]any{"role": "user", "content": string(bytes.Repeat([]byte("private"), 100)), "file_id": "file-example"}
	items := []Item{{Slot: SlotMessages, Kind: "message", Value: value}, {Slot: SlotMessages, Kind: "message", Value: value}}
	_, refs, err := prepareItems(newBinaryAccumulator(), items, objects)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealCandidates(cipher, encoder, objects, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(objects) != 1 || len(refs) != 2 || cipher.encryptions != 2 {
		t.Fatalf("objects=%d refs=%d encryptions=%d, want 1/2/2 (object and external reference)", len(objects), len(refs), cipher.encryptions)
	}
	// Existing request-local identity metadata must still be checked.
	for key, object := range objects {
		object.Object.Kind = "corrupt"
		objects[key] = object
	}
	if _, _, err := prepareItems(newBinaryAccumulator(), items, objects); err != ErrIntegrity {
		t.Fatalf("corrupt identity: %v", err)
	}
}

func TestContentEncoderIndependentStreams(t *testing.T) {
	t.Parallel()
	encoder := &contentEncoder{}
	defer encoder.release()
	values := [][]byte{bytes.Repeat([]byte("first-private-value"), 1024), bytes.Repeat([]byte("second"), 30), []byte("tiny"), bytes.Repeat([]byte{0}, 65537)}
	for repeat := 0; repeat < 3; repeat++ {
		for _, plain := range values {
			encoded, err := encoder.gzipBytes(plain)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := gzip.NewReader(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err = reader.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatal("compressed stream borrowed another object's dictionary")
			}
		}
	}
	encoder.release()
	if encoder.writer != nil {
		t.Fatal("release retained writer")
	}
}

func BenchmarkContentEncoderBatch(b *testing.B) {
	plain := bytes.Repeat([]byte("synthetic-history-item "), 200)
	for _, reuse := range []bool{false, true} {
		name := "fresh"
		if reuse {
			name = "request_local"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				encoder := &contentEncoder{}
				for i := 0; i < 64; i++ {
					var err error
					if reuse {
						_, _, err = encoder.compress(plain)
					} else {
						_, _, err = compressContent(plain)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				encoder.release()
			}
		})
	}
}
