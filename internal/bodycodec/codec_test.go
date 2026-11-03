package bodycodec

import (
	"bytes"
	"testing"
)

func TestEncodeCompressesJSONButNotPNG(t *testing.T) {
	t.Parallel()
	jsonBody := bytes.Repeat([]byte(`{"message":"compressible"}`), 4096)
	compression, encoded, err := Encode(jsonBody, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if compression != CompressionGZIP || len(encoded) >= len(jsonBody) {
		t.Fatalf("JSON compression = %q %d/%d", compression, len(encoded), len(jsonBody))
	}
	decoded, err := Decode(encoded, compression, len(jsonBody))
	if err != nil || !bytes.Equal(decoded, jsonBody) {
		t.Fatalf("Decode JSON: %v", err)
	}

	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x42}, 4096)...)
	compression, encoded, err = Encode(png, "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if compression != CompressionNone || !bytes.Equal(encoded, png) {
		t.Fatalf("PNG was recompressed: %q", compression)
	}
}

func TestEncoderReuseIndependentStreamsAndRelease(t *testing.T) {
	t.Parallel()
	encoder := &Encoder{}
	var saved [][]byte
	values := [][]byte{bytes.Repeat([]byte("first synthetic body"), 100), bytes.Repeat([]byte("second"), 100), []byte("tiny"), bytes.Repeat([]byte("third"), 20000)}
	for _, plain := range values {
		compression, encoded, err := encoder.Encode(plain, "application/json")
		if err != nil {
			t.Fatal(err)
		}
		freshCompression, fresh, err := Encode(plain, "application/json")
		if err != nil {
			t.Fatal(err)
		}
		if compression != freshCompression || !bytes.Equal(encoded, fresh) {
			t.Fatal("reusing writer changed wire encoding")
		}
		saved = append(saved, encoded)
	}
	for i, encoded := range saved {
		compression := CompressionGZIP
		if len(values[i]) < 128 {
			compression = CompressionNone
		}
		plain, err := Decode(encoded, compression, len(values[i]))
		if err != nil || !bytes.Equal(plain, values[i]) {
			t.Fatalf("independent decode %d: %v", i, err)
		}
	}
	encoder.Release()
	if encoder.writer != nil {
		t.Fatal("release retained compressor")
	}
	if _, _, err := encoder.Encode(values[0], "text/plain"); err != nil {
		t.Fatal("cannot reuse released encoder")
	}
	encoder.Release()
}
