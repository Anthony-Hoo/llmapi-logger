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
