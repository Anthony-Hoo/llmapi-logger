package headerblock

import (
	"net/http"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// realisticHeaders is a synthetic streaming request through the proxy: an SDK
// client behind Nginx, the request rewritten for NewAPI, and an SSE response.
// The values are made up but have realistic shapes and lengths.
func realisticHeaders() []capturedStage {
	inbound := http.Header{
		"Accept":                      {"application/json"},
		"Accept-Encoding":             {"gzip, deflate, br"},
		"Anthropic-Version":           {"2023-06-01"},
		"Authorization":               {"Bearer placeholder-token-for-tests-0000000000000000000000000000"},
		"Content-Length":              {"48213"},
		"Content-Type":                {"application/json"},
		"User-Agent":                  {"ExampleSDK/1.42.0 (example-agent; runtime 22.11.0)"},
		"X-Forwarded-For":             {"192.0.2.10, 198.51.100.7"},
		"X-Forwarded-Proto":           {"https"},
		"X-Real-Ip":                   {"192.0.2.10"},
		"X-Stainless-Arch":            {"x64"},
		"X-Stainless-Lang":            {"js"},
		"X-Stainless-Os":              {"Linux"},
		"X-Stainless-Package-Version": {"0.60.0"},
		"X-Stainless-Runtime":         {"node"},
	}
	sent := inbound.Clone()
	sent["Accept-Encoding"] = []string{"identity"}
	sent["X-Forwarded-Host"] = []string{"api.example.com"}
	response := http.Header{
		"Cache-Control":          {"no-cache"},
		"Content-Type":           {"text/event-stream; charset=utf-8"},
		"Date":                   {"Mon, 02 Nov 2026 08:00:00 GMT"},
		"Server":                 {"example-gateway"},
		"Vary":                   {"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"},
		"X-Accel-Buffering":      {"no"},
		"X-Oneapi-Request-Id":    {"20261102080000000000000000000000"},
		"X-Content-Type-Options": {"nosniff"},
	}
	return []capturedStage{
		{name: storage.StageRequestReceived, headers: inbound},
		{name: storage.StageRequestSent, headers: sent},
		{name: storage.StageResponseReceived, headers: response},
		{name: storage.StageResponseSent, headers: response.Clone()},
	}
}

func realisticStages() []Stage {
	var stages []Stage
	for _, stage := range realisticHeaders() {
		stages = append(stages, Stage{Name: stage.name, Headers: Snapshot(stage.headers), Trailers: Snapshot(stage.trailers)})
	}
	return stages
}

// TestRealisticBlockSize measures the block against today's per-value rows
// for the same Headers. Run with -v to see the numbers.
func TestRealisticBlockSize(t *testing.T) {
	c := testCipher(t)
	stages := realisticStages()
	plaintext, err := Encode(stages)
	if err != nil {
		t.Fatal(err)
	}
	compression, length, enc, err := Seal(c, testAuditID, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	rowCiphertext := 0
	rowColumns := 0
	for _, value := range Flatten(stages) {
		rows++
		// value_enc = nonce || ciphertext || tag
		rowCiphertext += security.NonceSize + len(value.Value) + 16
		// the identity columns each row repeats: audit_id, stage, kind, name
		rowColumns += len(testAuditID) + len(value.Stage) + len(value.Kind) + len(value.Name)
	}
	encodedLength := len(enc) - security.NonceSize - 16
	t.Logf("stages=4 values=%d plaintext=%d compression=%s encoded=%d sealed=%d", rows, length, compression, encodedLength, len(enc))
	t.Logf("version 1: value_enc total=%d, identity columns=%d, together=%d", rowCiphertext, rowColumns, rowCiphertext+rowColumns)
	t.Logf("sealed block / value_enc total = %.3f", float64(len(enc))/float64(rowCiphertext))
	if rows < 45 || rows > 60 {
		t.Fatalf("fixture has %d values, want about fifty", rows)
	}
	if compression != storage.ChunkCompressionGZIP {
		t.Fatalf("realistic block was not compressed: %s", compression)
	}
	if len(enc) >= rowCiphertext {
		t.Fatalf("sealed block (%d) is not smaller than the per-value ciphertext (%d)", len(enc), rowCiphertext)
	}
	if len(enc) > 3<<10 {
		t.Fatalf("sealed block is %d bytes, above the 1 to 3 KB the design expects", len(enc))
	}
}
