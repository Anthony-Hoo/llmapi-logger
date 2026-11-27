package auditmodel

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
)

// TestInlineDataPartsRuleIsOptIn: the Gemini inline part rule extracts the
// canonical base64 data of inlineData and inline_data objects only for a turn
// that asks for it. Every other turn, which is every other protocol, prepares
// the same value exactly as before: the data stays a string. A data URL is
// extracted either way, and the rebuilt value equals the original.
func TestInlineDataPartsRuleIsOptIn(t *testing.T) {
	t.Parallel()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{1, 2, 3, 4, 5}, 30)
	data := base64.StdEncoding.EncodeToString(payload)
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("another image"))
	content := func() any {
		return map[string]any{"role": "user", "parts": []any{
			map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": data}},
			map[string]any{"inline_data": map[string]any{"mime_type": "image/png", "data": data}},
			// Not the canonical padded encoding: kept as text.
			map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": strings.TrimRight(data, "=") + "\n"}},
			// The key alone does not make data binary.
			map[string]any{"other": map[string]any{"data": data}},
			map[string]any{"text": dataURL},
		}}
	}
	prepare := func(rule bool) PreparedTurn {
		t.Helper()
		turn := Turn{AuditID: "apx_inline", Protocol: "test", ParserName: "test.parser", CreatedAtNS: 1,
			RequestLayout: LayoutMarkerEnvelope, ResponseLayout: LayoutNone, InlineDataParts: rule,
			RequestEnvelope: map[string]any{"contents": []any{ItemMarker(0)}}, RequestOriginal: map[string]any{"contents": []any{content()}},
			RequestItems: []Item{{Slot: "contents", Kind: "user_content", Value: content()}}}
		prepared, err := Prepare(turn, cipher)
		if err != nil {
			t.Fatalf("rule=%v: %v", rule, err)
		}
		return prepared
	}
	pointers := func(prepared PreparedTurn) []string {
		var result []string
		for _, object := range prepared.Objects {
			for _, ref := range object.BinaryRefs {
				result = append(result, ref.JSONPointer+" "+ref.Encoding)
			}
		}
		return result
	}
	off, on := prepare(false), prepare(true)
	if got, want := pointers(off), []string{"/parts/4/text data_url"}; !reflect.DeepEqual(got, want) || len(off.Binaries) != 1 {
		t.Fatalf("without the rule: refs %q, %d binaries", got, len(off.Binaries))
	}
	if got, want := pointers(on), []string{"/parts/0/inlineData/data base64", "/parts/1/inline_data/data base64", "/parts/4/text data_url"}; !reflect.DeepEqual(got, want) || len(on.Binaries) != 2 {
		t.Fatalf("with the rule: refs %q, %d binaries", got, len(on.Binaries))
	}
}
