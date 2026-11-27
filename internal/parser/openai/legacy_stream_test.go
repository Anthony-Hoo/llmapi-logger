package openai

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
)

// TestVersion2StreamRowsRebuildAsBefore replays stream responses stored by
// parser version 2 (layout openai.stream.response: one descriptor per SSE
// event, display messages as the aggregate). The envelopes, items,
// reconstruction hashes and conversations in testdata were captured by
// running the version 2 normalizer at commit 003af28 on protofixture streams
// (seed 42) and a hand-made Completions stream. Rows of that layout must keep
// assembling to the same hash and projecting to the same conversation.
func TestVersion2StreamRowsRebuildAsBefore(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "legacy_stream_response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var captured []struct {
		Label    string          `json:"label"`
		Parser   string          `json:"parser"`
		Layout   string          `json:"layout"`
		Envelope json.RawMessage `json:"envelope"`
		Items    []struct {
			Slot  string          `json:"slot"`
			Kind  string          `json:"kind"`
			Value json.RawMessage `json:"value"`
		} `json:"items"`
		Conversation json.RawMessage `json:"conversation"`
		Rebuild      string          `json:"reconstruction_sha256"`
	}
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	if len(captured) < 10 {
		t.Fatalf("only %d captured rows", len(captured))
	}
	for _, row := range captured {
		if row.Layout != auditmodel.LayoutOpenAIStreamResponse {
			t.Fatalf("%s: layout %q", row.Label, row.Layout)
		}
		var envelope any
		if err := auditmodel.DecodeJSON(row.Envelope, &envelope); err != nil {
			t.Fatal(err)
		}
		items := make([]auditmodel.Item, 0, len(row.Items))
		for _, item := range row.Items {
			var value any
			if err := auditmodel.DecodeJSON(item.Value, &value); err != nil {
				t.Fatal(err)
			}
			items = append(items, auditmodel.Item{Slot: item.Slot, Kind: item.Kind, Value: value})
		}
		response, err := auditmodel.Assemble(row.Layout, envelope, items)
		if err != nil {
			t.Fatalf("%s: assemble: %v", row.Label, err)
		}
		canonical, err := auditmodel.CanonicalJSON(response)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(auditmodel.ReconstructionHash(canonical)); got != row.Rebuild {
			t.Errorf("%s: reconstruction hash %s, captured %s", row.Label, got, row.Rebuild)
		}
		adapter, err := Adapter(row.Parser)
		if err != nil {
			t.Fatal(err)
		}
		view, err := adapter.Conversation(nil, response, row.Layout)
		if err != nil {
			t.Fatalf("%s: conversation: %v", row.Label, err)
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var want bytes.Buffer
		if err := json.Compact(&want, row.Conversation); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, want.Bytes()) {
			t.Errorf("%s: conversation changed\ngot:      %s\ncaptured: %s", row.Label, encoded, want.Bytes())
		}
	}
}
