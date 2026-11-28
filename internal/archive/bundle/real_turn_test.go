package bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// realTurn normalises one OpenAI Responses exchange with an inline image as
// the parser and auditmodel.Prepare do, stores its objects in the fixture's
// payloads and returns the record's turn (a root turn in delta form) and the
// provider request and response bodies.
func (f *fixture) realTurn(auditID, conversationID string) (*archive.Turn, []byte, []byte) {
	t := f.t
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x62, 0x19}, 64)...)
	requestBody, err := auditmodel.CanonicalJSON(map[string]any{
		"model": "model-example",
		"input": []any{map[string]any{"type": "message", "role": "user", "content": []any{
			map[string]any{"type": "input_text", "text": "inspect the image " + contentMarker},
			map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := auditmodel.CanonicalJSON(map[string]any{
		"id": "response-current", "object": "response", "model": "model-result",
		"output": []any{map[string]any{"type": "message", "id": "message-current", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": "It looks valid."}}}},
		"usage": map[string]any{"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := base.Input{AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
		Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
		Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody}}
	normalized, err := implementation.NormalizeAudit(context.Background(), input, implementation.Parse(context.Background(), input))
	if err != nil {
		t.Fatal(err)
	}
	normalized.CreatedAtNS = minute(0) + 500
	prepared, err := auditmodel.Prepare(normalized, cipher)
	if err != nil {
		t.Fatal(err)
	}
	turn := &archive.Turn{
		Row: archive.TurnRow{TurnID: auditID, ConversationID: conversationID, ParentBase: auditmodel.ParentBaseRoot, LinkReason: "root",
			LinkConfidence: 100, RequestLayout: prepared.RequestLayout, ResponseLayout: prepared.ResponseLayout,
			RequestEnvelopeHash: prepared.RequestEnvelopeHash, ResponseEnvelopeHash: prepared.ResponseEnvelopeHash,
			RequestItemCount: int64(len(prepared.RequestRefs)), ResponseItemCount: int64(len(prepared.ResponseRefs)),
			RequestSequenceHash: prepared.RequestSequenceHash, ResponseSequenceHash: prepared.ResponseSequenceHash,
			RequestReconstructionHash: prepared.RequestReconstructionHash, ResponseReconstructionHash: prepared.ResponseReconstructionHash,
			ReconstructionStatus: "verified", CreatedAtNS: prepared.CreatedAtNS},
		Context:     archive.RequestContext{Form: archive.ContextDelta, Ops: archive.ContextOpsFrom(auditmodel.BuildDelta(nil, prepared.RequestRefs))},
		RequestRefs: append([]auditmodel.ObjectRef(nil), prepared.RequestRefs...),
	}
	if prepared.ResponseID != "" {
		turn.Row.ResponseID = text(prepared.ResponseID)
	}
	for index, ref := range prepared.ResponseRefs {
		turn.ResponseItems = append(turn.ResponseItems, archive.ResponseItem{Ordinal: int64(index), Slot: ref.Slot, ObjectHash: ref.ObjectHash, SemanticHash: ref.SemanticHash})
	}
	for _, object := range prepared.Objects {
		decoded, err := auditmodel.OpenObject(cipher, auditmodel.StoredContent{Hash: object.Hash, SemanticHash: object.SemanticHash,
			Kind: object.Kind, Compression: object.Compression, PlaintextLength: object.PlaintextLength,
			EncodedLength: object.EncodedLength, DataEnc: object.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := auditmodel.CanonicalJSON(decoded)
		if err != nil {
			t.Fatal(err)
		}
		f.payloads.contents[string(object.Hash)] = archive.ContentObject{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind,
			PlaintextLength: object.PlaintextLength, CreatedAtNS: baseTimeNS, Data: canonical}
		turn.Objects = append(turn.Objects, archive.ObjectMeta{Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind, PlaintextLength: object.PlaintextLength})
		for _, ref := range object.BinaryRefs {
			turn.BinaryRefs = append(turn.BinaryRefs, archive.BinaryRef{ObjectHash: object.Hash, JSONPointer: ref.JSONPointer, BinaryHash: ref.BinaryHash, MediaType: ref.MediaType, Encoding: ref.Encoding})
		}
	}
	for _, binary := range prepared.Binaries {
		data, err := auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{Hash: binary.Hash, MediaType: binary.MediaType,
			Compression: binary.Compression, PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc})
		if err != nil {
			t.Fatal(err)
		}
		f.payloads.binaries[string(binary.Hash)] = archive.BinaryObject{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength, CreatedAtNS: baseTimeNS, Data: data}
		turn.Binaries = append(turn.Binaries, archive.BinaryMeta{Hash: binary.Hash, MediaType: binary.MediaType, PlaintextLength: binary.PlaintextLength})
	}
	return turn, requestBody, responseBody
}

// A turn the real parser and auditmodel.Prepare produced (envelopes, items,
// an inline image as a binary object) passes Verify, and the query layer's
// plaintext assembly rebuilds the provider request and response from the
// bundle alone.
func TestRealTurnThroughTheQueryLayer(t *testing.T) {
	for _, encrypt := range []bool{true, false} {
		t.Run(map[bool]string{true: "encrypted", false: "plain"}[encrypt], func(t *testing.T) {
			f := newFixture(t)
			record := f.audit("real-1", "openai", minute(0), storage.CaptureVersion2)
			record.Audit.ParserName = openai.Responses
			turn, requestBody, responseBody := f.realTurn("real-1", "conv_real")
			record.Turn = turn
			record.Conversation = &archive.Conversation{ConversationID: "conv_real", Protocol: "openai", KeyHash: hashOf(0x81), CreatedAtNS: baseTimeNS}
			record.ParsedResult = &archive.ParsedResult{ParserName: openai.Responses, ParserVersion: "1", Status: storage.ParseOK, RequestModel: text("model-example"), ParsedAtNS: minute(0) + 600}
			canonical(t, record)
			if len(record.Turn.Binaries) != 1 {
				t.Fatalf("binaries = %d, want the inline image", len(record.Turn.Binaries))
			}

			sealed := f.writeSegment(f.options(t.TempDir(), encrypt), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_real", Index: 1}, record)
			bundle, report := f.verify(sealed.ManifestPath(), encrypt)
			if report.ContentObjects != int64(len(record.Turn.Objects)) || report.BinaryObjects != 1 || report.Members[0].Digest != digestOf(t, record) {
				t.Fatalf("report = %+v", report)
			}
			var read *archive.Record
			if err := bundle.Records(context.Background(), func(line Line) error { read = line.Record; return nil }); err != nil {
				t.Fatal(err)
			}
			objects, err := bundle.LoadObjects(context.Background(), read)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := read.PlainDetail(objects, nil)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := query.ReconstructPlainTurn(plain)
			if err != nil {
				t.Fatal(err)
			}
			encode := func(value any) []byte {
				encoded, err := auditmodel.CanonicalJSON(value)
				if err != nil {
					t.Fatal(err)
				}
				return encoded
			}
			if !bytes.Equal(encode(rebuilt.Request), requestBody) || !bytes.Equal(encode(rebuilt.Response), responseBody) {
				t.Fatal("provider request or response rebuilt from the bundle differs")
			}
			if _, err := read.Detail(objects, nil); err != nil {
				t.Fatalf("detail from the bundle: %v", err)
			}
		})
	}
}
