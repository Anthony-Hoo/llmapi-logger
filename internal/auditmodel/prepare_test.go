package auditmodel

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
)

func TestPrepareDeduplicatesDecodedDataURLAndReconstructs(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x33, 0x77}, 256)...)
	encoded := base64.StdEncoding.EncodeToString(png)
	wrapped := encoded[:40] + "\r\n" + encoded[40:]
	first := map[string]any{
		"role": "user",
		"content": []any{map[string]any{
			"type":      "input_image",
			"image_url": "data:image/png;base64," + encoded,
			"file_id":   "file-example-1",
		}},
	}
	second := map[string]any{
		"role": "user",
		"content": []any{map[string]any{
			"type":      "input_image",
			"image_url": "data:image/png;base64," + wrapped,
			"file_id":   "file-example-1",
		}},
	}
	requestOriginal := map[string]any{
		"model":    "model-example",
		"messages": []any{first, second},
	}
	prepared, err := Prepare(Turn{
		AuditID:          "audit-example",
		Protocol:         "openai",
		ParserName:       "openai.chat_completions",
		RequestLayout:    LayoutOpenAIChatRequest,
		ResponseLayout:   LayoutNone,
		RequestEnvelope:  map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{"id": "response-example"},
		RequestItems: []Item{
			{Slot: SlotMessages, Kind: "message", Value: first, Display: []DisplayMessage{{Role: conversation.RoleUser, Content: []DisplayPart{{Type: conversation.PartUnknown}}}}},
			{Slot: SlotMessages, Kind: "message", Value: second, Display: []DisplayMessage{{Role: conversation.RoleUser, Content: []DisplayPart{{Type: conversation.PartUnknown}}}}},
		},
		RequestOriginal:  requestOriginal,
		ResponseOriginal: map[string]any{"id": "response-example"},
		CreatedAtNS:      1,
	}, cipher)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(prepared.Binaries) != 1 {
		t.Fatalf("binary objects = %d, want 1", len(prepared.Binaries))
	}
	if prepared.Binaries[0].Compression != CompressionNone {
		t.Fatalf("PNG compression = %q, want none", prepared.Binaries[0].Compression)
	}
	if len(prepared.RequestRefs) != 2 || !EqualHash(prepared.RequestRefs[0].ObjectHash, prepared.RequestRefs[1].ObjectHash) {
		t.Fatalf("equivalent data URLs did not deduplicate: %+v", prepared.RequestRefs)
	}

	var itemObject ContentObject
	for _, object := range prepared.Objects {
		if EqualHash(object.Hash, prepared.RequestRefs[0].ObjectHash) {
			itemObject = object
		}
	}
	if len(itemObject.Hash) == 0 || len(itemObject.ExternalRefs) != 1 || bytes.Contains(itemObject.ExternalRefs[0].ValueEnc, []byte("file-example-1")) {
		t.Fatalf("external reference was not encrypted: %+v", itemObject.ExternalRefs)
	}
	decoded, err := OpenObject(cipher, StoredContent{
		Hash:            itemObject.Hash,
		Kind:            itemObject.Kind,
		Compression:     itemObject.Compression,
		PlaintextLength: itemObject.PlaintextLength,
		DataEnc:         itemObject.DataEnc,
	})
	if err != nil {
		t.Fatalf("OpenObject: %v", err)
	}
	binaryPlaintext, err := OpenBinary(cipher, StoredBinary{
		Hash:            prepared.Binaries[0].Hash,
		MediaType:       prepared.Binaries[0].MediaType,
		Compression:     prepared.Binaries[0].Compression,
		PlaintextLength: prepared.Binaries[0].PlaintextLength,
		DataEnc:         prepared.Binaries[0].DataEnc,
	})
	if err != nil {
		t.Fatalf("OpenBinary: %v", err)
	}
	defer clear(binaryPlaintext)
	restored, err := RestoreBinaries(decoded.Value, func(hash []byte) ([]byte, error) {
		if !EqualHash(hash, prepared.Binaries[0].Hash) {
			t.Fatalf("unexpected binary hash")
		}
		return binaryPlaintext, nil
	})
	if err != nil {
		t.Fatalf("RestoreBinaries: %v", err)
	}
	restoredJSON, err := CanonicalJSON(restored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(restoredJSON, []byte("data:image/png;base64,")) || !bytes.Contains(restoredJSON, []byte("file-example-1")) {
		t.Fatalf("restored item = %s", restoredJSON)
	}
}

func TestPrepareCompressesLongTextBeforeEncryption(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	text := strings.Repeat("compressible audit text ", 500)
	message := map[string]any{"role": "user", "content": text}
	prepared, err := Prepare(Turn{
		AuditID:          "audit-compression",
		Protocol:         "openai",
		ParserName:       "openai.chat_completions",
		RequestLayout:    LayoutOpenAIChatRequest,
		ResponseLayout:   LayoutNone,
		RequestEnvelope:  map[string]any{"model": "model-example"},
		ResponseEnvelope: map[string]any{},
		RequestItems:     []Item{{Slot: SlotMessages, Kind: "message", Value: message}},
		RequestOriginal:  map[string]any{"model": "model-example", "messages": []any{message}},
		ResponseOriginal: map[string]any{},
		CreatedAtNS:      2,
	}, cipher)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	var object ContentObject
	for _, candidate := range prepared.Objects {
		if EqualHash(candidate.Hash, prepared.RequestRefs[0].ObjectHash) {
			object = candidate
		}
	}
	if object.Compression != CompressionGZIP || object.EncodedLength >= object.PlaintextLength {
		t.Fatalf("content compression = %q %d/%d", object.Compression, object.EncodedLength, object.PlaintextLength)
	}
	if bytes.Contains(object.DataEnc, []byte("compressible audit text")) {
		t.Fatal("encrypted object contains plaintext canary")
	}
}

func TestPrepareRejectsReconstructionMismatch(t *testing.T) {
	t.Parallel()
	_, err := Prepare(Turn{
		AuditID:          "audit-mismatch",
		Protocol:         "openai",
		ParserName:       "openai.chat_completions",
		RequestLayout:    LayoutOpenAIChatRequest,
		ResponseLayout:   LayoutNone,
		RequestEnvelope:  map[string]any{"model": "model-a"},
		ResponseEnvelope: map[string]any{},
		RequestItems:     []Item{{Slot: SlotMessages, Kind: "message", Value: map[string]any{"role": "user", "content": "x"}}},
		RequestOriginal:  map[string]any{"model": "model-b", "messages": []any{map[string]any{"role": "user", "content": "x"}}},
		ResponseOriginal: map[string]any{},
		CreatedAtNS:      3,
	}, testCipher(t))
	if err == nil {
		t.Fatal("expected reconstruction mismatch")
	}
}

func testCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
