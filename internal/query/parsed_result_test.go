package query

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// parsedResultDetail returns a stored detail whose parsed_json_enc holds
// sealed, the way the store hands it to the service.
func parsedResultDetail(t *testing.T, cipher security.Cipher, auditID, parserName string, sealed []byte) sqlite.AuditQueryDetail {
	t.Helper()
	requestAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestAAD, []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	return sqlite.AuditQueryDetail{
		Audit: sqlite.AuditListRow{
			AuditID: auditID, StartedAtNS: 1, ParserName: parserName,
			ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CapturePartial, ParseStatus: sqlite.ParsePartial,
		},
		RequestURIEnc: requestURIEnc,
		ParsedResult: &sqlite.ParsedResultSummary{
			ParserName: parserName, ParserVersion: "2", Status: sqlite.ParsePartial,
			ParsedJSONEnc: sealed, ParsedAtNS: 2,
		},
	}
}

func largeFallbackConversation() *conversation.Conversation {
	view := conversation.New()
	for index := 0; index < 200; index++ {
		text := fmt.Sprintf("turn %d: %s", index, strings.Repeat(fmt.Sprintf("conversation-secret-%d ", index%17), 40))
		role, phase, direction := conversation.RoleUser, conversation.PhaseRequest, conversation.DirectionClientToUpstream
		if index%2 == 1 {
			role, phase, direction = conversation.RoleAssistant, conversation.PhaseResponse, conversation.DirectionUpstreamToClient
		}
		view.Append(conversation.Message{Role: role, Phase: phase, Direction: direction, Content: []conversation.Part{conversation.Text(text)}})
	}
	return view
}

// TestParsedResultReadersAcceptLegacyAndCompressedRows reads the same
// fallback conversation stored both ways, through every query reader of
// parsed_json_enc, and requires identical output.
func TestParsedResultReadersAcceptLegacyAndCompressedRows(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-parsed-formats"
	parserName := "openai.chat_completions"
	plaintext, err := json.Marshal(map[string]any{"status": "partial", "conversation": largeFallbackConversation()})
	if err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	// Built exactly as the base commit's writer did.
	legacy, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := auditmodel.SealParsedResult(cipher, auditID, parserName, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := cipher.Decrypt(aad, compressed); err != nil || !bytes.HasPrefix(payload, []byte{0x1f, 0x8b}) {
		t.Fatalf("fixture was not stored compressed: %v", err)
	}

	read := func(sealed []byte) (string, string) {
		service, err := New(&fakeStore{healthy: true, detail: parsedResultDetail(t, cipher, auditID, parserName, sealed)}, cipher)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := service.Get(context.Background(), auditID, nil)
		if err != nil {
			t.Fatal(err)
		}
		fromDetail, err := json.Marshal(detail.Conversation)
		if err != nil {
			t.Fatal(err)
		}
		session, err := service.SessionConversation(context.Background(), auditID)
		if err != nil {
			t.Fatal(err)
		}
		fromSession, err := json.Marshal(session)
		if err != nil {
			t.Fatal(err)
		}
		return string(fromDetail), string(fromSession)
	}
	legacyDetail, legacySession := read(legacy)
	compressedDetail, compressedSession := read(compressed)
	want, err := json.Marshal(largeFallbackConversation())
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"legacy detail": legacyDetail, "legacy session": legacySession,
		"compressed detail": compressedDetail, "compressed session": compressedSession,
	} {
		if got != string(want) {
			t.Fatalf("%s conversation differs from the stored one", name)
		}
	}
}

func TestParsedResultReadersRejectCorruptCompressedRows(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	auditID := "audit-parsed-corrupt"
	parserName := "openai.chat_completions"
	plaintext, err := json.Marshal(map[string]any{"conversation": largeFallbackConversation()})
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	writer := gzip.NewWriter(&stream)
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	aad, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	// Authentic ciphertext around a truncated gzip stream: decryption
	// succeeds and only decompression can catch it.
	truncated, err := cipher.Encrypt(aad, stream.Bytes()[:stream.Len()/2])
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(&fakeStore{healthy: true, detail: parsedResultDetail(t, cipher, auditID, parserName, truncated)}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	_, getErr := service.Get(context.Background(), auditID, nil)
	_, sessionErr := service.SessionConversation(context.Background(), auditID)
	for name, err := range map[string]error{"Get": getErr, "SessionConversation": sessionErr} {
		if !errors.Is(err, ErrIntegrity) || err.Error() != ErrIntegrity.Error() {
			t.Fatalf("%s error = %v, want the same ErrIntegrity a decryption failure gives", name, err)
		}
	}
}
