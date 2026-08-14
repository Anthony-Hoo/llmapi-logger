package query

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestContentAddressedStorageGrowsWithUniqueTurnsInsteadOfRepeatedHistory(t *testing.T) {
	t.Parallel()
	const turnCount = 24
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	cipher := testCipher(t)
	implementation, err := openai.New(openai.Responses)
	if err != nil {
		t.Fatal(err)
	}

	textCanary := "semantic-plaintext-canary-7e6a9d43"
	binaryCanary := []byte("binary-plaintext-canary-15b8f4c2")
	png := append([]byte("\x89PNG\r\n\x1a\n"), binaryCanary...)
	png = append(png, bytes.Repeat([]byte{0x6d, 0x23}, 256*1024)...)
	encodedPNG := base64.StdEncoding.EncodeToString(png)
	history := []any{map[string]any{
		"type": "message", "role": "user",
		"content": []any{
			map[string]any{"type": "input_text", "text": textCanary + " initial multimodal question"},
			map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + encodedPNG},
		},
	}}
	var previousResponseID string
	var repeatedWireBytes int64
	var itemOccurrences int
	requestBodies := make([][]byte, turnCount)
	responseBodies := make([][]byte, turnCount)
	for index := 0; index < turnCount; index++ {
		if index > 0 {
			history = append(history, map[string]any{
				"type": "message", "role": "user",
				"content": []any{map[string]any{"type": "input_text", "text": fmt.Sprintf("follow-up %02d", index)}},
			})
		}
		responseID := fmt.Sprintf("response-%02d", index)
		requestValue := map[string]any{
			"model":        "model-example",
			"instructions": "Keep the full audit trail.",
			"metadata":     map[string]any{"conversation_id": "conversation-capacity-example"},
			"input":        append([]any(nil), history...),
		}
		if previousResponseID != "" {
			requestValue["previous_response_id"] = previousResponseID
		}
		assistantItem := map[string]any{
			"type": "message", "id": fmt.Sprintf("message-%02d", index), "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": fmt.Sprintf("answer %02d", index)}},
		}
		responseValue := map[string]any{
			"id": responseID, "object": "response", "model": "model-result",
			"output": []any{assistantItem},
			"usage":  map[string]any{"input_tokens": 100 + index, "output_tokens": 10, "total_tokens": 110 + index},
		}
		requestBody, err := auditmodel.CanonicalJSON(requestValue)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, err := auditmodel.CanonicalJSON(responseValue)
		if err != nil {
			t.Fatal(err)
		}
		requestBodies[index] = append([]byte(nil), requestBody...)
		responseBodies[index] = append([]byte(nil), responseBody...)
		repeatedWireBytes += int64(len(requestBody) + len(responseBody))
		itemOccurrences += 1 + len(history) + 1 // instructions + input history + response item
		auditID := fmt.Sprintf("audit-capacity-%02d", index)
		requestURI, err := encryptRequestURI(cipher, auditID, "/v1/responses")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginAudit(ctx, sqlite.AuditRecord{
			AuditID: auditID, StartedAtNS: int64(index*10 + 1), RouteID: "responses-route",
			Protocol: "openai", ParserName: openai.Responses, Method: "POST", Path: "/v1/responses",
			RequestURIEnc: requestURI, Mode: "available",
		}); err != nil {
			t.Fatal(err)
		}
		status := 200
		if err := store.FinishAudit(ctx, sqlite.AuditFinish{
			AuditID: auditID, EndedAtNS: int64(index*10 + 2), StatusCode: &status,
			ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimPendingParse(ctx, auditID)
		if err != nil || !claimed {
			t.Fatalf("claim %s = %v, %v", auditID, claimed, err)
		}
		input := base.Input{
			AuditID: auditID, Protocol: "openai", Endpoint: "/v1/responses",
			Request:  base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: requestBody},
			Response: base.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: responseBody},
		}
		result := implementation.Parse(ctx, input)
		turn, err := implementation.NormalizeAudit(ctx, input, result)
		if err != nil {
			t.Fatal(err)
		}
		turn.CreatedAtNS = int64(index*10 + 3)
		prepared, err := auditmodel.Prepare(turn, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveParsedAudit(ctx, sqlite.ParsedAudit{
			Result: sqlite.ParsedResult{
				AuditID: auditID, ParserName: openai.Responses, ParserVersion: "2",
				Status: sqlite.ParseOK, ResponseID: &responseID, ParsedAtNS: int64(index*10 + 4),
			},
			Turn: &prepared,
		}); err != nil {
			t.Fatal(err)
		}
		history = append(history, assistantItem)
		previousResponseID = responseID
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < turnCount; index++ {
		auditID := fmt.Sprintf("audit-capacity-%02d", index)
		rebuilt, err := service.ReconstructTurn(ctx, auditID)
		if err != nil {
			t.Fatalf("reconstruct %s: %v", auditID, err)
		}
		requestBody, err := auditmodel.CanonicalJSON(rebuilt.Request)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, err := auditmodel.CanonicalJSON(rebuilt.Response)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(requestBody, requestBodies[index]) || !bytes.Equal(responseBody, responseBodies[index]) {
			t.Fatalf("reconstructed provider bodies differ for %s", auditID)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var turns, conversations, contentObjects, binaryObjects, contextOps int
	var semanticPlaintextBytes sql.NullInt64
	if err := database.QueryRow(`
SELECT
    (SELECT COUNT(*) FROM turns),
    (SELECT COUNT(*) FROM conversations),
    (SELECT COUNT(*) FROM content_objects),
    (SELECT COUNT(*) FROM binary_objects),
    (SELECT COUNT(*) FROM turn_context_ops),
    (SELECT SUM(plaintext_length) FROM content_objects) +
        (SELECT SUM(plaintext_length) FROM binary_objects)
`).Scan(&turns, &conversations, &contentObjects, &binaryObjects, &contextOps, &semanticPlaintextBytes); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	var quickCheck string
	if err := database.QueryRow("PRAGMA quick_check").Scan(&quickCheck); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if quickCheck != "ok" {
		_ = database.Close()
		t.Fatalf("PRAGMA quick_check = %q", quickCheck)
	}
	foreignKeys, err := database.Query("PRAGMA foreign_key_check")
	if err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if foreignKeys.Next() {
		_ = foreignKeys.Close()
		_ = database.Close()
		t.Fatal("PRAGMA foreign_key_check reported a violation")
	}
	if err := foreignKeys.Close(); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if turns != turnCount || conversations != 1 || binaryObjects != 1 {
		t.Fatalf("turns/conversations/binaries = %d/%d/%d", turns, conversations, binaryObjects)
	}
	if contentObjects*3 >= itemOccurrences || contextOps > turnCount*4 {
		t.Fatalf("objects/occurrences/context ops = %d/%d/%d", contentObjects, itemOccurrences, contextOps)
	}
	if !semanticPlaintextBytes.Valid || semanticPlaintextBytes.Int64*4 >= repeatedWireBytes {
		t.Fatalf("stored semantic bytes/wire bytes = %d/%d", semanticPlaintextBytes.Int64, repeatedWireBytes)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var sqliteBytes int64
	for _, candidate := range []string{path, path + "-wal"} {
		info, err := os.Stat(candidate)
		if err == nil {
			sqliteBytes += info.Size()
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if sqliteBytes*2 >= repeatedWireBytes {
		t.Fatalf("SQLite bytes/wire bytes = %d/%d", sqliteBytes, repeatedWireBytes)
	}
	assertSQLiteFilesDoNotContain(t, path, [][]byte{
		[]byte(textCanary),
		binaryCanary,
		[]byte(encodedPNG),
	})
	t.Logf(
		"turns=%d item_occurrences=%d content_objects=%d binary_objects=%d context_ops=%d semantic_plaintext_bytes=%d repeated_wire_bytes=%d sqlite_bytes=%d",
		turns, itemOccurrences, contentObjects, binaryObjects, contextOps,
		semanticPlaintextBytes.Int64, repeatedWireBytes, sqliteBytes,
	)
}

func assertSQLiteFilesDoNotContain(t *testing.T, path string, markers [][]byte) {
	t.Helper()
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range markers {
			if bytes.Contains(data, marker) {
				t.Fatalf("SQLite evidence file %q contains a plaintext canary", filepath.Base(candidate))
			}
		}
	}
}

func encryptRequestURI(cipher security.Cipher, auditID, value string) ([]byte, error) {
	aad, err := security.AAD(auditID, "request_uri")
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(aad, []byte(value))
}
