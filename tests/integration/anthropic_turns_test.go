package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A verified Messages audit is stored as a content-addressed turn: the raw
// bodies are released, no second copy of the conversation is kept in
// parsed_results, and the resent history is stored once. The session a client
// declares keeps its turns in one conversation and other sessions out of it.
func TestAnthropicMessagesAreStoredAsContentAddressedTurns(t *testing.T) {
	const canary = "anthropic-integration-canary-93ab17"
	padding := strings.Repeat("resent history line. ", 256)
	const system = `"system":[{"type":"text","text":"You are an agent.","cache_control":{"type":"ephemeral"}}]`
	firstMessage := `{"role":"user","content":"` + canary + ` ` + padding + `"}`
	session := func(id string) string {
		return `"metadata":{"user_id":"{\"device_id\":\"device-example\",\"session_id\":\"` + id + `\"}"},`
	}
	secondTurn := firstMessage + `,{"role":"assistant","content":[{"type":"text","text":"first answer"}]},{"role":"user","content":"go on"}`
	requests := [][]byte{
		[]byte(`{"model":"model-example","max_tokens":64,` + session("session-one") + system + `,"messages":[` + firstMessage + `]}`),
		[]byte(`{"model":"model-example","max_tokens":64,"stream":true,` + session("session-one") + system + `,"messages":[` + secondTurn + `]}`),
		[]byte(`{"model":"model-example","max_tokens":64,` + session("session-one") + system + `,"messages":[` + secondTurn +
			`,{"role":"assistant","content":[{"type":"text","text":"hello world"}]},{"role":"user","content":"and then"}]}`),
		// Another caller opens another session with the same first message.
		[]byte(`{"model":"model-example","max_tokens":64,` + session("session-two") + system + `,"messages":[` + firstMessage + `]}`),
	}
	jsonResponse := `{"id":"msg_first","type":"message","role":"assistant","model":"model-example","content":[{"type":"text","text":"first answer"}],` +
		`"stop_reason":"end_turn","usage":{"input_tokens":11,"cache_read_input_tokens":300,"output_tokens":2}}`
	streamResponse := "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_second","type":"message","role":"assistant","model":"model-example","content":[],"usage":{"input_tokens":4,"cache_read_input_tokens":900,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello "}}` + "\n\n" +
		"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}` + "\n\n" +
		"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}` + "\n\n" +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if bytes.Contains(body, []byte(`"stream":true`)) {
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(response, streamResponse)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, jsonResponse)
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/messages", false)
	cfg.Routes[0].Parser = "anthropic.messages"
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}
	auditIDs := make([]string, 0, len(requests))
	for index, body := range requests {
		request, err := http.NewRequest(http.MethodPost, running.baseURL+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "example-agent/1.0 integration")
		request.Header.Set("X-Api-Key", []string{"sk-callerone", "sk-callerone", "sk-callerone", "sk-callertwo"}[index])
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d err=%v", index, response.StatusCode, err)
		}
		auditIDs = append(auditIDs, waitForNextParsedAdminAudit(t, client, running.adminURL, auditIDs))
	}

	database := openAuditDatabase(t, cfg.DatabaseURL)
	defer database.Close()
	var turns, linkedTurns, retainedBodies, chunks, messageObjects, conversations int
	var largestParsedJSON int64
	var thirdParent, firstConversation, otherConversation string
	if err := database.QueryRow(`
SELECT
    (SELECT COUNT(*) FROM turns),
    (SELECT COUNT(*) FROM turns WHERE parent_turn_id IS NOT NULL),
    (SELECT COUNT(*) FROM body_streams WHERE retention_state <> 'metadata'),
    (SELECT COUNT(*) FROM body_chunks),
    (SELECT COUNT(*) FROM content_objects WHERE kind = 'user_message'),
    (SELECT COUNT(*) FROM conversations),
    (SELECT MAX(octet_length(parsed_json_enc)) FROM parsed_results),
    (SELECT COALESCE(parent_turn_id, '') FROM turns WHERE audit_id = $1),
    (SELECT conversation_id FROM turns WHERE audit_id = $2),
    (SELECT conversation_id FROM turns WHERE audit_id = $3)
`, auditIDs[2], auditIDs[0], auditIDs[3]).Scan(&turns, &linkedTurns, &retainedBodies, &chunks, &messageObjects, &conversations,
		&largestParsedJSON, &thirdParent, &firstConversation, &otherConversation); err != nil {
		t.Fatal(err)
	}
	if turns != 4 || retainedBodies != 0 || chunks != 0 {
		t.Fatalf("turns/retained bodies/chunks = %d/%d/%d", turns, retainedBodies, chunks)
	}
	// The first message is sent four times and stored once; each later
	// request of the session adds only its own user message.
	if messageObjects != 3 {
		t.Fatalf("user message objects = %d, want 3", messageObjects)
	}
	// The third request repeats the three messages of the second one. A
	// single shared message is no evidence of a parent, so the second request
	// starts its own root in the session's conversation.
	if linkedTurns != 1 || thirdParent != auditIDs[1] {
		t.Fatalf("linked turns = %d, parent of the third turn = %q", linkedTurns, thirdParent)
	}
	// The other session repeats the first request word for word and still
	// stays out of this conversation.
	if conversations != 2 || otherConversation == firstConversation {
		t.Fatalf("conversations = %d (%s / %s)", conversations, firstConversation, otherConversation)
	}
	if largestParsedJSON >= int64(len(padding)) {
		t.Fatalf("parsed_json_enc holds %d bytes: the conversation was stored a second time", largestParsedJSON)
	}
	assertPostgresRowsDoNotContain(t, cfg.DatabaseURL, [][]byte{[]byte(canary)})

	for index, auditID := range auditIDs {
		if status, body := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/raw/request"); status != http.StatusGone {
			t.Fatalf("raw request %d = %d %s", index, status, body)
		}
		reconstructed := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/reconstructed/request")
		assertJSONEquivalent(t, reconstructed, requests[index])
		var detail adminAuditDetail
		if err := json.Unmarshal(authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Conversation == nil || len(detail.Conversation.Messages) == 0 {
			t.Fatalf("audit %d has no conversation", index)
		}
		messages := detail.Conversation.Messages
		last := messages[len(messages)-1]
		want := []string{"first answer", "hello world", "first answer", "first answer"}[index]
		if len(last.Content) != 1 || last.Content[0].Text != want || !strings.Contains(messages[1].Content[0].Text, canary) {
			t.Fatalf("conversation %d = %+v", index, messages)
		}
	}
	assertJSONEquivalent(t, authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditIDs[0]+"/reconstructed/response"), []byte(jsonResponse))
	stream := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditIDs[1]+"/reconstructed/response")
	if !bytes.Contains(stream, []byte("hello world")) || !bytes.Contains(stream, []byte(`"format":"sse"`)) || !bytes.Contains(stream, []byte(`"cache_read":900`)) {
		t.Fatalf("reconstructed stream = %s", stream)
	}
}

// waitForNextParsedAdminAudit waits for an audit that is not in known and
// whose parse succeeded, and returns its id.
func waitForNextParsedAdminAudit(t *testing.T, client *http.Client, adminURL string, known []string) string {
	t.Helper()
	deadline := time.Now().Add(integrationTimeout)
	for time.Now().Before(deadline) {
		var page adminListPage
		body := authorizedAdminGET(t, client, adminURL+"/api/v1/audits?limit=50")
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode admin list: %v\n%s", err, body)
		}
	items:
		for _, item := range page.Items {
			for _, id := range known {
				if item.AuditID == id {
					continue items
				}
			}
			if item.ParseStatus == "ok" {
				return item.AuditID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for asynchronous parser result")
	return ""
}
