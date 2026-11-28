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

	"llmapi-logger/internal/config"
)

// A verified Gemini audit is stored as a content-addressed turn, JSON and
// SSE alike: the raw bodies are released, parsed_results keeps no second
// copy of the conversation, and the answer a client resends in the next
// request's contents is the object the response stored. A stream cut before
// its finish reason is not verified and keeps its raw.
func TestGeminiGenerateContentIsStoredAsContentAddressedTurns(t *testing.T) {
	const canary = "gemini-integration-canary-5c2e81"
	padding := strings.Repeat("resent history line. ", 256)
	system := `"systemInstruction":{"parts":[{"text":"You are an agent."}]}`
	user1 := `{"role":"user","parts":[{"text":"` + canary + ` ` + padding + `"}]}`
	answer1 := `{"role":"model","parts":[{"text":"first answer"}]}`
	user2 := `{"role":"user","parts":[{"text":"go on"}]}`
	requests := [][]byte{
		[]byte(`{` + system + `,"contents":[` + user1 + `]}`),
		[]byte(`{` + system + `,"contents":[` + user1 + `,` + answer1 + `,` + user2 + `]}`),
		[]byte(`{` + system + `,"contents":[` + user1 + `,` + answer1 + `,` + user2 + `]}`),
	}
	usage := `"usageMetadata":{"promptTokenCount":11,"cachedContentTokenCount":4,"candidatesTokenCount":2,"totalTokenCount":13},"modelVersion":"model-example"`
	jsonResponse := `{"candidates":[{"content":` + answer1 + `,"finishReason":"STOP","index":0}],` + usage + `,"responseId":"gem-first"}`
	chunk := func(text, finish string) string {
		return "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"" + text + "\"}]}" + finish + ",\"index\":0}]," + usage + ",\"responseId\":\"gem-second\"}\r\n\r\n"
	}
	streamResponse := chunk("hello ", "") + chunk("world", `,"finishReason":"STOP"`)
	// The same stream cut cleanly before the chunk with the finish reason.
	truncatedResponse := chunk("hello ", "")
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.ReadAll(request.Body)
		calls++
		switch {
		case !strings.Contains(request.URL.Path, ":streamGenerateContent"):
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, jsonResponse)
		case calls == 2:
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(response, streamResponse)
		default:
			response.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(response, truncatedResponse)
		}
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	cfg.Routes = append(cfg.Routes,
		config.RouteConfig{ID: "gemini-generate", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		config.RouteConfig{ID: "gemini-stream", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
	)
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}
	paths := []string{"/v1beta/models/model-example:generateContent", "/v1beta/models/model-example:streamGenerateContent?alt=sse",
		"/v1beta/models/model-example:streamGenerateContent?alt=sse"}
	auditIDs := make([]string, 0, len(requests))
	for index, body := range requests {
		request, err := http.NewRequest(http.MethodPost, running.baseURL+paths[index], bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "example-agent/1.0 integration")
		request.Header.Set("X-Goog-Api-Key", "sk-geminicaller")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d err=%v", index, response.StatusCode, err)
		}
		if index < 2 {
			auditIDs = append(auditIDs, waitForNextParsedAdminAudit(t, client, running.adminURL, auditIDs))
		} else {
			auditIDs = append(auditIDs, waitForNextSettledAdminAudit(t, client, running.adminURL, auditIDs))
		}
	}

	database := openAuditDatabase(t, cfg.DatabaseURL)
	defer database.Close()
	var turns, linked, released, truncatedRetained, truncatedReleased, modelObjects, userObjects int
	var largestParsedJSON int64
	var truncatedStatus, truncatedResponseLayout string
	if err := database.QueryRow(`
SELECT
    (SELECT COUNT(*) FROM turns),
    (SELECT COUNT(*) FROM turns WHERE parent_turn_id IS NOT NULL),
    (SELECT COUNT(*) FROM body_streams WHERE audit_id IN ($1, $2) AND retention_state = 'metadata'),
    (SELECT COUNT(*) FROM body_streams WHERE audit_id = $3 AND retention_state = 'full'
       AND stage IN ('response_received_from_newapi', 'response_from_newapi_sent_to_nginx')),
    (SELECT COUNT(*) FROM body_streams WHERE audit_id = $3 AND retention_state = 'metadata'
       AND stage IN ('request_for_newapi_received_from_nginx', 'request_sent_to_newapi')),
    (SELECT COUNT(*) FROM content_objects WHERE kind = 'model_content'),
    (SELECT COUNT(*) FROM content_objects WHERE kind = 'user_content'),

    (SELECT MAX(octet_length(parsed_json_enc)) FROM parsed_results WHERE audit_id IN ($1, $2)),
    (SELECT parse_status FROM audit_records WHERE audit_id = $3),
    (SELECT response_layout FROM turns WHERE audit_id = $3)
`, auditIDs[0], auditIDs[1], auditIDs[2]).Scan(&turns, &linked, &released, &truncatedRetained, &truncatedReleased, &modelObjects, &userObjects,
		&largestParsedJSON, &truncatedStatus, &truncatedResponseLayout); err != nil {
		t.Fatal(err)
	}
	// The stream without a finish reason is not verified as a response: it
	// gets a turn that carries only the request, keeps its response raw and
	// stays partial.
	if turns != 3 || released < 4 || truncatedRetained != 2 || truncatedReleased != 2 || truncatedStatus != "partial" || truncatedResponseLayout != "none" {
		t.Fatalf("turns %d, released bodies %d, truncated stream: %d full response bodies, %d released request bodies, parse %q, response layout %q",
			turns, released, truncatedRetained, truncatedReleased, truncatedStatus, truncatedResponseLayout)
	}
	// The first answer is stored once, shared by the first response and the
	// second request; the stream adds its own answer. The first user content
	// is sent twice and stored once.
	if modelObjects != 2 || userObjects != 2 {
		t.Fatalf("model contents %d, user contents %d, want 2 and 2", modelObjects, userObjects)
	}
	if largestParsedJSON >= int64(len(padding)) {
		t.Fatalf("parsed_json_enc holds %d bytes: the conversation was stored a second time", largestParsedJSON)
	}
	t.Logf("turns %d (linked %d), model contents %d, user contents %d", turns, linked, modelObjects, userObjects)
	assertPostgresRowsDoNotContain(t, cfg.DatabaseURL, [][]byte{[]byte(canary)})

	for index, auditID := range auditIDs[:2] {
		if status, body := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/raw/request"); status != http.StatusGone {
			t.Fatalf("raw request %d = %d %s", index, status, body)
		}
		assertJSONEquivalent(t, authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/reconstructed/request"), requests[index])
		var detail adminAuditDetail
		if err := json.Unmarshal(authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID), &detail); err != nil {
			t.Fatal(err)
		}
		messages := detail.Conversation.Messages
		last := messages[len(messages)-1]
		want := []string{"first answer", "hello world"}[index]
		if len(last.Content) != 1 || last.Content[0].Text != want || !strings.Contains(messages[1].Content[0].Text, canary) {
			t.Fatalf("conversation %d = %+v", index, messages)
		}
	}
	assertJSONEquivalent(t, authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditIDs[0]+"/reconstructed/response"), []byte(jsonResponse))
	stream := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditIDs[1]+"/reconstructed/response")
	if !bytes.Contains(stream, []byte("hello world")) || !bytes.Contains(stream, []byte(`"format":"sse"`)) || !bytes.Contains(stream, []byte(`"stop_reason":"STOP"`)) {
		t.Fatalf("reconstructed stream = %s", stream)
	}
	if status, _ := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditIDs[2]+"/raw/response"); status != http.StatusOK {
		t.Fatalf("truncated stream raw response = %d, want it kept", status)
	}
}

// waitForNextSettledAdminAudit waits for an audit that is not in known and
// whose parse finished, whatever its status, and returns its id.
func waitForNextSettledAdminAudit(t *testing.T, client *http.Client, adminURL string, known []string) string {
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
			if item.ParseStatus != "pending" && item.ParseStatus != "processing" && item.ParseStatus != "" {
				return item.AuditID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for asynchronous parser result")
	return ""
}
