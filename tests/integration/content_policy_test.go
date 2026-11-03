package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestContentPolicyEndToEnd exercises the real data/admin listeners: a rule
// created through the management API blocks a request before NewAPI, and an
// upstream cyber_policy rejection is classified and available through the
// audit list filter.
func TestContentPolicyEndToEnd(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(response, "read body", http.StatusInternalServerError)
			return
		}
		upstreamCalls.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "cyber_prompt") {
			response.WriteHeader(http.StatusBadRequest)
			_, _ = response.Write([]byte(`{"error":{"message":"This content was flagged for possible cybersecurity risk.","type":"invalid_request_error","code":"cyber_policy"}}`))
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"id":"chatcmpl-e2e","object":"chat.completion","model":"deepseek-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}

	adminJSON := func(method, path, body string) (int, []byte) {
		t.Helper()
		request, err := http.NewRequest(method, running.adminURL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new admin request: %v", err)
		}
		request.Header.Set("Authorization", "Bearer integration-admin-token")
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("send admin request: %v", err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read admin response: %v", err)
		}
		return response.StatusCode, payload
	}

	status, payload := adminJSON(http.MethodPost, "/api/v1/content-policy-rules",
		`{"name":"e2e keyword rule","enabled":true,"action":"block","model_pattern":"","scan_scopes":["latest_user"],"keywords":["forbidden"]}`)
	if status != http.StatusCreated {
		t.Fatalf("create content policy rule: status=%d body=%s", status, payload)
	}
	var rule struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(payload, &rule); err != nil || rule.ID <= 0 {
		t.Fatalf("decode content policy rule: %v body=%s", err, payload)
	}

	sendPrompt := func(prompt string) (int, string) {
		t.Helper()
		body := `{"model":"deepseek-test","messages":[{"role":"user","content":"` + prompt + `"}]}`
		request, err := http.NewRequest(http.MethodPost, running.baseURL+"/v1/chat/completions", strings.NewReader(body))
		if err != nil {
			t.Fatalf("new data request: %v", err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("send data request: %v", err)
		}
		defer response.Body.Close()
		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read data response: %v", err)
		}
		return response.StatusCode, string(responseBody)
	}

	blockStatus, blockBody := sendPrompt("forbidden")
	if blockStatus != http.StatusBadRequest || upstreamCalls.Load() != 0 ||
		blockBody != `{"error":{"code":"request_rejected","message":"request rejected"}}` {
		t.Fatalf("blocked request: status=%d upstream=%d body=%s", blockStatus, upstreamCalls.Load(), blockBody)
	}

	listBody := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits?block_code=content_policy_blocked&limit=50")
	var blockedPage struct {
		Items []struct {
			AuditID    string `json:"audit_id"`
			BlockedBy  string `json:"blocked_by"`
			BlockCode  string `json:"block_code"`
			ParseState string `json:"parse_status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listBody, &blockedPage); err != nil {
		t.Fatalf("decode blocked audit list: %v body=%s", err, listBody)
	}
	if len(blockedPage.Items) != 1 || blockedPage.Items[0].BlockedBy != "content_policy" ||
		blockedPage.Items[0].BlockCode != "content_policy_blocked" || blockedPage.Items[0].ParseState != "skipped" {
		t.Fatalf("blocked audit summary = %+v", blockedPage.Items)
	}

	allowedStatus, allowedBody := sendPrompt("ordinary request")
	if allowedStatus != http.StatusOK || upstreamCalls.Load() != 1 {
		t.Fatalf("allowed request: status=%d upstream=%d body=%s", allowedStatus, upstreamCalls.Load(), allowedBody)
	}

	rejectedStatus, rejectedBody := sendPrompt("cyber_prompt")
	if rejectedStatus != http.StatusBadRequest || upstreamCalls.Load() != 2 {
		t.Fatalf("upstream policy rejection: status=%d upstream=%d body=%s", rejectedStatus, upstreamCalls.Load(), rejectedBody)
	}

	deadline := time.Now().Add(integrationTimeout)
	for time.Now().Before(deadline) {
		listBody = authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits?upstream_error_class=cyber_policy&limit=50")
		var page struct {
			Items []struct {
				AuditID            string  `json:"audit_id"`
				ParseStatus        string  `json:"parse_status"`
				ParsedErrorCode    *string `json:"parsed_error_code"`
				UpstreamErrorClass *string `json:"upstream_error_class"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listBody, &page); err != nil {
			t.Fatalf("decode upstream class list: %v body=%s", err, listBody)
		}
		for _, item := range page.Items {
			if item.ParseStatus == "ok" && item.ParsedErrorCode != nil && *item.ParsedErrorCode == "cyber_policy" &&
				item.UpstreamErrorClass != nil && *item.UpstreamErrorClass == "cyber_policy" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for upstream_error_class=cyber_policy in the audit list")
}
