package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// NewAPI resolves a key by the segment before its first dash, so distinct test
// keys must differ before any dash. Real NewAPI keys are dash-free random
// strings; a trailing "-suffix" selects a channel for the same token.
const (
	developerKeyAlpha = "sk-testalphakey"
	developerKeyBeta  = "sk-testbetakey"
)

// newAPIWithTokenLogin serves both the proxied LLM route and the token log
// endpoint developer sign-in authenticates against.
func newAPIWithTokenLogin(t *testing.T, responseBody []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/log/token" {
			key := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
			switch key {
			case developerKeyAlpha:
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(`{"success":true,"data":[{"user_id":7,"username":"alpha","token_id":42,"token_name":"alpha-token"}]}`))
			case developerKeyBeta:
				response.Header().Set("Content-Type", "application/json")
				// A key NewAPI knows but has no logs for yet.
				_, _ = response.Write([]byte(`{"success":true,"data":[]}`))
			default:
				response.WriteHeader(http.StatusUnauthorized)
				_, _ = response.Write([]byte(`{"success":false,"message":"token invalid"}`))
			}
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	t.Cleanup(server.Close)
	return server
}

func proxyChatRequest(t *testing.T, client *http.Client, baseURL, apiKey, model string) {
	t.Helper()
	body := fmt.Appendf(nil, `{"model":%q,"stream":false,"messages":[{"role":"user","content":"hello"}]}`, model)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new proxied request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send proxied request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxied response status = %d", response.StatusCode)
	}
}

func developerLogin(t *testing.T, client *http.Client, adminURL, apiKey string) (*http.Cookie, int) {
	t.Helper()
	payload := fmt.Sprintf(`{"api_key":%q}`, apiKey)
	response, err := client.Post(adminURL+"/api/v1/session", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("developer login: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode
	}
	if bytes.Contains(body, []byte(apiKey)) {
		t.Fatal("login response echoed the submitted api key")
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %v", cookies)
	}
	return cookies[0], response.StatusCode
}

// listAuditsAs returns the audit ids visible to one session.
func listAuditsAs(t *testing.T, client *http.Client, adminURL string, cookie *http.Cookie) []adminAuditSummary {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, adminURL+"/api/v1/audits?limit=50", nil)
	if err != nil {
		t.Fatalf("new list request: %v", err)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	} else {
		request.Header.Set("Authorization", "Bearer integration-admin-token")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("list audits: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d body = %s", response.StatusCode, body)
	}
	var page adminListPage
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return page.Items
}

// waitForParsedAudits waits until the asynchronous parser has attached a model
// to every expected record, so scope assertions can identify them by model.
func waitForParsedAudits(t *testing.T, client *http.Client, adminURL string, want int) []adminAuditSummary {
	t.Helper()
	deadline := time.Now().Add(integrationTimeout)
	for {
		items := listAuditsAs(t, client, adminURL, nil)
		parsed := 0
		for _, item := range items {
			if item.RequestModel != nil {
				parsed++
			}
		}
		if parsed >= want {
			return items
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d parsed audits, saw %d of %d", want, parsed, len(items))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDeveloperSessionSeesOnlyItsOwnKeysAudits(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-local","model":"model-result","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	upstream := newAPIWithTokenLogin(t, responseBody)

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	cfg.DeveloperLogin.Enabled = true
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}

	proxyChatRequest(t, client, running.baseURL, developerKeyAlpha, "model-alpha")
	proxyChatRequest(t, client, running.baseURL, developerKeyBeta, "model-beta")
	// The same key spelled the way a channel-suffixed client sends it must land
	// in the alpha scope too.
	proxyChatRequest(t, client, running.baseURL, developerKeyAlpha+"-channel", "model-alpha-suffixed")

	all := waitForParsedAudits(t, client, running.adminURL, 3)
	if len(all) != 3 {
		t.Fatalf("administrator sees %d audits, want 3", len(all))
	}

	alphaCookie, _ := developerLogin(t, client, running.adminURL, developerKeyAlpha)
	alphaItems := listAuditsAs(t, client, running.adminURL, alphaCookie)
	if len(alphaItems) != 2 {
		t.Fatalf("alpha sees %d audits, want its own 2", len(alphaItems))
	}
	for _, item := range alphaItems {
		if item.RequestModel == nil || !strings.HasPrefix(*item.RequestModel, "model-alpha") {
			t.Fatalf("alpha saw a foreign audit: %+v", item)
		}
	}

	betaCookie, _ := developerLogin(t, client, running.adminURL, developerKeyBeta)
	betaItems := listAuditsAs(t, client, running.adminURL, betaCookie)
	if len(betaItems) != 1 {
		t.Fatalf("beta sees %d audits, want its own 1", len(betaItems))
	}
	if betaItems[0].RequestModel == nil || *betaItems[0].RequestModel != "model-beta" {
		t.Fatalf("beta saw a foreign audit: %+v", betaItems[0])
	}

	// Reading another developer's audit is indistinguishable from reading one
	// that does not exist.
	foreign := alphaItems[0].AuditID
	request, err := http.NewRequest(http.MethodGet, running.adminURL+"/api/v1/audits/"+foreign, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(betaCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("cross-tenant detail: %v", err)
	}
	crossBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant detail status = %d body = %s", response.StatusCode, crossBody)
	}

	// The owner reads the same audit in full.
	ownerRequest, err := http.NewRequest(http.MethodGet, running.adminURL+"/api/v1/audits/"+foreign, nil)
	if err != nil {
		t.Fatal(err)
	}
	ownerRequest.AddCookie(alphaCookie)
	ownerResponse, err := client.Do(ownerRequest)
	if err != nil {
		t.Fatalf("owner detail: %v", err)
	}
	ownerBody, _ := io.ReadAll(ownerResponse.Body)
	ownerResponse.Body.Close()
	if ownerResponse.StatusCode != http.StatusOK {
		t.Fatalf("owner detail status = %d body = %s", ownerResponse.StatusCode, ownerBody)
	}
	// Same depth as the administrator: the decrypted evidence is present.
	var detail adminAuditDetail
	if err := json.Unmarshal(ownerBody, &detail); err != nil {
		t.Fatalf("decode owner detail: %v", err)
	}
	if detail.Conversation == nil {
		t.Fatal("owner detail omitted the reconstructed conversation")
	}

	// Administrator-only surfaces stay closed.
	for _, path := range []string{"/healthz", "/api/v1/newapi/callers", "/api/v1/user-agent-rules"} {
		adminOnly, err := http.NewRequest(http.MethodGet, running.adminURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		adminOnly.AddCookie(alphaCookie)
		adminOnlyResponse, err := client.Do(adminOnly)
		if err != nil {
			t.Fatalf("developer %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, adminOnlyResponse.Body)
		adminOnlyResponse.Body.Close()
		if adminOnlyResponse.StatusCode != http.StatusForbidden {
			t.Fatalf("developer %s status = %d, want 403", path, adminOnlyResponse.StatusCode)
		}
	}
}

func TestDeveloperLoginRejectsUnknownKeyAndStaysOffByDefault(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-local","model":"model-result","choices":[{"message":{"role":"assistant","content":"hi"}}]}`)
	upstream := newAPIWithTokenLogin(t, responseBody)

	t.Run("unknown key", func(t *testing.T) {
		cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
		cfg.DeveloperLogin.Enabled = true
		running := startApp(t, cfg)
		client := &http.Client{Timeout: integrationTimeout}

		if _, status := developerLogin(t, client, running.adminURL, "sk-test-unknown-key"); status != http.StatusUnauthorized {
			t.Fatalf("unknown key login status = %d, want 401", status)
		}
	})

	t.Run("disabled by default", func(t *testing.T) {
		cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
		running := startApp(t, cfg)
		client := &http.Client{Timeout: integrationTimeout}

		if _, status := developerLogin(t, client, running.adminURL, developerKeyAlpha); status != http.StatusForbidden {
			t.Fatalf("login status with developer_login off = %d, want 403", status)
		}
	})
}
