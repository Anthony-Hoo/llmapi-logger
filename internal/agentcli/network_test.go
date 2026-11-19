package agentcli

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// TestTLSIsVerified: an unknown certificate fails; config.json's ca_file
// makes it trusted.
func TestTLSIsVerified(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defaultResponder(writer, request, nil)
	}))
	defer server.Close()
	h := newHarness(t)
	h.saveLogin(server.URL)
	body := h.expectFailure(h.run("whoami"), agentapi.CodeNetworkError, 1)
	if body.Details["reason"] != "tls" {
		t.Fatalf("details %v", body.Details)
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	writeFile(t, filepath.Join(h.home, configFile), `{"ca_file":"`+filepath.ToSlash(caFile)+`"}`)
	if exit := h.run("whoami"); exit != 0 {
		t.Fatalf("with ca_file: exit %d %s", exit, h.stderr.String())
	}
}

// TestTimeouts pins the per-command timeouts of contract section 6.1.
func TestTimeouts(t *testing.T) {
	want := map[string]time.Duration{
		"weekly me": 40 * time.Second, "weekly report": 40 * time.Second, "weekly trend": 40 * time.Second,
		"weekly project": 40 * time.Second, "weekly unattributed": 40 * time.Second, "weekly regenerate": 40 * time.Second,
		"config preview-project": 40 * time.Second,
		"requests export":        60 * time.Second,
		"analysis test-model":    70 * time.Second,
		"apply":                  130 * time.Second,
	}
	for _, spec := range allCommands() {
		expected, special := want[spec.name()]
		if !special {
			expected = 15 * time.Second
		}
		if got := spec.timeout(); got != expected {
			t.Errorf("%s: timeout %s, want %s", spec.name(), got, expected)
		}
	}
}
