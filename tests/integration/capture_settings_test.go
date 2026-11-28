package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/storage/postgres"
)

// adminBearerCall is one management API call with the admin token.
func adminBearerCall(t *testing.T, client *http.Client, method, target, token, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

// The retry count saved on the settings page reaches the unified write path
// of the running process: with 0 a failing final commit is attempted once,
// with 2 three times, without a restart (design I.7).
func TestCaptureSettingsRetryCountAppliesWithoutRestart(t *testing.T) {
	// The upstream holds the exchange until each checkpoint of the audit in
	// flight is in the database, so the final commit is a batch of its own
	// and the injected failure below hits only the commit. A checkpoint lost
	// with the commit's batch would mark the audit failed and let the retry
	// through.
	var ddl *sql.DB
	waitForStage := func(stage string) {
		deadline := time.Now().Add(integrationTimeout)
		for time.Now().Before(deadline) {
			var stored int
			if err := ddl.QueryRow(`SELECT count(*) FROM http_stages s JOIN audit_records a USING (audit_id)
WHERE a.ended_at_ns IS NULL AND s.stage = $1`, stage).Scan(&stored); err == nil && stored > 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Errorf("checkpoint with %s did not reach the database", stage)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		waitForStage("request_sent_to_newapi")
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		waitForStage("response_received_from_newapi")
		_, _ = io.WriteString(writer, `{"id":"chatcmpl-1","object":"chat.completion","model":"model-example","choices":[{"index":0,"message":{"role":"assistant","content":"reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
	}))
	defer upstream.Close()
	cfg := unifiedConfig(t, upstream.URL)
	// A file value other than the two saved below, so the attempt counts can
	// only come from the saved values.
	cfg.Audit.CommitRetries = 4
	var err error
	running := startApp(t, cfg)
	client := &http.Client{Timeout: 3 * integrationTimeout}
	settingsURL := running.adminURL + "/api/v1/settings/audit-capture"

	// The final commit's batch fails at COMMIT (a deferred foreign key the
	// commit's own UPDATE violates), which the session retries. The sequence
	// counts the attempts: nextval survives the rollback. Recovery, which
	// finalizes the audit as failed after the last attempt, is let through.
	ddl, err = sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer ddl.Close()
	if _, err := ddl.Exec(`CREATE SEQUENCE capture_commit_attempts;
CREATE TABLE fail_commit_audit (audit_id TEXT REFERENCES audit_records(audit_id) DEFERRABLE INITIALLY DEFERRED);
CREATE FUNCTION fail_commit_audit_fn() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	PERFORM nextval('capture_commit_attempts');
	INSERT INTO fail_commit_audit VALUES ('missing-parent');
	RETURN NEW;
END $$;
CREATE TRIGGER fail_commit_audit AFTER UPDATE OF ended_at_ns ON audit_records FOR EACH ROW
	WHEN (NEW.ended_at_ns IS NOT NULL AND NEW.capture_status = 'complete') EXECUTE FUNCTION fail_commit_audit_fn()`); err != nil {
		t.Fatal(err)
	}
	attempts := func() int64 {
		t.Helper()
		var value int64
		var called bool
		if err := ddl.QueryRow(`SELECT last_value, is_called FROM capture_commit_attempts`).Scan(&value, &called); err != nil {
			t.Fatal(err)
		}
		if !called {
			return 0
		}
		return value
	}
	// finishRequest proxies one request and waits until its audit is
	// finalized, which after the failed commit is recovery's work.
	finishRequest := func(finished int) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, running.baseURL+"/v1/chat/completions",
			strings.NewReader(`{"model":"model-example","messages":[{"role":"user","content":"hello"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer sk-synthetic-capture-settings")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("proxied request = %d", response.StatusCode)
		}
		deadline := time.Now().Add(3 * integrationTimeout)
		for {
			var ended, failed int
			if err := ddl.QueryRow(`SELECT count(*) FILTER (WHERE ended_at_ns IS NOT NULL), count(*) FILTER (WHERE capture_status = 'failed') FROM audit_records`).
				Scan(&ended, &failed); err != nil {
				t.Fatal(err)
			}
			if ended == finished {
				if failed != finished {
					t.Fatalf("%d audits ended, %d of them failed", ended, failed)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d of %d audits ended", ended, finished)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	save := func(retries string) {
		t.Helper()
		status, body := adminBearerCall(t, client, http.MethodPut, settingsURL, cfg.AdminToken, `{"commit_retries":`+retries+`}`)
		var view struct {
			Source   string `json:"source"`
			Settings struct {
				CommitRetries int `json:"commit_retries"`
			} `json:"settings"`
			File struct {
				CommitRetries int `json:"commit_retries"`
			} `json:"file"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil || view.Source != "saved" || view.File.CommitRetries != 4 {
			t.Fatalf("save %s = %d %s", retries, status, body)
		}
	}

	if status, body := adminBearerCall(t, client, http.MethodGet, settingsURL, cfg.AdminToken, ""); status != http.StatusOK ||
		!strings.Contains(string(body), `"source":"file"`) || !strings.Contains(string(body), `"commit_retries":4`) || !strings.Contains(string(body), `"write_path":"unified"`) {
		t.Fatalf("initial settings = %d %s", status, body)
	}
	if status, body := adminBearerCall(t, client, http.MethodPut, settingsURL, cfg.AdminToken, `{"commit_retries":6}`); status != http.StatusBadRequest ||
		!strings.Contains(string(body), "audit.commit_retries must be between 0 and 5") {
		t.Fatalf("out of range = %d %s", status, body)
	}

	save("0")
	finishRequest(1)
	if got := attempts(); got != 1 {
		t.Fatalf("with commit_retries 0: %d attempts, want 1", got)
	}
	save("2")
	started := time.Now()
	finishRequest(2)
	if got := attempts() - 1; got != 3 {
		t.Fatalf("with commit_retries 2: %d attempts, want 3\n%s", got, running.logs.snapshot())
	}
	// The two retries wait 100 and 200 ms.
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		t.Fatalf("three attempts took %s, less than the waits between them", elapsed)
	}

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}
	// Both failed audits verify after recovery.
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnableIntegrity(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatalf("integrity: %v", err)
	}
}
