package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/config"
)

// The whole agent flow against PostgreSQL: authorize, exchange, whoami, a
// restart that keeps the token, logout, and the audit rows.
func TestPostgresAgentAccessFlow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL application integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := fmt.Sprintf("app_agent_test_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	values := parsed.Query()
	values.Set("search_path", schema)
	parsed.RawQuery = values.Encode()

	cfg := testConfig(t)
	cfg.DatabaseURL = parsed.String()
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "synthetic-test-admin-token-0123456789"
	cfg.NewAPI.URL = "http://192.0.2.1:3000"
	cfg.RetentionDays = 0
	cfg.AgentAccess.Enabled = true
	cfg.Routes = []config.RouteConfig{{ID: "chat", Method: "POST", Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	application, err := NewContext(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	// The assembled application holds the agent service, so Close stops its
	// background work before the store closes (contract section 0.1 item 156).
	if application.agentAccess == nil {
		t.Fatal("the application does not hold the agent service it assembled")
	}
	serve := func(application *App, method, path, body, bearer string) (int, []byte) {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		application.adminServer.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes()
	}

	const verifier = "postgres-agent-flow-verifier-0123456789-abcdefgh"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	status, body := serve(application, http.MethodPost, "/api/v1/agent-access/authorizations",
		`{"challenge":"`+challenge+`","mode":"paste","device_name":"ci","cli_version":"0.1.0","tier":"read","decision":"approve"}`, cfg.AdminToken)
	var authorization struct {
		Code string `json:"code"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &authorization) != nil || authorization.Code == "" {
		t.Fatalf("authorize = %d %s", status, body)
	}
	status, body = serve(application, http.MethodPost, "/api/agent/v1/token", `{"code":"`+authorization.Code+`","code_verifier":"`+verifier+`"}`, "")
	var envelope agentapi.Response
	var token struct {
		Token string `json:"token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &envelope) != nil || json.Unmarshal(envelope.Data, &token) != nil || !agentapi.ValidTokenFormat(token.Token) {
		t.Fatalf("exchange = %d %s", status, body)
	}
	if status, body = serve(application, http.MethodGet, "/api/agent/v1/whoami", "", token.Token); status != http.StatusOK || !strings.Contains(string(body), `"role":"admin"`) {
		t.Fatalf("whoami = %d %s", status, body)
	}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewContext(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if status, body = serve(reopened, http.MethodGet, "/api/agent/v1/whoami", "", token.Token); status != http.StatusOK {
		t.Fatalf("whoami after restart = %d %s", status, body)
	}
	if status, body = serve(reopened, http.MethodGet, "/api/v1/agent-access/tokens", "", cfg.AdminToken); status != http.StatusOK ||
		!strings.Contains(string(body), `"device_name":"ci"`) || strings.Contains(string(body), token.Token) {
		t.Fatalf("token list = %d %s", status, body)
	}
	if status, body = serve(reopened, http.MethodPost, "/api/agent/v1/logout", "", token.Token); status != http.StatusOK {
		t.Fatalf("logout = %d %s", status, body)
	}
	if status, body = serve(reopened, http.MethodGet, "/api/agent/v1/whoami", "", token.Token); status != http.StatusUnauthorized || !strings.Contains(string(body), "TOKEN_REVOKED") {
		t.Fatalf("whoami after logout = %d %s", status, body)
	}
	var events []string
	rows, err := db.QueryContext(ctx, `SELECT event FROM `+schema+`.agent_audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var event string
		if err := rows.Scan(&event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	rows.Close()
	if strings.Join(events, ",") != "authorize_approved,token_issued,token_revoked" {
		t.Fatalf("audit events = %v", events)
	}
	var leaked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+schema+`.agent_audit_log WHERE concat_ws(' ', command, cli_version, object_id, changed_keys, error_code) LIKE '%lla_%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("audit rows holding a token = %d, %v", leaked, err)
	}
}

// The write facade as assembled for PostgreSQL: the services reach the
// facade through their agent entry points (a wiring mistake would answer
// UPSTREAM_UNAVAILABLE here), a plan is applied and persisted, and the change
// list reads the audit rows from the database.
func TestPostgresAgentWriteFlow(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL application integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := fmt.Sprintf("app_agent_write_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	values := parsed.Query()
	values.Set("search_path", schema)
	parsed.RawQuery = values.Encode()

	cfg := testConfig(t)
	cfg.DatabaseURL = parsed.String()
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "synthetic-test-admin-token-0123456789"
	cfg.NewAPI.URL = "http://192.0.2.1:3000"
	cfg.RetentionDays = 0
	cfg.AgentAccess.Enabled = true
	cfg.AgentAccess.AllowWrite = true
	cfg.Routes = []config.RouteConfig{{ID: "chat", Method: "POST", Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"}}
	application, err := NewContext(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	serve := func(method, path, body, bearer string) (int, []byte) {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		application.adminServer.Handler().ServeHTTP(response, request)
		return response.Code, response.Body.Bytes()
	}
	const verifier = "postgres-agent-write-verifier-0123456789-abcdefg"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	status, body := serve(http.MethodPost, "/api/v1/agent-access/authorizations",
		`{"challenge":"`+challenge+`","mode":"paste","device_name":"ci","cli_version":"0.1.0","tier":"write","decision":"approve"}`, cfg.AdminToken)
	var authorization struct {
		Code string `json:"code"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &authorization) != nil {
		t.Fatalf("authorize = %d %s", status, body)
	}
	status, body = serve(http.MethodPost, "/api/agent/v1/token", `{"code":"`+authorization.Code+`","code_verifier":"`+verifier+`"}`, "")
	var envelope agentapi.Response
	var token struct {
		Token string `json:"token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &envelope) != nil || json.Unmarshal(envelope.Data, &token) != nil {
		t.Fatalf("exchange = %d %s", status, body)
	}
	planAndApply := func(plan string) map[string]any {
		t.Helper()
		status, body := serve(http.MethodPost, "/api/agent/v1/plans", plan, token.Token)
		var created struct {
			Data struct {
				PlanID string `json:"plan_id"`
			} `json:"data"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &created) != nil {
			t.Fatalf("plan %s = %d %s", plan, status, body)
		}
		status, body = serve(http.MethodPost, "/api/agent/v1/plans/"+created.Data.PlanID+"/apply", "", token.Token)
		var applied struct {
			Data map[string]any `json:"data"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &applied) != nil {
			t.Fatalf("apply %s = %d %s", plan, status, body)
		}
		return applied.Data
	}
	rule := planAndApply(`{"op":"config.set","kind":"ua-rule","set":{"name":"pg rule","enabled":true,"model_pattern":"^pg-","user_agent_pattern":"^pg/"}}`)
	planAndApply(`{"op":"config.set","kind":"ua-rule","id":"` + rule["id"].(string) + `","set":{"enabled":false}}`)
	policy := planAndApply(`{"op":"config.set","kind":"content-rule","set":{"name":"pg policy","enabled":true,"action":"dry_run","keywords":["pg"]}}`)
	planAndApply(`{"op":"config.set","kind":"content-rule","id":"` + policy["id"].(string) + `","add":{"keywords":["second"]}}`)

	var enabled bool
	if err := db.QueryRowContext(ctx, `SELECT enabled FROM `+schema+`.user_agent_rules WHERE id = $1`, rule["id"]).Scan(&enabled); err != nil || enabled {
		t.Fatalf("stored ua rule enabled = %v, %v", enabled, err)
	}
	status, body = serve(http.MethodGet, "/api/agent/v1/config/content-rule", "", token.Token)
	if status != http.StatusOK || !strings.Contains(string(body), `"keywords_untrusted":["pg","second"]`) {
		t.Fatalf("content rules = %d %s", status, body)
	}
	status, body = serve(http.MethodGet, "/api/v1/agent-access/changes?limit=10", "", cfg.AdminToken)
	var changes struct {
		Items []struct {
			Event       string   `json:"event"`
			ObjectKind  string   `json:"object_kind"`
			ChangedKeys []string `json:"changed_keys"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &changes) != nil || len(changes.Items) != 4 ||
		changes.Items[0].ObjectKind != "content-rule" || strings.Join(changes.Items[0].ChangedKeys, ",") != "keywords" ||
		changes.Items[2].ObjectKind != "ua-rule" || strings.Join(changes.Items[2].ChangedKeys, ",") != "enabled" {
		t.Fatalf("changes = %d %s", status, body)
	}
}
