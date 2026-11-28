package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/legacyoracle"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage/postgres"
)

// maskHeaderJSON removes from an Agent API document what two runs cannot
// agree on: the audit id, Header entries of the exchange and request ids, and
// the value of the server's Date (its name and position stay). Everything
// else is kept.
func maskHeaderJSON(value any) any {
	switch typed := value.(type) {
	case []any:
		kept := make([]any, 0, len(typed))
		for _, entry := range typed {
			if object, ok := entry.(map[string]any); ok {
				name, _ := object["name_untrusted"].(string)
				if name == "" {
					name, _ = object["name"].(string)
				}
				switch http.CanonicalHeaderKey(name) {
				case "X-Oneapi-Request-Id", "X-Protofixture-Exchange":
					continue
				case "Date":
					masked := map[string]any{}
					for _, key := range []string{"stage", "kind", "name", "name_untrusted", "value_index"} {
						if field, ok := object[key]; ok {
							masked[key] = field
						}
					}
					kept = append(kept, masked)
					continue
				}
			}
			kept = append(kept, maskHeaderJSON(entry))
		}
		return kept
	case map[string]any:
		delete(typed, "audit_id")
		for key, field := range typed {
			typed[key] = maskHeaderJSON(field)
		}
		return typed
	default:
		return value
	}
}

// agentView is what the Agent API gives for one record: the Headers of
// `requests get --headers all` and the headers, conversation, request,
// response and raw exports. The timeline exports are left out: they hold
// observation times, which differ between the two runs.
func agentView(t *testing.T, cli *journeyCLI, auditID string) string {
	t.Helper()
	var parts []string
	exit, envelope := cli.run("requests", "get", auditID, "--headers", "all")
	var record map[string]any
	_ = json.Unmarshal(envelope.Data, &record)
	headers, _ := json.Marshal(maskHeaderJSON(record["headers"]))
	parts = append(parts, fmt.Sprintf("get exit=%d headers_scope=%v headers=%s", exit, record["headers_scope"], headers))
	for _, what := range []string{"headers", "conversation", "request", "response", "raw-request", "raw-response"} {
		out := filepath.Join(t.TempDir(), what+".out")
		exit, envelope := cli.run("requests", "export", auditID, "--what", what, "--out", out)
		code := ""
		if envelope.Error != nil {
			code = string(envelope.Error.Code)
		}
		content, _ := os.ReadFile(out)
		if (what == "headers" || what == "conversation") && len(content) != 0 {
			var document any
			if err := json.Unmarshal(content, &document); err != nil {
				t.Fatalf("%s export of %s is not JSON: %v", what, auditID, err)
			}
			content, _ = json.Marshal(maskHeaderJSON(document))
		}
		parts = append(parts, fmt.Sprintf("export %s exit=%d code=%s content=%s", what, exit, code, content))
	}
	return strings.Join(parts, "\n")
}

// agentLogin signs llmaudit in to a running app with a read token.
func agentLogin(t *testing.T, running *runningApp) *journeyCLI {
	t.Helper()
	client := &http.Client{Timeout: integrationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cookie := adminWebSession(t, client, running.adminURL)
	var codes []string
	cli := newJourneyCLI(t)
	cli.login(running.adminURL, pageApproval(t, client, running.adminURL, cookie, "read", &codes))
	return cli
}

// I.1 on PostgreSQL: the protofixture catalogue through legacy (version 1)
// and unified (version 2). The client sees the same bytes; the stored audits
// agree on every table as B.10 defines it, with Headers compared through
// headerblock.Expand; the detail API and the Agent API (its credential
// masking and the header, conversation, request, response and raw exports)
// give the same output;
// every audit verifies. Client-cancel scenarios are left out: where the client
// gives up depends on timing, not on the write path.
func TestUnifiedCaptureVersion2MatchesLegacyOnPostgreSQL(t *testing.T) {
	if testing.Short() {
		t.Skip("the fixture catalogue through both write paths")
	}
	upstream := protofixture.NewUpstream("v2")
	server := httptest.NewServer(upstream)
	defer server.Close()
	legacyConfig := unifiedConfig(t, server.URL, config.AuditWritePathLegacy)
	unifiedConfigValue := unifiedConfig(t, server.URL, config.AuditWritePathUnified)
	for _, cfg := range []*config.Config{&legacyConfig, &unifiedConfigValue} {
		cfg.AgentAccess.Enabled = true
		if err := config.Validate(*cfg); err != nil {
			t.Fatal(err)
		}
	}
	legacy := startApp(t, legacyConfig)
	unified := startApp(t, unifiedConfigValue)
	legacyCipher, unifiedCipher := appCipher(t, legacyConfig), appCipher(t, unifiedConfigValue)
	client := &http.Client{Timeout: 3 * integrationTimeout}
	legacyDB := openAuditDatabase(t, legacyConfig.DatabaseURL)
	defer legacyDB.Close()
	unifiedDB := openAuditDatabase(t, unifiedConfigValue.DatabaseURL)
	defer unifiedDB.Close()
	legacyCLI, unifiedCLI := agentLogin(t, legacy), agentLogin(t, unified)

	seen := map[*sql.DB][]string{legacyDB: {}, unifiedDB: {}}
	send := func(running *runningApp, database *sql.DB, exchange protofixture.Exchange) (int, []byte, string) {
		id := upstream.Register(&exchange)
		request, err := http.NewRequest(exchange.Method, running.baseURL+exchange.Path, bytes.NewReader(exchange.RequestBody))
		if err != nil {
			t.Fatal(err)
		}
		request.Header = exchange.RequestHeader.Clone()
		request.Header.Set("User-Agent", "client-example/1.0")
		request.Header.Set(protofixture.ExchangeHeader, id)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		// Requests are sent one at a time, so the newest audit is this
		// exchange's; not every answer echoes the request id the upstream
		// sets.
		var auditID string
		deadline := time.Now().Add(3 * integrationTimeout)
		for auditID == "" && time.Now().Before(deadline) {
			_ = database.QueryRow(`SELECT audit_id FROM audit_records WHERE NOT (audit_id = ANY($1)) ORDER BY started_at_ns DESC LIMIT 1`, seen[database]).Scan(&auditID)
			if auditID == "" {
				time.Sleep(10 * time.Millisecond)
			}
		}
		if auditID == "" {
			t.Fatalf("no audit for exchange %s", id)
		}
		seen[database] = append(seen[database], auditID)
		waitParsed(t, database, auditID)
		return response.StatusCode, body, auditID
	}

	exchanges, agentViews := 0, 0
	for index, value := range protofixture.Catalog() {
		if value.Scenario == protofixture.ScenarioClientCancel {
			continue
		}
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(index + 1)})
		if err != nil {
			t.Fatal(err)
		}
		for turn, exchange := range built {
			label := fmt.Sprintf("%s turn %d", value, turn)
			var legacySide *legacyApp
			var legacyStatus int
			var legacyBody []byte
			if legacy != nil {
				var legacyID string
				legacyStatus, legacyBody, legacyID = send(legacy, legacyDB, exchange)
				legacySide = &legacyApp{db: legacyDB, cipher: legacyCipher, id: legacyID}
			}
			unifiedStatus, unifiedBody, unifiedID := send(unified, unifiedDB, exchange)
			if want := frozenLegacy(t, "client/"+label, legacySide, func(*legacyApp) clientResult { return clientOf(legacyStatus, legacyBody) }); want != clientOf(unifiedStatus, unifiedBody) {
				t.Fatalf("%s: client saw %+v, unified %+v", label, want, clientOf(unifiedStatus, unifiedBody))
			}
			legacyShape := frozenLegacy(t, "shape/"+label, legacySide, func(run *legacyApp) storedShape {
				return readStoredShape(t, run.db, client, legacy.adminURL, run.cipher, run.id)
			})
			unifiedShape := readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedCipher, unifiedID)
			if !reflect.DeepEqual(legacyShape, unifiedShape) {
				t.Fatalf("%s: stored audits differ:\n legacy  %+v\n unified %+v", label, legacyShape, unifiedShape)
			}
			requireCaptureVersionsAcross(t, label, legacySide, unifiedDB, unifiedCipher, unifiedID)
			legacyView := frozenLegacy(t, "agent/"+label, legacySide, func(run *legacyApp) string { return legacyoracle.Digest(agentView(t, legacyCLI, run.id)) })
			if unifiedView := legacyoracle.Digest(agentView(t, unifiedCLI, unifiedID)); legacyView != unifiedView {
				t.Fatalf("%s: Agent API output differs:\n legacy  %s\n unified %s", label, legacyView, unifiedView)
			}
			agentViews++
			exchanges++
		}
	}
	for _, running := range []*runningApp{legacy, unified} {
		if err := running.stop(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []config.Config{legacyConfig, unifiedConfigValue} {
		store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.EnableIntegrity(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
			t.Fatalf("%s: integrity: %v", cfg.Audit.WritePath, err)
		}
		_ = store.Close()
	}
	var versionTwo int
	if err := unifiedDB.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE capture_version = 2`).Scan(&versionTwo); err != nil || versionTwo != exchanges {
		t.Fatalf("%d version 2 audits of %d: %v", versionTwo, exchanges, err)
	}
	// Header bytes per audit on these fixtures: version 1 rows against the
	// version 2 block plus user_agent_enc. "rows" is the stored row size
	// (pg_column_size of the row), "tables" the tables with their indexes.
	var legacyRows, legacyCiphertext, legacyTables, legacyRowCount int64
	if err := legacyDB.QueryRow(`SELECT COALESCE(SUM(pg_column_size(h.*)), 0), COALESCE(SUM(octet_length(value_enc)), 0), COUNT(*),
		pg_total_relation_size('http_headers') FROM http_headers AS h`).Scan(&legacyRows, &legacyCiphertext, &legacyRowCount, &legacyTables); err != nil {
		t.Fatal(err)
	}
	var unifiedRows, unifiedCiphertext, unifiedAgents, unifiedTables, plaintext int64
	if err := unifiedDB.QueryRow(`SELECT COALESCE(SUM(pg_column_size(b.*)), 0), COALESCE(SUM(octet_length(block_enc)), 0), COALESCE(SUM(plaintext_length), 0),
		(SELECT COALESCE(SUM(octet_length(user_agent_enc)), 0) FROM audit_records),
		pg_total_relation_size('http_header_blocks') + pg_total_relation_size('http_headers') FROM http_header_blocks AS b`).
		Scan(&unifiedRows, &unifiedCiphertext, &plaintext, &unifiedAgents, &unifiedTables); err != nil {
		t.Fatal(err)
	}
	per := func(value int64) int64 { return value / int64(exchanges) }
	t.Logf("header bytes per audit over %d audits: version 1 %d rows of %d bytes (ciphertext %d), tables %d; version 2 block rows %d bytes (ciphertext %d, plaintext %d) + user_agent_enc %d, tables %d",
		exchanges, legacyRowCount/int64(exchanges), per(legacyRows), per(legacyCiphertext), per(legacyTables),
		per(unifiedRows), per(unifiedCiphertext), per(plaintext), per(unifiedAgents), per(unifiedTables))
	t.Logf("%d exchanges per write path, %d Agent API views compared", exchanges, agentViews)
}
