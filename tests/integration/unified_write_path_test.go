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
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage/postgres"
)

// unifiedConfig is a configuration for the four protocols' routes on the
// given write path, with its own schema and key.
func unifiedConfig(t *testing.T, upstreamURL, writePath string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.NewAPI.URL = upstreamURL
	cfg.DatabaseURL = newIntegrationDatabaseURL(t)
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "integration-admin-token"
	cfg.RetentionDays = 0
	cfg.Audit.WritePath = writePath
	cfg.Routes = []config.RouteConfig{
		{ID: "chat", Method: http.MethodPost, Path: "/v1/chat/completions", Match: "exact", Parser: "openai.chat_completions"},
		{ID: "responses", Method: http.MethodPost, Path: "/v1/responses", Match: "exact", Parser: "openai.responses"},
		{ID: "messages", Method: http.MethodPost, Path: "/v1/messages", Match: "exact", Parser: "anthropic.messages"},
		{ID: "gemini", Method: http.MethodPost, Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"},
		{ID: "gemini-stream", Method: http.MethodPost, Path: "/v1beta/models/{model}:streamGenerateContent", Match: "template", Parser: "gemini.stream_generate_content"},
	}
	return cfg
}

// storedShape is what both write paths must agree on for one audit, without
// identifiers, times and ciphertext.
type storedShape struct {
	Audit  string
	Stages []string
	Bodies []string
	Chunks []string
	Header []string
	Detail string
}

func readStoredShape(t *testing.T, database *sql.DB, client *http.Client, adminURL, auditID string) storedShape {
	t.Helper()
	var shape storedShape
	var forward, capture, parse string
	var status sql.NullInt64
	if err := database.QueryRow(`SELECT forward_status, capture_status, parse_status, status_code FROM audit_records WHERE audit_id = $1`, auditID).
		Scan(&forward, &capture, &parse, &status); err != nil {
		t.Fatal(err)
	}
	shape.Audit = fmt.Sprintf("%s %s %s %v", forward, capture, parse, status.Int64)
	collect := func(query string) []string {
		rows, err := database.Query(query, auditID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		columns, _ := rows.Columns()
		var out []string
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprint(values...))
		}
		return out
	}
	shape.Stages = collect(`SELECT stage, state, status_code, content_length, error_code FROM http_stages WHERE audit_id = $1 ORDER BY stage`)
	shape.Bodies = collect(`SELECT stage, source_stage, observed_length, stored_length, encode(sha256, 'hex'), hash_complete, eof_seen, state,
		retention_state, chunk_count, stream_event_count, stream_timeline_complete, error_code FROM body_streams WHERE audit_id = $1 ORDER BY stage`)
	shape.Chunks = collect(`SELECT stage, seq, "offset", plaintext_length, compression FROM body_chunks WHERE audit_id = $1 ORDER BY stage, seq`)
	shape.Header = collect(`SELECT stage, kind, name, value_index, value_length FROM http_headers WHERE audit_id = $1
		AND name NOT IN ('X-Oneapi-Request-Id', 'X-Protofixture-Exchange') ORDER BY stage, kind, name, value_index`)
	var detail map[string]any
	if err := json.Unmarshal(authorizedAdminGET(t, client, adminURL+"/api/v1/audits/"+auditID), &detail); err != nil {
		t.Fatal(err)
	}
	conversation, _ := json.Marshal(detail["conversation"])
	parsed, _ := json.Marshal(detail["parsed_result"])
	shape.Detail = string(conversation) + string(parsedWithoutTimes(parsed))
	return shape
}

func parsedWithoutTimes(raw []byte) []byte {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return raw
	}
	for key := range value {
		if strings.HasSuffix(key, "_at_ns") || strings.HasSuffix(key, "_id") {
			delete(value, key)
		}
	}
	out, _ := json.Marshal(value)
	return out
}

func waitParsed(t *testing.T, database *sql.DB, auditID string) {
	t.Helper()
	deadline := time.Now().Add(3 * integrationTimeout)
	for time.Now().Before(deadline) {
		var parse string
		var ended sql.NullInt64
		if err := database.QueryRow(`SELECT parse_status, ended_at_ns FROM audit_records WHERE audit_id = $1`, auditID).Scan(&parse, &ended); err == nil &&
			ended.Valid && parse != "pending" && parse != "processing" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit %s did not finish parsing", auditID)
}

// The unified write path on PostgreSQL (version 1 rows): a few requests of
// every protocol are stored, parsed, verified and readable as on legacy.
func TestUnifiedWritePathOnPostgreSQL(t *testing.T) {
	upstream := protofixture.NewUpstream("ux")
	server := httptest.NewServer(upstream)
	defer server.Close()
	legacyConfig := unifiedConfig(t, server.URL, config.AuditWritePathLegacy)
	unifiedConfigValue := unifiedConfig(t, server.URL, config.AuditWritePathUnified)
	legacy := startApp(t, legacyConfig)
	unified := startApp(t, unifiedConfigValue)
	client := &http.Client{Timeout: 3 * integrationTimeout}
	legacyDB := openAuditDatabase(t, legacyConfig.DatabaseURL)
	defer legacyDB.Close()
	unifiedDB := openAuditDatabase(t, unifiedConfigValue.DatabaseURL)
	defer unifiedDB.Close()

	send := func(running *runningApp, database *sql.DB, exchange protofixture.Exchange) (int, []byte, string) {
		id := upstream.Register(&exchange)
		request, err := http.NewRequest(exchange.Method, running.baseURL+exchange.Path, bytes.NewReader(exchange.RequestBody))
		if err != nil {
			t.Fatal(err)
		}
		request.Header = exchange.RequestHeader.Clone()
		request.Header.Set(protofixture.ExchangeHeader, id)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		var auditID string
		deadline := time.Now().Add(3 * integrationTimeout)
		for auditID == "" && time.Now().Before(deadline) {
			_ = database.QueryRow(`SELECT audit_id FROM audit_records WHERE newapi_request_id = $1`, id).Scan(&auditID)
			if auditID == "" {
				time.Sleep(10 * time.Millisecond)
			}
		}
		if auditID == "" {
			t.Fatalf("no audit for exchange %s", id)
		}
		waitParsed(t, database, auditID)
		return response.StatusCode, body, auditID
	}

	cases := 0
	for _, protocol := range protofixture.Protocols() {
		for _, value := range []protofixture.Case{
			{Protocol: protocol, Scenario: protofixture.ScenarioBasic, Stream: false},
			{Protocol: protocol, Scenario: protofixture.ScenarioToolCalls, Stream: true},
			{Protocol: protocol, Scenario: protofixture.ScenarioError429, Stream: false},
		} {
			exchanges, err := protofixture.Build(value, protofixture.Options{Seed: uint64(10 + cases)})
			if err != nil {
				t.Fatal(err)
			}
			for _, exchange := range exchanges {
				legacyStatus, legacyBody, legacyID := send(legacy, legacyDB, exchange)
				unifiedStatus, unifiedBody, unifiedID := send(unified, unifiedDB, exchange)
				if legacyStatus != unifiedStatus || !bytes.Equal(legacyBody, unifiedBody) {
					t.Fatalf("%s: client saw %d and %d", value, legacyStatus, unifiedStatus)
				}
				legacyShape := readStoredShape(t, legacyDB, client, legacy.adminURL, legacyID)
				unifiedShape := readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedID)
				if !reflect.DeepEqual(legacyShape, unifiedShape) {
					t.Fatalf("%s: stored audits differ:\n legacy  %+v\n unified %+v", value, legacyShape, unifiedShape)
				}
				if !strings.HasPrefix(unifiedShape.Audit, "completed complete") || len(unifiedShape.Stages) != 4 {
					t.Fatalf("%s: unified audit %s with %d stages", value, unifiedShape.Audit, len(unifiedShape.Stages))
				}
				cases++
			}
		}
	}
	// A streamed answer over 2 MiB: the merged response pair's chunks reach
	// the PostgreSQL store, which keeps the session's chunk slices.
	large, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true}, protofixture.Options{Seed: 99})
	if err != nil {
		t.Fatal(err)
	}
	exchange := large[0]
	delta := exchange.Response.Chunks[1]
	chunks := [][]byte{exchange.Response.Chunks[0]}
	for size := 0; size < 5<<19; size += len(delta) {
		chunks = append(chunks, delta)
	}
	exchange.Response.Chunks = append(chunks, exchange.Response.Chunks[1:]...)
	legacyStatus, legacyBody, legacyID := send(legacy, legacyDB, exchange)
	unifiedStatus, unifiedBody, unifiedID := send(unified, unifiedDB, exchange)
	if legacyStatus != unifiedStatus || !bytes.Equal(legacyBody, unifiedBody) || len(unifiedBody) < 5<<19 {
		t.Fatalf("large answer: client saw %d (%d bytes) and %d (%d bytes)", legacyStatus, len(legacyBody), unifiedStatus, len(unifiedBody))
	}
	if legacyShape, unifiedShape := readStoredShape(t, legacyDB, client, legacy.adminURL, legacyID), readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedID); !reflect.DeepEqual(legacyShape, unifiedShape) {
		t.Fatalf("large answer: stored audits differ:\n legacy  %+v\n unified %+v", legacyShape, unifiedShape)
	}
	cases++
	// The same answer cut by the upstream after 2 MiB keeps its raw chunks:
	// response_sent writes its own, sealed from the bytes it borrowed.
	exchange.Response.CutAt, exchange.Response.Abort = 2<<20+333, true
	legacyStatus, _, legacyID = send(legacy, legacyDB, exchange)
	unifiedStatus, _, unifiedID = send(unified, unifiedDB, exchange)
	legacyShape, unifiedShape := readStoredShape(t, legacyDB, client, legacy.adminURL, legacyID), readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedID)
	if legacyStatus != unifiedStatus || !reflect.DeepEqual(legacyShape, unifiedShape) {
		t.Fatalf("cut answer: stored audits differ:\n legacy  %+v\n unified %+v", legacyShape, unifiedShape)
	}
	if responseChunks := strings.Count(strings.Join(unifiedShape.Chunks, "|"), "response_from_newapi_sent_to_nginx"); responseChunks < 2 {
		t.Fatalf("cut answer: response_sent has %d chunks: %v", responseChunks, unifiedShape.Chunks)
	}
	cases++
	for _, running := range []*runningApp{legacy, unified} {
		if err := running.stop(); err != nil {
			t.Fatal(err)
		}
	}
	// Every audit verifies: the chain and the capture payload digests.
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
	t.Logf("%d exchanges per write path", cases)
}
