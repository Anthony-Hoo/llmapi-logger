package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/legacyoracle"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// unifiedConfig is a configuration for the four protocols' routes, with its
// own schema, key and staging directory.
func unifiedConfig(t *testing.T, upstreamURL string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.NewAPI.URL = upstreamURL
	cfg.DatabaseURL = newIntegrationDatabaseURL(t)
	cfg.KeyPath = filepath.Join(t.TempDir(), "audit.key")
	cfg.AdminToken = "integration-admin-token"
	cfg.RetentionDays = 0
	cfg.Audit.WritePath = config.AuditWritePathUnified
	// A one-chunk stage budget sends every body over 1 MiB through local
	// staging (design F), so the large cases below cover it on PostgreSQL.
	cfg.Audit.Memory.StageBytes = 1 << 20
	cfg.Audit.Staging.Dir = filepath.Join(t.TempDir(), "staging")
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
// identifiers, times and ciphertext. Header is the audit's Headers expanded
// through headerblock.Expand, whichever capture version stored them;
// DetailHeaders is the same list as the detail API returns it.
type storedShape struct {
	Audit         string
	Stages        []string
	Bodies        []string
	Chunks        []string
	Header        []string
	DetailHeaders string
	Detail        string
	Events        []string
}

// headerValueShown is how a Header value enters the comparison: the values
// that differ between two runs by nature (the exchange id, the request id the
// fake upstream echoes, the server's Date) are left out or reduced to their
// length.
func headerValueShown(name, value string) (string, bool) {
	switch http.CanonicalHeaderKey(name) {
	case "X-Oneapi-Request-Id", "X-Protofixture-Exchange":
		return "", false
	case "Date":
		return fmt.Sprintf("len=%d", len(value)), true
	}
	return value, true
}

// readHeaderSource assembles the Header evidence of one audit as the store's
// detail reader does: capture_version, the http_headers rows, the block and
// the stage set.
func readHeaderSource(t *testing.T, database *sql.DB, auditID string) storage.HeaderSource {
	t.Helper()
	var source storage.HeaderSource
	if err := database.QueryRow(`SELECT capture_version FROM audit_records WHERE audit_id = $1`, auditID).Scan(&source.CaptureVersion); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Query(`SELECT stage, kind, name, value_index, value_length, value_enc FROM http_headers WHERE audit_id = $1`, auditID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var row storage.HeaderEvidence
		if err := rows.Scan(&row.Stage, &row.Kind, &row.Name, &row.ValueIndex, &row.ValueLength, &row.ValueEnc); err != nil {
			t.Fatal(err)
		}
		source.Rows = append(source.Rows, row)
	}
	rows.Close()
	var block storage.HeaderBlockEvidence
	switch err := database.QueryRow(`SELECT compression, plaintext_length, block_enc FROM http_header_blocks WHERE audit_id = $1`, auditID).
		Scan(&block.Compression, &block.PlaintextLength, &block.DataEnc); {
	case err == nil:
		source.Block = &block
	case !errors.Is(err, sql.ErrNoRows):
		t.Fatal(err)
	}
	stages, err := database.Query(`SELECT stage FROM http_stages WHERE audit_id = $1`, auditID)
	if err != nil {
		t.Fatal(err)
	}
	for stages.Next() {
		var stage string
		if err := stages.Scan(&stage); err != nil {
			t.Fatal(err)
		}
		source.StageSet = append(source.StageSet, stage)
	}
	stages.Close()
	return source
}

func expandStoredHeaders(t *testing.T, database *sql.DB, cipher security.Cipher, auditID string) []headerblock.Value {
	t.Helper()
	values, err := headerblock.Expand(cipher, auditID, readHeaderSource(t, database, auditID))
	if err != nil {
		t.Fatalf("%s: expand headers: %v", auditID, err)
	}
	return values
}

func readStoredShape(t *testing.T, database *sql.DB, client *http.Client, adminURL string, cipher security.Cipher, auditID string) storedShape {
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
	// host is left out: the two apps listen on different ports.
	shape.Stages = collect(`SELECT stage, state, proto, method, status_code, content_length, error_code FROM http_stages WHERE audit_id = $1 ORDER BY stage`)
	shape.Bodies = collect(`SELECT stage, source_stage, observed_length, stored_length, encode(sha256, 'hex'), hash_complete, eof_seen, state,
		retention_state, chunk_count, stream_event_count, stream_timeline_complete, error_code FROM body_streams WHERE audit_id = $1 ORDER BY stage`)
	shape.Chunks = collect(`SELECT stage, seq, "offset", plaintext_length, compression FROM body_chunks WHERE audit_id = $1 ORDER BY stage, seq`)
	shape.Events = collect(`SELECT event_type FROM integrity_events WHERE audit_id = $1 ORDER BY sequence`)
	for _, value := range expandStoredHeaders(t, database, cipher, auditID) {
		if shown, ok := headerValueShown(value.Name, string(value.Value)); ok {
			shape.Header = append(shape.Header, fmt.Sprintf("%s %s %s %d %q", value.Stage, value.Kind, value.Name, value.ValueIndex, shown))
		}
	}
	var detail map[string]any
	if err := json.Unmarshal(authorizedAdminGET(t, client, adminURL+"/api/v1/audits/"+auditID), &detail); err != nil {
		t.Fatal(err)
	}
	conversation, _ := json.Marshal(detail["conversation"])
	parsed, _ := json.Marshal(detail["parsed_result"])
	// Kept as a digest when long, as the legacy oracle keeps it.
	shape.Detail = legacyoracle.Digest(string(conversation) + string(parsedWithoutTimes(parsed)))
	headers, _ := detail["headers"].([]any)
	kept := make([]any, 0, len(headers))
	for _, entry := range headers {
		header, _ := entry.(map[string]any)
		name, _ := header["name"].(string)
		value, _ := header["value"].(string)
		if shown, ok := headerValueShown(name, value); ok {
			header["value"] = shown
			if http.CanonicalHeaderKey(name) == "Date" {
				delete(header, "value_length")
			}
			kept = append(kept, header)
		}
	}
	encoded, _ := json.Marshal(kept)
	shape.DetailHeaders = string(encoded)
	return shape
}

// frozenLegacy is the legacy oracle's value name: what the legacy write path
// (capture version 1) stored for the same exchange (internal/legacyoracle).
// The values carry no audit id, time or ciphertext: storedShape leaves them
// out, Header values are opened and the ones two runs cannot agree on are
// masked (headerValueShown), and long texts are kept as their digest
// (legacyoracle.Digest).
func frozenLegacy[T any](t *testing.T, name string) T {
	t.Helper()
	return legacyoracle.Value[T](t, name, nil)
}

// legacyExpectations is what the unified version 2 columns must hold, as the
// legacy (version 1) Header rows of the same exchange decide it.
type legacyExpectations struct {
	UserAgents []string
	// Content maps a stage to its Content-Type and Content-Encoding.
	Content map[string][2]string
}

// requireCaptureVersion2 checks what differs by design from the legacy
// rows (version 1, B.10): unified rows are version 2 with no header rows,
// the User-Agent the list reads and the content headers the parser would
// choose from the same Headers, as the legacy oracle froze them.
func requireCaptureVersion2(t *testing.T, label string, unifiedDB *sql.DB, unifiedCipher security.Cipher, unifiedID string) {
	t.Helper()
	var unifiedVersion, unifiedRows int
	var unifiedAgent []byte
	if err := unifiedDB.QueryRow(`SELECT capture_version, user_agent_enc, (SELECT COUNT(*) FROM http_headers WHERE audit_id = $1)
		FROM audit_records WHERE audit_id = $1`, unifiedID).Scan(&unifiedVersion, &unifiedAgent, &unifiedRows); err != nil {
		t.Fatal(err)
	}
	if unifiedVersion != 2 || unifiedRows != 0 {
		t.Fatalf("%s: unified version %d with %d header rows", label, unifiedVersion, unifiedRows)
	}
	expected := frozenLegacy[legacyExpectations](t, "expectations/"+label)
	agents, err := headerblock.OpenUserAgent(unifiedCipher, unifiedID, unifiedAgent)
	if want := expected.UserAgents; err != nil || !reflect.DeepEqual(agents, want) {
		t.Fatalf("%s: user_agent_enc %q (%v), legacy User-Agent %q", label, agents, err, want)
	}
	rows, err := unifiedDB.Query(`SELECT stage, content_type, content_encoding FROM http_stages WHERE audit_id = $1`, unifiedID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var stage string
		var contentType, contentEncoding sql.NullString
		if err := rows.Scan(&stage, &contentType, &contentEncoding); err != nil {
			t.Fatal(err)
		}
		wantType, wantEncoding := expected.Content[stage][0], expected.Content[stage][1]
		if contentType.String != wantType || contentType.Valid != (wantType != "") ||
			contentEncoding.String != wantEncoding || contentEncoding.Valid != (wantEncoding != "") {
			t.Fatalf("%s: %s content columns %v %v, legacy headers say %q %q", label, stage, contentType, contentEncoding, wantType, wantEncoding)
		}
	}
}

// appCipher opens the audit key of a running app's configuration.
func appCipher(t *testing.T, cfg config.Config) security.Cipher {
	t.Helper()
	key, err := security.LoadOrCreateKey(cfg.KeyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
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

// requireAppIntegrity verifies the chain and every capture payload digest
// of an app's database.
func requireAppIntegrity(t *testing.T, cfg config.Config) {
	t.Helper()
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

// clientResult is what the client got, as the legacy oracle keeps it.
type clientResult struct {
	Status     int
	BodyLength int
	BodySHA256 string
}

func clientOf(status int, body []byte) clientResult {
	sum := sha256.Sum256(body)
	return clientResult{Status: status, BodyLength: len(body), BodySHA256: hex.EncodeToString(sum[:])}
}

// The unified write path on PostgreSQL stores capture version 2: a few
// requests of every protocol, a large streamed answer and one cut after 2 MiB
// are stored, parsed, verified and read back as on legacy (version 1), whose
// side is the legacy oracle.
func TestUnifiedWritePathOnPostgreSQL(t *testing.T) {
	upstream := protofixture.NewUpstream("ux")
	server := httptest.NewServer(upstream)
	defer server.Close()
	unifiedConfigValue := unifiedConfig(t, server.URL)
	unified := startApp(t, unifiedConfigValue)
	unifiedCipher := appCipher(t, unifiedConfigValue)
	client := &http.Client{Timeout: 3 * integrationTimeout}
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
	// exchange sends one exchange and compares what the client got and the
	// app stored with the legacy oracle's "client/<key>" and "shape/<key>".
	exchange := func(key string, value protofixture.Exchange, versions bool) storedShape {
		t.Helper()
		unifiedStatus, unifiedBody, unifiedID := send(unified, unifiedDB, value)
		if want := frozenLegacy[clientResult](t, "client/"+key); want != clientOf(unifiedStatus, unifiedBody) {
			t.Fatalf("%s: client saw %+v, unified %+v", key, want, clientOf(unifiedStatus, unifiedBody))
		}
		legacyShape := frozenLegacy[storedShape](t, "shape/"+key)
		unifiedShape := readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedCipher, unifiedID)
		if versions {
			requireCaptureVersion2(t, key, unifiedDB, unifiedCipher, unifiedID)
		}
		if !reflect.DeepEqual(legacyShape, unifiedShape) {
			t.Fatalf("%s: stored audits differ:\n legacy  %+v\n unified %+v", key, legacyShape, unifiedShape)
		}
		return unifiedShape
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
			for _, built := range exchanges {
				unifiedShape := exchange(fmt.Sprintf("%02d %s", cases, value), built, true)
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
	answer := large[0]
	delta := answer.Response.Chunks[1]
	chunks := [][]byte{answer.Response.Chunks[0]}
	for size := 0; size < 5<<19; size += len(delta) {
		chunks = append(chunks, delta)
	}
	answer.Response.Chunks = append(chunks, answer.Response.Chunks[1:]...)
	exchange("large answer", answer, false)
	cases++
	// The same answer cut by the upstream after 2 MiB keeps its raw chunks:
	// response_sent writes its own, sealed from the bytes it borrowed.
	answer.Response.CutAt, answer.Response.Abort = 2<<20+333, true
	unifiedShape := exchange("cut answer", answer, false)
	if responseChunks := strings.Count(strings.Join(unifiedShape.Chunks, "|"), "response_from_newapi_sent_to_nginx"); responseChunks < 2 {
		t.Fatalf("cut answer: response_sent has %d chunks: %v", responseChunks, unifiedShape.Chunks)
	}
	cases++
	// A request over the stage budget: its chunks are staged during the
	// upload and written by checkpoint 1, merged.
	heavy, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		protofixture.Options{Seed: 98, HistoryItems: 700, ItemBytes: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if len(heavy[0].RequestBody) < 2<<20 {
		t.Fatalf("heavy request is only %d bytes", len(heavy[0].RequestBody))
	}
	if unifiedShape := exchange("heavy request", heavy[0], true); !strings.HasPrefix(unifiedShape.Audit, "completed complete") {
		t.Fatalf("heavy request: unified audit %s", unifiedShape.Audit)
	}
	cases++
	if entries, err := os.ReadDir(unifiedConfigValue.Audit.Staging.Dir); err != nil || len(entries) != 0 {
		t.Fatalf("staging directory holds %v (%v)", entries, err)
	}
	if err := unified.stop(); err != nil {
		t.Fatal(err)
	}
	// Every audit verifies: the chain and the capture payload digests.
	requireAppIntegrity(t, unifiedConfigValue)
	t.Logf("%d exchanges", cases)
}
