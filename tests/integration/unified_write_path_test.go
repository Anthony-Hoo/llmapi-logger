package integration_test

import (
	"bytes"
	"context"
	"database/sql"
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
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
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
	shape.Detail = string(conversation) + string(parsedWithoutTimes(parsed))
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

// requireCaptureVersionsAcross checks what differs by design between the two write
// paths on PostgreSQL (B.10): legacy rows are version 1 with no block,
// User-Agent or content columns; unified rows are version 2 with no header
// rows, the User-Agent the list reads and the content headers the parser
// would choose from the same Headers.
func requireCaptureVersionsAcross(t *testing.T, label string, legacyDB, unifiedDB *sql.DB, legacyCipher, unifiedCipher security.Cipher, legacyID, unifiedID string) {
	t.Helper()
	var legacyVersion, unifiedVersion, legacyBlocks, unifiedRows, legacyContent int
	var legacyAgent, unifiedAgent []byte
	if err := legacyDB.QueryRow(`SELECT capture_version, user_agent_enc, (SELECT COUNT(*) FROM http_header_blocks WHERE audit_id = $1),
		(SELECT COUNT(*) FROM http_stages WHERE audit_id = $1 AND (content_type IS NOT NULL OR content_encoding IS NOT NULL))
		FROM audit_records WHERE audit_id = $1`, legacyID).Scan(&legacyVersion, &legacyAgent, &legacyBlocks, &legacyContent); err != nil {
		t.Fatal(err)
	}
	if err := unifiedDB.QueryRow(`SELECT capture_version, user_agent_enc, (SELECT COUNT(*) FROM http_headers WHERE audit_id = $1)
		FROM audit_records WHERE audit_id = $1`, unifiedID).Scan(&unifiedVersion, &unifiedAgent, &unifiedRows); err != nil {
		t.Fatal(err)
	}
	if legacyVersion != 1 || legacyAgent != nil || legacyBlocks != 0 || legacyContent != 0 || unifiedVersion != 2 || unifiedRows != 0 {
		t.Fatalf("%s: legacy version %d (user agent %v, %d blocks, %d content columns), unified version %d with %d header rows",
			label, legacyVersion, legacyAgent != nil, legacyBlocks, legacyContent, unifiedVersion, unifiedRows)
	}
	legacyHeaders := expandStoredHeaders(t, legacyDB, legacyCipher, legacyID)
	var fields []headerblock.Field
	for _, value := range legacyHeaders {
		if value.Stage == storage.StageRequestReceived && value.Kind == storage.HeaderKindHeader {
			if len(fields) == 0 || fields[len(fields)-1].Name != value.Name {
				fields = append(fields, headerblock.Field{Name: value.Name})
			}
			fields[len(fields)-1].Values = append(fields[len(fields)-1].Values, value.Value)
		}
	}
	agents, err := headerblock.OpenUserAgent(unifiedCipher, unifiedID, unifiedAgent)
	if want := headerblock.UserAgentValues(fields); err != nil || !reflect.DeepEqual(agents, want) {
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
		// The parser's rule on the legacy rows (decryptContentHeaders): the
		// first non-empty value of a Header whose lower-case name matches.
		var wantType, wantEncoding string
		for _, value := range legacyHeaders {
			if value.Stage != stage || value.Kind != storage.HeaderKindHeader || len(value.Value) == 0 {
				continue
			}
			switch strings.ToLower(value.Name) {
			case "content-type":
				if wantType == "" {
					wantType = string(value.Value)
				}
			case "content-encoding":
				if wantEncoding == "" {
					wantEncoding = string(value.Value)
				}
			}
		}
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

// The unified write path on PostgreSQL stores capture version 2: a few
// requests of every protocol, a large streamed answer and one cut after 2 MiB
// are stored, parsed, verified and read back as on legacy (version 1).
func TestUnifiedWritePathOnPostgreSQL(t *testing.T) {
	upstream := protofixture.NewUpstream("ux")
	server := httptest.NewServer(upstream)
	defer server.Close()
	legacyConfig := unifiedConfig(t, server.URL, config.AuditWritePathLegacy)
	unifiedConfigValue := unifiedConfig(t, server.URL, config.AuditWritePathUnified)
	legacy := startApp(t, legacyConfig)
	unified := startApp(t, unifiedConfigValue)
	cipher := appCipher(t, legacyConfig)
	unifiedCipher := appCipher(t, unifiedConfigValue)
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
				legacyShape := readStoredShape(t, legacyDB, client, legacy.adminURL, cipher, legacyID)
				unifiedShape := readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedCipher, unifiedID)
				requireCaptureVersionsAcross(t, value.String(), legacyDB, unifiedDB, cipher, unifiedCipher, legacyID, unifiedID)
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
	if legacyShape, unifiedShape := readStoredShape(t, legacyDB, client, legacy.adminURL, cipher, legacyID), readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedCipher, unifiedID); !reflect.DeepEqual(legacyShape, unifiedShape) {
		t.Fatalf("large answer: stored audits differ:\n legacy  %+v\n unified %+v", legacyShape, unifiedShape)
	}
	cases++
	// The same answer cut by the upstream after 2 MiB keeps its raw chunks:
	// response_sent writes its own, sealed from the bytes it borrowed.
	exchange.Response.CutAt, exchange.Response.Abort = 2<<20+333, true
	legacyStatus, _, legacyID = send(legacy, legacyDB, exchange)
	unifiedStatus, _, unifiedID = send(unified, unifiedDB, exchange)
	legacyShape, unifiedShape := readStoredShape(t, legacyDB, client, legacy.adminURL, cipher, legacyID), readStoredShape(t, unifiedDB, client, unified.adminURL, unifiedCipher, unifiedID)
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
