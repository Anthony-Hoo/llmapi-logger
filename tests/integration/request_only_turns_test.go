package integration_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/parser/streamevidence"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
)

const requestOnlyHalfStream = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_half\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"model-example\",\"content\":[],\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"half an ans\"}}\n\n"

// requestOnlyNoStop is complete as bytes and has no message_stop.
const requestOnlyNoStop = requestOnlyHalfStream +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n"

func requestOnlyComplete(extra string) string {
	return requestOnlyHalfStream + extra +
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
}

func requestOnlyBody(messages string) string {
	return `{"model":"model-example","max_tokens":64,"stream":true,` +
		`"metadata":{"user_id":"{\"device_id\":\"device-example\",\"session_id\":\"session-request-only\"}"},` +
		`"system":"You are an agent.","messages":[` + messages + `]}`
}

// largeText is about size bytes of words, deterministic, compressing about
// as well as ordinary prose.
func largeText(size int) string {
	words := strings.Fields("the build reads each module and writes its report before the next step starts so a failure stops early and names the file it was reading when it stopped")
	random := rand.New(rand.NewPCG(59, 9))
	var text strings.Builder
	for text.Len() < size {
		text.WriteString(words[random.IntN(len(words))])
		text.WriteByte(' ')
	}
	return text.String()
}

func gzipString(t *testing.T, text string) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := io.WriteString(writer, text); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

type requestOnlyCase struct {
	name     string
	body     string
	encoding string
	// stream is what the upstream sends; status, when set, is a JSON error
	// answer instead.
	stream string
	status int
	// cancel makes the client go away once it has read the whole stream,
	// which the upstream then holds open.
	cancel bool
}

type storedSide struct {
	retention []string
	stored    int64
	chunks    int
	chunkSize int64
}

func readSide(t *testing.T, database *sql.DB, auditID string, stages ...string) storedSide {
	t.Helper()
	var side storedSide
	for _, stage := range stages {
		var retention string
		var stored int64
		if err := database.QueryRow(`SELECT retention_state, stored_length FROM body_streams WHERE audit_id = $1 AND stage = $2`, auditID, stage).Scan(&retention, &stored); err != nil {
			t.Fatalf("%s %s: %v", auditID, stage, err)
		}
		side.retention = append(side.retention, retention)
		side.stored += stored
	}
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(SUM(octet_length(data_enc)), 0) FROM body_chunks WHERE audit_id = $1 AND stage IN ($2, $3)`,
		auditID, stages[0], stages[1]).Scan(&side.chunks, &side.chunkSize); err != nil {
		t.Fatal(err)
	}
	return side
}

func (side storedSide) is(retention string) bool {
	return len(side.retention) == 2 && side.retention[0] == retention && side.retention[1] == retention
}

// Audits whose response cannot be carried by a turn, through the real proxy,
// PostgreSQL store and parser worker: each case of design 5.9's table whose
// request is usable gets a request-only turn (request stages metadata with
// their chunks gone, response stages full and downloadable byte for byte, no
// fallback conversation, the integrity events verifying); those whose
// request is not usable keep four full stages and no turn. The turn after a
// request-only turn links to it. It also measures, for a mid-stream cancel
// with a request of about 1 MB, the bytes stored before and after.
func TestRequestOnlyTurnsOnPostgreSQL(t *testing.T) {
	big := requestOnlyBody(`{"role":"user","content":"` + largeText(1<<20) + `"}`)
	small := requestOnlyBody(`{"role":"user","content":"explain the build"}`)
	cases := []requestOnlyCase{
		{name: "big-cancelled", body: big, stream: requestOnlyHalfStream, cancel: true},
		// The same request kept in full (an unclassified 400): the size of
		// its request raw is what the cancel stored before this change.
		{name: "big-kept", body: big, status: http.StatusBadRequest},
		{name: "no-stop", body: small, stream: requestOnlyNoStop},
		{name: "residue", body: small, stream: requestOnlyComplete("event: x_unknown\ndata: {\"type\":\"x_unknown\",\"padding\":\"" + strings.Repeat("p", streamevidence.MaxResidueBytes) + "\"}\n\n")},
		{name: "over-limit", body: gzipString(t, requestOnlyBody(`{"role":"user","content":"`+strings.Repeat("a", 512<<10)+`"}`)), encoding: "gzip", stream: requestOnlyNoStop},
		{name: "not-json", body: `{"model":"model-example","messages":[`, stream: requestOnlyNoStop},
		// The three request-only turns of small share one request; the next
		// turn links to the newest of them, this one.
		{name: "cancelled", body: small, stream: requestOnlyHalfStream, cancel: true},
		{name: "next", body: requestOnlyBody(`{"role":"user","content":"explain the build"},{"role":"assistant","content":[{"type":"text","text":"half an ans"}]},{"role":"user","content":"go on"}`),
			stream: requestOnlyComplete("")},
	}
	byName := map[string]requestOnlyCase{}
	for _, test := range cases {
		byName[test.name] = test
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		test := byName[request.Header.Get("X-Test-Case")]
		if test.status != 0 {
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(test.status)
			_, _ = io.WriteString(response, `{"type":"error","error":{"type":"invalid_request_error","message":"example rejection"}}`)
			return
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, test.stream)
		response.(http.Flusher).Flush()
		if test.cancel {
			select {
			case <-request.Context().Done():
			case <-time.After(integrationTimeout):
			}
		}
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/messages", false)
	cfg.Routes[0].Parser = "anthropic.messages"
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}
	database := openAuditDatabase(t, cfg.DatabaseURL)
	defer database.Close()
	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	contentBytes := func() int64 {
		var total int64
		if err := database.QueryRow(`SELECT COALESCE(SUM(octet_length(data_enc)), 0) FROM content_objects`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		return total
	}
	ids := map[string]string{}
	objectBytes := map[string]int64{}
	for _, test := range cases {
		before := contentBytes()
		request, err := http.NewRequest(http.MethodPost, running.baseURL+"/v1/messages", strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Api-Key", "sk-requestonly")
		request.Header.Set("X-Test-Case", test.name)
		if test.encoding != "" {
			request.Header.Set("Content-Encoding", test.encoding)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if test.cancel {
			// Read what was sent, then go away while the stream is open.
			if _, err := io.ReadFull(response.Body, make([]byte, len(test.stream))); err != nil {
				t.Fatal(err)
			}
		} else {
			_, _ = io.Copy(io.Discard, response.Body)
		}
		response.Body.Close()
		ids[test.name] = waitForParsedAudit(t, database, ids)
		objectBytes[test.name] = contentBytes() - before
	}

	type row struct {
		status, code, responseLayout, parent string
		turn                                 bool
		events                               []string
		parsed                               []byte
	}
	load := func(auditID string) row {
		var result row
		var code, layout, parent sql.NullString
		var parsed []byte
		if err := database.QueryRow(`
SELECT p.status, p.error_code, p.parsed_json_enc, t.response_layout, t.parent_turn_id
FROM parsed_results AS p LEFT JOIN turns AS t ON t.audit_id = p.audit_id
WHERE p.audit_id = $1`, auditID).Scan(&result.status, &code, &parsed, &layout, &parent); err != nil {
			t.Fatal(err)
		}
		result.code, result.responseLayout, result.parent, result.turn = code.String, layout.String, parent.String, layout.Valid
		plaintext, err := auditmodel.OpenParsedResult(cipher, auditID, "anthropic.messages", parsed)
		if err != nil {
			t.Fatal(err)
		}
		result.parsed = plaintext
		rows, err := database.Query(`SELECT event_type FROM integrity_events WHERE audit_id = $1 ORDER BY sequence`, auditID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var eventType string
			if err := rows.Scan(&eventType); err != nil {
				t.Fatal(err)
			}
			result.events = append(result.events, eventType)
		}
		return result
	}
	requestStages := []string{stageRequestReceived, stageRequestSent}
	responseStages := []string{stageResponseReceived, stageResponseSent}

	for _, name := range []string{"big-cancelled", "cancelled", "no-stop", "residue"} {
		test, auditID := byName[name], ids[name]
		stored := load(auditID)
		wantStatus, wantCode := "partial", ""
		if name == "no-stop" {
			wantCode = "missing_message_stop"
		}
		if name == "residue" {
			wantStatus, wantCode = "ok", parser.ErrorCodeResponseNotNormalized
		}
		if !stored.turn || stored.responseLayout != auditmodel.LayoutNone || stored.status != wantStatus || (wantCode != "" && stored.code != wantCode) ||
			stored.code == "" || stored.code == "normalization_failed" || strings.Join(stored.events, ",") != "capture_finalized,semantic_compacted" {
			t.Fatalf("%s: %+v", name, stored)
		}
		t.Logf("%s: saved as %s / %s", name, stored.status, stored.code)
		if bytes.Contains(stored.parsed, []byte(`"conversation"`)) || bytes.Contains(stored.parsed, []byte("explain the build")) ||
			!bytes.Contains(stored.parsed, []byte(`"partial_response_messages"`)) {
			t.Fatalf("%s: parsed result %s", name, stored.parsed)
		}
		if side := readSide(t, database, auditID, requestStages...); !side.is("metadata") || side.stored != 0 || side.chunks != 0 {
			t.Fatalf("%s: request side %+v", name, side)
		}
		if side := readSide(t, database, auditID, responseStages...); !side.is("full") || side.chunks == 0 {
			t.Fatalf("%s: response side %+v", name, side)
		}
		if status, body := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/raw/response"); status != http.StatusOK || string(body) != test.stream {
			t.Fatalf("%s: raw response %d (%d bytes)", name, status, len(body))
		}
		if status, _ := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/raw/request"); status != http.StatusGone {
			t.Fatalf("%s: raw request %d", name, status)
		}
		if status, _ := authorizedAdminResponse(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/reconstructed/response"); status != http.StatusNotFound {
			t.Fatalf("%s: reconstructed response %d", name, status)
		}
		assertJSONEquivalent(t, authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID+"/reconstructed/request"), []byte(test.body))
		var detail adminAuditDetail
		if err := json.Unmarshal(authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+auditID), &detail); err != nil {
			t.Fatal(err)
		}
		// The detail shows what the fallback conversation showed: the parse of
		// the request and the response as they were captured.
		fallback := anthropic.New().Parse(context.Background(), parser.Input{
			Request:  parser.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(test.body)},
			Response: parser.BodySource{Present: true, Complete: !test.cancel, ContentType: "text/event-stream", Data: []byte(test.stream)},
		}).Conversation
		got, _ := json.Marshal(detail.Conversation)
		want, _ := json.Marshal(fallback)
		if string(got) != string(want) {
			t.Fatalf("%s: detail conversation\n got: %s\nwant: %s", name, got, want)
		}
		messages := detail.Conversation.Messages
		if last := messages[len(messages)-1]; last.Phase != "response" || last.Index != len(messages)-1 || last.Content[0].Text == "" {
			t.Fatalf("%s: conversation %+v", name, messages)
		}
	}
	for _, name := range []string{"over-limit", "not-json"} {
		auditID := ids[name]
		stored := load(auditID)
		if stored.turn || stored.status != "partial" || strings.Join(stored.events, ",") != "capture_finalized" ||
			!bytes.Contains(stored.parsed, []byte(`"conversation"`)) {
			t.Fatalf("%s: %+v", name, stored)
		}
		t.Logf("%s: saved as %s / %s", name, stored.status, stored.code)
		if side := readSide(t, database, auditID, requestStages...); !side.is("full") || side.chunks == 0 {
			t.Fatalf("%s: request side %+v", name, side)
		}
		if side := readSide(t, database, auditID, responseStages...); !side.is("full") || side.chunks == 0 {
			t.Fatalf("%s: response side %+v", name, side)
		}
	}
	if next := load(ids["next"]); !next.turn || next.parent == "" {
		t.Fatalf("next turn: %+v", next)
	} else {
		var parentAudit string
		if err := database.QueryRow(`SELECT audit_id FROM turns WHERE turn_id = $1`, next.parent).Scan(&parentAudit); err != nil || parentAudit != ids["cancelled"] {
			t.Fatalf("next turn's parent is %s (%v), want the cancelled turn %s", parentAudit, err, ids["cancelled"])
		}
	}
	_ = authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+ids["next"]+"/reconstructed/request")

	// Bytes stored for the 1 MB mid-stream cancel. Before: its request raw,
	// measured on the same request kept in full, the response raw and the
	// fallback conversation sealed as the old worker sealed it. After: what
	// is stored now.
	kept := readSide(t, database, ids["big-kept"], requestStages...)
	response := readSide(t, database, ids["big-cancelled"], responseStages...)
	parse := anthropic.New().Parse(context.Background(), parser.Input{
		Request:  parser.BodySource{Present: true, Complete: true, ContentType: "application/json", Data: []byte(big)},
		Response: parser.BodySource{Present: true, ContentType: "text/event-stream", Data: []byte(requestOnlyHalfStream)},
	})
	var envelope map[string]any
	if err := json.Unmarshal(parse.ParsedJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["conversation"] = parse.Conversation
	fallbackPlaintext, _ := json.Marshal(envelope)
	fallbackSealed, err := auditmodel.SealParsedResult(cipher, ids["big-cancelled"], "anthropic.messages", fallbackPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	var parsedNow int64
	if err := database.QueryRow(`SELECT octet_length(parsed_json_enc) FROM parsed_results WHERE audit_id = $1`, ids["big-cancelled"]).Scan(&parsedNow); err != nil {
		t.Fatal(err)
	}
	beforeBytes := kept.chunkSize + response.chunkSize + int64(len(fallbackSealed))
	afterBytes := response.chunkSize + parsedNow + objectBytes["big-cancelled"]
	t.Logf("1 MB mid-stream cancel (request %d bytes): before %d bytes (request raw %d, response raw %d, fallback %d); after %d bytes (response raw %d, parsed result %d, new content objects %d)",
		len(big), beforeBytes, kept.chunkSize, response.chunkSize, len(fallbackSealed), afterBytes, response.chunkSize, parsedNow, objectBytes["big-cancelled"])
	if afterBytes >= beforeBytes {
		t.Fatalf("a request-only turn stores %d bytes, not less than the %d before", afterBytes, beforeBytes)
	}

	if err := running.stop(); err != nil {
		t.Fatal(err)
	}
	store, err := postgres.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.EnableIntegrity(context.Background(), key); err != nil {
		t.Fatalf("integrity chain: %v", err)
	}
	if err := store.VerifyIntegrityPayloads(context.Background()); err != nil {
		t.Fatalf("integrity payloads: %v", err)
	}
}

// waitForParsedAudit waits for an audit not in known whose parse finished,
// and returns its id.
func waitForParsedAudit(t *testing.T, database *sql.DB, known map[string]string) string {
	t.Helper()
	seen := map[string]bool{}
	for _, id := range known {
		seen[id] = true
	}
	deadline := time.Now().Add(integrationTimeout)
	for time.Now().Before(deadline) {
		rows, err := database.Query(`SELECT audit_id FROM audit_records WHERE ended_at_ns IS NOT NULL AND parse_status NOT IN ('pending', 'processing') ORDER BY started_at_ns DESC`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			if !seen[id] {
				rows.Close()
				return id
			}
		}
		rows.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a parsed audit")
	return ""
}
