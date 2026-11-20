package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// addExportRecords adds own records that lack some content, each for a
// reason that ends (or does not end) with the record's processing.
func addExportRecords(fixture *readFixture) {
	add := func(id string, offset time.Duration, change func(*query.Detail)) {
		record := fixtureAudit(id, offset, fixture.ownFingerprint, 42, storage.ForwardCompleted, nil)
		change(&record.detail)
		record.row.ForwardStatus = record.detail.Audit.ForwardStatus
		fixture.audits.records = append([]auditRecord{record}, fixture.audits.records...)
	}
	// An Anthropic record: parsed, with a conversation, but only the OpenAI
	// parser rebuilds a request and a response.
	add("anthropic-no-turn", 20*time.Second, func(detail *query.Detail) {
		detail.Audit.Protocol, detail.Audit.ParserName, detail.Turn = "anthropic", "anthropic.messages", nil
	})
	add("parse-failed", 21*time.Second, func(detail *query.Detail) {
		detail.Audit.ParseStatus, detail.Turn, detail.Conversation = storage.ParseError, nil, nil
	})
	add("parse-pending", 22*time.Second, func(detail *query.Detail) {
		detail.Audit.ParseStatus, detail.Turn, detail.Conversation = storage.ParsePending, nil, nil
	})
	add("released", 23*time.Second, func(detail *query.Detail) {
		detail.Bodies[1].RetentionState = storage.RetentionMetadata
	})
	add("retention-pending", 24*time.Second, func(detail *query.Detail) {
		detail.Bodies[0].RetentionState = storage.RetentionPending
	})
	add("capturing", 25*time.Second, func(detail *query.Detail) {
		detail.Audit.ForwardStatus, detail.Audit.ParseStatus, detail.Audit.EndedAtNS = storage.ForwardInProgress, storage.ParsePending, nil
		detail.Turn, detail.Conversation = nil, nil
		detail.Bodies[1].State, detail.Bodies[1].StreamEventCount = storage.StageStateStreaming, 0
	})
}

// codeOfExportState is the answer an export gives for a predicted state.
var codeOfExportState = map[string]agentapi.Code{
	exportAvailable: "", exportPending: agentapi.CodeNotReady, exportNotAvailable: agentapi.CodeNotAvailable, exportNotRetained: agentapi.CodeNotRetained,
}

// webExportRoutes are the web routes of the export kinds the web serves on
// their own (the conversation and the headers are part of the web detail).
var webExportRoutes = map[string]string{
	"request": "/reconstructed/request", "response": "/reconstructed/response",
	"timeline-request": "/timeline/request", "timeline-response": "/timeline/response",
	"raw-request": "/raw/request", "raw-response": "/raw/response",
}

// requests get says, in data.exports, what every export kind of the record
// gives, and the export answers exactly that: available content is served,
// content still being produced is NOT_READY, content the record will never
// have is NOT_AVAILABLE with the reason (a blocked record, a skipped or
// failed parse, a protocol without reconstruction, an unstreamed body), a
// released raw body NOT_RETAINED. The web routes serve exactly the kinds
// predicted available.
func TestAgentExportStatesPredictTheExport(t *testing.T) {
	fixture := newReadFixture(t)
	addExportRecords(fixture)
	want := map[string]map[string]agentExportState{
		"anthropic-no-turn": {"request": {exportNotAvailable, exportReasonNotReconstructed}, "conversation": {State: exportAvailable}},
		"parse-failed":      {"conversation": {exportNotAvailable, exportReasonParseFailed}, "response": {exportNotAvailable, exportReasonParseFailed}},
		"parse-pending":     {"conversation": {exportPending, exportReasonParsePending}, "request": {exportPending, exportReasonParsePending}},
		"released":          {"raw-response": {exportNotRetained, exportReasonReleased}, "raw-request": {State: exportAvailable}},
		"retention-pending": {"raw-request": {exportPending, exportReasonRetentionPending}},
		"capturing":         {"timeline-response": {exportPending, exportReasonCapturing}, "raw-response": {exportPending, exportReasonCapturing}, "request": {exportPending, exportReasonInProgress}},
		"blocked-own": {"conversation": {exportNotAvailable, exportReasonBlocked}, "request": {exportNotAvailable, exportReasonBlocked},
			"timeline-response": {exportNotAvailable, exportReasonBlocked}, "raw-response": {exportNotAvailable, exportReasonBlocked},
			"raw-request": {State: exportAvailable}, "headers": {State: exportAvailable}},
		"own-1": {"timeline-request": {exportNotAvailable, exportReasonNotStreamed}, "timeline-response": {State: exportAvailable},
			"request": {State: exportAvailable}, "raw-response": {State: exportAvailable}},
	}
	for id, expected := range want {
		detail := decodeAgent(t, fixture.facade(http.MethodGet, "/requests/"+id, "", fixture.adminRead))
		var data struct {
			Exports map[string]agentExportState `json:"exports"`
		}
		if err := json.Unmarshal(detail.Data, &data); err != nil || len(data.Exports) != len(agentapi.ExportKinds) {
			t.Fatalf("%s: requests get exports = %s", id, detail.Data)
		}
		for what, state := range expected {
			if !reflect.DeepEqual(data.Exports[what], state) {
				t.Errorf("%s %s: exports says %+v, want %+v", id, what, data.Exports[what], state)
			}
		}
		for _, what := range agentapi.ExportKinds {
			state := data.Exports[what]
			response := fixture.facade(http.MethodGet, "/requests/"+id+"/export/"+what, "", fixture.adminRead)
			if got := facadeOutcome(t, response); got != codeOfExportState[state.State] {
				t.Errorf("%s %s: exports says %+v, the export answered %q", id, what, state, got)
				continue
			}
			if state.State != exportAvailable {
				body := decodeAgent(t, response)
				if body.Error.Details["reason"] != state.Reason || body.Error.Details["what"] != what {
					t.Errorf("%s %s: details %v, want reason %q", id, what, body.Error.Details, state.Reason)
				}
				if state.State == exportNotAvailable && body.Error.Hint == agentapi.Failure(agentapi.CodeNotReady, "", "", nil).Error.Hint {
					t.Errorf("%s %s: content that will never exist is answered with the NOT_READY hint", id, what)
				}
			}
			if route, ok := webExportRoutes[what]; ok {
				web := fixture.web(http.MethodGet, "/api/v1/audits/"+id+route, "", fixture.adminWeb)
				if (web.Code == http.StatusOK) != (state.State == exportAvailable) {
					t.Errorf("%s %s: web %d, exports says %+v", id, what, web.Code, state)
				}
			}
		}
	}
}

// exportCompleteness reads the completeness headers of one export answer.
func exportCompletenessOf(t *testing.T, response *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("export = %d %s", response.Code, response.Body.String())
	}
	return response.Header().Get(headerExportComplete), response.Header().Get(headerExportIncomplete)
}

// A record whose parse is partial (a stream cut before its end, with the
// capture complete) is not complete: requests get says parse_partial, and so
// does every export built from the parse (the conversation; a request or
// response reconstruction when one exists) and the response timeline (the
// timing of a response the parser found cut short; the capture keeps a
// complete timeline of what arrived, as internal/audit seals it whenever no
// event is left open). The other exports of captured content (headers, raw
// bodies, the request timeline) follow the capture, which is complete.
// data.exports keeps predicting exactly what the export answers.
func TestPartialParseIsNotComplete(t *testing.T) {
	fixture := newReadFixture(t)
	add := func(id string, offset time.Duration, change func(*query.Detail)) {
		record := fixtureAudit(id, offset, fixture.ownFingerprint, 42, storage.ForwardCompleted, nil)
		change(&record.detail)
		record.row.ForwardStatus = record.detail.Audit.ForwardStatus
		fixture.audits.records = append([]auditRecord{record}, fixture.audits.records...)
	}
	// What the worker stores for an Anthropic stream cut before
	// message_stop: capture complete, parse partial, a conversation and no
	// turn graph.
	add("cut-stream", 30*time.Second, func(detail *query.Detail) {
		detail.Audit.Protocol, detail.Audit.ParserName = "anthropic", "anthropic.messages"
		detail.Audit.ParseStatus, detail.ParsedResult.Status, detail.Turn = storage.ParsePartial, storage.ParsePartial, nil
	})
	// The same with a turn graph, so the reconstruction exports exist too.
	add("partial-with-turn", 31*time.Second, func(detail *query.Detail) {
		detail.Audit.ParseStatus, detail.ParsedResult.Status = storage.ParsePartial, storage.ParsePartial
	})
	for _, id := range []string{"cut-stream", "partial-with-turn"} {
		for _, token := range []string{fixture.adminRead, fixture.developer} {
			detail := decodeAgent(t, fixture.facade(http.MethodGet, "/requests/"+id, "", token))
			if detail.Meta == nil || detail.Meta.Complete || detail.Meta.IncompleteReason != auditIncompleteParsePartial {
				t.Fatalf("%s: requests get meta %+v, want complete=false parse_partial", id, detail.Meta)
			}
			var data struct {
				Exports map[string]agentExportState `json:"exports"`
			}
			_ = json.Unmarshal(detail.Data, &data)
			for _, what := range agentapi.ExportKinds {
				response := fixture.facade(http.MethodGet, "/requests/"+id+"/export/"+what, "", token)
				if (data.Exports[what].State == exportAvailable) != (response.Code == http.StatusOK) {
					t.Errorf("%s %s: exports says %+v, export answered %d", id, what, data.Exports[what], response.Code)
					continue
				}
				if response.Code != http.StatusOK {
					continue
				}
				complete, reason := exportCompletenessOf(t, response)
				switch what {
				case "conversation", "request", "response", "timeline-response":
					if complete != "false" || reason != auditIncompleteParsePartial {
						t.Errorf("%s %s: complete=%q reason=%q, want false parse_partial", id, what, complete, reason)
					}
				default:
					if complete != "true" || reason != "" {
						t.Errorf("%s %s: complete=%q reason=%q, want true (captured content follows the capture)", id, what, complete, reason)
					}
				}
			}
		}
	}
	// The cut stream's conversation is served (it is what the parser kept),
	// just not called complete.
	if response := fixture.facade(http.MethodGet, "/requests/cut-stream/export/conversation", "", fixture.developer); response.Code != http.StatusOK {
		t.Fatalf("conversation of a cut stream = %d", response.Code)
	}
	// parse=ok, error and skipped records are not affected.
	for _, id := range []string{"own-1", "blocked-own"} {
		if meta := decodeAgent(t, fixture.facade(http.MethodGet, "/requests/"+id, "", fixture.adminRead)).Meta; meta == nil || !meta.Complete {
			t.Errorf("%s: meta %+v", id, meta)
		}
	}
}

// The fixture's timeline and raw metadata follow the body's own columns, as
// query.Service does, so the content-incomplete paths of the exports are
// exercised: a stream whose timeline is not complete gives a timeline export
// complete=false timeline_incomplete, and a truncated stored body gives a raw
// export complete=false capture_incomplete, while the record itself is
// complete.
func TestCapturedContentIncompleteExports(t *testing.T) {
	fixture := newReadFixture(t)
	record := fixtureAudit("short-content", 30*time.Second, fixture.ownFingerprint, 42, storage.ForwardCompleted, nil)
	record.detail.Bodies[1].StreamTimelineComplete = false
	record.detail.Bodies[0].StoredLength, record.detail.Bodies[0].HashComplete = 4, false
	fixture.audits.records = append([]auditRecord{record}, fixture.audits.records...)
	if meta := decodeAgent(t, fixture.facade(http.MethodGet, "/requests/short-content", "", fixture.developer)).Meta; meta == nil || !meta.Complete {
		t.Fatalf("precondition: the record is complete, meta %+v", meta)
	}
	for what, want := range map[string][2]string{
		"timeline-response": {"false", exportIncompleteTimeline},
		"raw-request":       {"false", exportIncompleteRawCapture},
		"raw-response":      {"true", ""},
		"conversation":      {"true", ""},
	} {
		complete, reason := exportCompletenessOf(t, fixture.facade(http.MethodGet, "/requests/short-content/export/"+what, "", fixture.developer))
		if complete != want[0] || reason != want[1] {
			t.Errorf("%s: complete=%q reason=%q, want %v", what, complete, reason, want)
		}
	}
	raw := fixture.facade(http.MethodGet, "/requests/short-content/export/raw-request", "", fixture.developer)
	if raw.Header().Get("X-Audit-Stored-Length") != "4" || raw.Body.Len() != 4 {
		t.Fatalf("raw body: stored length %q, %d bytes", raw.Header().Get("X-Audit-Stored-Length"), raw.Body.Len())
	}
}
