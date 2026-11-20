package web

import (
	"encoding/json"
	"net/http"
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
