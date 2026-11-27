package parser

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/storage/sqlite"
)

// decliningParser parses ok and declines to normalize, as a stream
// normalizer does when the stream's residue is over its limit.
type decliningParser struct{ recordingParser }

func (*decliningParser) NormalizeAudit(context.Context, Input, Result) (auditmodel.Turn, error) {
	return auditmodel.Turn{}, errors.New("stream residue exceeds the limit")
}

// TestDeclinedNormalizationKeepsRawEvidence pins what a normalizer error
// other than ErrStreamResidueTooLarge does: no turn is prepared, so the store
// has nothing verified to release the raw chunks for (module 18 §6), and the
// parse is recorded as partial with normalization_failed, which also stores
// the fallback conversation.
func TestDeclinedNormalizationKeepsRawEvidence(t *testing.T) {
	t.Parallel()
	store := newFakeStore("audit-declined", "test.parser")
	worker, err := NewWorker(store, testCipher(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	implementation := &decliningParser{recordingParser{name: "test.parser"}}
	result := Result{Status: StatusOK, ResponseModel: "model"}
	input := Input{
		Request:  BodySource{Present: true, Complete: true, Data: []byte(`{}`)},
		Response: BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte("data: {}\n\n")},
	}
	prepared := worker.prepareTurn(context.Background(), sqlite.ParserAudit{AuditID: "audit-declined", ParserName: "test.parser"}, implementation, input, &result)
	if prepared != nil || result.Status != StatusPartial || result.ErrorCode != "normalization_failed" || result.ParsedJSON != nil {
		t.Fatalf("prepared = %v, result = %+v", prepared, result)
	}
}

// residueParser declines a response as a stream normalizer does when the
// residue is over its limit. With the response removed it normalizes the
// request, unless requestFails is set.
type residueParser struct {
	recordingParser
	requestFails bool
}

func (implementation *residueParser) NormalizeAudit(_ context.Context, input Input, _ Result) (auditmodel.Turn, error) {
	if input.Response.Present || implementation.requestFails {
		return auditmodel.Turn{}, ErrStreamResidueTooLarge
	}
	var root map[string]any
	if err := json.Unmarshal(input.Request.Data, &root); err != nil {
		return auditmodel.Turn{}, err
	}
	messages := root["messages"].([]any)
	envelope := map[string]any{}
	return auditmodel.Turn{
		RequestLayout: auditmodel.LayoutOpenAIChatRequest, ResponseLayout: auditmodel.LayoutNone,
		RequestEnvelope: envelope, RequestOriginal: root,
		RequestItems: []auditmodel.Item{{Slot: auditmodel.SlotMessages, Kind: "user_message", Value: messages[0]}},
	}, nil
}

// A stream declined with ErrStreamResidueTooLarge was complete and parsed:
// it gets a request-only turn and its parse stays ok, with an error code that
// says the response was not normalized. When even the request cannot be
// normalized, the audit takes the normalization_failed path as before.
func TestResidueDeclineGetsARequestOnlyTurn(t *testing.T) {
	t.Parallel()
	audit := sqlite.ParserAudit{AuditID: "audit-residue", Protocol: "test", ParserName: "test.parser"}
	input := Input{
		Request:  BodySource{Present: true, Complete: true, Data: []byte(`{"messages":[{"role":"user","content":"x"}]}`)},
		Response: BodySource{Present: true, Complete: true, ContentType: "text/event-stream", Data: []byte("data: {}\n\n")},
	}
	for _, test := range []struct {
		name         string
		requestFails bool
	}{{"request normalizes", false}, {"request fails too", true}} {
		worker, err := NewWorker(newFakeStore(audit.AuditID, audit.ParserName), testCipher(t), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		implementation := &residueParser{recordingParser: recordingParser{name: "test.parser"}, requestFails: test.requestFails}
		result := Result{Status: StatusOK, ResponseModel: "model", ParsedJSON: []byte(`{"status":"ok"}`)}
		prepared := worker.prepareTurn(context.Background(), audit, implementation, input, &result)
		if test.requestFails {
			if prepared != nil || result.Status != StatusPartial || result.ErrorCode != "normalization_failed" {
				t.Fatalf("%s: prepared = %v, result = %+v", test.name, prepared, result)
			}
			continue
		}
		if prepared == nil || prepared.ResponseLayout != auditmodel.LayoutNone || prepared.RequestLayout != auditmodel.LayoutOpenAIChatRequest ||
			result.Status != StatusOK || result.ErrorCode != ErrorCodeResponseNotNormalized || result.ParsedJSON == nil {
			t.Fatalf("%s: prepared = %+v, result = %+v", test.name, prepared, result)
		}
	}
}

// A partial parse or an incomplete response gets a request-only turn only
// when the request parses on its own; otherwise nothing is prepared and the
// result is left exactly as it was.
func TestRequestOnlyTurnNeedsARequestThatParsesAlone(t *testing.T) {
	t.Parallel()
	audit := sqlite.ParserAudit{AuditID: "audit-partial", Protocol: "test", ParserName: "test.parser"}
	request := BodySource{Present: true, Complete: true, Data: []byte(`{"messages":[{"role":"user","content":"x"}]}`)}
	response := BodySource{Present: true, Complete: false, ErrorCode: "capture_partial", ContentType: "text/event-stream", Data: []byte("data: {}\n\n")}
	for _, test := range []struct {
		name     string
		request  BodySource
		response BodySource
		alone    string
		want     bool
	}{
		{"incomplete response", request, response, StatusOK, true},
		{"request parse partial", request, response, StatusPartial, false},
		{"incomplete request", BodySource{Present: true, Complete: false, ErrorCode: "capture_partial", Data: request.Data}, response, StatusOK, false},
		{"request error code", BodySource{Present: true, Complete: true, ErrorCode: "gzip_ratio_exceeded", Data: request.Data}, response, StatusOK, false},
		{"no response", request, BodySource{}, StatusOK, false},
		{"response not read as stored", request, BodySource{Present: true, ErrorCode: "capture_integrity_error"}, StatusOK, false},
	} {
		worker, err := NewWorker(newFakeStore(audit.AuditID, audit.ParserName), testCipher(t), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		alone := Result{Status: test.alone, RequestModel: "model"}
		implementation := &residueParser{recordingParser: recordingParser{name: "test.parser", result: &alone}}
		result := Result{Status: StatusPartial, ErrorCode: "capture_partial", ParsedJSON: []byte(`{"status":"partial"}`)}
		before := result
		prepared := worker.prepareTurn(context.Background(), audit, implementation, Input{Request: test.request, Response: test.response}, &result)
		if (prepared != nil) != test.want || result.Status != before.Status || result.ErrorCode != before.ErrorCode || string(result.ParsedJSON) != string(before.ParsedJSON) {
			t.Fatalf("%s: prepared = %v, result = %+v", test.name, prepared != nil, result)
		}
		if prepared != nil && prepared.ResponseLayout != auditmodel.LayoutNone {
			t.Fatalf("%s: response layout %q", test.name, prepared.ResponseLayout)
		}
	}
}
