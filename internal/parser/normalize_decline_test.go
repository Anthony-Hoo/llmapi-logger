package parser

import (
	"context"
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

// TestDeclinedNormalizationKeepsRawEvidence pins the path a stream normalizer
// uses to keep a stream's raw body: no turn is prepared, so the store has
// nothing verified to release the raw chunks for (module 18 §6), and the
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
