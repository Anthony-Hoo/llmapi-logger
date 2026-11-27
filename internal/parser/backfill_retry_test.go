package parser

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestBackfillFailureIsRetriedOnLaterScan(t *testing.T) {
	w := &Worker{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.backfillFail("retry-me", "store_failed", errors.New("temporary"), nil)
	if _, ok := w.backfillSkipped["retry-me"]; ok {
		t.Fatal("transient failure permanently skipped")
	}
	if _, ok := w.backfillRetry["retry-me"]; !ok {
		t.Fatal("transient failure not kept for a retry")
	}
	w.backfillSkip("permanent", "no_body")
	if _, ok := w.backfillSkipped["permanent"]; !ok {
		t.Fatal("permanent skip not remembered")
	}
}
