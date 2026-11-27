package parser

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

func TestBackfillFailureIsRetriedOnLaterScan(t *testing.T) {
	w := &Worker{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now}
	w.backfillFail("retry-me", "store_failed", storage.ErrQueueFull, nil, true)
	if _, ok := w.backfillSkipped["retry-me"]; ok {
		t.Fatal("transient failure permanently skipped")
	}
	if _, ok := w.backfillRetry["retry-me"]; !ok {
		t.Fatal("transient failure not kept for a retry")
	}
	w.backfillFail("doomed", "analysis_failed", errors.New("not JSON"), nil, false)
	if _, ok := w.backfillSkipped["doomed"]; !ok {
		t.Fatal("a failure that cannot clear must skip the audit")
	}
	w.backfillSkip("permanent", "no_body", nil)
	if _, ok := w.backfillSkipped["permanent"]; !ok {
		t.Fatal("permanent skip not remembered")
	}
}

type sqlStateError string

func (err sqlStateError) Error() string    { return "sqlstate " + string(err) }
func (err sqlStateError) SQLState() string { return string(err) }

// A storage outage or overload must stay retryable through every wrapper
// the stores and the insights runner add; an analysis that rejects the
// evidence must not.
func TestRetryableFailureClassification(t *testing.T) {
	t.Parallel()
	wrap := func(err error) error {
		return &insights.RunError{Code: insights.ErrorCodeAnalysisSaveFailed, Err: fmt.Errorf("postgres writer: %w", err)}
	}
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, true},
		{"bad connection", driver.ErrBadConn, true},
		{"connection cut mid-reply", io.ErrUnexpectedEOF, true},
		{"store closed", storage.ErrClosed, true},
		{"writer queue full", storage.ErrQueueFull, true},
		{"timeout while the worker runs", context.DeadlineExceeded, true},
		{"connection failure", sqlStateError("08006"), true},
		{"serialization failure", sqlStateError("40001"), true},
		{"disk full", sqlStateError("53100"), true},
		{"lock not available", sqlStateError("55P03"), true},
		{"admin shutdown", sqlStateError("57P01"), true},
		{"io error", sqlStateError("58030"), true},
		{"constraint violation", sqlStateError("23505"), false},
		{"invalid JSON request", errors.New("insights: request is not valid JSON"), false},
		{"analyzer panic", errAnalyzerPanic, false},
		{"missing row", fmt.Errorf("load: %w", errors.New("no rows")), false},
	} {
		if got := retryableFailure(wrap(test.err)); got != test.want {
			t.Errorf("%s: retryable = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestRetryBackoffDoublesUpToItsCap(t *testing.T) {
	t.Parallel()
	want := []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 80 * time.Minute}
	for index, delay := range want {
		if got := retryDelay(index + 1); got != delay {
			t.Errorf("after %d failures: %v, want %v", index+1, got, delay)
		}
	}
}
