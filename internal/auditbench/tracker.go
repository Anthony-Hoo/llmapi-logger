package auditbench

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"llmapi-logger/internal/protofixture"
)

// queryTracker measures, per request, the time from the client reading the
// end of the response until the audit row is visible with a terminal parse
// status. It polls with one indexed lookup per tick for all open requests,
// so its resolution is the poll interval.
type queryTracker struct {
	stats *statsConn

	mu       sync.Mutex
	pending  map[string]time.Time
	latency  map[string]time.Duration
	auditIDs map[string]string
}

func newQueryTracker(stats *statsConn) *queryTracker {
	return &queryTracker{stats: stats, pending: make(map[string]time.Time), latency: make(map[string]time.Duration), auditIDs: make(map[string]string)}
}

func (tracker *queryTracker) watch(id string, end time.Time) {
	tracker.mu.Lock()
	tracker.pending[id] = end
	tracker.mu.Unlock()
}

func (tracker *queryTracker) open() int {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return len(tracker.pending)
}

func (tracker *queryTracker) loop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queryContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			tracker.poll(queryContext)
			cancel()
		}
	}
}

func (tracker *queryTracker) poll(ctx context.Context) {
	tracker.mu.Lock()
	ids := make([]string, 0, min(len(tracker.pending), 2000))
	for id := range tracker.pending {
		ids = append(ids, id)
		if len(ids) == 2000 {
			break
		}
	}
	tracker.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	found := make(map[string]string)
	err := tracker.stats.inTx(ctx, true, func(tx pgx.Tx) error {
		tracker.stats.latencyPolls++
		rows, err := tx.Query(ctx, `
SELECT newapi_request_id, audit_id FROM audit_records
WHERE newapi_request_id = ANY($1) AND ended_at_ns IS NOT NULL AND parse_status NOT IN ('pending', 'processing')`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var requestID, auditID string
			if err := rows.Scan(&requestID, &auditID); err != nil {
				return err
			}
			found[requestID] = auditID
		}
		return rows.Err()
	})
	if err != nil {
		return
	}
	now := time.Now()
	tracker.mu.Lock()
	for requestID, auditID := range found {
		if end, ok := tracker.pending[requestID]; ok {
			tracker.latency[requestID] = now.Sub(end)
			tracker.auditIDs[requestID] = auditID
			delete(tracker.pending, requestID)
		}
	}
	tracker.mu.Unlock()
}

func (tracker *queryTracker) results() (map[string]time.Duration, map[string]string, int) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	latency := make(map[string]time.Duration, len(tracker.latency))
	for key, value := range tracker.latency {
		latency[key] = value
	}
	ids := make(map[string]string, len(tracker.auditIDs))
	for key, value := range tracker.auditIDs {
		ids[key] = value
	}
	return latency, ids, len(tracker.pending)
}

// fakeNewAPI answers the read-only NewAPI management endpoints the audit
// proxy calls: /api/status, the user directory and the request log lookup.
// Every audited request is reported as one consumed log row of its synthetic
// user, so caller resolution and token links behave as in production.
type fakeNewAPI struct {
	mu      sync.Mutex
	entries map[string]newAPIEntry
	lookups atomic.Int64
}

type newAPIEntry struct {
	user       int
	model      string
	prompt     int64
	completion int64
}

func newFakeNewAPI() *fakeNewAPI { return &fakeNewAPI{entries: make(map[string]newAPIEntry)} }

func (fake *fakeNewAPI) remember(id string, exchange *protofixture.Exchange) {
	entry := newAPIEntry{user: max(1, exchange.User), model: exchange.Expect.RequestModel}
	if exchange.Expect.Usage.Input != nil {
		entry.prompt = *exchange.Expect.Usage.Input
	}
	if exchange.Expect.Usage.Output != nil {
		entry.completion = *exchange.Expect.Usage.Output
	}
	fake.mu.Lock()
	fake.entries[id] = entry
	fake.mu.Unlock()
}

const fakeNewAPIUsers = 8

func (fake *fakeNewAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	switch request.URL.Path {
	case "/api/status":
		_ = encoder.Encode(map[string]any{"success": true, "data": map[string]any{"quota_per_unit": 500000}})
	case "/api/user/":
		page, _ := strconv.Atoi(request.URL.Query().Get("p"))
		items := make([]map[string]any, 0, fakeNewAPIUsers)
		if page == 0 {
			for id := 1; id <= fakeNewAPIUsers; id++ {
				items = append(items, map[string]any{"id": id, "username": fmt.Sprintf("bench-user-%d", id),
					"display_name": fmt.Sprintf("Bench User %d", id), "status": 1, "group": "default"})
			}
		}
		_ = encoder.Encode(map[string]any{"success": true, "data": map[string]any{"total": fakeNewAPIUsers, "items": items}})
	case "/api/log/":
		fake.lookups.Add(1)
		id := request.URL.Query().Get("request_id")
		fake.mu.Lock()
		entry, ok := fake.entries[id]
		fake.mu.Unlock()
		items := []map[string]any{}
		if ok {
			items = append(items, map[string]any{
				"user_id": entry.user, "username": fmt.Sprintf("bench-user-%d", entry.user),
				"token_id": entry.user*10 + 1, "token_name": fmt.Sprintf("bench-token-%d", entry.user),
				"model_name": entry.model, "request_id": id, "created_at": time.Now().Unix(), "type": 2,
				"quota": entry.prompt + entry.completion*4, "prompt_tokens": entry.prompt, "completion_tokens": entry.completion,
			})
		}
		_ = encoder.Encode(map[string]any{"success": true, "data": map[string]any{"total": len(items), "items": items}})
	default:
		writer.WriteHeader(http.StatusNotFound)
		_ = encoder.Encode(map[string]any{"success": false, "message": "not found"})
	}
}
