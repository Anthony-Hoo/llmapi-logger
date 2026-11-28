package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// timingStore records when Finish reaches its first write, which separates
// the CPU work Finish does before committing from the commit itself.
type timingStore struct {
	*sqlite.Store
	firstWrite time.Time
}

func (store *timingStore) mark() {
	if store.firstWrite.IsZero() {
		store.firstWrite = time.Now()
	}
}

func (store *timingStore) FinishStage(ctx context.Context, finish storage.StageFinish) error {
	store.mark()
	return store.Store.FinishStage(ctx, finish)
}

func (store *timingStore) CommitAudit(ctx context.Context, commit storage.AuditCommit) (storage.AuditFinish, error) {
	store.mark()
	return store.Store.CommitAudit(ctx, commit)
}

func sseBody(size int, seed uint64) []byte {
	random := rand.New(rand.NewPCG(seed, seed))
	words := []string{"alpha", "beta", "gamma", "delta", "tool", "call", "result", "the", "model", "answer", "token"}
	var builder bytes.Buffer
	for builder.Len() < size {
		builder.WriteString(`data: {"choices":[{"delta":{"content":"`)
		for range 6 {
			builder.WriteString(words[random.IntN(len(words))])
			builder.WriteByte(' ')
		}
		fmt.Fprintf(&builder, `%x"}}]}`+"\n\n", random.Uint64())
	}
	return builder.Bytes()
}

// TestMeasureFinish reports how long Session.Finish takes for a streamed
// response, and how much of it is spent before the first write. It only runs
// with LLMAPI_MEASURE_FINISH=1. The legacy numbers next to these (design
// stage 3, R.7) came from the binary that still had the legacy path.
func TestMeasureFinish(t *testing.T) {
	if os.Getenv("LLMAPI_MEASURE_FINISH") != "1" {
		t.Skip("set LLMAPI_MEASURE_FINISH=1 to measure")
	}
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1 << 20, 8 << 20} {
		response := sseBody(size, uint64(size))
		request := []byte(`{"model":"model-example","stream":true}`)
		var totals, before []time.Duration
		for round := range 9 {
			store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), fmt.Sprintf("m%d.db", round)))
			if err != nil {
				t.Fatal(err)
			}
			timing := &timingStore{Store: store}
			// A stage budget above the body keeps the body in memory.
			manager := newTestManager(t, timing, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)),
				Options{StageBytes: 16 << 20, GlobalBytes: 64 << 20})
			session := driveStream(t, manager, request, response)
			started := time.Now()
			if err := session.Finish(); err != nil {
				t.Fatal(err)
			}
			totals = append(totals, time.Since(started))
			before = append(before, timing.firstWrite.Sub(started))
			_ = store.Close()
		}
		t.Logf("%d MiB stream: Finish median %v (before first write %v)", size>>20, median(totals), median(before))
	}
}

func median(values []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	return sorted[len(sorted)/2]
}

// driveStream runs one request as the proxy does, up to (not including)
// Finish.
func driveStream(t *testing.T, manager *Manager, request, response []byte) *Session {
	t.Helper()
	ctx := context.Background()
	inbound := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", bytes.NewReader(request))
	inbound.Header.Set("Content-Type", "application/json")
	session, err := manager.Begin(ctx, inbound, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	outbound := inbound.Clone(ctx)
	outbound.Body = inbound.Body
	outbound.Host = "newapi.example.com"
	session.WrapRequestSent(outbound)
	_, _ = io.Copy(io.Discard, outbound.Body)
	_ = outbound.Body.Close()
	upstream := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", ContentLength: -1, Request: outbound,
		Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(bytes.NewReader(response))}
	session.WrapResponseReceived(upstream)
	writer := session.WrapResponseWriter(httptest.NewRecorder(), inbound)
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.WriteHeader(200)
	buffer := make([]byte, 32<<10)
	for {
		count, err := upstream.Body.Read(buffer)
		if count > 0 {
			_, _ = writer.Write(buffer[:count])
		}
		if err != nil {
			break
		}
	}
	writer.CaptureTrailers()
	if strings.Contains(session.ID(), " ") {
		t.Fatal("unexpected id")
	}
	return session
}
