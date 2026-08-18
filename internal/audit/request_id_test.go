package audit

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestSessionPersistsNewAPIRequestIDAndNotifiesCallerWorker(t *testing.T) {
	t.Parallel()
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan string, 1)
	manager.SetCallerNotifier(func(auditID string) bool {
		notified <- auditID
		return true
	})

	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	session, err := manager.Begin(context.Background(), request, routing.Match{
		RouteID: "chat", Parser: "openai.chat_completions",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{
		StatusCode: http.StatusOK, Proto: "HTTP/1.1", Header: make(http.Header),
		Body: http.NoBody, ContentLength: 0,
	}
	response.Header.Set(newAPIRequestIDHeader, "req-caller")
	session.WrapResponseReceived(response)
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	select {
	case auditID := <-notified:
		if auditID != session.ID() {
			t.Fatalf("notified audit = %q", auditID)
		}
	default:
		t.Fatal("caller worker was not notified")
	}
	snapshot, err := store.Snapshot(context.Background(), session.ID())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.NewAPIRequestID == nil || *snapshot.Audit.NewAPIRequestID != "req-caller" ||
		snapshot.Audit.CallerStatus != sqlite.CallerPending {
		t.Fatalf("audit caller state = %+v", snapshot.Audit)
	}
}

func TestSessionIgnoresInvalidNewAPIRequestID(t *testing.T) {
	t.Parallel()
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, _ := security.NewAESGCM(make([]byte, 32))
	manager, _ := NewManager(store, cipher, nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	session, err := manager.Begin(context.Background(), request, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{newAPIRequestIDHeader: []string{"bad\nvalue"}}, Body: http.NoBody}
	session.WrapResponseReceived(response)
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(context.Background(), session.ID())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Audit.NewAPIRequestID != nil || snapshot.Audit.CallerStatus != sqlite.CallerNone {
		t.Fatalf("invalid request id was persisted: %+v", snapshot.Audit)
	}
}
