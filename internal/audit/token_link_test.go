package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestTokenLinkFailureDoesNotBlockAuditAdmission(t *testing.T) {
	t.Parallel()

	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	failingStore := &tokenLinkFailStore{Store: store}
	manager, err := NewManager(
		failingStore,
		cipher,
		ModeAvailable,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetTokenResolver(staticTokenResolver{})

	request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
	request.Header.Set("Authorization", "Bearer raw-client-key")
	session, err := manager.Begin(context.Background(), request, routing.Match{
		RouteID: "chat",
		Parser:  "openai.chat_completions",
	})
	if err != nil || session == nil {
		t.Fatalf("Begin() session=%v error=%v", session, err)
	}
	if failingStore.calls.Load() != 1 {
		t.Fatalf("token link writes = %d, want 1", failingStore.calls.Load())
	}
	session.MarkRejected(http.StatusBadRequest, "test", "test_rejection")
	if err := session.Finish(); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
}

type tokenLinkFailStore struct {
	*sqlite.Store
	calls atomic.Int32
}

func (store *tokenLinkFailStore) UpsertTokenLink(context.Context, sqlite.TokenLink) error {
	store.calls.Add(1)
	return errors.New("synthetic token link failure")
}

type staticTokenResolver struct{}

func (staticTokenResolver) ResolveToken(*http.Request) (TokenMetadata, bool) {
	return TokenMetadata{ID: 42, Name: "personal", MaskedKey: "abcd**********wxyz"}, true
}
