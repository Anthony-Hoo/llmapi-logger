package audit

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
)

type noUnifiedStore struct{ Store }

func (noUnifiedStore) SupportsUnifiedWrite() bool { return false }

func optionsCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(make([]byte, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// NewManager builds a manager on the unified write path, the only one: a
// session writes its start row with the inbound stage and one commit, and
// never a per-operation write (commitStore panics on those).
func TestNewManagerWritesThroughTheUnifiedPath(t *testing.T) {
	store := &commitStore{}
	manager, err := NewManager(store, optionsCipher(t), nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if manager.CommitRetries() != 0 {
		t.Fatalf("retries %d", manager.CommitRetries())
	}
	request := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions", strings.NewReader(`{"model":"model-example"}`))
	session, err := manager.Begin(context.Background(), request, routing.Match{RouteID: "chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, request.Body)
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(store.begins) != 1 || store.begins[0].Inbound == nil || len(store.commits) != 1 {
		t.Fatalf("%d begins (inbound %v), %d commits", len(store.begins), len(store.begins) == 1 && store.begins[0].Inbound != nil, len(store.commits))
	}
}

func TestManagerRefusesAStoreThatCannotServeTheWritePath(t *testing.T) {
	_, err := NewManagerWithOptions(noUnifiedStore{}, optionsCipher(t), nil, ModeStrict, nil, Options{CommitRetries: 3})
	if err == nil || !strings.Contains(err.Error(), "cannot serve") {
		t.Fatalf("error = %v", err)
	}
}

func TestManagerOptionsValidation(t *testing.T) {
	for _, options := range []Options{
		{CommitRetries: -1},
		{CommitRetries: 6},
		{StageBytes: 1<<20 - 1},
		{StageBytes: 4 << 20, GlobalBytes: 2 << 20},
	} {
		if _, err := NewManagerWithOptions(&commitStore{}, optionsCipher(t), nil, ModeAvailable, nil, options); err == nil {
			t.Fatalf("options %+v accepted", options)
		}
	}
}

func TestSetCommitRetriesClamps(t *testing.T) {
	manager, err := NewManagerWithOptions(&commitStore{}, optionsCipher(t), nil, ModeAvailable, nil, Options{CommitRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if manager.CommitRetries() != 2 {
		t.Fatalf("retries = %d", manager.CommitRetries())
	}
	for value, want := range map[int]int{0: 0, 5: 5, -3: 0, 9: 5, 4: 4} {
		manager.SetCommitRetries(value)
		if manager.CommitRetries() != want {
			t.Fatalf("SetCommitRetries(%d) = %d, want %d", value, manager.CommitRetries(), want)
		}
	}
}
