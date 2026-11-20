package agentaccess_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// panickingStore panics in the token lookup while panics > 0.
type panickingStore struct {
	*agentaccesstest.Store
	mu     sync.Mutex
	panics int
}

func (store *panickingStore) FindAgentTokenByMAC(ctx context.Context, mac []byte) (storage.AgentToken, error) {
	store.mu.Lock()
	if store.panics > 0 {
		store.panics--
		store.mu.Unlock()
		panic("synthetic store driver panic")
	}
	store.mu.Unlock()
	return store.Store.FindAgentTokenByMAC(ctx, mac)
}

// The in-flight place of a token lookup is released on every path, a panic
// of the store included (net/http recovers a handler's panic, so the server
// keeps running). Before, 32 panics filled the address's in-flight cap for
// good: the place never expires.
func TestLookupPanicReleasesTheInFlightPlace(t *testing.T) {
	store := &panickingStore{Store: agentaccesstest.NewStore()}
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	issued := agentaccesstest.IssueAdmin(t, service, agentapi.TierRead)
	const source = "192.0.2.77"
	store.mu.Lock()
	store.panics = 40
	store.mu.Unlock()
	for range 40 {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("the store's panic did not propagate")
				}
			}()
			_, _ = service.Authenticate(context.Background(), bearer(issued.Token), source)
		}()
	}
	if _, err := service.Authenticate(context.Background(), bearer(issued.Token), source); err != nil {
		t.Fatalf("valid token after 40 store panics = %v", err)
	}
	// Panics are not failures: ten wrong tokens are still allowed before the
	// failure limit.
	for index := range 10 {
		if _, err := service.Authenticate(context.Background(), bearer(agentapi.TokenPrefix+strings.Repeat("A", 43)), source); codeOf(err) != agentapi.CodeUnauthenticated {
			t.Fatalf("wrong token %d = %v", index, err)
		}
	}
}
