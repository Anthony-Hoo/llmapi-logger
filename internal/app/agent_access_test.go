package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentdist"
	"llmapi-logger/internal/web"
)

func TestAgentAccessIsUnassembledWhenDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	application, err := newSQLiteTest(insightsTestConfig(t, upstream.URL, true, ""), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	for _, path := range []string{"/api/agent/v1/whoami", "/api/agent/v1/token"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer app-test-admin-token")
		response := httptest.NewRecorder()
		application.adminServer.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "FEATURE_DISABLED") {
			t.Fatalf("disabled %s = %d %s", path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent-access/tokens", nil)
	request.Header.Set("Authorization", "Bearer app-test-admin-token")
	response := httptest.NewRecorder()
	application.adminServer.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled web-side route = %d", response.Code)
	}
}

// Contract 0.1 #11: an available-mode start without a database leaves the
// module unassembled with a warning instead of failing the process.
func TestEnabledAgentAccessWithoutAStoreStaysOff(t *testing.T) {
	logs := &bytes.Buffer{}
	configuration := insightsTestConfig(t, "http://192.0.2.1:3000", true, "")
	configuration.AgentAccess.Enabled = true
	service, err := assembleAgentAccess(configuration, nil, web.DeveloperLogin{}, slog.New(slog.NewTextHandler(logs, nil)))
	if service != nil || err != nil {
		t.Fatalf("assemble without a store = %v, %v", service, err)
	}
	if !strings.Contains(logs.String(), "agent_access_unavailable") {
		t.Fatalf("no warning logged: %q", logs.String())
	}
	configuration.AgentAccess.Enabled = false
	if service, err := assembleAgentAccess(configuration, nil, web.DeveloperLogin{}, slog.New(slog.NewTextHandler(io.Discard, nil))); service != nil || err != nil {
		t.Fatalf("disabled assemble = %v, %v", service, err)
	}
}

func TestEnabledAgentAccessRefusesAStoreWithoutAgentSupport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	configuration := insightsTestConfig(t, upstream.URL, true, "")
	configuration.AgentAccess.Enabled = true
	application, err := newSQLiteTest(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if application != nil {
		_ = application.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "agent access") {
		t.Fatalf("New with the legacy test store = %v, want an agent access error", err)
	}
}

// closeProbeStore is the audit store of an App built by hand: only Close is
// ever called on it (closeComponents), and onClose runs inside it.
type closeProbeStore struct {
	runtimeStore
	closes  int
	onClose func()
}

func (store *closeProbeStore) Close() error {
	store.closes++
	if store.onClose != nil {
		store.onClose()
	}
	return nil
}

// syncLog is a log destination the agent service's background goroutine and
// the test read and write at once.
type syncLog struct {
	mu   sync.Mutex
	text bytes.Buffer
}

func (log *syncLog) Write(data []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.text.Write(data)
}

func (log *syncLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.text.String()
}

// Contract section 0.1 items 127 and 156: closing the application stops the
// agent service's background revocation retry before the store closes, and
// no revocation is attempted afterwards; closing twice, or an application
// without agent access, is safe.
func TestClosingTheAppStopsTheAgentRevocationRetryBeforeTheStore(t *testing.T) {
	ctx := context.Background()
	logs := &syncLog{}
	tokens := agentaccesstest.NewStore()
	service, err := agentaccess.New(agentaccess.Options{AdminToken: "app-test-admin-token", Store: tokens, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	authorization, err := service.Approve(ctx, agentaccess.Grantor{Role: agentapi.RoleAdmin}, agentaccesstest.Request(agentapi.TierRead), "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.90", agentaccess.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	// A replay whose revocation keeps failing hands it to the background.
	tokens.SetFailRevokeTimes(1 << 30)
	if _, err := service.Exchange(ctx, authorization.Code, agentaccesstest.Verifier, "192.0.2.91", agentaccess.RequestMeta{}); err == nil {
		t.Fatal("a replayed code was exchanged")
	}
	if !strings.Contains(logs.String(), "retrying in the background") {
		t.Fatalf("no background retry started: %s", logs.String())
	}

	stopped := -1
	store := &closeProbeStore{onClose: func() {
		// The retry has already ended when the store closes.
		if !strings.Contains(logs.String(), "outcome=service_stopped") {
			t.Errorf("the store closed while the revocation retry was running: %s", logs.String())
		}
		stopped = tokens.RevokeAttemptCount()
	}}
	application := &App{agentAccess: service, auditStore: store}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	if err := application.Close(); err != nil || store.closes != 1 {
		t.Fatalf("second Close = %v, store closed %d times", err, store.closes)
	}
	// Longer than the retry's first wait (400 ms): nothing more is tried.
	time.Sleep(time.Second)
	if stopped < 0 || tokens.RevokeAttemptCount() != stopped {
		t.Fatalf("revocation attempts: %d when the store closed, %d now", stopped, tokens.RevokeAttemptCount())
	}

	// Without agent access (not enabled, or no database) Close works too.
	bare := &closeProbeStore{}
	unassembled := &App{auditStore: bare}
	if err := unassembled.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unassembled.Close(); err != nil || bare.closes != 1 {
		t.Fatalf("unassembled second Close = %v, store closed %d times", err, bare.closes)
	}
	if err := (&App{}).Close(); err != nil {
		t.Fatal(err)
	}
}

// A deployment without packages still starts: one warning with a stable
// code, and a service whose endpoints answer that no packages ship here. No
// agent access means no distribution service at all.
func TestAgentDistWithoutPackagesWarnsAndStarts(t *testing.T) {
	configuration := insightsTestConfig(t, "http://192.0.2.1:3000", true, "")
	configuration.AgentAccess.Enabled = true
	if service := assembleAgentDist(configuration, nil, "", slog.New(slog.NewTextHandler(io.Discard, nil))); service != nil {
		t.Fatal("distribution assembled without agent access")
	}
	agent, err := agentaccess.New(agentaccess.Options{AdminToken: configuration.AdminToken, Store: agentaccesstest.NewStore()})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	service := assembleAgentDist(configuration, agent, filepath.Join(t.TempDir(), agentdist.PackageDirName), slog.New(slog.NewTextHandler(logs, nil)))
	if service == nil || !errors.Is(service.LoadError(), agentdist.ErrNoPackages) {
		t.Fatalf("service %v, load error %v", service, service.LoadError())
	}
	if strings.Count(logs.String(), "agent_packages_unavailable") != 1 || strings.Contains(logs.String(), configuration.AdminToken) {
		t.Fatalf("warning log = %q", logs.String())
	}
	// The default directory is next to the executable.
	logs.Reset()
	if service := assembleAgentDist(configuration, agent, "", slog.New(slog.NewTextHandler(logs, nil))); service == nil {
		t.Fatal("no service for the default directory")
	} else if want, _ := agentdist.DefaultPackageDir(); service.PackageDir() != want {
		t.Fatalf("package dir %q, want %q", service.PackageDir(), want)
	}
}
