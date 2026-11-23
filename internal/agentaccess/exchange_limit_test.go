package agentaccess_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// exchangeGate holds the writes a failing exchange makes (its
// token_exchange_failed audit row, or the revocation of a replayed code's
// token) until release is closed, and signals each arrival. Other writes
// (approvals, issued tokens) pass straight through.
type exchangeGate struct {
	*agentaccesstest.Store
	mu          sync.Mutex
	holdAudit   bool
	holdRevoke  bool
	arrived     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func newExchangeGate() *exchangeGate {
	return &exchangeGate{Store: agentaccesstest.NewStore(), arrived: make(chan struct{}, 256), release: make(chan struct{})}
}

func (gate *exchangeGate) open() { gate.releaseOnce.Do(func() { close(gate.release) }) }

func (gate *exchangeGate) hold(audit, revoke bool) {
	gate.mu.Lock()
	gate.holdAudit, gate.holdRevoke = audit, revoke
	gate.mu.Unlock()
}

func (gate *exchangeGate) wait(held bool) {
	if held {
		gate.arrived <- struct{}{}
		<-gate.release
	}
}

func (gate *exchangeGate) InsertAgentAudit(ctx context.Context, entry storage.AgentAuditEntry) error {
	gate.mu.Lock()
	held := gate.holdAudit && entry.Event == agentaccess.EventTokenExchangeFailed
	gate.mu.Unlock()
	gate.wait(held)
	return gate.Store.InsertAgentAudit(ctx, entry)
}

func (gate *exchangeGate) RevokeAgentToken(ctx context.Context, id, atNS int64, scope *storage.AgentTokenScope) (bool, error) {
	gate.mu.Lock()
	held := gate.holdRevoke
	gate.mu.Unlock()
	gate.wait(held)
	return gate.Store.RevokeAgentToken(ctx, id, atNS, scope)
}

func exchangeFailures(store *exchangeGate) int {
	failures := 0
	for _, entry := range store.Audit() {
		if entry.Event == agentaccess.EventTokenExchangeFailed {
			failures++
		}
	}
	return failures
}

// burstExchange starts attempts concurrent exchanges of code from source,
// waits until exactly held of them are held inside the gate and the rest
// have answered, and returns the codes of the rest. It fails (instead of
// hanging) when more than held attempts get past the limiter.
func burstExchange(t *testing.T, service *agentaccess.Service, gate *exchangeGate, code, source string, attempts, held int) (refused []error, finish func() []agentapi.Code) {
	t.Helper()
	t.Cleanup(gate.open)
	results := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := service.Exchange(context.Background(), code, agentaccesstest.Verifier, source, agentaccess.RequestMeta{})
			results <- err
		}()
	}
	timeout := time.After(10 * time.Second)
	arrived := 0
	for arrived < held || len(refused) < attempts-held {
		select {
		case <-gate.arrived:
			arrived++
			if arrived > held {
				t.Fatalf("%d attempts got past the limiter, want at most %d", arrived, held)
			}
		case err := <-results:
			refused = append(refused, err)
			if len(refused) > attempts-held {
				t.Fatalf("%d attempts answered while %d should be held: %v", len(refused), held, err)
			}
		case <-timeout:
			t.Fatalf("burst: %d attempts held, %d answered; want %d held and %d answered", arrived, len(refused), held, attempts-held)
		}
	}
	return refused, func() []agentapi.Code {
		gate.open()
		group.Wait()
		close(results)
		var codes []agentapi.Code
		for err := range results {
			codes = append(codes, codeOf(err))
		}
		return codes
	}
}

// requireCapRefusals checks that every refused attempt of a burst was
// refused by the in-flight cap: RATE_LIMITED with the limiter's short wait.
func requireCapRefusals(t *testing.T, refused []error) {
	t.Helper()
	for _, err := range refused {
		var coded *agentaccess.Error
		if codeOf(err) != agentapi.CodeRateLimited || !asError(err, &coded) || coded.RetryAfter != time.Second {
			t.Fatalf("attempt beyond the in-flight cap = %v", err)
		}
	}
}

// Contract section 0.1 item 186: a burst of failing exchanges from one
// address cannot all pass the failure check before the first of them is
// counted. With the address one failure short of the limit, a burst of forty
// unknown codes lets exactly exchangeInFlightCap of them in; the rest are
// refused by the in-flight cap without writing an audit row, and once the
// admitted ones have failed the address is refused for the window. At most
// limit + cap failure rows are written.
func TestExchangeFailureBurstIsBoundedByTheInFlightCap(t *testing.T) {
	const source, attempts = "203.0.113.30", 40
	limit, inFlight := agentaccess.ExchangeFailureLimit, agentaccess.ExchangeInFlightCap
	gate := newExchangeGate()
	h := newHarnessWithStore(t, gate, &clock{now: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)})
	unknown := strings.Repeat("B", 43)
	for range limit - 1 {
		if _, err := h.service.Exchange(context.Background(), unknown, agentaccesstest.Verifier, source, agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("sequential failure = %v", err)
		}
	}
	gate.hold(true, false)
	refused, finish := burstExchange(t, h.service, gate, unknown, source, attempts, inFlight)
	requireCapRefusals(t, refused)
	if failures := exchangeFailures(gate); failures != limit-1 {
		t.Fatalf("a refused attempt wrote a failure row: %d rows", failures)
	}
	for _, code := range finish() {
		if code != agentapi.CodeInvalidGrant {
			t.Fatalf("admitted attempt = %s", code)
		}
	}
	if failures := exchangeFailures(gate); failures != limit-1+inFlight || failures > limit+inFlight {
		t.Fatalf("failure rows = %d, want %d (at most %d)", failures, limit-1+inFlight, limit+inFlight)
	}
	// The failures are counted now: the window refuses with its own wait.
	_, err := h.service.Exchange(context.Background(), unknown, agentaccesstest.Verifier, source, agentaccess.RequestMeta{})
	var coded *agentaccess.Error
	if codeOf(err) != agentapi.CodeRateLimited || !asError(err, &coded) || coded.RetryAfter <= time.Second {
		t.Fatalf("attempt after the burst = %v", err)
	}
	if failures := exchangeFailures(gate); failures != limit-1+inFlight {
		t.Fatalf("the limited attempt wrote a failure row: %d rows", failures)
	}
}

// A burst of replays of one redeemed code from one address reaches the
// revocation path (a store write per attempt) at most exchangeInFlightCap
// times; the rest are refused before they touch the code (item 186).
func TestExchangeReplayBurstIsBoundedByTheInFlightCap(t *testing.T) {
	const source, attempts = "203.0.113.31", 40
	inFlight := agentaccess.ExchangeInFlightCap
	gate := newExchangeGate()
	h := newHarnessWithStore(t, gate, &clock{now: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)})
	authorization := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	if _, err := h.service.Exchange(context.Background(), authorization.Code, agentaccesstest.Verifier, "198.51.100.31", agentaccess.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	gate.hold(false, true)
	refused, finish := burstExchange(t, h.service, gate, authorization.Code, source, attempts, inFlight)
	requireCapRefusals(t, refused)
	for _, code := range finish() {
		if code != agentapi.CodeInvalidGrant {
			t.Fatalf("admitted replay = %s", code)
		}
	}
	if revocations := gate.RevokeAttemptCount(); revocations != inFlight {
		t.Fatalf("revocation attempts = %d, want %d", revocations, inFlight)
	}
	if failures := exchangeFailures(gate); failures != inFlight {
		t.Fatalf("failure rows = %d, want %d", failures, inFlight)
	}
	if tokens := gate.Tokens(); len(tokens) != 1 || tokens[0].RevokedAtNS == nil {
		t.Fatalf("token after the replays = %+v", tokens)
	}
}

// The in-flight cap changes nothing for one client at a time: a login (approve
// then exchange) works, and sequential failures hit the documented limit
// exactly, each with its own failure row.
func TestExchangeSequentialFailuresHitTheLimitExactly(t *testing.T) {
	ctx := context.Background()
	const source = "203.0.113.32"
	limit := agentaccess.ExchangeFailureLimit
	gate := newExchangeGate()
	h := newHarnessWithStore(t, gate, &clock{now: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)})
	login := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	if issued, err := h.service.Exchange(ctx, login.Code, agentaccesstest.Verifier, source, agentaccess.RequestMeta{}); err != nil || issued.Token == "" {
		t.Fatalf("login = %+v, %v", issued, err)
	}
	for attempt := range limit {
		if _, err := h.service.Exchange(ctx, strings.Repeat("C", 43), agentaccesstest.Verifier, source, agentaccess.RequestMeta{}); codeOf(err) != agentapi.CodeInvalidGrant {
			t.Fatalf("failure %d = %v", attempt+1, err)
		}
	}
	if failures := exchangeFailures(gate); failures != limit {
		t.Fatalf("failure rows = %d, want %d", failures, limit)
	}
	next := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	_, err := h.service.Exchange(ctx, next.Code, agentaccesstest.Verifier, source, agentaccess.RequestMeta{})
	var coded *agentaccess.Error
	if codeOf(err) != agentapi.CodeRateLimited || !asError(err, &coded) || coded.RetryAfter <= time.Second {
		t.Fatalf("exchange after %d failures = %v", limit, err)
	}
	if failures := exchangeFailures(gate); failures != limit {
		t.Fatalf("the limited attempt wrote a failure row: %d rows", failures)
	}
	h.clock.Advance(5*time.Minute + time.Second)
	later := approve(t, h, agentapi.TierRead, agentaccess.ModeLoopback)
	if _, err := h.service.Exchange(ctx, later.Code, agentaccesstest.Verifier, source, agentaccess.RequestMeta{}); err != nil {
		t.Fatalf("login after the window = %v", err)
	}
}

// newHarnessWithStore is newHarness over a store that wraps the in-memory one.
func newHarnessWithStore(t *testing.T, store *exchangeGate, c *clock) harness {
	t.Helper()
	service, err := agentaccess.New(agentaccess.Options{
		AdminToken: testAdminToken, Store: store, AllowWrite: true, DeveloperLogins: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return harness{service: service, store: store.Store, clock: c}
}
