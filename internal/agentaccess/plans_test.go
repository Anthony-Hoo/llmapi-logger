package agentaccess

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

func codeOf(t *testing.T, err error) agentapi.Code {
	t.Helper()
	if err == nil {
		return ""
	}
	return CodeOf(err)
}

func TestPlanStoreSingleUseOwnerAndExpiry(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)}
	store := NewPlanStore(clock.Now, nil)
	plan, err := store.Put(1, "payload")
	if err != nil || !strings.HasPrefix(plan.ID, "pln_") || !plan.ExpiresAt.Equal(clock.Now().Add(PlanLifetime)) {
		t.Fatalf("put = %+v, %v", plan, err)
	}
	// Another token cannot see it, and asking does not consume it.
	if _, err := store.Take(2, plan.ID); codeOf(t, err) != agentapi.CodePlanNotFound {
		t.Fatalf("foreign take = %v", err)
	}
	if !ValidPlanID(plan.ID) || ValidPlanID("pln_x") || ValidPlanID(plan.ID+"=") || ValidPlanID("abc_"+plan.ID[4:]) {
		t.Fatalf("plan id shape check fails for %q", plan.ID)
	}
	taken, err := store.Take(1, plan.ID)
	if err != nil || taken.Payload != "payload" {
		t.Fatalf("take = %+v, %v", taken, err)
	}
	if _, err := store.Take(1, plan.ID); codeOf(t, err) != agentapi.CodePlanNotFound {
		t.Fatalf("second take = %v", err)
	}

	expiring, _ := store.Put(1, "late")
	clock.Advance(PlanLifetime)
	if _, err := store.Take(2, expiring.ID); codeOf(t, err) != agentapi.CodePlanNotFound {
		t.Fatalf("foreign expired take = %v", err)
	}
	if _, err := store.Take(1, expiring.ID); codeOf(t, err) != agentapi.CodePlanExpired {
		t.Fatalf("expired take = %v", err)
	}
	if _, err := store.Take(1, expiring.ID); codeOf(t, err) != agentapi.CodePlanNotFound {
		t.Fatalf("expired plan is gone after one answer, got %v", err)
	}
}

func TestPlanStoreIsBounded(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)}
	store := NewPlanStore(clock.Now, nil)
	for range MaxPlans {
		if _, err := store.Put(1, nil); err != nil {
			t.Fatal(err)
		}
	}
	var coded *Error
	if _, err := store.Put(1, nil); !errors.As(err, &coded) || coded.Code != agentapi.CodeRateLimited || coded.RetryAfter <= 0 {
		t.Fatalf("full store = %v", err)
	}
	clock.Advance(PlanLifetime)
	if _, err := store.Put(1, nil); err != nil {
		t.Fatalf("expired plans make room: %v", err)
	}
	clock.Advance(planRetention)
	if _, err := store.Put(1, nil); err != nil || store.Len() > 2 {
		t.Fatalf("sweep left %d plans (%v)", store.Len(), err)
	}
}

func newQuotaService(t *testing.T, clock *testClock) *Service {
	t.Helper()
	service, err := New(Options{AdminToken: "admin-token-for-quota-tests", Store: &auditStore{}, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// auditStore records audit rows; the other methods are unused here.
type auditStore struct {
	Store
	mu      sync.Mutex
	entries []storage.AgentAuditEntry
}

func (store *auditStore) InsertAgentAudit(_ context.Context, entry storage.AgentAuditEntry) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries = append(store.entries, entry)
	return nil
}

func TestQuotasFollowTheContract(t *testing.T) {
	cases := []struct {
		quota  Quota
		limit  int
		window time.Duration
		global bool
	}{
		{QuotaRead, 120, time.Minute, false},
		{QuotaSensitiveRead, 20, time.Minute, false},
		{QuotaWrite, 60, 10 * time.Minute, false},
		{QuotaAnalysisRun, 1, 10 * time.Minute, true},
		{QuotaRegenerate, 6, time.Hour, true},
		{QuotaTestModel, 12, time.Hour, false},
		{QuotaDeniedAudit, 60, 10 * time.Minute, false},
	}
	for _, test := range cases {
		clock := &testClock{now: time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)}
		service := newQuotaService(t, clock)
		first, second := Identity{TokenID: 1}, Identity{TokenID: 2}
		for index := 0; index < test.limit; index++ {
			if err := service.Take(test.quota, first); err != nil {
				t.Fatalf("quota %d event %d: %v", test.quota, index, err)
			}
		}
		var coded *Error
		if err := service.Take(test.quota, first); !errors.As(err, &coded) || coded.Code != agentapi.CodeRateLimited || coded.RetryAfter != test.window {
			t.Fatalf("quota %d over the limit = %v", test.quota, err)
		}
		err := service.Take(test.quota, second)
		if test.global && codeOf(t, err) != agentapi.CodeRateLimited {
			t.Fatalf("global quota %d admitted another token", test.quota)
		}
		if !test.global && err != nil {
			t.Fatalf("per-token quota %d refused another token: %v", test.quota, err)
		}
		clock.Advance(test.window - time.Second)
		if codeOf(t, service.Take(test.quota, first)) != agentapi.CodeRateLimited {
			t.Fatalf("quota %d reopened early", test.quota)
		}
		clock.Advance(time.Second)
		if err := service.Take(test.quota, first); err != nil {
			t.Fatalf("quota %d did not reopen: %v", test.quota, err)
		}
	}
}

func TestRecordWriteKeepsKeyNamesOnly(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)}
	store := &auditStore{}
	service, err := New(Options{AdminToken: "admin-token-for-quota-tests", Store: store, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{TokenID: 9, Role: agentapi.RoleAdmin, Tier: agentapi.TierWrite}
	service.RecordWrite(context.Background(), identity, RequestMeta{Command: "apply", CLIVersion: "1.0.0"}, WriteAudit{
		Event: EventWriteApplied, ObjectKind: "content-rule", ObjectID: "12", ChangedKeys: []string{"enabled", "keywords"}, Outcome: OutcomeOK,
	})
	service.RecordWrite(context.Background(), identity, RequestMeta{}, WriteAudit{
		Event: EventWriteFailed, ObjectKind: "content-rule", ObjectID: "12", Outcome: OutcomeFailed, ErrorCode: agentapi.CodeVersionConflict,
	})
	if len(store.entries) != 2 {
		t.Fatalf("rows = %d", len(store.entries))
	}
	applied, failed := store.entries[0], store.entries[1]
	if applied.Event != EventWriteApplied || applied.ChangedKeys != `["enabled","keywords"]` || applied.ObjectKind != "content-rule" ||
		applied.ObjectID != "12" || applied.TokenID == nil || *applied.TokenID != 9 || applied.Role != "admin" || applied.Command != "apply" {
		t.Fatalf("applied row = %+v", applied)
	}
	if failed.ChangedKeys != "" || failed.ErrorCode != "VERSION_CONFLICT" || failed.Outcome != OutcomeFailed {
		t.Fatalf("failed row = %+v", failed)
	}
}
