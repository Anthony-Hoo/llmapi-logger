package agentaccess

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"
	"time"

	"llmapi-logger/internal/agentapi"
)

// Plans of the write facade (contract section 4.5.1). A plan is created by
// POST /plans after full validation and executed once by POST
// /plans/{plan_id}/apply. It lives in process memory, is bound to the token
// that created it and expires after PlanLifetime; a restart drops every plan.
// The store does not know what a plan does: Payload is the caller's.

// Plan limits.
const (
	// PlanLifetime is how long a plan can be applied.
	PlanLifetime = 10 * time.Minute
	// planRetention keeps an expired plan this much longer, so applying it
	// says PLAN_EXPIRED rather than PLAN_NOT_FOUND.
	planRetention = 10 * time.Minute
	// MaxPlans bounds the plans held at once across all tokens. The write
	// limit (60 per token in 10 minutes) bounds one token far below it.
	MaxPlans     = 1024
	planIDPrefix = "pln_"
	planIDBytes  = 16
)

// ValidPlanID reports whether id has the shape of a plan id: the prefix and
// 16 random bytes in unpadded base64url. Only such a value is recorded in an
// audit row; anything else in the path is a client's text.
func ValidPlanID(id string) bool {
	if len(id) != len(planIDPrefix)+22 || id[:len(planIDPrefix)] != planIDPrefix {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(id[len(planIDPrefix):])
	return err == nil
}

// Plan is one stored plan.
type Plan struct {
	ID        string
	TokenID   int64
	ExpiresAt time.Time
	Payload   any
}

// PlanStore holds the plans of one process.
type PlanStore struct {
	mu     sync.Mutex
	plans  map[string]*Plan
	now    func() time.Time
	random io.Reader
}

// NewPlanStore returns an empty store. now and random may be nil.
func NewPlanStore(now func() time.Time, random io.Reader) *PlanStore {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &PlanStore{plans: make(map[string]*Plan), now: now, random: random}
}

// Put stores payload as a new plan of tokenID. It fails with RATE_LIMITED
// when MaxPlans live plans are held.
func (store *PlanStore) Put(tokenID int64, payload any) (Plan, error) {
	random := make([]byte, planIDBytes)
	if _, err := io.ReadFull(store.random, random); err != nil {
		return Plan{}, fail(agentapi.CodeInternal)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now()
	store.sweepLocked(now)
	if len(store.plans) >= MaxPlans {
		soonest := now.Add(PlanLifetime)
		for _, plan := range store.plans {
			if plan.ExpiresAt.Before(soonest) {
				soonest = plan.ExpiresAt
			}
		}
		return Plan{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: soonest.Sub(now)}
	}
	plan := &Plan{ID: planIDPrefix + base64.RawURLEncoding.EncodeToString(random), TokenID: tokenID,
		ExpiresAt: now.Add(PlanLifetime), Payload: payload}
	store.plans[plan.ID] = plan
	return *plan, nil
}

// Take removes and returns plan id of tokenID. A plan of another token is
// PLAN_NOT_FOUND and stays where it is (its owner can still apply it); an
// expired plan is removed and PLAN_EXPIRED. Taking is the single use: the
// plan is gone before the caller executes it, so two concurrent applies
// cannot both run it.
func (store *PlanStore) Take(tokenID int64, id string) (Plan, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	plan, ok := store.plans[id]
	if !ok || plan.TokenID != tokenID {
		return Plan{}, fail(agentapi.CodePlanNotFound)
	}
	delete(store.plans, id)
	if !store.now().Before(plan.ExpiresAt) {
		return Plan{}, fail(agentapi.CodePlanExpired)
	}
	return *plan, nil
}

// Len reports the plans held, expired ones not yet swept included.
func (store *PlanStore) Len() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.plans)
}

func (store *PlanStore) sweepLocked(now time.Time) {
	for id, plan := range store.plans {
		if !now.Before(plan.ExpiresAt.Add(planRetention)) {
			delete(store.plans, id)
		}
	}
	if len(store.plans) < MaxPlans {
		return
	}
	// Full of live or recently expired plans: expired ones go first.
	for id, plan := range store.plans {
		if !now.Before(plan.ExpiresAt) {
			delete(store.plans, id)
		}
	}
}
