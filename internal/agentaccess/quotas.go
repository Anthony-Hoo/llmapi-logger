package agentaccess

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Quota is one of the per-token or global limits of contract section 7 that
// apply to authenticated facade requests.
type Quota int

const (
	// QuotaRead: every read-tier request of a token except logout.
	QuotaRead Quota = iota
	// QuotaSensitiveRead: input pack and facet reads of a token, counted in
	// addition to QuotaRead.
	QuotaSensitiveRead
	// QuotaWrite: plan creation, plan execution and setting or clearing the
	// model key, per token.
	QuotaWrite
	// QuotaAnalysisRun: executions of analysis.run, for the whole process.
	QuotaAnalysisRun
	// QuotaRegenerate: executions of weekly.regenerate, for the whole
	// process.
	QuotaRegenerate
	// QuotaTestModel: connection tests of a token.
	QuotaTestModel
	// QuotaDeniedAudit bounds the write_denied rows one token can cause: a
	// refused request is not counted by the write limits, and without it a
	// token without write rights could add rows at the request rate.
	QuotaDeniedAudit
)

// Quota sizes (contract section 7). They are implementation constants, not
// configuration.
var quotaSizes = map[Quota]struct {
	limit  int
	window time.Duration
	global bool
}{
	QuotaRead:          {120, time.Minute, false},
	QuotaSensitiveRead: {20, time.Minute, false},
	QuotaWrite:         {60, 10 * time.Minute, false},
	QuotaAnalysisRun:   {1, 10 * time.Minute, true},
	QuotaRegenerate:    {6, time.Hour, true},
	QuotaTestModel:     {12, time.Hour, false},
	QuotaDeniedAudit:   {60, 10 * time.Minute, false},
}

func newQuotaLimiters(now func() time.Time) map[Quota]*windowLimiter {
	limiters := make(map[Quota]*windowLimiter, len(quotaSizes))
	for quota, size := range quotaSizes {
		limiters[quota] = newWindowLimiter(size.limit, size.window, now)
	}
	return limiters
}

// Take counts one event against quota for the calling token and refuses it
// with RATE_LIMITED (and the wait) when the window is full. A refused event is
// not counted.
func (service *Service) Take(quota Quota, identity Identity) error {
	limiter, ok := service.quotas[quota]
	if !ok {
		return fail(agentapi.CodeInternal)
	}
	key := "global"
	if !quotaSizes[quota].global {
		key = strconv.FormatInt(identity.TokenID, 10)
	}
	if allowed, wait := limiter.take(key); !allowed {
		return &Error{Code: agentapi.CodeRateLimited, RetryAfter: wait}
	}
	return nil
}

// WriteAudit describes one write_applied, write_failed or write_denied row.
// ChangedKeys are key names only; nothing in it may be a written value.
type WriteAudit struct {
	Event       string
	ObjectKind  string
	ObjectID    string
	ChangedKeys []string
	Outcome     string
	ErrorCode   agentapi.Code
}

// RecordWrite appends a write audit row for the calling token. Like
// RecordAudit it never fails the caller.
func (service *Service) RecordWrite(ctx context.Context, identity Identity, meta RequestMeta, write WriteAudit) {
	entry := auditFor(identity, meta, write.Event, write.Outcome)
	entry.ObjectKind, entry.ObjectID = write.ObjectKind, write.ObjectID
	if write.ChangedKeys != nil {
		encoded, err := json.Marshal(write.ChangedKeys)
		if err == nil {
			entry.ChangedKeys = string(encoded)
		}
	}
	entry.ErrorCode = string(write.ErrorCode)
	service.RecordAudit(ctx, entry)
}

// storage outcome names, re-exported for callers of RecordWrite.
const (
	OutcomeOK     = storage.AgentOutcomeOK
	OutcomeDenied = storage.AgentOutcomeDenied
	OutcomeFailed = storage.AgentOutcomeFailed
)
