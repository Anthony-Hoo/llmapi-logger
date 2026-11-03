// Package contentpolicy provides dynamically configurable model-scoped
// keyword rules for matched LLM API requests (doc/features/22-content-policy.md).
//
// The package is deliberately independent of internal/parser and
// internal/storage/sqlite. storage/sqlite imports this package for the Rule
// and Repository types, and parser/storage already form an import chain back
// to internal/interceptor; importing parser helpers here would create a cycle.
package contentpolicy

import (
	"context"
	"errors"
	"net/http"

	"llmapi-logger/internal/interceptor"
)

const (
	// InterceptorID is the stable interceptor instance id used by the engine
	// and by audit blocked_by.
	InterceptorID = "content_policy"
	// BlockCode is the stable audit block code for a keyword rejection.
	BlockCode = "content_policy_blocked"
	// RejectStatusCode mirrors OpenAI's own policy rejection status. The
	// framework maps any explicit 4xx to the fixed request_rejected envelope.
	RejectStatusCode = http.StatusBadRequest

	MaxNameBytes         = 128
	MaxModelPatternBytes = 2048
	MaxKeywords          = 500
	MaxKeywordBytes      = 200
	MaxKeywordsJSONBytes = 64 << 10
	MaxScanScopesJSON    = 512
	// MaxScanBodyBytes bounds the decoded request body handed to the
	// extractor. The interceptor still declares the engine-wide body limit so
	// an ordinary large request is not rejected by the 413 path; the policy
	// simply skips scanning and records a stable log code.
	MaxScanBodyBytes = 8 << 20

	ActionBlock  = "block"
	ActionDryRun = "dry_run"

	ScopeSystem          = "system"
	ScopeLatestUser      = "latest_user"
	ScopeUserHistory     = "user_history"
	ScopeAssistant       = "assistant"
	ScopeToolCalls       = "tool_calls"
	ScopeToolResults     = "tool_results"
	ScopeToolDefinitions = "tool_definitions"
)

// AllScanScopes lists the supported scan classes in UI order. A new rule
// defaults to every class; the owner can narrow it per rule.
var AllScanScopes = []string{
	ScopeSystem,
	ScopeLatestUser,
	ScopeUserHistory,
	ScopeAssistant,
	ScopeToolCalls,
	ScopeToolResults,
	ScopeToolDefinitions,
}

var (
	// ErrInvalidRule is returned for any rule that fails validation or
	// compilation. The management API maps it to 400 invalid_rule without
	// echoing the submitted content.
	ErrInvalidRule = errors.New("invalid content policy rule")
	// ErrNotFound is returned by update/delete when the id does not exist.
	ErrNotFound = errors.New("content policy rule not found")
)

// Rule is the persisted and public representation of one content policy.
// ScanScopes and Keywords are JSON arrays in the database.
type Rule struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Action       string   `json:"action"`
	ModelPattern string   `json:"model_pattern"`
	ScanScopes   []string `json:"scan_scopes"`
	Keywords     []string `json:"keywords"`
	CreatedAtNS  int64    `json:"created_at_ns,string"`
	UpdatedAtNS  int64    `json:"updated_at_ns,string"`
}

// RuleInput is accepted by create and update. Its zero values are normalized
// by the service: empty Action becomes block, empty ScanScopes become all
// scopes.
type RuleInput struct {
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Action       string   `json:"action"`
	ModelPattern string   `json:"model_pattern"`
	ScanScopes   []string `json:"scan_scopes"`
	Keywords     []string `json:"keywords"`
}

// Repository persists rules in the same local database as audit evidence.
type Repository interface {
	ListContentPolicyRules(context.Context) ([]Rule, error)
	CreateContentPolicyRule(context.Context, Rule) (Rule, error)
	UpdateContentPolicyRule(context.Context, Rule) (Rule, error)
	DeleteContentPolicyRule(context.Context, int64) error
}

// RuleSet is the stable surface shared by the data-plane interceptor and the
// authenticated management API.
type RuleSet interface {
	interceptor.Interceptor
	List() []Rule
	Create(context.Context, RuleInput) (Rule, error)
	Update(context.Context, int64, RuleInput) (Rule, error)
	Delete(context.Context, int64) error
}

// DefaultScanScopes returns a copy of every supported scope.
func DefaultScanScopes() []string {
	return append([]string(nil), AllScanScopes...)
}

// ValidAction reports whether action is a supported stable action value.
func ValidAction(action string) bool {
	return action == ActionBlock || action == ActionDryRun
}

// ValidScanScope reports whether scope is a supported scan class.
func ValidScanScope(scope string) bool {
	switch scope {
	case ScopeSystem, ScopeLatestUser, ScopeUserHistory, ScopeAssistant,
		ScopeToolCalls, ScopeToolResults, ScopeToolDefinitions:
		return true
	default:
		return false
	}
}
