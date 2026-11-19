package storage

import "errors"

// Agent access storage types (doc/features/25-agent-access.md section 4).

// ErrAgentTokenNotFound means no token row matches. Callers answer it as an
// unknown token, never as a storage failure.
var ErrAgentTokenNotFound = errors.New("agent token not found")

// Agent token roles and tiers as stored.
const (
	AgentRoleAdmin     = "admin"
	AgentRoleDeveloper = "developer"
	AgentTierRead      = "read"
	AgentTierWrite     = "write"
)

// Agent audit outcomes.
const (
	AgentOutcomeOK     = "ok"
	AgentOutcomeDenied = "denied"
	AgentOutcomeFailed = "failed"
)

// AgentToken is one authorized device. TokenMAC is HMAC-SHA-256 of the token
// under a key derived from admin_token; the plaintext is never stored.
//
// The Scope* fields carry a developer token's read scope, copied from the
// authorizing web session; all of them are empty for an administrator token.
// ScopeFingerprint is the keyed API-key fingerprint and must never leave the
// server.
type AgentToken struct {
	ID            int64
	TokenMAC      []byte
	DisplayPrefix string
	Role          string
	Tier          string
	DeviceName    string
	CLIVersion    string

	ScopeFingerprint []byte
	ScopeTokenID     *int64
	ScopeUserID      int64
	ScopeUsername    string
	ScopeTokenName   string

	CreatedAtNS  int64
	ExpiresAtNS  int64
	RevokedAtNS  *int64
	LastUsedAtNS *int64
}

// AgentTokenScope selects developer tokens whose scope equals a web session's
// scope: same key fingerprint and same NewAPI token ID (both absent counts as
// equal).
type AgentTokenScope struct {
	Fingerprint []byte
	TokenID     *int64
}

// AgentTokenListLimit bounds one token listing; the newest rows come first.
const AgentTokenListLimit = 500

// AgentAuditEntry is one agent_audit_log row. Empty strings are stored as
// NULL. No field may hold a token, an authorization code, a key or a value
// that was written: ChangedKeys is a JSON array of key names.
type AgentAuditEntry struct {
	ID          int64
	AtNS        int64
	Event       string
	TokenID     *int64
	Role        string
	Command     string
	CLIVersion  string
	ObjectKind  string
	ObjectID    string
	ChangedKeys string
	Outcome     string
	ErrorCode   string
}

// AgentAuditListLimit bounds one audit listing.
const AgentAuditListLimit = 200
