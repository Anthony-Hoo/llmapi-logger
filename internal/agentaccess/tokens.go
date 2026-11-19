package agentaccess

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// generateToken returns a fresh token: the fixed prefix and 32 random bytes in
// unpadded base64url.
func (service *Service) generateToken() (string, error) {
	random := make([]byte, agentapi.TokenRandomBytes)
	if _, err := io.ReadFull(service.random, random); err != nil {
		return "", err
	}
	return agentapi.TokenPrefix + base64.RawURLEncoding.EncodeToString(random), nil
}

// tokenMAC is HMAC-SHA-256(K, token) with K derived from admin_token
// (plan section 5.1); only this value is stored.
func (service *Service) tokenMAC(token string) []byte {
	mac := hmac.New(sha256.New, service.tokenKey[:])
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}

// Authenticate checks the Authorization header of one facade request, in the
// order of plan section 5.3 up to the scope check; Permit does the rest.
// source is the client address the failed-lookup limiter buckets by.
//
// Only a well-formed token that matches no row counts as a failure. Once an
// address is over the limit every token request from it is refused until the
// window ends, a valid token included, so guessing cannot continue at full
// speed behind a working client.
//
// The attempt holds its place in the limiter before the lookup runs and gives
// it back unless the lookup found no row, so concurrent guesses from one
// address cannot all be looked up before the first failure is counted: at
// most the limit of lookups are ever in flight or failed per window.
func (service *Service) Authenticate(ctx context.Context, authorization, source string) (Identity, error) {
	token, ok := bearerToken(authorization)
	if !ok || !agentapi.ValidTokenFormat(token) {
		return Identity{}, fail(agentapi.CodeUnauthenticated)
	}
	if allowed, retryAfter := service.lookups.reserve(source); !allowed {
		return Identity{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: retryAfter}
	}
	row, err := service.store.FindAgentTokenByMAC(ctx, service.tokenMAC(token))
	if errors.Is(err, storage.ErrAgentTokenNotFound) {
		service.lookups.confirm(source)
		return Identity{}, fail(agentapi.CodeUnauthenticated)
	}
	service.lookups.release(source)
	if err != nil {
		service.logger.Warn("agent token lookup failed", "error_category", "agent_store_unavailable")
		return Identity{}, fail(agentapi.CodeUpstreamUnavailable)
	}
	now := service.now()
	if row.RevokedAtNS != nil {
		return Identity{}, fail(agentapi.CodeTokenRevoked)
	}
	if now.UnixNano() >= row.ExpiresAtNS {
		return Identity{}, fail(agentapi.CodeTokenExpired)
	}
	if row.Role == storage.AgentRoleDeveloper && !service.developerLogins {
		// Disabling developer sign-in must invalidate developer tokens already
		// out there, exactly as it invalidates developer cookies.
		return Identity{}, fail(agentapi.CodeRoleUnavailable)
	}
	identity, ok := RestoreIdentity(row)
	if !ok {
		// Scope == nil means "reads everything" in this code base, so a row
		// whose scope cannot be restored completely is refused, never used
		// unscoped.
		service.logger.Warn("agent token refused: incomplete scope", "error_category", "agent_scope_incomplete", "agent_token_id", row.ID)
		return Identity{}, fail(agentapi.CodeUnauthenticated)
	}
	service.touch(ctx, identity.TokenID, now)
	return identity, nil
}

// RestoreIdentity rebuilds the identity of a stored token. It fails closed:
// an unknown role or tier, an administrator row carrying any scope column, or
// a developer row without a complete read scope is not an identity.
func RestoreIdentity(row storage.AgentToken) (Identity, bool) {
	tier := agentapi.Tier(row.Tier)
	if row.ID <= 0 || !tier.Valid() {
		return Identity{}, false
	}
	identity := Identity{
		TokenID: row.ID, Tier: tier, ExpiresAt: time.Unix(0, row.ExpiresAtNS).UTC(),
		DeviceName: row.DeviceName, CLIVersion: row.CLIVersion,
	}
	switch row.Role {
	case storage.AgentRoleAdmin:
		if len(row.ScopeFingerprint) != 0 || row.ScopeTokenID != nil || row.ScopeUserID != 0 ||
			row.ScopeUsername != "" || row.ScopeTokenName != "" {
			return Identity{}, false
		}
		identity.Role = agentapi.RoleAdmin
	case storage.AgentRoleDeveloper:
		if len(row.ScopeFingerprint) != storage.APIKeyFingerprintSize || tier != agentapi.TierRead ||
			(row.ScopeTokenID != nil && *row.ScopeTokenID < 0) {
			return Identity{}, false
		}
		identity.Role = agentapi.RoleDeveloper
		identity.Scope = &Scope{
			Fingerprint: append([]byte(nil), row.ScopeFingerprint...),
			TokenID:     cloneInt64(row.ScopeTokenID),
			UserID:      row.ScopeUserID, Username: row.ScopeUsername, TokenName: row.ScopeTokenName,
		}
	default:
		return Identity{}, false
	}
	return identity, true
}

// Permit applies the last two checks of plan section 5.3 for one endpoint:
// the role the endpoint admits, then for a write endpoint the token tier and
// the deployment write switch.
func (service *Service) Permit(identity Identity, endpoint agentapi.Endpoint) error {
	switch endpoint.Access {
	case agentapi.AccessAnonymous:
		return nil
	case agentapi.AccessAny:
		if identity.Role != agentapi.RoleAdmin && identity.Role != agentapi.RoleDeveloper {
			return fail(agentapi.CodeUnauthenticated)
		}
	case agentapi.AccessAdmin:
		if identity.Role != agentapi.RoleAdmin {
			return fail(agentapi.CodeForbiddenRole)
		}
	default:
		// An endpoint registered without a known access value admits nobody.
		return fail(agentapi.CodeForbiddenRole)
	}
	switch endpoint.Tier {
	case agentapi.TierRead:
		return nil
	case agentapi.TierWrite:
		if identity.Tier != agentapi.TierWrite {
			return fail(agentapi.CodeReadOnlyToken)
		}
		if !service.allowWrite {
			return fail(agentapi.CodeWriteDisabled)
		}
		return nil
	default:
		return fail(agentapi.CodeReadOnlyToken)
	}
}

// touch records last use at most once a minute per token. A failure is only
// logged.
func (service *Service) touch(ctx context.Context, tokenID int64, now time.Time) {
	service.touchMu.Lock()
	last, seen := service.touchedAt[tokenID]
	if seen && now.Sub(last) < touchInterval {
		service.touchMu.Unlock()
		return
	}
	service.touchedAt[tokenID] = now
	service.touchMu.Unlock()
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), touchWriteTimeout)
	defer cancel()
	if err := service.store.TouchAgentToken(writeCtx, tokenID, now.UnixNano()); err != nil {
		service.logger.Warn("agent token last-used write failed", "error_category", "agent_touch_failed")
	}
}

// Logout revokes the calling token.
func (service *Service) Logout(ctx context.Context, identity Identity, meta RequestMeta) error {
	if _, err := service.store.RevokeAgentToken(ctx, identity.TokenID, service.now().UnixNano(), nil); err != nil {
		service.logger.Warn("agent token revocation failed", "error_category", "agent_store_unavailable")
		return fail(agentapi.CodeUpstreamUnavailable)
	}
	service.RecordAudit(ctx, auditFor(identity, meta, EventTokenRevoked, storage.AgentOutcomeOK))
	return nil
}

// ListTokens lists the tokens a web session may see: every token for an
// administrator, and for a developer only developer tokens whose scope equals
// the session's.
func (service *Service) ListTokens(ctx context.Context, viewer Viewer) ([]storage.AgentToken, error) {
	scope, err := viewerScope(viewer)
	if err != nil {
		return nil, err
	}
	tokens, err := service.store.ListAgentTokens(ctx, scope)
	if err != nil {
		service.logger.Warn("agent token listing failed", "error_category", "agent_store_unavailable")
		return nil, fail(agentapi.CodeUpstreamUnavailable)
	}
	return tokens, nil
}

// RevokeToken revokes one token on behalf of a web session. It is idempotent:
// an unknown, already revoked, expired or (for a developer) invisible token is
// not an error and revokes nothing.
func (service *Service) RevokeToken(ctx context.Context, viewer Viewer, id int64) error {
	scope, err := viewerScope(viewer)
	if err != nil {
		return err
	}
	revoked, err := service.store.RevokeAgentToken(ctx, id, service.now().UnixNano(), scope)
	if err != nil {
		service.logger.Warn("agent token revocation failed", "error_category", "agent_store_unavailable")
		return fail(agentapi.CodeUpstreamUnavailable)
	}
	if revoked {
		tokenID := id
		service.RecordAudit(ctx, storage.AgentAuditEntry{
			Event: EventTokenRevoked, TokenID: &tokenID, Role: string(viewer.Role), Command: CommandWeb,
			ObjectKind: ObjectKindToken, ObjectID: formatID(id), Outcome: storage.AgentOutcomeOK,
		})
	}
	return nil
}

// WriteEvents are the audit events of agent writes: the rows of the
// administrator's "recent agent changes" view.
var WriteEvents = []string{EventWriteApplied, EventWriteFailed, EventWriteDenied}

// ListAudit returns the newest audit rows of events (all rows when events is
// empty), for the administrator's "recent agent changes" view.
func (service *Service) ListAudit(ctx context.Context, limit int, events []string) ([]storage.AgentAuditEntry, error) {
	entries, err := service.store.ListAgentAudit(ctx, limit, events)
	if err != nil {
		service.logger.Warn("agent audit listing failed", "error_category", "agent_store_unavailable")
		return nil, fail(agentapi.CodeUpstreamUnavailable)
	}
	return entries, nil
}

// viewerScope maps a web viewer to a storage filter. A developer without a
// complete scope is refused rather than given the administrator view.
func viewerScope(viewer Viewer) (*storage.AgentTokenScope, error) {
	switch viewer.Role {
	case agentapi.RoleAdmin:
		return nil, nil
	case agentapi.RoleDeveloper:
		if viewer.Scope == nil || len(viewer.Scope.Fingerprint) != storage.APIKeyFingerprintSize {
			return nil, fail(agentapi.CodeForbiddenRole)
		}
		return &storage.AgentTokenScope{Fingerprint: viewer.Scope.Fingerprint, TokenID: viewer.Scope.TokenID}, nil
	default:
		return nil, fail(agentapi.CodeForbiddenRole)
	}
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", false
	}
	return fields[1], true
}

// Command values of audit rows. CommandWeb is what the server records for an
// action taken on the web page; no client may record it. CommandUnknown
// replaces a client-reported command that is malformed or reserved.
const (
	CommandWeb     = "web"
	CommandUnknown = "unknown"
)

// reservedCommands are the command values only the server assigns.
var reservedCommands = map[string]bool{CommandWeb: true}

// cleanCommand keeps a client-reported command name only when it looks like
// one ("requests.list") and is not a value the server itself assigns. An
// absent command stays empty; a malformed or reserved one is recorded as
// CommandUnknown, so a row never claims to come from the web page and never
// stores text a client chose.
func cleanCommand(value string) string {
	if value == "" {
		return ""
	}
	if len(value) > 64 || reservedCommands[value] {
		return CommandUnknown
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '.', char == '-', char == '_':
		default:
			return CommandUnknown
		}
	}
	return value
}

// cleanVersion keeps a client-reported version only when it is a plausible
// version string.
func cleanVersion(value string) string {
	if value == "" || len(value) > 32 {
		return ""
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9',
			char == '.', char == '-', char == '+':
		default:
			return ""
		}
	}
	return value
}

// cleanDeviceName removes control characters and invalid bytes, trims
// surrounding space and caps the name at 64 characters. The page shows it as
// plain text.
func cleanDeviceName(value string) string {
	return cleanDisplayText(value, 64)
}

// cleanDisplayText removes invalid bytes and control characters, trims
// surrounding space and caps the text at max characters.
func cleanDisplayText(value string, max int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	value = strings.Map(func(char rune) rune {
		if unicode.IsControl(char) || char == utf8.RuneError {
			return -1
		}
		return char
	}, value)
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) > max {
		value = strings.TrimSpace(string([]rune(value)[:max]))
	}
	return value
}

func formatID(id int64) string { return strconv.FormatInt(id, 10) }

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
