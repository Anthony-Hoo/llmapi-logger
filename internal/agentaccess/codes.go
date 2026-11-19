package agentaccess

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"sync"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/storage"
)

// Authorization codes (contract section 3.1).
const (
	ModeLoopback = "loopback"
	ModePaste    = "paste"

	loopbackCodeTTL = 60 * time.Second
	pasteCodeTTL    = 300 * time.Second
	// redeemedCodeMemory keeps a redeemed code's record so a replay can still
	// be recognized, and the token it issued revoked, after the code's own
	// lifetime.
	redeemedCodeMemory = 10 * time.Minute
	// maxCodes bounds the in-memory store; authorizations beyond it are
	// refused until entries expire.
	maxCodes = 1024
	// maxCodesPerApprover bounds the unredeemed, unexpired codes of one
	// approving identity, so that one session cannot fill the store and stop
	// every other identity from authorizing.
	maxCodesPerApprover = 8

	codeRandomBytes   = 32
	codeEncodedChars  = 43
	minVerifierLength = 43
	maxVerifierLength = 128
	minLoopbackPort   = 1024
	maxLoopbackPort   = 65535
	maxCLIVersionLen  = 32

	// PlaceholderDeviceName and PlaceholderCLIVersion stand in for an empty
	// device name or client version on the confirmation request.
	PlaceholderDeviceName = "unnamed"
	PlaceholderCLIVersion = "unknown"
)

// AuthorizationRequest is what the confirmation page submits. The web layer
// decodes it; the service validates every field.
type AuthorizationRequest struct {
	Challenge  string
	Mode       string
	Port       int
	DeviceName string
	CLIVersion string
	Tier       agentapi.Tier
}

// Grantor is the web session approving an authorization.
type Grantor struct {
	Role agentapi.Role
	// SessionExpiresAt is when the authorizing web session ends. A developer
	// token never outlives it, so it is required for a developer.
	SessionExpiresAt time.Time
	// Scope is required for a developer and must be nil for an administrator.
	Scope *Scope
}

// Authorization is an approved authorization. Code is shown or handed to the
// client exactly once; only its SHA-256 is kept.
type Authorization struct {
	Code      string
	ExpiresIn time.Duration
	// RedirectURI is the loopback callback, without a query: the page appends
	// code and state itself. Empty in paste mode.
	RedirectURI string
	// TokenExpiresAt is when a token issued from this code will expire.
	TokenExpiresAt time.Time
}

// Issued is the result of a successful exchange. Token is the only plaintext
// copy the server ever produces.
type Issued struct {
	Token    string
	Identity Identity
}

type codeEntry struct {
	// approver is the approving identity's limiter key (approverKey).
	approver   string
	challenge  string
	identity   Identity
	expiresAt  time.Time
	forgetAt   time.Time
	redeemed   bool
	replayed   bool
	issuedID   int64
	deviceName string
}

type codeStore struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]*codeEntry
}

func newCodeStore() *codeStore {
	return &codeStore{entries: make(map[[sha256.Size]byte]*codeEntry)}
}

// sweepLocked drops entries that can no longer matter.
func (store *codeStore) sweepLocked(now time.Time) {
	for key, entry := range store.entries {
		if !now.Before(entry.forgetAt) {
			delete(store.entries, key)
		}
	}
}

// openLocked counts approver's codes that can still be redeemed (neither
// redeemed nor expired) and reports when the first of them expires.
func (store *codeStore) openLocked(approver string, now time.Time) (int, time.Time) {
	open, soonest := 0, time.Time{}
	for _, entry := range store.entries {
		if entry.approver != approver || entry.redeemed || !now.Before(entry.expiresAt) {
			continue
		}
		open++
		if soonest.IsZero() || entry.expiresAt.Before(soonest) {
			soonest = entry.expiresAt
		}
	}
	return open, soonest
}

// LoopbackRedirectURI is the only callback accepted: http, the IPv4 loopback
// literal (never "localhost") and the fixed path.
func LoopbackRedirectURI(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"
}

// ValidPort reports whether port is a loopback callback port.
func ValidPort(port int) bool {
	return port >= minLoopbackPort && port <= maxLoopbackPort
}

// validateRequest checks the request shape shared by approve and deny.
func validateMode(request AuthorizationRequest) error {
	switch request.Mode {
	case ModeLoopback:
		if !ValidPort(request.Port) {
			return invalid("port")
		}
	case ModePaste:
		if request.Port != 0 {
			return invalid("port")
		}
	default:
		return invalid("mode")
	}
	return nil
}

// approverKey is the authorization limiter's key for a web session: the
// approving identity, not its address, so that sessions sharing an address
// (behind one reverse proxy, say) do not use up each other's allowance. Every
// administrator session is the one administrator identity; a developer is
// the scope of the key it signed in with. It is derived before the grantor
// is validated, so a malformed grantor is counted too, under its address.
func approverKey(grantor Grantor, source string) string {
	switch {
	case grantor.Role == agentapi.RoleAdmin:
		return "admin"
	case grantor.Role == agentapi.RoleDeveloper && grantor.Scope != nil && len(grantor.Scope.Fingerprint) > 0:
		key := "developer:" + hex.EncodeToString(grantor.Scope.Fingerprint) + ":"
		if grantor.Scope.TokenID != nil {
			key += strconv.FormatInt(*grantor.Scope.TokenID, 10)
		}
		return key
	default:
		return "source:" + source
	}
}

// Approve records an approved authorization and returns its code. source is
// the web session's address, used by the authorization limiter only for a
// grantor that names no identity.
func (service *Service) Approve(ctx context.Context, grantor Grantor, request AuthorizationRequest, source string) (Authorization, error) {
	approver := approverKey(grantor, source)
	if allowed, retryAfter := service.authorizations.take(approver); !allowed {
		return Authorization{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: retryAfter}
	}
	if err := validateMode(request); err != nil {
		return Authorization{}, err
	}
	if !validChallenge(request.Challenge) {
		return Authorization{}, invalid("challenge")
	}
	// Both values are display-only and already cleaned by the page; an empty
	// or unusable one becomes a placeholder instead of failing the flow.
	deviceName := cleanDeviceName(request.DeviceName)
	if deviceName == "" {
		deviceName = PlaceholderDeviceName
	}
	cliVersion := cleanVersion(request.CLIVersion)
	if cliVersion == "" || len(cliVersion) > maxCLIVersionLen {
		cliVersion = PlaceholderCLIVersion
	}
	if !request.Tier.Valid() {
		return Authorization{}, invalid("tier")
	}
	now := service.now()
	identity := Identity{Tier: request.Tier, DeviceName: deviceName, CLIVersion: cliVersion}
	switch grantor.Role {
	case agentapi.RoleAdmin:
		if grantor.Scope != nil {
			return Authorization{}, fail(agentapi.CodeForbiddenRole)
		}
		if request.Tier == agentapi.TierWrite && !service.allowWrite {
			// Never downgraded silently: the caller asked for something the
			// deployment does not allow.
			return Authorization{}, invalid("tier")
		}
		identity.Role = agentapi.RoleAdmin
		lifetime := AdminReadLifetime
		if request.Tier == agentapi.TierWrite {
			lifetime = AdminWriteLifetime
		}
		identity.ExpiresAt = now.Add(lifetime).UTC().Truncate(time.Second)
	case agentapi.RoleDeveloper:
		if request.Tier != agentapi.TierRead {
			return Authorization{}, invalid("tier")
		}
		if !service.developerLogins {
			return Authorization{}, fail(agentapi.CodeRoleUnavailable)
		}
		scope := grantor.Scope
		if scope == nil || len(scope.Fingerprint) != storage.APIKeyFingerprintSize || (scope.TokenID != nil && *scope.TokenID < 0) {
			return Authorization{}, fail(agentapi.CodeForbiddenRole)
		}
		// The token lives exactly as long as the authorizing session, and a
		// session without a known end cannot authorize one.
		expires := grantor.SessionExpiresAt.UTC()
		if expires.IsZero() || !now.Before(expires) {
			return Authorization{}, fail(agentapi.CodeUnauthenticated)
		}
		if limit := now.Add(MaxDeveloperLifetime); expires.After(limit) {
			expires = limit
		}
		identity.Role = agentapi.RoleDeveloper
		identity.ExpiresAt = expires.Truncate(time.Second)
		identity.Scope = &Scope{
			Fingerprint: append([]byte(nil), scope.Fingerprint...), TokenID: cloneInt64(scope.TokenID),
			// The names are display-only copies of what NewAPI reported; they
			// are cleaned like the device name so that an odd token name can
			// never make the storage write fail after the code is consumed.
			UserID: scope.UserID, Username: cleanDisplayText(scope.Username, 256), TokenName: cleanDisplayText(scope.TokenName, 256),
		}
		if !identity.ExpiresAt.After(now) {
			return Authorization{}, fail(agentapi.CodeUnauthenticated)
		}
	default:
		return Authorization{}, fail(agentapi.CodeForbiddenRole)
	}

	code, err := service.randomString(codeRandomBytes)
	if err != nil {
		return Authorization{}, fail(agentapi.CodeInternal)
	}
	ttl := loopbackCodeTTL
	if request.Mode == ModePaste {
		ttl = pasteCodeTTL
	}
	entry := &codeEntry{
		approver: approver, challenge: request.Challenge, identity: identity,
		expiresAt: now.Add(ttl), forgetAt: now.Add(ttl + redeemedCodeMemory), deviceName: deviceName,
	}
	key := sha256.Sum256([]byte(code))
	service.codes.mu.Lock()
	service.codes.sweepLocked(now)
	if open, soonest := service.codes.openLocked(approver, now); open >= maxCodesPerApprover {
		service.codes.mu.Unlock()
		return Authorization{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: soonest.Sub(now)}
	}
	if len(service.codes.entries) >= maxCodes {
		service.codes.mu.Unlock()
		return Authorization{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: ttl}
	}
	service.codes.entries[key] = entry
	service.codes.mu.Unlock()

	service.RecordAudit(ctx, storage.AgentAuditEntry{
		Event: EventAuthorizeApproved, Role: string(identity.Role), CLIVersion: cliVersion,
		Command: CommandWeb, Outcome: storage.AgentOutcomeOK,
	})
	authorization := Authorization{Code: code, ExpiresIn: ttl, TokenExpiresAt: identity.ExpiresAt}
	if request.Mode == ModeLoopback {
		authorization.RedirectURI = LoopbackRedirectURI(request.Port)
	}
	return authorization, nil
}

// Deny records a refused authorization and returns the loopback callback the
// page sends the refusal to (empty in paste mode). It shares Approve's
// limiter key.
func (service *Service) Deny(ctx context.Context, grantor Grantor, request AuthorizationRequest, source string) (string, error) {
	if allowed, retryAfter := service.authorizations.take(approverKey(grantor, source)); !allowed {
		return "", &Error{Code: agentapi.CodeRateLimited, RetryAfter: retryAfter}
	}
	if err := validateMode(request); err != nil {
		return "", err
	}
	service.RecordAudit(ctx, storage.AgentAuditEntry{
		Event: EventAuthorizeDenied, Role: string(grantor.Role), CLIVersion: cleanVersion(request.CLIVersion),
		Command: CommandWeb, Outcome: storage.AgentOutcomeDenied,
	})
	if request.Mode == ModeLoopback {
		return LoopbackRedirectURI(request.Port), nil
	}
	return "", nil
}

// Exchange redeems an authorization code for a token (the anonymous
// POST /api/agent/v1/token). A code is consumed by its first redemption even
// when a later step fails; redeeming it again revokes the token it issued.
// source is the client address for the exchange-failure limiter.
func (service *Service) Exchange(ctx context.Context, code, verifier, source string, meta RequestMeta) (Issued, error) {
	if allowed, retryAfter := service.exchanges.allow(source); !allowed {
		return Issued{}, &Error{Code: agentapi.CodeRateLimited, RetryAfter: retryAfter}
	}
	refuse := func(role agentapi.Role) (Issued, error) {
		service.exchanges.record(source)
		service.RecordAudit(ctx, storage.AgentAuditEntry{
			Event: EventTokenExchangeFailed, Role: string(role), Command: cleanCommand(meta.Command),
			CLIVersion: cleanVersion(meta.CLIVersion), Outcome: storage.AgentOutcomeFailed,
			ErrorCode: string(agentapi.CodeInvalidGrant),
		})
		return Issued{}, fail(agentapi.CodeInvalidGrant)
	}
	if !validCode(code) {
		return refuse("")
	}
	now := service.now()
	key := sha256.Sum256([]byte(code))

	service.codes.mu.Lock()
	service.codes.sweepLocked(now)
	entry, found := service.codes.entries[key]
	if !found {
		service.codes.mu.Unlock()
		return refuse("")
	}
	if entry.redeemed {
		entry.replayed = true
		issued := entry.issuedID
		role := entry.identity.Role
		service.codes.mu.Unlock()
		if issued > 0 {
			service.revokeReplayed(ctx, issued, role, meta)
		}
		return refuse(role)
	}
	entry.redeemed = true
	entry.forgetAt = now.Add(redeemedCodeMemory)
	expired := !now.Before(entry.expiresAt)
	challenge := entry.challenge
	identity := entry.identity
	service.codes.mu.Unlock()

	if expired || !verifierMatches(verifier, challenge) {
		return refuse(identity.Role)
	}
	if identity.Role == agentapi.RoleDeveloper && !service.developerLogins {
		return refuse(identity.Role)
	}
	if !identity.ExpiresAt.After(now) {
		return refuse(identity.Role)
	}

	token, err := service.generateToken()
	if err != nil {
		return Issued{}, fail(agentapi.CodeInternal)
	}
	row := storage.AgentToken{
		TokenMAC: service.tokenMAC(token), DisplayPrefix: token[:tokenDisplayPrefixLength],
		Role: string(identity.Role), Tier: string(identity.Tier),
		DeviceName: identity.DeviceName, CLIVersion: identity.CLIVersion,
		CreatedAtNS: now.UnixNano(), ExpiresAtNS: identity.ExpiresAt.UnixNano(),
	}
	if identity.Scope != nil {
		row.ScopeFingerprint = identity.Scope.Fingerprint
		row.ScopeTokenID = identity.Scope.TokenID
		row.ScopeUserID = identity.Scope.UserID
		row.ScopeUsername = identity.Scope.Username
		row.ScopeTokenName = identity.Scope.TokenName
	}
	created, err := service.store.CreateAgentToken(ctx, row)
	if err != nil {
		service.logger.Warn("agent token issuance failed", "error_category", "agent_store_unavailable")
		return Issued{}, fail(agentapi.CodeUpstreamUnavailable)
	}
	identity.TokenID = created.ID

	service.codes.mu.Lock()
	entry.issuedID = created.ID
	replayed := entry.replayed
	service.codes.mu.Unlock()
	if replayed {
		// A replay arrived while this redemption was issuing: the code may
		// have leaked, so neither copy keeps a token.
		service.revokeReplayed(ctx, created.ID, identity.Role, meta)
		return refuse(identity.Role)
	}
	service.RecordAudit(ctx, auditFor(identity, meta, EventTokenIssued, storage.AgentOutcomeOK))
	return Issued{Token: token, Identity: identity}, nil
}

func (service *Service) revokeReplayed(ctx context.Context, tokenID int64, role agentapi.Role, meta RequestMeta) {
	revoked, err := service.store.RevokeAgentToken(ctx, tokenID, service.now().UnixNano(), nil)
	if err != nil {
		service.logger.Warn("agent token revocation after code replay failed", "error_category", "agent_store_unavailable")
		return
	}
	if revoked {
		service.RecordAudit(ctx, auditFor(Identity{TokenID: tokenID, Role: role}, meta, EventTokenRevoked, storage.AgentOutcomeOK))
	}
}

func (service *Service) randomString(size int) (string, error) {
	random := make([]byte, size)
	if _, err := io.ReadFull(service.random, random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// validChallenge accepts BASE64URL(SHA-256(verifier)): exactly 43 unpadded
// base64url characters. Only S256 exists, so there is no method field.
func validChallenge(value string) bool {
	if len(value) != codeEncodedChars || !base64URL(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validCode(value string) bool {
	return len(value) == codeEncodedChars && base64URL(value)
}

// verifierMatches checks an RFC 7636 code_verifier (43 to 128 unreserved
// characters) against the stored S256 challenge in constant time.
func verifierMatches(verifier, challenge string) bool {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength {
		return false
	}
	for index := 0; index < len(verifier); index++ {
		char := verifier[index]
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9',
			char == '-', char == '.', char == '_', char == '~':
		default:
			return false
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func base64URL(value string) bool {
	for index := 0; index < len(value); index++ {
		char := value[index]
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-', char == '_':
		default:
			return false
		}
	}
	return true
}
