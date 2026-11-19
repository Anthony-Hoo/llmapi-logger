package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"llmapi-logger/internal/storage"
)

// Agent access persistence (doc/features/25-agent-access.md section 4).
//
// Token issuance and revocation take the definitive-outcome path
// (submitPolicySync): a device the user just authorized or just revoked must
// not be reported as failed while the writer goes on to commit it. The audit
// log and last-used stamps take the ordinary path; their callers only log a
// failure.

const (
	agentDeviceNameMax  = 64
	agentCLIVersionMax  = 32
	agentPrefixMax      = 16
	agentAuditEventMax  = 64
	agentAuditTextMax   = 128
	agentAuditKeysMax   = 4096
	agentScopeStringMax = 256
)

const agentTokenColumns = `id, token_mac, display_prefix, role, tier, device_name, cli_version,
scope_fingerprint, scope_token_id, scope_user_id, scope_username, scope_token_name,
created_at_ns, expires_at_ns, revoked_at_ns, last_used_at_ns`

// CreateAgentToken inserts one token row and returns it with its ID.
func (store *Store) CreateAgentToken(ctx context.Context, token storage.AgentToken) (storage.AgentToken, error) {
	if ctx == nil {
		return storage.AgentToken{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.AgentToken{}, ErrClosed
	}
	if err := validateAgentToken(token); err != nil {
		return storage.AgentToken{}, err
	}
	owned := token
	owned.TokenMAC = append([]byte(nil), token.TokenMAC...)
	owned.ScopeFingerprint = cloneBytesOrNil(token.ScopeFingerprint)
	owned.ScopeTokenID = cloneInt64(token.ScopeTokenID)
	owned.RevokedAtNS, owned.LastUsedAtNS = nil, nil
	err := store.submitPolicySync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		err := tx.QueryRow(`
INSERT INTO agent_tokens (token_mac, display_prefix, role, tier, device_name, cli_version,
    scope_fingerprint, scope_token_id, scope_user_id, scope_username, scope_token_name,
    created_at_ns, expires_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
			owned.TokenMAC, owned.DisplayPrefix, owned.Role, owned.Tier, owned.DeviceName, owned.CLIVersion,
			nullableBytes(owned.ScopeFingerprint), owned.ScopeTokenID, nullableScopeInt(owned.ScopeUserID),
			nullableScopeString(owned.ScopeUsername), nullableScopeString(owned.ScopeTokenName),
			owned.CreatedAtNS, owned.ExpiresAtNS).Scan(&owned.ID)
		if err != nil {
			return fmt.Errorf("postgres writer: create agent token: %w", err)
		}
		if counting, ok := tx.(*countingTx); ok {
			counting.mutations++
		}
		return nil
	})})
	if err != nil {
		return storage.AgentToken{}, err
	}
	return owned, nil
}

// FindAgentTokenByMAC returns the token whose MAC matches, revoked and expired
// rows included: the caller tells those states apart.
func (store *Store) FindAgentTokenByMAC(ctx context.Context, mac []byte) (storage.AgentToken, error) {
	if ctx == nil {
		return storage.AgentToken{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.AgentToken{}, ErrClosed
	}
	if len(mac) != 32 {
		return storage.AgentToken{}, storage.ErrAgentTokenNotFound
	}
	row := store.readerDB.QueryRowContext(ctx, `SELECT `+agentTokenColumns+` FROM agent_tokens WHERE token_mac = $1`, mac)
	token, err := scanAgentToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.AgentToken{}, storage.ErrAgentTokenNotFound
	}
	if err != nil {
		return storage.AgentToken{}, fmt.Errorf("postgres: find agent token: %w", err)
	}
	return token, nil
}

// RevokeAgentToken stamps revoked_at_ns on one unrevoked token and reports
// whether it did. It is idempotent: an unknown, already revoked or (with a
// scope) out-of-scope token is not an error and revokes nothing. A non-nil
// scope limits the revocation to developer tokens of exactly that scope.
func (store *Store) RevokeAgentToken(ctx context.Context, id, atNS int64, scope *storage.AgentTokenScope) (bool, error) {
	if ctx == nil {
		return false, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return false, ErrClosed
	}
	if id <= 0 || atNS <= 0 {
		return false, nil
	}
	var fingerprint []byte
	var tokenID *int64
	if scope != nil {
		if len(scope.Fingerprint) != storage.APIKeyFingerprintSize {
			// An incomplete scope must never widen into "every token".
			return false, nil
		}
		fingerprint = append([]byte(nil), scope.Fingerprint...)
		tokenID = cloneInt64(scope.TokenID)
	}
	var revoked bool
	err := store.submitPolicySync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		var result sql.Result
		var err error
		if scope == nil {
			result, err = tx.Exec(`UPDATE agent_tokens SET revoked_at_ns = $2 WHERE id = $1 AND revoked_at_ns IS NULL`, id, atNS)
		} else {
			result, err = tx.Exec(`
UPDATE agent_tokens SET revoked_at_ns = $2
WHERE id = $1 AND revoked_at_ns IS NULL AND role = 'developer'
  AND scope_fingerprint = $3 AND scope_token_id IS NOT DISTINCT FROM $4`, id, atNS, fingerprint, tokenID)
		}
		if err != nil {
			return fmt.Errorf("postgres writer: revoke agent token: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("postgres writer: read revoked agent tokens: %w", err)
		}
		revoked = affected > 0
		return nil
	})})
	if err != nil {
		return false, err
	}
	return revoked, nil
}

// TouchAgentToken records a use. It never moves last_used_at_ns backwards and
// ignores an unknown token. Callers rate-limit it and only log a failure.
func (store *Store) TouchAgentToken(ctx context.Context, id, atNS int64) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if id <= 0 || atNS <= 0 {
		return nil
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		if _, err := tx.Exec(`
UPDATE agent_tokens SET last_used_at_ns = $2
WHERE id = $1 AND (last_used_at_ns IS NULL OR last_used_at_ns < $2)`, id, atNS); err != nil {
			return fmt.Errorf("postgres writer: touch agent token: %w", err)
		}
		return nil
	})})
}

// ListAgentTokens returns the newest tokens first, at most
// storage.AgentTokenListLimit. A nil scope lists every token (administrator
// view); a non-nil scope lists only developer tokens of exactly that scope.
func (store *Store) ListAgentTokens(ctx context.Context, scope *storage.AgentTokenScope) ([]storage.AgentToken, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	var rows *sql.Rows
	var err error
	if scope == nil {
		rows, err = store.readerDB.QueryContext(ctx, `SELECT `+agentTokenColumns+` FROM agent_tokens ORDER BY id DESC LIMIT $1`, storage.AgentTokenListLimit)
	} else {
		if len(scope.Fingerprint) != storage.APIKeyFingerprintSize {
			return []storage.AgentToken{}, nil
		}
		rows, err = store.readerDB.QueryContext(ctx, `SELECT `+agentTokenColumns+` FROM agent_tokens
WHERE role = 'developer' AND scope_fingerprint = $1 AND scope_token_id IS NOT DISTINCT FROM $2
ORDER BY id DESC LIMIT $3`, scope.Fingerprint, scope.TokenID, storage.AgentTokenListLimit)
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: list agent tokens: %w", err)
	}
	defer rows.Close()
	tokens := make([]storage.AgentToken, 0)
	for rows.Next() {
		token, err := scanAgentToken(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan agent token: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent tokens: %w", err)
	}
	return tokens, nil
}

// InsertAgentAudit appends one audit row. Every text field is reduced to valid
// UTF-8 without control characters and capped: several of them come from
// request headers, and a value PostgreSQL rejects (a NUL byte, invalid UTF-8)
// would otherwise fail the whole writer batch and the capture writes in it.
func (store *Store) InsertAgentAudit(ctx context.Context, entry storage.AgentAuditEntry) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	owned := sanitizeAgentAudit(entry)
	if owned.AtNS <= 0 || owned.Event == "" {
		return errors.New("postgres: invalid agent audit entry")
	}
	switch owned.Outcome {
	case storage.AgentOutcomeOK, storage.AgentOutcomeDenied, storage.AgentOutcomeFailed:
	default:
		return errors.New("postgres: invalid agent audit outcome")
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		if _, err := tx.Exec(`
INSERT INTO agent_audit_log (at_ns, event, token_id, role, command, cli_version, object_kind, object_id, changed_keys, outcome, error_code)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			owned.AtNS, owned.Event, owned.TokenID, nullableScopeString(owned.Role), nullableScopeString(owned.Command),
			nullableScopeString(owned.CLIVersion), nullableScopeString(owned.ObjectKind), nullableScopeString(owned.ObjectID),
			nullableScopeString(owned.ChangedKeys), owned.Outcome, nullableScopeString(owned.ErrorCode)); err != nil {
			return fmt.Errorf("postgres writer: insert agent audit: %w", err)
		}
		return nil
	})})
}

// ListAgentAudit returns the newest audit rows first.
func (store *Store) ListAgentAudit(ctx context.Context, limit int) ([]storage.AgentAuditEntry, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if limit <= 0 || limit > storage.AgentAuditListLimit {
		limit = storage.AgentAuditListLimit
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT id, at_ns, event, token_id, role, command, cli_version, object_kind, object_id, changed_keys, outcome, error_code
FROM agent_audit_log ORDER BY at_ns DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list agent audit: %w", err)
	}
	defer rows.Close()
	entries := make([]storage.AgentAuditEntry, 0)
	for rows.Next() {
		var entry storage.AgentAuditEntry
		var tokenID sql.NullInt64
		var role, command, cliVersion, objectKind, objectID, changedKeys, errorCode sql.NullString
		if err := rows.Scan(&entry.ID, &entry.AtNS, &entry.Event, &tokenID, &role, &command, &cliVersion,
			&objectKind, &objectID, &changedKeys, &entry.Outcome, &errorCode); err != nil {
			return nil, fmt.Errorf("postgres: scan agent audit: %w", err)
		}
		entry.TokenID = nullInt64Pointer(tokenID)
		entry.Role, entry.Command, entry.CLIVersion = role.String, command.String, cliVersion.String
		entry.ObjectKind, entry.ObjectID, entry.ChangedKeys, entry.ErrorCode = objectKind.String, objectID.String, changedKeys.String, errorCode.String
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate agent audit: %w", err)
	}
	return entries, nil
}

type agentTokenScanner interface {
	Scan(...any) error
}

func scanAgentToken(row agentTokenScanner) (storage.AgentToken, error) {
	var token storage.AgentToken
	var scopeTokenID, scopeUserID, revoked, lastUsed sql.NullInt64
	var username, tokenName sql.NullString
	if err := row.Scan(&token.ID, &token.TokenMAC, &token.DisplayPrefix, &token.Role, &token.Tier,
		&token.DeviceName, &token.CLIVersion, &token.ScopeFingerprint, &scopeTokenID, &scopeUserID,
		&username, &tokenName, &token.CreatedAtNS, &token.ExpiresAtNS, &revoked, &lastUsed); err != nil {
		return storage.AgentToken{}, err
	}
	if len(token.ScopeFingerprint) == 0 {
		token.ScopeFingerprint = nil
	}
	token.ScopeTokenID = nullInt64Pointer(scopeTokenID)
	token.ScopeUserID = scopeUserID.Int64
	token.ScopeUsername, token.ScopeTokenName = username.String, tokenName.String
	token.RevokedAtNS, token.LastUsedAtNS = nullInt64Pointer(revoked), nullInt64Pointer(lastUsed)
	return token, nil
}

// validateAgentToken rejects a row the schema would refuse, before it reaches
// the writer queue. The schema checks stay as the second line.
func validateAgentToken(token storage.AgentToken) error {
	if len(token.TokenMAC) != 32 {
		return errors.New("postgres: invalid agent token mac")
	}
	if token.DisplayPrefix == "" || len(token.DisplayPrefix) > agentPrefixMax || !cleanAgentText(token.DisplayPrefix) {
		return errors.New("postgres: invalid agent token prefix")
	}
	if !agentTextWithin(token.DeviceName, agentDeviceNameMax) || !agentTextWithin(token.CLIVersion, agentCLIVersionMax) {
		return errors.New("postgres: invalid agent token device or version")
	}
	if token.CreatedAtNS <= 0 || token.ExpiresAtNS <= token.CreatedAtNS {
		return errors.New("postgres: invalid agent token lifetime")
	}
	switch token.Tier {
	case storage.AgentTierRead, storage.AgentTierWrite:
	default:
		return errors.New("postgres: invalid agent token tier")
	}
	switch token.Role {
	case storage.AgentRoleAdmin:
		if len(token.ScopeFingerprint) != 0 || token.ScopeTokenID != nil || token.ScopeUserID != 0 ||
			token.ScopeUsername != "" || token.ScopeTokenName != "" {
			return errors.New("postgres: administrator agent token must not carry a scope")
		}
	case storage.AgentRoleDeveloper:
		if len(token.ScopeFingerprint) != storage.APIKeyFingerprintSize || token.Tier != storage.AgentTierRead {
			return errors.New("postgres: developer agent token needs a complete read scope")
		}
		if token.ScopeTokenID != nil && *token.ScopeTokenID < 0 {
			return errors.New("postgres: invalid developer agent token scope")
		}
		if !agentScopeText(token.ScopeUsername) || !agentScopeText(token.ScopeTokenName) {
			return errors.New("postgres: invalid developer agent token identity")
		}
	default:
		return errors.New("postgres: invalid agent token role")
	}
	return nil
}

func agentTextWithin(value string, max int) bool {
	count := utf8.RuneCountInString(value)
	return count >= 1 && count <= max && cleanAgentText(value)
}

func agentScopeText(value string) bool {
	return utf8.RuneCountInString(value) <= agentScopeStringMax && cleanAgentText(value)
}

func cleanAgentText(value string) bool {
	return utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// sanitizeAgentText forces valid UTF-8, drops control characters and caps
// the length in runes.
func sanitizeAgentText(value string, max int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	value = strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return -1
		}
		return char
	}, value)
	if utf8.RuneCountInString(value) > max {
		value = string([]rune(value)[:max])
	}
	return value
}

func sanitizeAgentAudit(entry storage.AgentAuditEntry) storage.AgentAuditEntry {
	entry.Event = sanitizeAgentText(entry.Event, agentAuditEventMax)
	entry.Role = sanitizeAgentText(entry.Role, agentAuditTextMax)
	entry.Command = sanitizeAgentText(entry.Command, agentAuditTextMax)
	entry.CLIVersion = sanitizeAgentText(entry.CLIVersion, agentAuditTextMax)
	entry.ObjectKind = sanitizeAgentText(entry.ObjectKind, agentAuditTextMax)
	entry.ObjectID = sanitizeAgentText(entry.ObjectID, agentAuditTextMax)
	entry.ChangedKeys = sanitizeAgentText(entry.ChangedKeys, agentAuditKeysMax)
	entry.Outcome = sanitizeAgentText(entry.Outcome, agentAuditTextMax)
	entry.ErrorCode = sanitizeAgentText(entry.ErrorCode, agentAuditTextMax)
	entry.TokenID = cloneInt64(entry.TokenID)
	return entry
}

func nullableScopeString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableScopeInt(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func cloneBytesOrNil(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}
