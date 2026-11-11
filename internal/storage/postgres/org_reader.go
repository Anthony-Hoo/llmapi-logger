package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"llmapi-logger/internal/orgreport"
)

var _ orgreport.DataStore = (*Store)(nil)

// maxOrgRequestRows bounds one report load so a runaway week cannot exhaust
// memory; about 300 bytes per row in Go.
const maxOrgRequestRows = 2_000_000

// LoadOrgRequests reads every analysed audit that started in [fromNS, toNS)
// with its caller, usage, billing and identity fingerprint. Requests without
// an analysis row are not agent requests the report can time and are left
// out. Only plaintext columns are read; nothing is decrypted here.
func (store *Store) LoadOrgRequests(ctx context.Context, fromNS, toNS int64) ([]orgreport.Request, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if toNS <= fromNS {
		return nil, errors.New("postgres: invalid org report range")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT aa.audit_id, aa.started_at_ns, ar.ended_at_ns,
       COALESCE(aa.agent_client, ''), COALESCE(aa.agent_role, ''),
       aa.agent_root_fpr, aa.agent_node_fpr, COALESCE(aa.session_link, ''),
       COALESCE(aa.u_uncached_input, 0), COALESCE(aa.u_cache_read, 0),
       COALESCE(aa.u_cache_write, 0), COALESCE(aa.u_output, 0),
       COALESCE(tl.newapi_user_id, 0), COALESCE(tl.newapi_token_id, 0),
       COALESCE(tl.billing_state, ''), tl.quota, tl.quota_per_unit,
       pi.identity_fpr
FROM audit_analysis AS aa
JOIN audit_records AS ar ON ar.audit_id = aa.audit_id
LEFT JOIN token_links AS tl ON tl.audit_id = aa.audit_id
LEFT JOIN audit_project_identity AS pi ON pi.audit_id = aa.audit_id
WHERE aa.started_at_ns >= $1 AND aa.started_at_ns < $2
ORDER BY aa.started_at_ns, aa.audit_id
LIMIT $3`, fromNS, toNS, maxOrgRequestRows+1)
	if err != nil {
		return nil, fmt.Errorf("postgres: load org requests: %w", err)
	}
	defer rows.Close()
	requests := make([]orgreport.Request, 0, 1024)
	for rows.Next() {
		var request orgreport.Request
		var endedAtNS sql.NullInt64
		var rootFPR, nodeFPR, identityFPR []byte
		var sessionLink, billingState string
		var quota sql.NullInt64
		var quotaPerUnit sql.NullFloat64
		if err := rows.Scan(&request.AuditID, &request.StartNS, &endedAtNS, &request.Client, &request.Role,
			&rootFPR, &nodeFPR, &sessionLink,
			&request.Tokens.Uncached, &request.Tokens.CacheRead, &request.Tokens.CacheWrite, &request.Tokens.Output,
			&request.UserID, &request.TokenID, &billingState, &quota, &quotaPerUnit, &identityFPR); err != nil {
			return nil, fmt.Errorf("postgres: scan org request: %w", err)
		}
		request.EndNS = request.StartNS
		if endedAtNS.Valid && endedAtNS.Int64 > request.StartNS {
			request.EndNS = endedAtNS.Int64
		}
		request.RootKey = hex.EncodeToString(rootFPR)
		request.NodeKey = hex.EncodeToString(nodeFPR)
		request.IdentityKey = hex.EncodeToString(identityFPR)
		request.Inferred = sessionLink == "inferred"
		if billingState == "billed" && quota.Valid && quotaPerUnit.Valid && quotaPerUnit.Float64 > 0 {
			request.Billed = true
			request.CostUSD = float64(quota.Int64) / quotaPerUnit.Float64
		}
		requests = append(requests, request)
		if len(requests) > maxOrgRequestRows {
			return nil, errors.New("postgres: org report range has too many requests")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate org requests: %w", err)
	}
	return requests, nil
}

var _ orgreport.SessionDataStore = (*Store)(nil)

// LoadOrgSession reads the attribution input of one analysis session: the
// non-rejected requests of one agent-tree root sent with one API key (nil:
// requests without a key fingerprint), in start order, and one sealed
// identity per distinct identity fingerprint among them. Only plaintext
// columns are read; nothing is decrypted here.
func (store *Store) LoadOrgSession(ctx context.Context, agentRootFPR, apiKeyFPR []byte) (orgreport.SessionInput, error) {
	if ctx == nil {
		return orgreport.SessionInput{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return orgreport.SessionInput{}, ErrClosed
	}
	if len(agentRootFPR) != 32 {
		return orgreport.SessionInput{}, errors.New("postgres: agent root fingerprint must be 32 bytes")
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT aa.audit_id, aa.started_at_ns, COALESCE(aa.agent_client, ''), COALESCE(aa.agent_role, ''), aa.agent_node_fpr,
       COALESCE(tl.newapi_user_id, 0), COALESCE(tl.newapi_token_id, 0),
       pi.audit_id IS NOT NULL, pi.identity_fpr
FROM audit_analysis AS aa
JOIN audit_records AS ar ON ar.audit_id = aa.audit_id
LEFT JOIN token_links AS tl ON tl.audit_id = aa.audit_id
LEFT JOIN audit_project_identity AS pi ON pi.audit_id = aa.audit_id
WHERE aa.agent_root_fpr = $1 AND ar.api_key_fpr IS NOT DISTINCT FROM $2 AND ar.forward_status <> $3
ORDER BY aa.started_at_ns, aa.audit_id
LIMIT $4`, agentRootFPR, nullableBytes(apiKeyFPR), ForwardRejected, maxSessionAuditRows)
	if err != nil {
		return orgreport.SessionInput{}, fmt.Errorf("postgres: load org session requests: %w", err)
	}
	defer rows.Close()
	input := orgreport.SessionInput{Requests: make([]orgreport.Request, 0, 64), Identities: make([]orgreport.SealedIdentity, 0, 4)}
	root := hex.EncodeToString(agentRootFPR)
	for rows.Next() {
		request := orgreport.Request{RootKey: root}
		var nodeFPR, identityFPR []byte
		var extracted bool
		if err := rows.Scan(&request.AuditID, &request.StartNS, &request.Client, &request.Role, &nodeFPR,
			&request.UserID, &request.TokenID, &extracted, &identityFPR); err != nil {
			return orgreport.SessionInput{}, fmt.Errorf("postgres: scan org session request: %w", err)
		}
		request.EndNS = request.StartNS
		request.NodeKey = hex.EncodeToString(nodeFPR)
		request.IdentityKey = hex.EncodeToString(identityFPR)
		if extracted {
			input.Extracted++
		}
		input.Requests = append(input.Requests, request)
	}
	if err := rows.Err(); err != nil {
		return orgreport.SessionInput{}, fmt.Errorf("postgres: iterate org session requests: %w", err)
	}
	sealed, err := store.readerDB.QueryContext(ctx, `
SELECT DISTINCT ON (pi.identity_fpr) pi.identity_fpr, pi.audit_id, pi.identity_version, pi.identity_enc
FROM audit_project_identity AS pi
JOIN audit_analysis AS aa ON aa.audit_id = pi.audit_id
JOIN audit_records AS ar ON ar.audit_id = pi.audit_id
WHERE aa.agent_root_fpr = $1 AND ar.api_key_fpr IS NOT DISTINCT FROM $2 AND ar.forward_status <> $3
  AND pi.identity_fpr IS NOT NULL AND pi.identity_enc IS NOT NULL
ORDER BY pi.identity_fpr, pi.audit_id`, agentRootFPR, nullableBytes(apiKeyFPR), ForwardRejected)
	if err != nil {
		return orgreport.SessionInput{}, fmt.Errorf("postgres: load org session identities: %w", err)
	}
	defer sealed.Close()
	for sealed.Next() {
		var fingerprint []byte
		var identity orgreport.SealedIdentity
		if err := sealed.Scan(&fingerprint, &identity.AuditID, &identity.Version, &identity.Enc); err != nil {
			return orgreport.SessionInput{}, fmt.Errorf("postgres: scan org session identity: %w", err)
		}
		identity.Key = hex.EncodeToString(fingerprint)
		input.Identities = append(input.Identities, identity)
	}
	if err := sealed.Err(); err != nil {
		return orgreport.SessionInput{}, fmt.Errorf("postgres: iterate org session identities: %w", err)
	}
	return input, nil
}

// LoadOrgIdentities returns one sealed identity per distinct identity
// fingerprint among the audits of [fromNS, toNS), so each is decrypted once.
func (store *Store) LoadOrgIdentities(ctx context.Context, fromNS, toNS int64) ([]orgreport.SealedIdentity, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT DISTINCT ON (pi.identity_fpr) pi.identity_fpr, pi.audit_id, pi.identity_version, pi.identity_enc
FROM audit_project_identity AS pi
JOIN audit_analysis AS aa ON aa.audit_id = pi.audit_id
WHERE aa.started_at_ns >= $1 AND aa.started_at_ns < $2
  AND pi.identity_fpr IS NOT NULL AND pi.identity_enc IS NOT NULL
ORDER BY pi.identity_fpr, pi.audit_id`, fromNS, toNS)
	if err != nil {
		return nil, fmt.Errorf("postgres: load org identities: %w", err)
	}
	defer rows.Close()
	identities := make([]orgreport.SealedIdentity, 0, 64)
	for rows.Next() {
		var fingerprint []byte
		var identity orgreport.SealedIdentity
		if err := rows.Scan(&fingerprint, &identity.AuditID, &identity.Version, &identity.Enc); err != nil {
			return nil, fmt.Errorf("postgres: scan org identity: %w", err)
		}
		identity.Key = hex.EncodeToString(fingerprint)
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate org identities: %w", err)
	}
	return identities, nil
}
