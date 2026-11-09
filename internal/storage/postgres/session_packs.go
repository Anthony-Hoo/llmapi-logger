package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

// SaveSessionPack upserts one input pack and replaces its member list
// (chat digests only; a session pack has no members).
func (store *Store) SaveSessionPack(ctx context.Context, pack storage.SessionPack, members [][]byte) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	owned, ownedMembers, err := ownSessionPack(pack, members)
	if err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		return upsertSessionPack(tx, owned, ownedMembers)
	})})
}

// ownSessionPack validates a pack and copies it for the writer goroutine.
func ownSessionPack(pack storage.SessionPack, members [][]byte) (storage.SessionPack, [][]byte, error) {
	if len(pack.SessionKey) != 32 || len(pack.PackEnc) == 0 || len(pack.PackHash) != 64 || pack.LastAuditID == "" ||
		(pack.Kind != storage.PackKindSession && pack.Kind != storage.PackKindChatDigest) {
		return storage.SessionPack{}, nil, errors.New("postgres: invalid session pack")
	}
	owned := pack
	owned.SessionKey = append([]byte(nil), pack.SessionKey...)
	owned.APIKeyFPR = append([]byte(nil), pack.APIKeyFPR...)
	owned.PackEnc = append([]byte(nil), pack.PackEnc...)
	if owned.RefMap == "" {
		owned.RefMap = "{}"
	}
	ownedMembers := make([][]byte, 0, len(members))
	for _, member := range members {
		if len(member) != 32 {
			return storage.SessionPack{}, nil, errors.New("postgres: pack member key must be 32 bytes")
		}
		ownedMembers = append(ownedMembers, append([]byte(nil), member...))
	}
	return owned, ownedMembers, nil
}

// upsertSessionPack writes one pack and replaces its member list.
func upsertSessionPack(tx dbTransaction, owned storage.SessionPack, ownedMembers [][]byte) error {
	_, err := tx.Exec(`
INSERT INTO session_packs (session_key, kind, api_key_fpr, newapi_token_id, client, pack_hash, pack_enc, ref_map,
    token_estimate, truncated, members, first_ns, last_ns, last_audit_id, built_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (session_key) DO UPDATE SET
    kind = excluded.kind, api_key_fpr = excluded.api_key_fpr, newapi_token_id = excluded.newapi_token_id,
    client = excluded.client, pack_hash = excluded.pack_hash, pack_enc = excluded.pack_enc, ref_map = excluded.ref_map,
    token_estimate = excluded.token_estimate, truncated = excluded.truncated, members = excluded.members,
    first_ns = excluded.first_ns, last_ns = excluded.last_ns, last_audit_id = excluded.last_audit_id,
    built_at_ns = excluded.built_at_ns`,
		owned.SessionKey, owned.Kind, nullableBytes(owned.APIKeyFPR), owned.NewAPITokenID, nullText(owned.Client),
		owned.PackHash, owned.PackEnc, owned.RefMap, owned.TokenEstimate, owned.Truncated, owned.Members,
		owned.FirstNS, owned.LastNS, owned.LastAuditID, owned.BuiltAtNS)
	if err != nil {
		return fmt.Errorf("postgres writer: upsert session pack: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM session_pack_members WHERE pack_key = $1`, owned.SessionKey); err != nil {
		return fmt.Errorf("postgres writer: clear pack members: %w", err)
	}
	for _, member := range ownedMembers {
		if _, err := tx.Exec(`INSERT INTO session_pack_members (pack_key, session_key) VALUES ($1, $2) ON CONFLICT DO NOTHING`, owned.SessionKey, member); err != nil {
			return fmt.Errorf("postgres writer: add pack member: %w", err)
		}
	}
	return nil
}

// LoadSessionPack returns the pack of a session: its own pack, or the chat
// digest it belongs to. sql.ErrNoRows when there is none.
func (store *Store) LoadSessionPack(ctx context.Context, sessionKey []byte) (storage.SessionPack, error) {
	if ctx == nil {
		return storage.SessionPack{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.SessionPack{}, ErrClosed
	}
	var pack storage.SessionPack
	var client sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT p.session_key, p.kind, p.api_key_fpr, p.newapi_token_id, p.client, p.pack_hash, p.pack_enc, p.ref_map,
       p.token_estimate, p.truncated, p.members, p.first_ns, p.last_ns, p.last_audit_id, p.built_at_ns
FROM session_packs AS p
WHERE p.session_key = $1
   OR p.session_key IN (SELECT m.pack_key FROM session_pack_members AS m WHERE m.session_key = $1)
ORDER BY (p.session_key = $1) DESC, p.built_at_ns DESC
LIMIT 1`, sessionKey).Scan(&pack.SessionKey, &pack.Kind, &pack.APIKeyFPR, &pack.NewAPITokenID, &client, &pack.PackHash,
		&pack.PackEnc, &pack.RefMap, &pack.TokenEstimate, &pack.Truncated, &pack.Members, &pack.FirstNS, &pack.LastNS,
		&pack.LastAuditID, &pack.BuiltAtNS)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.SessionPack{}, sql.ErrNoRows
		}
		return storage.SessionPack{}, fmt.Errorf("postgres: read session pack: %w", err)
	}
	pack.Client = client.String
	return pack, nil
}

// ListChatDigestMembers returns the single-turn chat sessions of one key and
// client whose last request falls in [fromNS, toNS), oldest first.
func (store *Store) ListChatDigestMembers(ctx context.Context, apiKeyFPR []byte, client string, fromNS, toNS int64, limit int) ([]storage.SessionSignals, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	keyCondition := "s.api_key_fpr IS NULL"
	arguments := []any{fromNS, toNS, client, limit}
	if len(apiKeyFPR) != 0 {
		keyCondition = "s.api_key_fpr = $5"
		arguments = append(arguments, apiKeyFPR)
	}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+sessionSignalColumns+`
FROM session_signals AS s
WHERE s.last_ns >= $1 AND s.last_ns < $2 AND COALESCE(s.client, 'unknown') = $3 AND s.kind = 'chat'
  AND s.skip_reason = 'single_turn_chat' AND `+keyCondition+`
ORDER BY s.last_ns, s.session_key
LIMIT $4`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list chat digest members: %w", err)
	}
	defer rows.Close()
	out := make([]storage.SessionSignals, 0)
	for rows.Next() {
		row, err := scanSessionSignals(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan chat digest member: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate chat digest members: %w", err)
	}
	return out, nil
}

// ListPendingDigestMembers returns single-turn chats whose digest bucket still
// has to be rebuilt: new members, and members of digests that were dropped
// because another member left or expired. Oldest first.
func (store *Store) ListPendingDigestMembers(ctx context.Context, limit int) ([]storage.SessionSignals, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if limit <= 0 {
		return nil, errors.New("postgres: pending digest limit must be positive")
	}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+sessionSignalColumns+`
FROM session_signals AS s
WHERE s.digest_pending
ORDER BY s.last_ns, s.session_key
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list pending digest members: %w", err)
	}
	defer rows.Close()
	out := make([]storage.SessionSignals, 0)
	for rows.Next() {
		row, err := scanSessionSignals(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan pending digest member: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate pending digest members: %w", err)
	}
	return out, nil
}

// SaveChatDigests replaces the digest packs of one bucket in one transaction:
// it upserts chunks with their members, deletes the digests named by
// staleKeys (chunks the bucket no longer fills), and clears the pending flag
// of every chat in the bucket. A failure leaves the members pending.
func (store *Store) SaveChatDigests(ctx context.Context, bucket storage.ChatDigestBucket, chunks []storage.ChatDigestChunk, staleKeys [][]byte) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if bucket.ToNS <= bucket.FromNS || bucket.Client == "" {
		return errors.New("postgres: invalid chat digest bucket")
	}
	type ownedChunk struct {
		pack    storage.SessionPack
		members [][]byte
	}
	owned := make([]ownedChunk, 0, len(chunks))
	for _, chunk := range chunks {
		if chunk.Pack.Kind != storage.PackKindChatDigest || len(chunk.Members) == 0 {
			return errors.New("postgres: a digest chunk must be a chat digest with members")
		}
		pack, members, err := ownSessionPack(chunk.Pack, chunk.Members)
		if err != nil {
			return err
		}
		owned = append(owned, ownedChunk{pack: pack, members: members})
	}
	stale := make([][]byte, 0, len(staleKeys))
	for _, key := range staleKeys {
		if len(key) != 32 {
			return errors.New("postgres: digest key must be 32 bytes")
		}
		stale = append(stale, append([]byte(nil), key...))
	}
	apiKey := append([]byte(nil), bucket.APIKeyFPR...)
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		for _, chunk := range owned {
			if err := upsertSessionPack(tx, chunk.pack, chunk.members); err != nil {
				return err
			}
		}
		for _, key := range stale {
			if _, err := tx.Exec(`DELETE FROM session_packs WHERE session_key = $1 AND kind = $2`, key, storage.PackKindChatDigest); err != nil {
				return fmt.Errorf("postgres writer: drop surplus chat digest: %w", err)
			}
		}
		keyCondition := "api_key_fpr IS NULL"
		arguments := []any{bucket.FromNS, bucket.ToNS, bucket.Client}
		if len(apiKey) != 0 {
			keyCondition = "api_key_fpr = $4"
			arguments = append(arguments, apiKey)
		}
		if _, err := tx.Exec(`
UPDATE session_signals SET digest_pending = FALSE
WHERE digest_pending AND last_ns >= $1 AND last_ns < $2 AND COALESCE(client, 'unknown') = $3 AND `+keyCondition, arguments...); err != nil {
			return fmt.Errorf("postgres writer: clear pending digest members: %w", err)
		}
		return nil
	})})
}

// RecordAnalysisView appends one view-log row.
func (store *Store) RecordAnalysisView(ctx context.Context, view storage.AnalysisView) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if len(view.SessionKey) != 32 || (view.ViewerRole != "admin" && view.ViewerRole != "developer") ||
		(view.Resource != "pack" && view.Resource != "facet") {
		return errors.New("postgres: invalid analysis view")
	}
	key := append([]byte(nil), view.SessionKey...)
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO analysis_view_log (at_ns, viewer_role, viewer_user_id, viewer_token_id, resource, session_key)
VALUES ($1, $2, $3, $4, $5, $6)`, view.AtNS, view.ViewerRole, view.ViewerUserID, view.ViewerTokenID, view.Resource, key)
		if err != nil {
			return fmt.Errorf("postgres writer: record analysis view: %w", err)
		}
		return nil
	})})
}
