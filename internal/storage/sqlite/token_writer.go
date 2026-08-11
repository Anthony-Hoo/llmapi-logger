package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

// UpsertTokenLink persists the latest non-secret NewAPI token snapshot for an
// existing audit. Repeating the same link is idempotent; a later call replaces
// the snapshot through the same ordered writer used by all audit data.
func (store *Store) UpsertTokenLink(ctx context.Context, link TokenLink) error {
	if err := validateTokenLink(link); err != nil {
		return err
	}
	return store.submitSync(ctx, writeRequest{kind: writeUpsertTokenLink, data: link})
}

func upsertTokenLink(transaction *sql.Tx, link TokenLink) error {
	_, err := transaction.Exec(`
INSERT INTO token_links (
    audit_id, newapi_token_id, token_name, masked_key, linked_at_ns
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(audit_id) DO UPDATE SET
    newapi_token_id = excluded.newapi_token_id,
    token_name = excluded.token_name,
    masked_key = excluded.masked_key,
    linked_at_ns = excluded.linked_at_ns`,
		link.AuditID,
		link.NewAPITokenID,
		link.TokenName,
		link.MaskedKey,
		link.LinkedAtNS,
	)
	if err != nil {
		return fmt.Errorf("sqlite writer: upsert token link: %w", err)
	}
	return nil
}
