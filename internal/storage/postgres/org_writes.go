package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

// orgWrite is one organisation-report write executed by the single writer
// inside its per-operation savepoint (writeOrg).
type orgWrite func(dbTransaction) error

// submitOrg queues an org write and waits like the analysis writes do.
func (store *Store) submitOrg(ctx context.Context, write orgWrite) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeOrg, data: write})
}

// submitOrgAdmin queues an administrator change with the policy lifecycle:
// once admitted, the caller waits for a definitive commit or rollback, so the
// service can publish a snapshot that matches the database.
func (store *Store) submitOrgAdmin(ctx context.Context, write orgWrite) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitPolicySync(ctx, writeRequest{kind: writeOrg, data: write})
}

// SaveProjectIdentity upserts one audit's project identity. A missing audit
// (retention won the race) is an isolated sql.ErrNoRows. The row is derived
// data outside every integrity digest.
func (store *Store) SaveProjectIdentity(ctx context.Context, row storage.ProjectIdentityRow) error {
	if err := validateProjectIdentityRow(row); err != nil {
		return err
	}
	owned := cloneProjectIdentityRow(row)
	return store.submitOrg(ctx, func(transaction dbTransaction) error {
		return saveProjectIdentity(transaction, owned)
	})
}

func validateProjectIdentityRow(row storage.ProjectIdentityRow) error {
	if row.AuditID == "" || row.Version <= 0 || row.ExtractedAtNS <= 0 || row.Source == "" {
		return localWriteError("postgres: invalid project identity row")
	}
	for _, tag := range [][]byte{row.IdentityFPR, row.RemoteFPR, row.RootFPR, row.CwdFPR} {
		if tag != nil && len(tag) != storage.ProjectFingerprintSize {
			return localWriteError("postgres: invalid project identity fingerprint")
		}
	}
	return nil
}

func cloneProjectIdentityRow(row storage.ProjectIdentityRow) storage.ProjectIdentityRow {
	clone := func(value []byte) []byte {
		if value == nil {
			return nil
		}
		return append([]byte(nil), value...)
	}
	row.IdentityFPR, row.RemoteFPR, row.RootFPR, row.CwdFPR = clone(row.IdentityFPR), clone(row.RemoteFPR), clone(row.RootFPR), clone(row.CwdFPR)
	row.IdentityEnc = clone(row.IdentityEnc)
	return row
}

func saveProjectIdentity(transaction dbTransaction, row storage.ProjectIdentityRow) error {
	var exists int
	if err := transaction.QueryRow(`SELECT 1 FROM audit_records WHERE audit_id = $1`, row.AuditID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("postgres writer: project identity for unknown audit: %w", sql.ErrNoRows)
		}
		return fmt.Errorf("postgres writer: read project identity audit: %w", err)
	}
	_, err := transaction.Exec(`
INSERT INTO audit_project_identity (
    audit_id, identity_version, extracted_at_ns, source, body_scanned,
    identity_fpr, remote_fpr, repo_root_fpr, cwd_fpr, identity_enc
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (audit_id) DO UPDATE SET
    identity_version = EXCLUDED.identity_version,
    extracted_at_ns = EXCLUDED.extracted_at_ns,
    source = EXCLUDED.source,
    body_scanned = EXCLUDED.body_scanned,
    identity_fpr = EXCLUDED.identity_fpr,
    remote_fpr = EXCLUDED.remote_fpr,
    repo_root_fpr = EXCLUDED.repo_root_fpr,
    cwd_fpr = EXCLUDED.cwd_fpr,
    identity_enc = EXCLUDED.identity_enc`,
		row.AuditID, row.Version, row.ExtractedAtNS, row.Source, boolInt(row.BodyScanned),
		row.IdentityFPR, row.RemoteFPR, row.RootFPR, row.CwdFPR, row.IdentityEnc)
	if err != nil {
		return fmt.Errorf("postgres writer: save project identity: %w", err)
	}
	return nil
}

// ListProjectIdentityBackfillCandidates returns up to limit analysed audits
// whose identity row is missing or older than version, newest first; before
// continues below a cursor.
func (store *Store) ListProjectIdentityBackfillCandidates(ctx context.Context, version int, before *storage.ProjectBackfillCursor, limit int) ([]storage.ProjectBackfillCandidate, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if version <= 0 || limit <= 0 || limit > maxParserReadLimit {
		return nil, errors.New("postgres: invalid project identity backfill request")
	}
	query := `
SELECT aa.audit_id, aa.started_at_ns, aa.protocol
FROM audit_analysis AS aa
LEFT JOIN audit_project_identity AS pi ON pi.audit_id = aa.audit_id
WHERE (pi.audit_id IS NULL OR pi.identity_version < $1)`
	arguments := []any{version}
	if before != nil {
		query += `
  AND (aa.started_at_ns < $2 OR (aa.started_at_ns = $3 AND aa.audit_id < $4))`
		arguments = append(arguments, before.StartedAtNS, before.StartedAtNS, before.AuditID)
	}
	query += `
ORDER BY aa.started_at_ns DESC, aa.audit_id DESC
LIMIT ` + parameter(len(arguments)+1)
	arguments = append(arguments, limit)
	rows, err := store.readerDB.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list project identity candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]storage.ProjectBackfillCandidate, 0, limit)
	for rows.Next() {
		var candidate storage.ProjectBackfillCandidate
		if err := rows.Scan(&candidate.AuditID, &candidate.StartedAtNS, &candidate.Protocol); err != nil {
			return nil, fmt.Errorf("postgres: scan project identity candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate project identity candidates: %w", err)
	}
	return candidates, nil
}

// LoadProjectIdentity reads one stored row (tests and diagnostics).
func (store *Store) LoadProjectIdentity(ctx context.Context, auditID string) (storage.ProjectIdentityRow, error) {
	if store == nil || store.isClosed() {
		return storage.ProjectIdentityRow{}, ErrClosed
	}
	var row storage.ProjectIdentityRow
	var bodyScanned int64
	err := store.readerDB.QueryRowContext(ctx, `
SELECT audit_id, identity_version, extracted_at_ns, source, body_scanned,
       identity_fpr, remote_fpr, repo_root_fpr, cwd_fpr, identity_enc
FROM audit_project_identity WHERE audit_id = $1`, auditID).Scan(
		&row.AuditID, &row.Version, &row.ExtractedAtNS, &row.Source, &bodyScanned,
		&row.IdentityFPR, &row.RemoteFPR, &row.RootFPR, &row.CwdFPR, &row.IdentityEnc)
	row.BodyScanned = bodyScanned != 0
	return row, err
}
