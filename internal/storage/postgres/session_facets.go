package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

const sessionPackColumns = `p.session_key, p.kind, p.api_key_fpr, p.newapi_token_id, COALESCE(p.client, ''), p.pack_hash, p.pack_enc,
    p.ref_map, p.token_estimate, p.truncated, p.members, p.first_ns, p.last_ns, p.last_audit_id, p.built_at_ns`

func scanSessionPack(scanner interface{ Scan(...any) error }) (storage.SessionPack, error) {
	var pack storage.SessionPack
	err := scanner.Scan(&pack.SessionKey, &pack.Kind, &pack.APIKeyFPR, &pack.NewAPITokenID, &pack.Client, &pack.PackHash,
		&pack.PackEnc, &pack.RefMap, &pack.TokenEstimate, &pack.Truncated, &pack.Members, &pack.FirstNS, &pack.LastNS,
		&pack.LastAuditID, &pack.BuiltAtNS)
	return pack, err
}

// ListFacetCandidates returns the packs that went quiet before settledBeforeNS
// and have no facet for their current text, prompt version and model, or
// whose last attempt failed for a transient reason. Most recent first.
func (store *Store) ListFacetCandidates(ctx context.Context, settledBeforeNS int64, promptVersion, model string, limit int) ([]storage.SessionPack, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	if limit <= 0 {
		return nil, errors.New("postgres: facet candidate limit must be positive")
	}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT `+sessionPackColumns+`
FROM session_packs AS p
LEFT JOIN session_facets AS f ON f.session_key = p.session_key
WHERE p.last_ns < $1
  AND (f.session_key IS NULL OR f.pack_hash <> p.pack_hash OR f.prompt_version <> $2 OR f.model <> $3 OR f.facet_status = 'failed')
ORDER BY p.last_ns DESC, p.session_key
LIMIT $4`, settledBeforeNS, promptVersion, model, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list facet candidates: %w", err)
	}
	defer rows.Close()
	out := make([]storage.SessionPack, 0)
	for rows.Next() {
		pack, err := scanSessionPack(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan facet candidate: %w", err)
		}
		out = append(out, pack)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate facet candidates: %w", err)
	}
	return out, nil
}

// SaveSessionFacet upserts one facet and replaces its instruction and skill
// fingerprints. A failed attempt keeps counting attempts on the same row.
func (store *Store) SaveSessionFacet(ctx context.Context, facet storage.SessionFacet, fprs []storage.SessionTextFPR) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if len(facet.SessionKey) != 32 || facet.PromptVersion == "" || facet.Model == "" ||
		(facet.Status != "ok" && facet.Status != "invalid" && facet.Status != "failed") {
		return errors.New("postgres: invalid session facet")
	}
	owned := facet
	owned.SessionKey = append([]byte(nil), facet.SessionKey...)
	owned.APIKeyFPR = append([]byte(nil), facet.APIKeyFPR...)
	owned.TextEnc = append([]byte(nil), facet.TextEnc...)
	for _, field := range []*string{&owned.Friction, &owned.Items, &owned.InvalidFields} {
		if *field == "" {
			*field = "[]"
		}
	}
	ownedFPRs := make([]storage.SessionTextFPR, 0, len(fprs))
	for _, fpr := range fprs {
		if len(fpr.FPR) != 32 {
			return errors.New("postgres: facet fingerprint must be 32 bytes")
		}
		ownedFPRs = append(ownedFPRs, storage.SessionTextFPR{Source: fpr.Source, FPR: append([]byte(nil), fpr.FPR...), APIKeyFPR: append([]byte(nil), fpr.APIKeyFPR...), SeenAtNS: fpr.SeenAtNS})
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO session_facets (session_key, kind, api_key_fpr, newapi_token_id, last_ns, pack_hash, prompt_version, model,
    facet_status, task_type, outcome, collaboration, work_relevance, friction, items, invalid_fields, text_enc,
    input_tokens, output_tokens, latency_ms, attempts, created_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, 1, $21)
ON CONFLICT (session_key) DO UPDATE SET
    kind = excluded.kind, api_key_fpr = excluded.api_key_fpr, newapi_token_id = excluded.newapi_token_id,
    last_ns = excluded.last_ns, pack_hash = excluded.pack_hash, prompt_version = excluded.prompt_version,
    model = excluded.model, facet_status = excluded.facet_status, task_type = excluded.task_type,
    outcome = excluded.outcome, collaboration = excluded.collaboration, work_relevance = excluded.work_relevance,
    friction = excluded.friction, items = excluded.items, invalid_fields = excluded.invalid_fields,
    text_enc = excluded.text_enc, input_tokens = excluded.input_tokens, output_tokens = excluded.output_tokens,
    latency_ms = excluded.latency_ms,
    attempts = CASE WHEN session_facets.pack_hash = excluded.pack_hash AND session_facets.facet_status = 'failed'
                    THEN session_facets.attempts + 1 ELSE 1 END,
    created_at_ns = excluded.created_at_ns`,
			owned.SessionKey, owned.Kind, nullableBytes(owned.APIKeyFPR), owned.NewAPITokenID, owned.LastNS, owned.PackHash,
			owned.PromptVersion, owned.Model, owned.Status, nullText(owned.TaskType), nullText(owned.Outcome),
			nullText(owned.Collaboration), nullText(owned.WorkRelevance), owned.Friction, owned.Items, owned.InvalidFields,
			nullableBytes(owned.TextEnc), owned.InputTokens, owned.OutputTokens, owned.LatencyMS, owned.CreatedAtNS)
		if err != nil {
			return fmt.Errorf("postgres writer: upsert session facet: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM session_text_fprs WHERE session_key = $1 AND source IN ($2, $3)`,
			owned.SessionKey, storage.TextSourceFacetInstruction, storage.TextSourceFacetSkill); err != nil {
			return fmt.Errorf("postgres writer: clear facet fingerprints: %w", err)
		}
		for _, fpr := range ownedFPRs {
			if _, err := tx.Exec(`
INSERT INTO session_text_fprs (session_key, source, fpr, api_key_fpr, seen_at_ns)
VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_key, source, fpr) DO UPDATE SET seen_at_ns = excluded.seen_at_ns`,
				owned.SessionKey, fpr.Source, fpr.FPR, nullableBytes(fpr.APIKeyFPR), fpr.SeenAtNS); err != nil {
				return fmt.Errorf("postgres writer: add facet fingerprint: %w", err)
			}
		}
		return nil
	})})
}

// LoadSessionFacet returns the facet of a session: its own, or that of the
// chat digest it belongs to. sql.ErrNoRows when there is none.
func (store *Store) LoadSessionFacet(ctx context.Context, sessionKey []byte) (storage.SessionFacet, error) {
	if ctx == nil {
		return storage.SessionFacet{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.SessionFacet{}, ErrClosed
	}
	var facet storage.SessionFacet
	var taskType, outcome, collaboration, relevance sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT f.session_key, f.kind, f.api_key_fpr, f.newapi_token_id, f.last_ns, f.pack_hash, f.prompt_version, f.model,
       f.facet_status, f.task_type, f.outcome, f.collaboration, f.work_relevance, f.friction, f.items, f.invalid_fields,
       f.text_enc, f.input_tokens, f.output_tokens, f.latency_ms, f.attempts, f.created_at_ns
FROM session_facets AS f
WHERE f.session_key = $1
   OR f.session_key IN (SELECT m.pack_key FROM session_pack_members AS m WHERE m.session_key = $1)
ORDER BY (f.session_key = $1) DESC, f.created_at_ns DESC
LIMIT 1`, sessionKey).Scan(&facet.SessionKey, &facet.Kind, &facet.APIKeyFPR, &facet.NewAPITokenID, &facet.LastNS,
		&facet.PackHash, &facet.PromptVersion, &facet.Model, &facet.Status, &taskType, &outcome, &collaboration, &relevance,
		&facet.Friction, &facet.Items, &facet.InvalidFields, &facet.TextEnc, &facet.InputTokens, &facet.OutputTokens,
		&facet.LatencyMS, &facet.Attempts, &facet.CreatedAtNS)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.SessionFacet{}, sql.ErrNoRows
		}
		return storage.SessionFacet{}, fmt.Errorf("postgres: read session facet: %w", err)
	}
	facet.TaskType, facet.Outcome, facet.Collaboration, facet.WorkRelevance = taskType.String, outcome.String, collaboration.String, relevance.String
	return facet, nil
}

// SaveFacetCalibration appends one calibration result.
func (store *Store) SaveFacetCalibration(ctx context.Context, calibration storage.FacetCalibration) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`INSERT INTO facet_calibrations (created_at_ns, prompt_version, model, samples, agreement) VALUES ($1, $2, $3, $4, $5)`,
			calibration.CreatedAtNS, calibration.PromptVersion, calibration.Model, calibration.Samples, calibration.Agreement)
		if err != nil {
			return fmt.Errorf("postgres writer: save facet calibration: %w", err)
		}
		return nil
	})})
}

// LatestFacetCalibration returns the newest calibration of one prompt version
// and model, or sql.ErrNoRows.
func (store *Store) LatestFacetCalibration(ctx context.Context, promptVersion, model string) (storage.FacetCalibration, error) {
	if ctx == nil {
		return storage.FacetCalibration{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.FacetCalibration{}, ErrClosed
	}
	var calibration storage.FacetCalibration
	err := store.readerDB.QueryRowContext(ctx, `
SELECT id, created_at_ns, prompt_version, model, samples, agreement FROM facet_calibrations
WHERE prompt_version = $1 AND model = $2 ORDER BY id DESC LIMIT 1`, promptVersion, model).Scan(
		&calibration.ID, &calibration.CreatedAtNS, &calibration.PromptVersion, &calibration.Model, &calibration.Samples, &calibration.Agreement)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.FacetCalibration{}, sql.ErrNoRows
		}
		return storage.FacetCalibration{}, fmt.Errorf("postgres: read facet calibration: %w", err)
	}
	return calibration, nil
}
