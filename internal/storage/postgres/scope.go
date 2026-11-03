package postgres

import "llmapi-logger/internal/storage"

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// developerVisibleBlockCodes lists the locally rejected requests a developer
// session may still read.
//
// The rule is deliberately an allow list rather than "hide 401 responses":
// blocked_by and block_code describe the protection policy itself, so every
// interceptor rejection is hidden by default and a new interceptor stays hidden
// until someone explicitly decides its block code is safe to expose. Inverting
// this into a deny list would silently leak the next policy interceptor that
// blocks with a status other than 401.
//
// body_too_large is listed because a request-size limit is a property of the
// caller's own request rather than of the site's protection rules, and seeing it
// is what lets a developer fix their agent.
var developerVisibleBlockCodes = []string{"body_too_large"}

// AuditScope restricts every read to the audits produced by one NewAPI user API
// key. Fingerprint is required; TokenID additionally admits records that were
// attributed through the NewAPI request log before this database ever stored
// fingerprints.
type AuditScope = storage.AuditScope

// AuditScopeRow is the minimal ownership and visibility projection of one audit,
// read by the primary key so detail endpoints can authorize without paying for
// the full detail projection.
type AuditScopeRow = storage.AuditScopeRow

func visibleToDeveloper(forwardStatus string, blockCode *string) bool {
	if forwardStatus != ForwardRejected {
		return true
	}
	if blockCode == nil {
		return false
	}
	for _, code := range developerVisibleBlockCodes {
		if *blockCode == code {
			return true
		}
	}
	return false
}

// condition renders the same rule as SQL, for the audit list query. The list
// already joins token_links as t and audit_records as a.
func scopeCondition(scope *AuditScope, offset ...int) (string, []any) {
	return scopeConditionWithAliases(scope, "a", "t", offset...)
}

func scopeConditionWithAliases(scope *AuditScope, auditAlias, tokenAlias string, offset ...int) (string, []any) {
	start := 0
	if len(offset) > 0 {
		start = offset[0]
	}
	arguments := []any{scope.Fingerprint}
	ownership := auditAlias + ".api_key_fpr = " + parameter(start+1)
	if scope.TokenID != nil {
		ownership = "(" + auditAlias + ".api_key_fpr = " + parameter(start+1) + " OR " + tokenAlias + ".newapi_token_id = " + parameter(start+2) + ")"
		arguments = append(arguments, *scope.TokenID)
	}
	visible := auditAlias + ".forward_status <> " + parameter(start+len(arguments)+1)
	arguments = append(arguments, ForwardRejected)
	if len(developerVisibleBlockCodes) > 0 {
		visible = "(" + visible + " OR " + auditAlias + ".block_code IN (" + placeholders(len(developerVisibleBlockCodes), start+len(arguments)) + "))"
		for _, code := range developerVisibleBlockCodes {
			arguments = append(arguments, code)
		}
	}
	return ownership + " AND " + visible, arguments
}

// QueryAuditScope reads only what authorization needs. Callers must treat a
// missing row and an out-of-scope row identically so the response never reveals
// whether some other tenant's audit exists.
func (store *Store) QueryAuditScope(ctx context.Context, auditID string) (AuditScopeRow, error) {
	if ctx == nil {
		return AuditScopeRow{}, errors.New("postgres: nil context")
	}
	if auditID == "" {
		return AuditScopeRow{}, errors.New("postgres: empty audit id")
	}
	if store == nil || store.isClosed() {
		return AuditScopeRow{}, ErrClosed
	}
	var row AuditScopeRow
	err := store.readerDB.QueryRowContext(ctx, `
SELECT a.api_key_fpr, t.newapi_token_id, a.forward_status, a.block_code
FROM audit_records AS a
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
WHERE a.audit_id = $1`, auditID).Scan(&row.APIKeyFPR, &row.NewAPITokenID, &row.ForwardStatus, &row.BlockCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuditScopeRow{}, sql.ErrNoRows
		}
		return AuditScopeRow{}, fmt.Errorf("postgres: read audit scope: %w", err)
	}
	return row, nil
}
