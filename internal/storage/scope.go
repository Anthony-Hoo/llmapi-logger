package storage

import (
	"bytes"

	"errors"
	"fmt"
)

// AuditScope restricts every read to the audits produced by one NewAPI user API
// key. Fingerprint is required; TokenID additionally admits records that were
// attributed through the NewAPI request log before this database ever stored
// fingerprints.
type AuditScope struct {
	Fingerprint []byte
	TokenID     *int64
}

// AuditScopeRow is the minimal ownership and visibility projection of one audit,
// read by the primary key so detail endpoints can authorize without paying for
// the full detail projection.
type AuditScopeRow struct {
	APIKeyFPR     []byte
	NewAPITokenID *int64
	ForwardStatus string
	BlockCode     *string
}

// Validate rejects a scope that could not have come from a real session.
func (scope *AuditScope) Validate() error {
	if scope == nil {
		return errors.New("sqlite: nil audit scope")
	}
	if len(scope.Fingerprint) != APIKeyFingerprintSize {
		return fmt.Errorf("sqlite: audit scope fingerprint must be %d bytes", APIKeyFingerprintSize)
	}
	if scope.TokenID != nil && *scope.TokenID < 0 {
		return errors.New("sqlite: audit scope token id must not be negative")
	}
	return nil
}

// Allows reports whether one audit is readable in this scope. It is the Go
// counterpart of condition and must stay in step with it: both combine
// ownership with the policy-block exclusion, and neither may be applied alone.
func (scope *AuditScope) Allows(row AuditScopeRow) bool {
	if scope == nil {
		return false
	}
	owned := len(row.APIKeyFPR) != 0 && bytes.Equal(row.APIKeyFPR, scope.Fingerprint)
	if !owned && scope.TokenID != nil && row.NewAPITokenID != nil {
		owned = *row.NewAPITokenID == *scope.TokenID
	}
	return owned && visibleToDeveloper(row.ForwardStatus, row.BlockCode)
}

func visibleToDeveloper(status string, code *string) bool {
	return status != ForwardRejected || (code != nil && *code == "body_too_large")
}
