package storage

// ProjectFingerprintSize is the length of every project identity tag.
const ProjectFingerprintSize = 32

// ProjectIdentityRow is one audit_project_identity row
// (doc/features/23-org-project-reports.md section 4). It is derived data:
// outside the integrity chain and deleted with its audit. Paths, remotes and
// declared names exist only inside IdentityEnc; the fingerprints are keyed
// HMAC tags that group equal values without revealing them.
type ProjectIdentityRow struct {
	AuditID       string
	Version       int
	ExtractedAtNS int64
	Source        string
	// BodyScanned reports whether text and body signals were read; false
	// means only headers were available.
	BodyScanned bool
	IdentityFPR []byte
	RemoteFPR   []byte
	RootFPR     []byte
	CwdFPR      []byte
	IdentityEnc []byte
}

// ProjectBackfillCursor is the keyset position of the identity backfill,
// which walks newest first.
type ProjectBackfillCursor struct {
	StartedAtNS int64
	AuditID     string
}

// ProjectBackfillCandidate is one analysed audit without a current identity.
type ProjectBackfillCandidate struct {
	AuditID     string
	StartedAtNS int64
	Protocol    string
}
