package storage

// Sections of runtime_settings: the settings an administrator saves from the
// management UI. A saved section overrides the configuration file for the
// fields it holds.
const (
	SettingsSessionAnalysis = "session_analysis"
	SettingsOrgReports      = "org_reports"
	// SettingsAuditCapture holds the CommitAudit retry count. The database
	// accepts it from migration 007 on.
	SettingsAuditCapture = "audit_capture"
)

// RuntimeSettings is one row of runtime_settings. Settings is plaintext JSON
// of the saved fields; SecretEnc is the section's secret as AES-GCM
// ciphertext, or empty when none is saved.
type RuntimeSettings struct {
	Section     string
	Settings    string
	SecretEnc   []byte
	UpdatedAtNS int64
}
