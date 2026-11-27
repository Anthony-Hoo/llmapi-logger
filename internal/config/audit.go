package config

import "fmt"

// Audit write paths (doc/design/issue-59-stage3-write-path.md H.1).
const (
	AuditWritePathLegacy  = "legacy"
	AuditWritePathUnified = "unified"
)

// Audit capture defaults (design F.1 and H.3).
const (
	DefaultAuditCommitRetries     = 3
	MaxAuditCommitRetries         = 5
	DefaultAuditMemoryStageBytes  = 8 << 20
	DefaultAuditMemoryGlobalBytes = 256 << 20
	// MinAuditMemoryStageBytes keeps every chunk that leaves memory a whole
	// 1 MiB chunk.
	MinAuditMemoryStageBytes = 1 << 20
)

// AuditConfig selects how the capture session writes an audit. The default,
// legacy, is the per-operation write path; unified keeps bodies in memory and
// writes an audit in at most four writer operations.
type AuditConfig struct {
	WritePath string `yaml:"write_path"`
	// CommitRetries bounds the retries of the final write of the unified path.
	// The management UI can override it at run time.
	CommitRetries int               `yaml:"commit_retries"`
	Memory        AuditMemoryConfig `yaml:"memory"`
}

// AuditMemoryConfig is the plaintext budget the unified path holds in memory,
// per stage and for the whole process.
type AuditMemoryConfig struct {
	StageBytes  int64 `yaml:"stage_bytes"`
	GlobalBytes int64 `yaml:"global_bytes"`
}

// DefaultAudit returns the audit section with every default filled.
func DefaultAudit() AuditConfig {
	return AuditConfig{
		WritePath:     AuditWritePathLegacy,
		CommitRetries: DefaultAuditCommitRetries,
		Memory: AuditMemoryConfig{
			StageBytes:  DefaultAuditMemoryStageBytes,
			GlobalBytes: DefaultAuditMemoryGlobalBytes,
		},
	}
}

func validateAudit(audit AuditConfig) error {
	if audit.WritePath != AuditWritePathLegacy && audit.WritePath != AuditWritePathUnified {
		return fmt.Errorf("audit.write_path must be legacy or unified, got %q", audit.WritePath)
	}
	if err := ValidateAuditCommitRetries(audit.CommitRetries); err != nil {
		return err
	}
	if audit.Memory.StageBytes < MinAuditMemoryStageBytes {
		return fmt.Errorf("audit.memory.stage_bytes must be at least %d, got %d", MinAuditMemoryStageBytes, audit.Memory.StageBytes)
	}
	if audit.Memory.StageBytes > audit.Memory.GlobalBytes {
		return fmt.Errorf("audit.memory.stage_bytes (%d) must not exceed audit.memory.global_bytes (%d)", audit.Memory.StageBytes, audit.Memory.GlobalBytes)
	}
	return nil
}

// ValidateAuditCommitRetries checks the retry count of the final write, which
// the configuration file and the run-time settings share.
func ValidateAuditCommitRetries(retries int) error {
	if retries < 0 || retries > MaxAuditCommitRetries {
		return fmt.Errorf("audit.commit_retries must be between 0 and %d", MaxAuditCommitRetries)
	}
	return nil
}
