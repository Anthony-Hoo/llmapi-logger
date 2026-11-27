package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

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
	// DefaultAuditStagingMaxBytes bounds the local staging directory.
	DefaultAuditStagingMaxBytes = 4 << 30
)

// AuditConfig selects how the capture session writes an audit. The default,
// legacy, is the per-operation write path; unified keeps bodies in memory and
// writes an audit in at most four writer operations.
type AuditConfig struct {
	WritePath string `yaml:"write_path"`
	// CommitRetries bounds the retries of the final write of the unified path.
	// The management UI can override it at run time.
	CommitRetries int                `yaml:"commit_retries"`
	Memory        AuditMemoryConfig  `yaml:"memory"`
	Staging       AuditStagingConfig `yaml:"staging"`
}

// AuditStagingConfig is the local staging of body content beyond the memory
// budget (design F.1). Dir is required for unified; when it is set the start
// imports what a previous run left there whatever the write path, so it stays
// configured after switching back to legacy until the directory is empty.
type AuditStagingConfig struct {
	Dir      string `yaml:"dir"`
	MaxBytes int64  `yaml:"max_bytes"`
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
		Staging: AuditStagingConfig{MaxBytes: DefaultAuditStagingMaxBytes},
	}
}

func validateAudit(audit AuditConfig, keyPath string) error {
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
	return validateAuditStaging(audit, keyPath)
}

// validateAuditStaging checks audit.staging: required for unified, an
// absolute path, and apart from the key: not the key's directory, nor
// containing it or inside it, so that a volume holding staged ciphertext
// never holds the key that opens it.
func validateAuditStaging(audit AuditConfig, keyPath string) error {
	staging := audit.Staging
	if staging.MaxBytes <= 0 {
		return fmt.Errorf("audit.staging.max_bytes must be positive, got %d", staging.MaxBytes)
	}
	if staging.Dir == "" {
		if audit.WritePath == AuditWritePathUnified {
			return errors.New("audit.staging.dir is required when audit.write_path is unified")
		}
		return nil
	}
	if !filepath.IsAbs(staging.Dir) {
		return fmt.Errorf("audit.staging.dir must be an absolute path, got %q", staging.Dir)
	}
	dir := filepath.Clean(staging.Dir)
	keyDir, err := filepath.Abs(filepath.Dir(keyPath))
	if err != nil {
		return fmt.Errorf("audit.staging.dir: resolve the key directory: %w", err)
	}
	if within(dir, keyDir) || within(keyDir, dir) {
		return errors.New("audit.staging.dir must not be the directory of key_path, contain it or be inside it")
	}
	return nil
}

// within reports whether path is base or below it.
func within(path, base string) bool {
	relative, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// ValidateAuditCommitRetries checks the retry count of the final write, which
// the configuration file and the run-time settings share.
func ValidateAuditCommitRetries(retries int) error {
	if retries < 0 || retries > MaxAuditCommitRetries {
		return fmt.Errorf("audit.commit_retries must be between 0 and %d", MaxAuditCommitRetries)
	}
	return nil
}
