package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// AuditWritePathUnified is the only capture write path. audit.write_path
// may still name it; the legacy path it used to select against was removed
// (doc/design/issue-59-stage3-write-path.md R.8).
const AuditWritePathUnified = "unified"

// auditWritePathLegacy is the removed value, recognised to say so.
const auditWritePathLegacy = "legacy"

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

// AuditConfig is how the capture session writes an audit: bodies are kept
// in memory and an audit is written in at most four writer operations, plus
// one for each stage that spills to staging.
type AuditConfig struct {
	// WritePath is accepted when absent or "unified" and selects nothing; the
	// removed "legacy" is refused.
	WritePath string `yaml:"write_path"`
	// CommitRetries bounds the retries of the final write of the unified path.
	// The management UI can override it at run time.
	CommitRetries int                `yaml:"commit_retries"`
	Memory        AuditMemoryConfig  `yaml:"memory"`
	Staging       AuditStagingConfig `yaml:"staging"`
}

// AuditStagingConfig is the local staging of body content beyond the memory
// budget (design F.1). Dir is required; the start imports what a previous run
// left there before interrupted audits are recovered.
type AuditStagingConfig struct {
	Dir      string `yaml:"dir"`
	MaxBytes int64  `yaml:"max_bytes"`
}

// AuditMemoryConfig is the plaintext budget the capture session holds in memory,
// per stage and for the whole process.
type AuditMemoryConfig struct {
	StageBytes  int64 `yaml:"stage_bytes"`
	GlobalBytes int64 `yaml:"global_bytes"`
}

// DefaultAudit returns the audit section with every default filled.
func DefaultAudit() AuditConfig {
	return AuditConfig{
		WritePath:     AuditWritePathUnified,
		CommitRetries: DefaultAuditCommitRetries,
		Memory: AuditMemoryConfig{
			StageBytes:  DefaultAuditMemoryStageBytes,
			GlobalBytes: DefaultAuditMemoryGlobalBytes,
		},
		Staging: AuditStagingConfig{MaxBytes: DefaultAuditStagingMaxBytes},
	}
}

func validateAudit(audit AuditConfig, keyPath string) error {
	switch audit.WritePath {
	case "", AuditWritePathUnified:
	case auditWritePathLegacy:
		return errors.New("audit.write_path legacy was removed in this version: unified is the only write path; remove the key or set it to unified, and configure audit.staging.dir")
	default:
		return fmt.Errorf("audit.write_path must be unified (or absent), got %q", audit.WritePath)
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

// validateAuditStaging checks audit.staging: required, an absolute path, and apart from the key: not the key's directory, nor
// containing it or inside it, so that a volume holding staged ciphertext
// never holds the key that opens it.
func validateAuditStaging(audit AuditConfig, keyPath string) error {
	staging := audit.Staging
	if staging.MaxBytes <= 0 {
		return fmt.Errorf("audit.staging.max_bytes must be positive, got %d", staging.MaxBytes)
	}
	if staging.Dir == "" {
		return errors.New("audit.staging.dir is required: the capture session keeps body content beyond the memory budget there")
	}
	if !filepath.IsAbs(staging.Dir) {
		return fmt.Errorf("audit.staging.dir must be an absolute path, got %q", staging.Dir)
	}
	dir := filepath.Clean(staging.Dir)
	keyDir, err := filepath.Abs(filepath.Dir(keyPath))
	if err != nil {
		return fmt.Errorf("audit.staging.dir: resolve the key directory: %w", err)
	}
	// The key file itself may be a link, so its real directory is checked too.
	if overlap(dir, keyDir) || overlap(physical(dir), filepath.Dir(physical(keyPath))) {
		return errors.New("audit.staging.dir must not be the directory of key_path, contain it or be inside it")
	}
	return nil
}

// overlap reports whether directories a and b are the same or one contains
// the other, either as written or where they really are once symbolic links
// are followed. It runs when the configuration is loaded: a link changed while
// the proxy runs is not seen.
func overlap(a, b string) bool {
	if within(a, b) || within(b, a) {
		return true
	}
	a, b = physical(a), physical(b)
	return within(a, b) || within(b, a)
}

// physical returns the absolute path with every symbolic link along it
// followed. The part that does not exist yet is appended as written, so a
// directory created later is compared by where it will be created; a link
// whose target does not exist yet is followed by its text. When the path
// cannot be resolved it is returned as written, which the lexical check
// still covers.
func physical(path string) string {
	written, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	current, missing := written, ""
	// Each step either follows one dangling link or moves up one directory;
	// the bound stops a loop of dangling links.
	for step := 0; step < 255; step++ {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, missing)
		}
		if info, err := os.Lstat(current); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil {
				return written
			}
			if !filepath.IsAbs(target) {
				// The link exists, so its directory does: resolve it before
				// joining, so that a ".." in the target is taken from the real
				// directory.
				parent := filepath.Dir(current)
				if resolved, err := filepath.EvalSymlinks(parent); err == nil {
					parent = resolved
				}
				target = filepath.Join(parent, target)
			}
			current = filepath.Clean(target)
			continue
		}
		parent := filepath.Dir(current)
		if parent == current {
			return written
		}
		missing = filepath.Join(filepath.Base(current), missing)
		current = parent
	}
	return written
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
