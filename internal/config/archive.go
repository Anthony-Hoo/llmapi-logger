package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Archive modes (doc/design/issue-59-stage4-cold-archive.md L.1).
const (
	ArchiveModeOff               = "off"
	ArchiveModeExportOnly        = "export_only"
	ArchiveModeArchiveThenDelete = "archive_then_delete"
)

// Archive defaults (L.1, P items 3, 5 and 9).
const (
	DefaultArchiveRunAt                = "03:00"
	DefaultArchiveSegmentMaxBytes      = 256 << 20
	DefaultArchiveConversationMinTurns = 16
	DefaultArchiveConversationMinBytes = 16 << 20
	DefaultArchivePassAudits           = 5000
	DefaultArchiveRunDeadlineMinutes   = 240
	DefaultArchiveVerifySample         = 0.05

	MinArchiveSegmentMaxBytes = 16 << 20
	MaxArchiveSegmentMaxBytes = 4 << 30
	// MaxArchivePassAudits is the largest page the export snapshot selects.
	MaxArchivePassAudits         = 10000
	MaxArchiveConversationTurns  = 1_000_000
	MaxArchiveRunDeadlineMinutes = 24 * 60
)

// ArchiveConfig is the cold archive (L.1). It is off by default: retention
// then keeps deleting directly. With export_only or archive_then_delete the
// archive runner exports due audits once a day and retention's direct delete
// is not assembled (5.7).
type ArchiveConfig struct {
	Mode string `yaml:"mode"`
	// Dir is the archive directory, an absolute path apart from the key and
	// the staging directory.
	Dir     string `yaml:"dir"`
	Encrypt bool   `yaml:"encrypt"`
	// RunAt is the local daily run time HH:MM in Timezone.
	RunAt string `yaml:"run_at"`
	// Timezone is an IANA name; empty means org_reports.timezone (P item 1).
	Timezone             string  `yaml:"timezone"`
	SegmentMaxBytes      int64   `yaml:"segment_max_bytes"`
	ConversationMinTurns int     `yaml:"conversation_min_turns"`
	ConversationMinBytes int64   `yaml:"conversation_min_bytes"`
	PassAudits           int     `yaml:"pass_audits"`
	RunDeadlineMinutes   int     `yaml:"run_deadline_minutes"`
	VerifySample         float64 `yaml:"verify_sample"`
}

// Enabled reports whether the archive runs (mode is not off).
func (archive ArchiveConfig) Enabled() bool {
	return archive.Mode != "" && archive.Mode != ArchiveModeOff
}

// DefaultArchive returns the disabled section with every default filled.
func DefaultArchive() ArchiveConfig {
	return ArchiveConfig{
		Mode:                 ArchiveModeOff,
		Encrypt:              true,
		RunAt:                DefaultArchiveRunAt,
		SegmentMaxBytes:      DefaultArchiveSegmentMaxBytes,
		ConversationMinTurns: DefaultArchiveConversationMinTurns,
		ConversationMinBytes: DefaultArchiveConversationMinBytes,
		PassAudits:           DefaultArchivePassAudits,
		RunDeadlineMinutes:   DefaultArchiveRunDeadlineMinutes,
		VerifySample:         DefaultArchiveVerifySample,
	}
}

// ArchiveLocation is the zone of archive.run_at: archive.timezone, or
// org_reports.timezone when it is empty (P item 1), whether or not the
// organisation reports are enabled.
func ArchiveLocation(cfg Config) (*time.Location, error) {
	name := cfg.Archive.Timezone
	field := "archive.timezone"
	if name == "" {
		name, field = cfg.OrgReports.Timezone, "org_reports.timezone (archive.timezone is empty)"
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return nil, fmt.Errorf("%s must be a non-empty IANA zone name", field)
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("%s %q is not a known IANA zone", field, name)
	}
	return location, nil
}

// validateArchive checks the archive section and guards 1 and 4 of 5.7
// (L.2), plus P item 13. A section in mode off is not inspected further.
func validateArchive(cfg Config) error {
	archive := cfg.Archive
	switch archive.Mode {
	case "", ArchiveModeOff:
		return nil
	case ArchiveModeExportOnly, ArchiveModeArchiveThenDelete:
	default:
		return fmt.Errorf("archive.mode must be off, export_only or archive_then_delete, got %q", archive.Mode)
	}
	// Guard 1: archiving decides what is due by retention_days.
	if cfg.RetentionDays == 0 {
		return errors.New("archive.mode " + archive.Mode + " requires retention_days > 0: an audit becomes due for the archive when retention would delete it")
	}
	if archive.Dir == "" {
		return errors.New("archive.dir is required when archive.mode is not off")
	}
	if !filepath.IsAbs(archive.Dir) {
		return fmt.Errorf("archive.dir must be an absolute path, got %q", archive.Dir)
	}
	dir := filepath.Clean(archive.Dir)
	// Guard 4: the archive never shares a directory with the key that opens it.
	keyDir, err := filepath.Abs(filepath.Dir(cfg.KeyPath))
	if err != nil {
		return fmt.Errorf("archive.dir: resolve the key directory: %w", err)
	}
	if within(dir, keyDir) || within(keyDir, dir) {
		return errors.New("archive.dir must not be the directory of key_path, contain it or be inside it")
	}
	// P item 13: the staging directory holds ciphertext too.
	if staging := cfg.Audit.Staging.Dir; staging != "" && filepath.IsAbs(staging) {
		stagingDir := filepath.Clean(staging)
		if within(dir, stagingDir) || within(stagingDir, dir) {
			return errors.New("archive.dir must not be audit.staging.dir, contain it or be inside it")
		}
	}
	if _, _, err := ParseRunAt(archive.RunAt); err != nil {
		return fmt.Errorf("archive.run_at %w", err)
	}
	if _, err := ArchiveLocation(cfg); err != nil {
		return err
	}
	if archive.SegmentMaxBytes < MinArchiveSegmentMaxBytes || archive.SegmentMaxBytes > MaxArchiveSegmentMaxBytes {
		return fmt.Errorf("archive.segment_max_bytes must be between %d and %d, got %d", MinArchiveSegmentMaxBytes, MaxArchiveSegmentMaxBytes, archive.SegmentMaxBytes)
	}
	if archive.ConversationMinTurns < 1 || archive.ConversationMinTurns > MaxArchiveConversationTurns {
		return fmt.Errorf("archive.conversation_min_turns must be between 1 and %d, got %d", MaxArchiveConversationTurns, archive.ConversationMinTurns)
	}
	if archive.ConversationMinBytes < 1 || archive.ConversationMinBytes > MaxArchiveSegmentMaxBytes {
		return fmt.Errorf("archive.conversation_min_bytes must be between 1 and %d, got %d", MaxArchiveSegmentMaxBytes, archive.ConversationMinBytes)
	}
	if archive.PassAudits < 1 || archive.PassAudits > MaxArchivePassAudits {
		return fmt.Errorf("archive.pass_audits must be between 1 and %d, got %d", MaxArchivePassAudits, archive.PassAudits)
	}
	if archive.RunDeadlineMinutes < 1 || archive.RunDeadlineMinutes > MaxArchiveRunDeadlineMinutes {
		return fmt.Errorf("archive.run_deadline_minutes must be between 1 and %d, got %d", MaxArchiveRunDeadlineMinutes, archive.RunDeadlineMinutes)
	}
	// NaN fails both comparisons, so it is refused too.
	if !(archive.VerifySample >= 0 && archive.VerifySample <= 1) {
		return fmt.Errorf("archive.verify_sample must be between 0 and 1, got %v", archive.VerifySample)
	}
	return nil
}
