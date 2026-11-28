package app

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/archive/runner"
	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/postgres"
)

// The cold archive's assembly (doc/design/issue-59-stage4-cold-archive.md
// H.1, L.2): the runner when archive.mode is not off, and the start-up
// guards 2, 3 and 5 of decision 5.7.

// archiveSeams are test seams of the archive runner; production passes none.
type archiveSeams struct {
	now   func() time.Time
	fault func(operation, path string) error
	step  func(step string) error
	// formatVersion, when set, is runner.Options.FormatVersionOverride:
	// tests leave catalog rows of the trial format version 0.
	formatVersion *int64
}

// archiveFormatVersion is the format version the runner works with: the
// built-in archive.FormatVersion unless a test seam overrides it.
func archiveFormatVersion(seams archiveSeams) int64 {
	if seams.formatVersion != nil {
		return *seams.formatVersion
	}
	version, err := strconv.ParseInt(archive.FormatVersion, 10, 64)
	if err != nil {
		return 0
	}
	return version
}

// withArchiveSeams sets the archive runner's clock and fault hooks.
func withArchiveSeams(seams archiveSeams) Option {
	return func(options *assemblyOptions) { options.archive = seams }
}

// archiveManifestsPresent reports whether the archive directory of an
// enabled archive holds any manifest (P item 12): a new key would make every
// one of those bundles unreadable, so none may be created. A directory that
// cannot be read counts as holding one.
func archiveManifestsPresent(configuration config.Config) bool {
	if !configuration.Archive.Enabled() || configuration.Archive.Dir == "" {
		return false
	}
	// WalkDir does not follow a symlink given as its root: walk the
	// directory a symlinked archive directory points to, as BuildIndex does.
	root, err := filepath.EvalSymlinks(configuration.Archive.Dir)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	found := false
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				return fs.SkipAll
			}
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), bundle.ManifestSuffix) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found || err != nil
}

// archiveKeys derives the archive keys and the integrity signer that checks
// the copied events of a re-read bundle, while the master key is in scope.
func archiveKeys(configuration config.Config, key []byte) (*security.ArchiveKeys, *security.IntegritySigner, error) {
	if !configuration.Archive.Enabled() {
		return nil, nil, nil
	}
	keys, err := security.DeriveArchiveKeys(key)
	if err != nil {
		return nil, nil, err
	}
	signer, err := security.NewIntegritySigner(key)
	if err != nil {
		return nil, nil, err
	}
	return keys, signer, nil
}

// warnArchiveMode writes the start-up lines of guard 2 (L.2, H.5): with the
// archive on, retention's direct delete is not assembled. export_only says
// the hot store keeps growing. archive_then_delete says verified removal is
// active for bundles of format version 1 or later, with the format version
// the runner writes. (The trial format version 0 had a line of its own;
// since the freeze the runner never writes version 0, and segments of
// version 0 left in the catalog are re-exported and never removed, design
// R.10.)
func warnArchiveMode(configuration config.Config, formatVersion int64, logger *slog.Logger) {
	switch configuration.Archive.Mode {
	case config.ArchiveModeExportOnly:
		logger.Warn("archive export only: hot store keeps growing", "error_category", "archive_export_only")
	case config.ArchiveModeArchiveThenDelete:
		logger.Warn("archive verified removal active: archived audits are removed from the hot store once their bundle of format version 1 or later is sealed and their change stamp is unchanged",
			"error_category", "archive_removal_active", "format_version", formatVersion)
	}
}

// warnDirectDeleteResumed is guard 3 (L.2): the archive is off while
// retention deletes directly, and the catalog shows the archive ran before.
func warnDirectDeleteResumed(ctx context.Context, configuration config.Config, store runtimeStore, logger *slog.Logger) {
	if configuration.Archive.Enabled() || configuration.RetentionDays <= 0 || store == nil {
		return
	}
	catalog, ok := store.(runner.PostgresStore)
	if !ok {
		return
	}
	checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	used, err := runner.FromPostgres(catalog, postgres.ArchiveSnapshotOptions{}).AnyRun(checkContext)
	if err != nil || !used {
		return
	}
	logger.Warn("archive is off and retention deletes directly again; to pause archiving set retention_days: 0",
		"error_category", "archive_direct_delete_resumed", "retention_days", configuration.RetentionDays)
}

// assembleArchive builds the archive runner, or returns nil with a warning
// when it cannot run: no usable audit store, query service or keys, or an
// archive directory that cannot be prepared. The proxy and the audit keep
// working either way; retention's direct delete stays unassembled.
func assembleArchive(configuration config.Config, runtime auditRuntime, service *query.Service, seams archiveSeams, logger *slog.Logger) *runner.Runner {
	section := configuration.Archive
	if !section.Enabled() {
		return nil
	}
	catalog, ok := runtime.store.(runner.PostgresStore)
	if runtime.store == nil || service == nil || runtime.archiveKeys == nil || !ok {
		logger.Warn("archive runner unavailable", "error_category", "archive_unavailable", "reason", "audit_unavailable")
		return nil
	}
	if err := staging.PrepareDirectory(section.Dir); err != nil {
		logger.Warn("archive runner unavailable", "error_category", "archive_unavailable", "reason", "dir_"+staging.Reason(err))
		return nil
	}
	location, err := config.ArchiveLocation(configuration)
	if err != nil {
		logger.Warn("archive runner unavailable", "error_category", "archive_unavailable", "reason", "invalid_timezone")
		return nil
	}
	archiveRunner, err := runner.New(runner.Options{
		Mode: section.Mode, Dir: filepath.Clean(section.Dir), Encrypt: section.Encrypt, RunAt: section.RunAt, Location: location,
		RetentionDays: configuration.RetentionDays, SegmentMaxBytes: section.SegmentMaxBytes,
		ConversationMinTurns: section.ConversationMinTurns, ConversationMinBytes: section.ConversationMinBytes,
		PassAudits: section.PassAudits, RunDeadline: time.Duration(section.RunDeadlineMinutes) * time.Minute,
		VerifySample: section.VerifySample,
		Store:        runner.FromPostgres(catalog, postgres.ArchiveSnapshotOptions{Cipher: runtime.cipher, Fingerprinter: runtime.archiveKeys}),
		Keys:         runtime.archiveKeys, Events: runtime.eventSigner,
		Sampler:             runner.QuerySampler{Hot: service, Fingerprinter: runtime.archiveKeys},
		SourceSchemaVersion: strconv.Itoa(postgres.LatestSchemaVersion),
		Logger:              logger, Now: seams.now, Fault: seams.fault, Step: seams.step,
		FormatVersionOverride: seams.formatVersion,
	})
	if err != nil {
		logger.Warn("archive runner unavailable", "error_category", "archive_unavailable", "reason", "invalid_options")
		return nil
	}
	return archiveRunner
}
