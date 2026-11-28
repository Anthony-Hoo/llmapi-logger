package app

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/config"
)

// archiveTestConfig is a SQLite-backed configuration with the archive in
// mode, the archive directory beside the key and staging directories.
func archiveTestConfig(t *testing.T, mode string) config.Config {
	t.Helper()
	base := t.TempDir()
	cfg := testConfig(t)
	cfg.DBPath = filepath.Join(base, "audit.db")
	cfg.KeyPath = filepath.Join(base, "key", "audit.key")
	cfg.AdminToken = "app-test-admin-token"
	cfg.RetentionDays = 30
	cfg.Archive.Mode = mode
	cfg.Archive.Dir = filepath.Join(base, "archive")
	return cfg
}

// Guard 2 (L.2): with the archive on, retention's direct delete is not
// assembled. export_only says the hot store keeps growing; archive_then_delete
// says verified removal is active for format version 1 and later and, at the
// built-in trial format version 0, that nothing is removed. Off, retention
// runs as before and nothing is said.
func TestArchiveModeReplacesDirectRetention(t *testing.T) {
	for _, test := range []struct {
		mode      string
		retention bool
		lines     []string
	}{
		{config.ArchiveModeOff, true, nil},
		{config.ArchiveModeExportOnly, false, []string{`"error_category":"archive_export_only"`}},
		{config.ArchiveModeArchiveThenDelete, false, []string{`"error_category":"archive_removal_active"`, `"error_category":"archive_removal_trial_format"`}},
	} {
		t.Run(test.mode, func(t *testing.T) {
			cfg := archiveTestConfig(t, test.mode)
			var logs bytes.Buffer
			application, err := newSQLiteTest(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = application.Close() })
			if application.auditStore == nil {
				t.Fatal("no audit store")
			}
			if (application.retention != nil) != test.retention {
				t.Fatalf("retention assembled = %v, want %v", application.retention != nil, test.retention)
			}
			for _, line := range test.lines {
				if !strings.Contains(logs.String(), line) {
					t.Fatalf("logs %s, want %s", logs.String(), line)
				}
			}
			if test.mode == config.ArchiveModeOff && strings.Contains(logs.String(), "archive") {
				t.Fatalf("archive off logged %s", logs.String())
			}
			// The SQLite store has no catalog: the runner is not started, the
			// audit and the proxy keep working.
			if test.mode != config.ArchiveModeOff {
				if application.archive != nil || !strings.Contains(logs.String(), `"error_category":"archive_unavailable"`) {
					t.Fatalf("archive runner %v, logs %s", application.archive, logs.String())
				}
				if application.auditSink == nil || !application.auditSink.Healthy() {
					t.Fatal("the audit stopped working without the archive runner")
				}
			}
		})
	}
}

// Guard 5 (5.7) and P item 12: with the archive on, a manifest in the
// archive directory forbids creating a key, as audits or integrity events
// in the database do; without one, or with the archive off, a first start
// creates the key.
func TestArchiveManifestsForbidCreatingAKey(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     string
		manifest bool
		create   bool
	}{
		{"manifest, archive on", config.ArchiveModeExportOnly, true, false},
		{"manifest in a subdirectory, archive_then_delete", config.ArchiveModeArchiveThenDelete, true, false},
		{"no manifest", config.ArchiveModeExportOnly, false, true},
		{"manifest, archive off", config.ArchiveModeOff, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := archiveTestConfig(t, test.mode)
			dir := filepath.Join(cfg.Archive.Dir, "sessions", "2026", "11")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.manifest {
				if err := os.WriteFile(filepath.Join(dir, "x_s0001.manifest.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			runtime := assembleSQLiteTest(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
			if runtime.store != nil {
				defer runtime.store.Close()
			}
			_, err := os.Stat(cfg.KeyPath)
			created := err == nil
			if created != test.create {
				t.Fatalf("key created = %v, want %v (logs %s)", created, test.create, logs.String())
			}
			if !test.create {
				if !errors.Is(err, fs.ErrNotExist) || runtime.store != nil ||
					!strings.Contains(logs.String(), `"reason":"archive_manifests_present"`) {
					t.Fatalf("stat %v, store %v, logs %s", err, runtime.store, logs.String())
				}
			}
		})
	}
}

// The archive keys are derived with the other sub-keys when the archive is
// on, and an archive path that is not a directory does not stop the audit.
func TestArchiveKeysAreDerivedAtStart(t *testing.T) {
	cfg := archiveTestConfig(t, config.ArchiveModeExportOnly)
	if err := os.WriteFile(cfg.Archive.Dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	runtime := assembleSQLiteTest(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if runtime.store == nil {
		t.Fatalf("audit unavailable: %s", logs.String())
	}
	defer runtime.store.Close()
	if runtime.archiveKeys == nil || runtime.eventSigner == nil {
		t.Fatal("archive keys not derived")
	}
	off := archiveTestConfig(t, config.ArchiveModeOff)
	offRuntime := assembleSQLiteTest(context.Background(), off, slog.New(slog.NewJSONHandler(&logs, nil)))
	if offRuntime.store == nil {
		t.Fatal("audit unavailable")
	}
	defer offRuntime.store.Close()
	if offRuntime.archiveKeys != nil {
		t.Fatal("archive keys derived with the archive off")
	}
}
