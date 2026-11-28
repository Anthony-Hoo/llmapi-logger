package config

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The section is optional: absent, it is off with every default filled, so
// the example configurations keep loading.
func TestArchiveDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := ArchiveConfig{Mode: "off", Encrypt: true, RunAt: "03:00", SegmentMaxBytes: 256 << 20, ConversationMinTurns: 16,
		ConversationMinBytes: 16 << 20, PassAudits: 5000, RunDeadlineMinutes: 240, VerifySample: 0.05}
	if cfg.Archive != want || cfg.Archive.Enabled() {
		t.Fatalf("Archive = %+v, want %+v", cfg.Archive, want)
	}
}

// L.1 writes `mode: off` unquoted. YAML 1.1 would read that as false; the
// decoder must keep it the string off, and the other modes load too.
func TestLoadArchiveSection(t *testing.T) {
	base := t.TempDir()
	archiveDir := filepath.Join(base, "archive")
	for _, mode := range []string{"off", "export_only", "archive_then_delete"} {
		cfg, err := Load(writeConfig(t, `admin_token: test-token
key_path: '`+filepath.Join(base, "data", "audit.key")+`'
archive:
  mode: `+mode+`
  dir: '`+archiveDir+`'
  encrypt: false
  run_at: "04:30"
  timezone: UTC
  verify_sample: 1
audit:
  staging:
    dir: '`+filepath.Join(base, "staging")+`'
`))
		if err != nil {
			t.Fatalf("%s: Load() error = %v", mode, err)
		}
		got := cfg.Archive
		if got.Mode != mode || got.Dir != archiveDir || got.Encrypt || got.RunAt != "04:30" || got.Timezone != "UTC" ||
			got.VerifySample != 1 || got.PassAudits != DefaultArchivePassAudits || got.Enabled() != (mode != "off") {
			t.Fatalf("%s: Archive = %+v", mode, got)
		}
	}
	if _, err := Load(writeConfig(t, "admin_token: test-token\narchive:\n  directory: /x\n")); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("unknown archive key: %v", err)
	}
}

func TestValidateArchive(t *testing.T) {
	base := t.TempDir()
	keyDir := filepath.Join(base, "data")
	stagingDir := filepath.Join(base, "staging")
	archiveDir := filepath.Join(base, "archive")
	valid := func() Config {
		cfg := testConfig()
		cfg.KeyPath = filepath.Join(keyDir, "audit.key")
		cfg.Audit.Staging.Dir = stagingDir
		cfg.RetentionDays = 30
		cfg.Archive.Mode = ArchiveModeExportOnly
		cfg.Archive.Dir = archiveDir
		return cfg
	}
	for _, mode := range []string{ArchiveModeExportOnly, ArchiveModeArchiveThenDelete} {
		cfg := valid()
		cfg.Archive.Mode = mode
		if err := Validate(cfg); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"unknown mode", func(cfg *Config) { cfg.Archive.Mode = "delete" }, "archive.mode must be off, export_only or archive_then_delete"},
		// Guard 1 (5.7): an archive without retention has nothing due.
		{"guard 1: export_only without retention", func(cfg *Config) { cfg.RetentionDays = 0 }, "requires retention_days > 0"},
		{"guard 1: archive_then_delete without retention", func(cfg *Config) {
			cfg.Archive.Mode = ArchiveModeArchiveThenDelete
			cfg.RetentionDays = 0
		}, "requires retention_days > 0"},
		{"no dir", func(cfg *Config) { cfg.Archive.Dir = "" }, "archive.dir is required"},
		{"relative dir", func(cfg *Config) { cfg.Archive.Dir = "archive" }, "archive.dir must be an absolute path"},
		// Guard 4 (5.7): never with the key.
		{"guard 4: dir is the key directory", func(cfg *Config) { cfg.Archive.Dir = keyDir }, "must not be the directory of key_path"},
		{"guard 4: dir inside the key directory", func(cfg *Config) { cfg.Archive.Dir = filepath.Join(keyDir, "archive") }, "must not be the directory of key_path"},
		{"guard 4: dir contains the key directory", func(cfg *Config) { cfg.Archive.Dir = base }, "must not be the directory of key_path"},
		// P item 13: nor with the staging directory.
		{"P13: dir is the staging directory", func(cfg *Config) { cfg.Archive.Dir = stagingDir }, "must not be audit.staging.dir"},
		{"P13: dir inside the staging directory", func(cfg *Config) { cfg.Archive.Dir = filepath.Join(stagingDir, "a") }, "must not be audit.staging.dir"},
		{"P13: dir contains the staging directory", func(cfg *Config) {
			cfg.Archive.Dir = filepath.Join(base, "volume")
			cfg.Audit.Staging.Dir = filepath.Join(base, "volume", "staging")
		}, "must not be audit.staging.dir"},
		{"run_at", func(cfg *Config) { cfg.Archive.RunAt = "3:00" }, "archive.run_at must be HH:MM"},
		{"timezone", func(cfg *Config) { cfg.Archive.Timezone = "Mars/Base" }, "archive.timezone \"Mars/Base\" is not a known IANA zone"},
		{"fallback timezone", func(cfg *Config) { cfg.OrgReports.Timezone = "Mars/Base" }, "org_reports.timezone (archive.timezone is empty)"},
		{"segment too small", func(cfg *Config) { cfg.Archive.SegmentMaxBytes = 16<<20 - 1 }, "archive.segment_max_bytes must be between"},
		{"segment too large", func(cfg *Config) { cfg.Archive.SegmentMaxBytes = 4<<30 + 1 }, "archive.segment_max_bytes must be between"},
		{"turns", func(cfg *Config) { cfg.Archive.ConversationMinTurns = 0 }, "archive.conversation_min_turns"},
		{"bytes", func(cfg *Config) { cfg.Archive.ConversationMinBytes = 0 }, "archive.conversation_min_bytes"},
		{"pass size", func(cfg *Config) { cfg.Archive.PassAudits = 10001 }, "archive.pass_audits must be between 1 and 10000"},
		{"deadline", func(cfg *Config) { cfg.Archive.RunDeadlineMinutes = 0 }, "archive.run_deadline_minutes"},
		{"sample above one", func(cfg *Config) { cfg.Archive.VerifySample = 1.5 }, "archive.verify_sample must be between 0 and 1"},
		{"sample negative", func(cfg *Config) { cfg.Archive.VerifySample = -0.1 }, "archive.verify_sample must be between 0 and 1"},
		{"sample NaN", func(cfg *Config) { cfg.Archive.VerifySample = math.NaN() }, "archive.verify_sample must be between 0 and 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			test.mutate(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
	// Off is not inspected beyond the mode: retention 0 and no directory are
	// fine, as is the default section.
	cfg := valid()
	cfg.Archive.Mode = ArchiveModeOff
	cfg.Archive.Dir = ""
	cfg.RetentionDays = 0
	if err := Validate(cfg); err != nil {
		t.Fatalf("off: %v", err)
	}
}

// P item 1: an empty archive.timezone takes org_reports.timezone whether or
// not the organisation reports are enabled, never the process's zone.
func TestArchiveLocationFallsBackToTheReportZone(t *testing.T) {
	cfg := Default()
	location, err := ArchiveLocation(cfg)
	if err != nil || location.String() != DefaultOrgTimezone {
		t.Fatalf("location = %v, %v; want %s", location, err, DefaultOrgTimezone)
	}
	cfg.Archive.Timezone = "UTC"
	if location, err := ArchiveLocation(cfg); err != nil || location.String() != "UTC" {
		t.Fatalf("location = %v, %v", location, err)
	}
}

// The directories are kept apart where they really are, not only as written:
// a symbolic link must not put the key inside the archive or the staging
// directory, nor the staging directory inside the archive.
func TestDirectorySeparationFollowsSymlinks(t *testing.T) {
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("creating a symbolic link needs a privilege this Windows account lacks: %v", err)
			}
			t.Fatal(err)
		}
	}
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const keyGuard = "archive.dir must not be the directory of key_path"
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, base string, cfg *Config)
		want  string // empty: accepted
	}{
		{"key directory is an alias of the archive", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "archive"))
			link(t, filepath.Join(base, "archive"), filepath.Join(base, "key-alias"))
			cfg.KeyPath = filepath.Join(base, "key-alias", "audit.key")
		}, keyGuard},
		{"archive is an alias of the key directory", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "data"))
			link(t, filepath.Join(base, "data"), filepath.Join(base, "archive-alias"))
			cfg.Archive.Dir = filepath.Join(base, "archive-alias", "bundles")
		}, keyGuard},
		{"staging directory is an alias of the key directory", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "data"))
			link(t, filepath.Join(base, "data"), filepath.Join(base, "staging-alias"))
			cfg.Audit.Staging.Dir = filepath.Join(base, "staging-alias")
		}, "audit.staging.dir must not be the directory of key_path"},
		{"archive contains the staging directory through an alias", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "volume"))
			link(t, filepath.Join(base, "volume"), filepath.Join(base, "staging-alias"))
			cfg.Audit.Staging.Dir = filepath.Join(base, "staging-alias", "staging")
			cfg.Archive.Dir = filepath.Join(base, "volume")
		}, "archive.dir must not be audit.staging.dir"},
		{"alias with missing directories on both sides", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "volume"))
			link(t, filepath.Join(base, "volume"), filepath.Join(base, "alias"))
			cfg.KeyPath = filepath.Join(base, "alias", "keys", "audit.key")
			cfg.Archive.Dir = filepath.Join(base, "volume", "keys", "archive")
		}, keyGuard},
		{"key file is a link into the archive", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "archive"))
			mkdir(t, filepath.Join(base, "data"))
			if err := os.WriteFile(filepath.Join(base, "archive", "audit.key"), make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
			link(t, filepath.Join(base, "archive", "audit.key"), filepath.Join(base, "data", "audit.key"))
		}, keyGuard},
		{"key directory is a dangling relative alias of the archive", func(t *testing.T, base string, cfg *Config) {
			link(t, "archive", filepath.Join(base, "key-alias"))
			cfg.KeyPath = filepath.Join(base, "key-alias", "keys", "audit.key")
			cfg.Archive.Dir = filepath.Join(base, "archive", "keys")
		}, keyGuard},
		{"key directory written inside the archive stays refused though it links elsewhere", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "elsewhere"))
			mkdir(t, filepath.Join(base, "archive"))
			link(t, filepath.Join(base, "elsewhere"), filepath.Join(base, "archive", "key-alias"))
			cfg.KeyPath = filepath.Join(base, "archive", "key-alias", "audit.key")
		}, keyGuard},
		{"dangling relative link with .. under an aliased directory", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "real", "sub"))
			link(t, filepath.Join(base, "real", "sub"), filepath.Join(base, "sub-alias"))
			// sub-alias/keys -> ../archive resolves from real/sub to real/archive.
			link(t, filepath.Join("..", "archive"), filepath.Join(base, "real", "sub", "keys"))
			cfg.KeyPath = filepath.Join(base, "sub-alias", "keys", "audit.key")
			cfg.Archive.Dir = filepath.Join(base, "real", "archive")
		}, keyGuard},
		{"alias pointing elsewhere is accepted", func(t *testing.T, base string, cfg *Config) {
			mkdir(t, filepath.Join(base, "elsewhere"))
			mkdir(t, filepath.Join(base, "archive"))
			link(t, filepath.Join(base, "elsewhere"), filepath.Join(base, "key-alias"))
			cfg.KeyPath = filepath.Join(base, "key-alias", "audit.key")
		}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := t.TempDir()
			cfg := testConfig()
			cfg.KeyPath = filepath.Join(base, "data", "audit.key")
			cfg.Audit.Staging.Dir = filepath.Join(base, "staging")
			cfg.RetentionDays = 30
			cfg.Archive.Mode = ArchiveModeExportOnly
			cfg.Archive.Dir = filepath.Join(base, "archive")
			test.setup(t, base, &cfg)
			err := Validate(cfg)
			if test.want == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}
