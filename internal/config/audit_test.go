package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := DefaultAudit()
	want.Staging.Dir = cfg.Audit.Staging.Dir
	if cfg.Audit != want {
		t.Fatalf("Audit = %+v, want %+v", cfg.Audit, want)
	}
	if cfg.Audit.WritePath != "unified" || cfg.Audit.CommitRetries != 3 ||
		cfg.Audit.Memory.StageBytes != 8<<20 || cfg.Audit.Memory.GlobalBytes != 256<<20 || cfg.Audit.Staging.MaxBytes != 4<<30 {
		t.Fatalf("defaults drifted: %+v", cfg.Audit)
	}
}

func TestLoadAuditSection(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "staging")
	for _, writePath := range []string{"", "  write_path: unified\n"} {
		cfg, err := Load(writeConfig(t, `admin_token: test-token
audit:
`+writePath+`  commit_retries: 0
  memory:
    stage_bytes: 2097152
  staging:
    dir: '`+staging+`'
`))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		want := AuditConfig{WritePath: "unified", CommitRetries: 0, Memory: AuditMemoryConfig{StageBytes: 2 << 20, GlobalBytes: 256 << 20},
			Staging: AuditStagingConfig{Dir: staging, MaxBytes: 4 << 30}}
		if cfg.Audit != want {
			t.Fatalf("Audit = %+v, want %+v", cfg.Audit, want)
		}
	}
}

// A configuration that still selects the removed legacy write path is
// refused with an error that says so, never ignored.
func TestLoadAuditRefusesTheRemovedLegacyWritePath(t *testing.T) {
	_, err := Load(writeConfig(t, `admin_token: test-token
audit:
  write_path: legacy
  staging:
    dir: '`+filepath.Join(t.TempDir(), "staging")+`'
`))
	if err == nil || !strings.Contains(err.Error(), "audit.write_path legacy was removed in this version") {
		t.Fatalf("Load() error = %v, want the removal named", err)
	}
}

func TestLoadAuditRequiresTheStagingDirectory(t *testing.T) {
	_, err := Load(writeConfig(t, "admin_token: test-token\naudit:\n  commit_retries: 2\n"))
	if err == nil || !strings.Contains(err.Error(), "audit.staging.dir is required") {
		t.Fatalf("Load() error = %v, want the staging directory required", err)
	}
}

func TestLoadAuditRejectsUnknownKeys(t *testing.T) {
	_, err := Load(writeConfig(t, "admin_token: test-token\naudit:\n  staging:\n    path: x\n"))
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("Load() error = %v, want unknown key", err)
	}
}

func TestValidateAudit(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "data")
	sibling := filepath.Join(filepath.Dir(keyDir), "data-staging")
	for _, test := range []struct {
		name   string
		mutate func(*AuditConfig)
		want   string
	}{
		{"unknown write path", func(audit *AuditConfig) { audit.WritePath = "fast" }, "audit.write_path must be unified"},
		{"removed write path", func(audit *AuditConfig) { audit.WritePath = "legacy" }, "audit.write_path legacy was removed in this version"},
		{"negative retries", func(audit *AuditConfig) { audit.CommitRetries = -1 }, "audit.commit_retries must be between 0 and 5"},
		{"too many retries", func(audit *AuditConfig) { audit.CommitRetries = 6 }, "audit.commit_retries must be between 0 and 5"},
		{"stage budget under one chunk", func(audit *AuditConfig) { audit.Memory.StageBytes = 1<<20 - 1 }, "audit.memory.stage_bytes must be at least 1048576"},
		{"stage budget over global", func(audit *AuditConfig) {
			audit.Memory.StageBytes = 4 << 20
			audit.Memory.GlobalBytes = 2 << 20
		}, "must not exceed audit.memory.global_bytes"},
		{"no staging", func(audit *AuditConfig) { audit.Staging.Dir = "" }, "audit.staging.dir is required"},
		{"no staging, strict", func(audit *AuditConfig) { audit.Staging.Dir = "" }, "audit.staging.dir is required"},
		{"relative staging", func(audit *AuditConfig) { audit.Staging.Dir = "staging" }, "audit.staging.dir must be an absolute path"},
		{"staging is the key directory", func(audit *AuditConfig) { audit.Staging.Dir = keyDir }, "must not be the directory of key_path"},
		{"staging inside the key directory", func(audit *AuditConfig) { audit.Staging.Dir = filepath.Join(keyDir, "staging") }, "must not be the directory of key_path"},
		{"staging contains the key directory", func(audit *AuditConfig) { audit.Staging.Dir = filepath.Dir(keyDir) }, "must not be the directory of key_path"},
		{"staging max bytes", func(audit *AuditConfig) { audit.Staging.MaxBytes = 0 }, "audit.staging.max_bytes must be positive"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			if strings.HasSuffix(test.name, "strict") {
				cfg.Mode = "strict"
			}
			cfg.KeyPath = filepath.Join(keyDir, "audit.key")
			test.mutate(&cfg.Audit)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
	for _, writePath := range []string{"", AuditWritePathUnified} {
		for _, retries := range []int{0, 5} {
			cfg := testConfig()
			cfg.Audit.CommitRetries = retries
			cfg.Audit.WritePath = writePath
			cfg.Audit.Memory = AuditMemoryConfig{StageBytes: 1 << 20, GlobalBytes: 1 << 20}
			cfg.KeyPath = filepath.Join(keyDir, "audit.key")
			cfg.Audit.Staging.Dir = sibling
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate(write path %q, retries=%d) error = %v", writePath, retries, err)
			}
		}
	}
}
