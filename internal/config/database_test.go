package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseURLRequiredAndSanitized(t *testing.T) {
	for _, dsn := range []string{"", "sqlite:///tmp/audit.db", "postgres://user:PRIVATE_SECRET@host/%zz", "postgres://user:PRIVATE_SECRET@host/", "postgres://user:PRIVATE_SECRET@host/db#fragment"} {
		cfg := testConfig()
		cfg.DatabaseURL = dsn
		err := Validate(cfg)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_SECRET") {
			t.Fatalf("invalid DSN was accepted or leaked")
		}
	}
}
func TestLoadRejectsLegacySQLitePath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.yaml")
	if err := os.WriteFile(p, []byte("admin_token: test\ndb_path: audit.db\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("legacy SQLite runtime config accepted")
	}
}
