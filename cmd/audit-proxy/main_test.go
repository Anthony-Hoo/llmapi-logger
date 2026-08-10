package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresConfigFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--config is required") {
		t.Fatalf("stderr = %q, want missing config message", stderr.String())
	}
}

func TestRunValidatesConfigWithoutStartingServer(t *testing.T) {
	configPath := writeValidConfig(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"--config", configPath, "--validate-config"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stdout.String() != "configuration valid\n" {
		t.Fatalf("stdout = %q, want validation confirmation", stdout.String())
	}
}

func writeValidConfig(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	contents := fmt.Sprintf(`listen: 127.0.0.1:18080
admin_listen: 127.0.0.1:18081
newapi_url: http://127.0.0.1:3000
mode: available
db_path: '%s'
key_path: '%s'
admin_token: test-admin-token
retention_days: 0
newapi_token_db_path: ''
interceptors: {}
routes:
  - id: chat
    method: POST
    path: /v1/chat/completions
    match: exact
    parser: openai.chat_completions
`, yamlString(filepath.ToSlash(filepath.Join(tempDir, "audit.db"))), yamlString(filepath.ToSlash(filepath.Join(tempDir, "audit.key"))))
	path := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func yamlString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
