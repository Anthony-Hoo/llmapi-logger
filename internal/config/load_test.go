package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesDefaults(t *testing.T) {
	path := writeConfig(t, "admin_token: test-token\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Listen != DefaultListen || cfg.AdminListen != DefaultAdminListen {
		t.Fatalf("listen defaults = %q, %q", cfg.Listen, cfg.AdminListen)
	}
	if cfg.NewAPI.URL != DefaultNewAPIURL || cfg.Mode != DefaultMode {
		t.Fatalf("upstream defaults = %q, %q", cfg.NewAPI.URL, cfg.Mode)
	}
	if cfg.NewAPI.ProxyURL != "" {
		t.Fatalf("NewAPI.ProxyURL = %q, want direct connection", cfg.NewAPI.ProxyURL)
	}
	if cfg.NewAPI.ResponseHeaderTimeoutSeconds != DefaultNewAPIResponseHeaderTimeoutSecs || cfg.NewAPI.PreserveHost {
		t.Fatalf("NewAPI transport defaults = timeout:%d preserve_host:%v", cfg.NewAPI.ResponseHeaderTimeoutSeconds, cfg.NewAPI.PreserveHost)
	}
	if cfg.DBPath != DefaultDBPath || cfg.KeyPath != DefaultKeyPath {
		t.Fatalf("data path defaults = %q, %q", cfg.DBPath, cfg.KeyPath)
	}
	if cfg.RetentionDays != DefaultRetentionDays {
		t.Fatalf("RetentionDays = %d, want %d", cfg.RetentionDays, DefaultRetentionDays)
	}
	if cfg.ShutdownTimeoutSeconds != DefaultShutdownTimeoutSecs {
		t.Fatalf("ShutdownTimeoutSeconds = %d, want %d", cfg.ShutdownTimeoutSeconds, DefaultShutdownTimeoutSecs)
	}
	if cfg.Interceptors == nil || cfg.Routes == nil {
		t.Fatal("map and slice defaults must be non-nil")
	}
}

func TestLoadCompleteConfig(t *testing.T) {
	path := writeConfig(t, `
listen: 127.0.0.1:18080
admin_listen: 127.0.0.1:18081
newapi:
  url: https://newapi.example:8443
  proxy_url: http://proxy.example:7897
  response_header_timeout_seconds: 3900
  preserve_host: true
  access_token: management-secret
  user_id: 42
mode: strict
db_path: ./state/audit.db
key_path: ./state/audit.key
admin_token: secret
shutdown_timeout_seconds: 3900
retention_days: 0
interceptors:
  credential:
    type: require_credential
  body-limit:
    type: max_body_bytes
    config:
      max_bytes: 1048576
routes:
  - id: openai-responses
    method: POST
    path: /v1/responses
    match: exact
    parser: openai.responses
    interceptors: [credential, body-limit]
  - id: gemini-generate
    method: POST
    path: /v1beta/models/{model}:generateContent
    match: template
    parser: gemini.generate_content
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != "strict" || cfg.RetentionDays != 0 || len(cfg.Routes) != 2 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.NewAPI.ProxyURL != "http://proxy.example:7897" || cfg.NewAPI.AccessToken != "management-secret" || cfg.NewAPI.UserID != 42 {
		t.Fatalf("NewAPI = %+v", cfg.NewAPI)
	}
	if cfg.NewAPI.ResponseHeaderTimeoutSeconds != 3900 || !cfg.NewAPI.PreserveHost || cfg.ShutdownTimeoutSeconds != 3900 {
		t.Fatalf("timeouts/Host = upstream:%d preserve:%v shutdown:%d", cfg.NewAPI.ResponseHeaderTimeoutSeconds, cfg.NewAPI.PreserveHost, cfg.ShutdownTimeoutSeconds)
	}
	if got := cfg.Interceptors["body-limit"].Config["max_bytes"]; got != 1048576 {
		t.Fatalf("max_bytes = %#v", got)
	}
}

func TestLoadRejectsUnknownAndAdditionalDocuments(t *testing.T) {
	tests := map[string]string{
		"top level field":       "admin_token: x\nunknown: true\n",
		"interceptor field":     "admin_token: x\ninterceptors:\n  auth:\n    type: require_credential\n    unknown: true\n",
		"route field":           "admin_token: x\nroutes:\n  - id: x\n    method: POST\n    path: /v1/x\n    match: exact\n    parser: x\n    unknown: true\n",
		"additional document":   "admin_token: x\n---\nadmin_token: y\n",
		"duplicate mapping key": "admin_token: x\nadmin_token: y\n",
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, contents))
			if err == nil {
				t.Fatal("Load() error = nil")
			}
		})
	}
}

func TestLoadReturnsContextForMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestExampleConfigsLoad(t *testing.T) {
	for _, name := range []string{"audit-proxy.example.yaml", "audit-proxy.docker.yaml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "configs", name)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load(%q) error = %v", path, err)
			}
			if len(cfg.Routes) != 7 {
				t.Fatalf("len(Routes) = %d, want 7", len(cfg.Routes))
			}
		})
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimLeft(contents, "\n")), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
