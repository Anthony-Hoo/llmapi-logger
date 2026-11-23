package config

import (
	"strings"
	"testing"
)

func TestAgentAccessDefaultsToDisabled(t *testing.T) {
	cfg, err := Load(writeConfig(t, "admin_token: test-token\n"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AgentAccess != (AgentAccessConfig{}) {
		t.Fatalf("AgentAccess = %+v, want the zero (disabled) section", cfg.AgentAccess)
	}
	if Default().AgentAccess != (AgentAccessConfig{}) {
		t.Fatalf("Default().AgentAccess = %+v", Default().AgentAccess)
	}
}

func TestLoadAgentAccessSection(t *testing.T) {
	cfg, err := Load(writeConfig(t, `admin_token: test-token
agent_access:
  enabled: true
  allow_write: true
  public_url: https://audit.example.com/admin
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := AgentAccessConfig{Enabled: true, AllowWrite: true, PublicURL: "https://audit.example.com/admin"}
	if cfg.AgentAccess != want {
		t.Fatalf("AgentAccess = %+v, want %+v", cfg.AgentAccess, want)
	}
}

// Loading is strict: an unknown key in the section fails startup, which is
// why the upgrade order in the contract (section 8.3) is fixed.
func TestLoadAgentAccessRejectsUnknownKeysAndWrongTypes(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key": "agent_access:\n  enabled: true\n  allow_writes: true\n",
		"wrong type":  "agent_access:\n  enabled: yes-please\n",
		"not a map":   "agent_access: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, "admin_token: test-token\n"+body)); err == nil {
				t.Fatal("Load() accepted an invalid agent_access section")
			}
		})
	}
}

func TestAgentAccessPublicURL(t *testing.T) {
	valid := []string{
		"",
		"http://192.0.2.10:8081",
		"https://audit.example.com",
		"https://audit.example.com/",
		"https://audit.example.com/prefix/admin",
		"http://[2001:db8::1]:8081",
		"https://audit.example.com/admin_1/v~2/a%20b",
	}
	for _, value := range valid {
		cfg := testConfig()
		cfg.AgentAccess = AgentAccessConfig{Enabled: true, PublicURL: value}
		if err := Validate(cfg); err != nil {
			t.Errorf("public_url %q rejected: %v", value, err)
		}
	}
	invalid := []string{
		"audit.example.com",
		"ftp://audit.example.com",
		"https://",
		"https://user:secret@audit.example.com",
		"https://audit.example.com/?next=1",
		"https://audit.example.com/?",
		"https://audit.example.com/#top",
		"https://audit.example.com:0",
		"https://audit.example.com:65536",
		"https://audit.example.com:",
		" https://audit.example.com",
		"https://audit.example.com/a b",
		"https://audit.example.com/\x01",
		// Characters the install prompt refuses inside its shell commands.
		"https://audit.example.com/a$b",
		"https://audit.example.com/a`b",
		`https://audit.example.com/a"b`,
		"https://audit.example.com/a'b",
		`https://audit.example.com/a\b`,
		"https://audit.example.com/a;b",
		"https://audit.example.com/a&b",
		"https://audit.example.com/a!b",
		"https://audit.example.com/a(b)",
		"https://audit.example.com/a+b",
		"https://audit.example.com/a,b",
		"https://audit.example.com/a=b",
		"https://audit.example.com/a*b",
		"https://audit.example.com/a@b",
		"https://audit.example.com/a|b",
		"https://audit.example.com/a<b>",
		"https://bücher.example.com",
		"https://audit.example.com/" + strings.Repeat("a", 2048),
	}
	for _, value := range invalid {
		cfg := testConfig()
		cfg.AgentAccess = AgentAccessConfig{Enabled: true, PublicURL: value}
		err := Validate(cfg)
		if err == nil {
			t.Errorf("public_url %q accepted", value)
			continue
		}
		if !strings.Contains(err.Error(), "agent_access.public_url") {
			t.Errorf("error for %q does not name the key: %v", value, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("error for %q echoed userinfo: %v", value, err)
		}
	}
}

func TestDisabledAgentAccessIsNeverInspected(t *testing.T) {
	cfg := testConfig()
	cfg.AgentAccess = AgentAccessConfig{AllowWrite: true, PublicURL: "not a url"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("disabled agent_access must not be validated: %v", err)
	}
}
