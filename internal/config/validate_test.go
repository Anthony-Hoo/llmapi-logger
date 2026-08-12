package config

import (
	"strings"
	"testing"
)

func TestValidateRejectsInvalidCoreFields(t *testing.T) {
	valid := testConfig()
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"invalid listen", func(cfg *Config) { cfg.Listen = "127.0.0.1" }, "listen"},
		{"invalid admin listen", func(cfg *Config) { cfg.AdminListen = "127.0.0.1:0" }, "admin_listen"},
		{"same listeners", func(cfg *Config) { cfg.AdminListen = cfg.Listen }, "must be different"},
		{"wildcard listeners", func(cfg *Config) { cfg.Listen = ":18080"; cfg.AdminListen = "0.0.0.0:18080" }, "must be different"},
		{"invalid mode", func(cfg *Config) { cfg.Mode = "fast" }, "mode"},
		{"empty db path", func(cfg *Config) { cfg.DBPath = "" }, "db_path"},
		{"directory db path", func(cfg *Config) { cfg.DBPath = t.TempDir() }, "must name a file"},
		{"empty key path", func(cfg *Config) { cfg.KeyPath = " " }, "key_path"},
		{"empty admin token", func(cfg *Config) { cfg.AdminToken = "\t" }, "admin_token"},
		{"admin token whitespace", func(cfg *Config) { cfg.AdminToken = "token with spaces" }, "admin_token"},
		{"negative retention", func(cfg *Config) { cfg.RetentionDays = -1 }, "retention_days"},
		{"large retention", func(cfg *Config) { cfg.RetentionDays = 3651 }, "retention_days"},
		{"management user without token", func(cfg *Config) { cfg.NewAPI.UserID = 1 }, "newapi.user_id"},
		{"management token without user", func(cfg *Config) { cfg.NewAPI.AccessToken = "secret" }, "newapi.user_id"},
		{"management token whitespace", func(cfg *Config) { cfg.NewAPI.AccessToken = "bad token"; cfg.NewAPI.UserID = 1 }, "newapi.access_token"},
		{"zero response header timeout", func(cfg *Config) { cfg.NewAPI.ResponseHeaderTimeoutSeconds = 0 }, "newapi.response_header_timeout_seconds"},
		{"negative response header timeout", func(cfg *Config) { cfg.NewAPI.ResponseHeaderTimeoutSeconds = -1 }, "newapi.response_header_timeout_seconds"},
		{"large response header timeout", func(cfg *Config) { cfg.NewAPI.ResponseHeaderTimeoutSeconds = 86401 }, "newapi.response_header_timeout_seconds"},
		{"zero shutdown timeout", func(cfg *Config) { cfg.ShutdownTimeoutSeconds = 0 }, "shutdown_timeout_seconds"},
		{"negative shutdown timeout", func(cfg *Config) { cfg.ShutdownTimeoutSeconds = -1 }, "shutdown_timeout_seconds"},
		{"large shutdown timeout", func(cfg *Config) { cfg.ShutdownTimeoutSeconds = 86401 }, "shutdown_timeout_seconds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateNewAPIURL(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:3000",
		"https://newapi.example",
		"http://[::1]:3000",
	}
	for _, value := range valid {
		t.Run("valid "+value, func(t *testing.T) {
			cfg := testConfig()
			cfg.NewAPI.URL = value
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	invalid := []string{
		"",
		"ftp://newapi.example",
		"http://",
		"http://user:pass@newapi.example",
		"http://newapi.example/",
		"http://newapi.example/v1",
		"http://newapi.example?x=1",
		"http://newapi.example?",
		"http://newapi.example#fragment",
		"http://newapi.example:",
		"http://newapi.example:70000",
	}
	for _, value := range invalid {
		t.Run("invalid "+value, func(t *testing.T) {
			cfg := testConfig()
			cfg.NewAPI.URL = value
			if err := Validate(cfg); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestValidateNewAPIProxyURL(t *testing.T) {
	valid := []string{
		"",
		"http://127.0.0.1:7897",
		"https://proxy.example",
		"http://[::1]:7897",
	}
	for _, value := range valid {
		t.Run("valid "+value, func(t *testing.T) {
			cfg := testConfig()
			cfg.NewAPI.ProxyURL = value
			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	invalid := []string{
		" ",
		"ftp://proxy.example",
		"http://",
		"http://user:pass@proxy.example",
		"http://proxy.example/",
		"http://proxy.example/connect",
		"http://proxy.example?x=1",
		"http://proxy.example?",
		"http://proxy.example#fragment",
		"http://proxy.example:",
		"http://proxy.example:70000",
	}
	for _, value := range invalid {
		t.Run("invalid "+value, func(t *testing.T) {
			cfg := testConfig()
			cfg.NewAPI.ProxyURL = value
			err := Validate(cfg)
			if err == nil || !strings.Contains(err.Error(), "newapi.proxy_url") {
				t.Fatalf("Validate() error = %v, want newapi.proxy_url error", err)
			}
		})
	}
}

func TestValidateInterceptors(t *testing.T) {
	tests := []struct {
		name         string
		interceptors map[string]InterceptorConfig
		wantError    bool
	}{
		{"none", nil, false},
		{"credential", map[string]InterceptorConfig{"auth": {Type: "require_credential"}}, false},
		{"factory config remains raw", map[string]InterceptorConfig{"limit": {Type: "max_body_bytes", Config: map[string]any{"max_bytes": 1048576}}}, false},
		{"custom type remains extensible", map[string]InterceptorConfig{"policy": {Type: "custom_policy", Config: map[string]any{"future_field": true}}}, false},
		{"empty id", map[string]InterceptorConfig{"": {Type: "require_credential"}}, true},
		{"empty type", map[string]InterceptorConfig{"x": {}}, true},
		{"type whitespace", map[string]InterceptorConfig{"x": {Type: " custom"}}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Interceptors = test.interceptors
			err := Validate(cfg)
			if (err != nil) != test.wantError {
				t.Fatalf("Validate() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestValidateRoutes(t *testing.T) {
	baseRoute := RouteConfig{
		ID:     "responses",
		Method: "POST",
		Path:   "/v1/responses",
		Match:  "exact",
		Parser: "openai.responses",
	}
	tests := []struct {
		name      string
		routes    []RouteConfig
		configure func(*Config)
		wantError bool
	}{
		{"valid exact", []RouteConfig{baseRoute}, nil, false},
		{"valid template", []RouteConfig{{ID: "gemini", Method: "POST", Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "gemini.generate_content"}}, nil, false},
		{"duplicate id", []RouteConfig{baseRoute, baseRoute}, nil, true},
		{"empty parser", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact"}}, nil, true},
		{"lower method", []RouteConfig{{ID: "x", Method: "post", Path: "/v1/x", Match: "exact", Parser: "x"}}, nil, true},
		{"unknown match", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "prefix", Parser: "x"}}, nil, true},
		{"exact placeholder", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/{model}", Match: "exact", Parser: "x"}}, nil, true},
		{"template without placeholder", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "template", Parser: "x"}}, nil, true},
		{"placeholder mid segment", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x{model}", Match: "template", Parser: "x"}}, nil, true},
		{"unsupported suffix", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/{model}.json", Match: "template", Parser: "x"}}, nil, true},
		{"trailing slash", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x/", Match: "exact", Parser: "x"}}, nil, true},
		{"dot segment", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/../x", Match: "exact", Parser: "x"}}, nil, true},
		{"encoded slash", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1%2fx", Match: "exact", Parser: "x"}}, nil, true},
		{"duplicate exact", []RouteConfig{baseRoute, {ID: "responses-2", Method: "POST", Path: "/v1/responses", Match: "exact", Parser: "x"}}, nil, true},
		{"exact template overlap", []RouteConfig{{ID: "exact", Method: "POST", Path: "/v1beta/models/gemini-2.5:generateContent", Match: "exact", Parser: "x"}, {ID: "template", Method: "POST", Path: "/v1beta/models/{model}:generateContent", Match: "template", Parser: "x"}}, nil, true},
		{"different methods", []RouteConfig{baseRoute, {ID: "responses-get", Method: "GET", Path: "/v1/responses", Match: "exact", Parser: "x"}}, nil, false},
		{"unknown interceptor", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x", Interceptors: []string{"missing"}}}, nil, true},
		{"known interceptor", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x", Interceptors: []string{"auth"}}}, func(cfg *Config) {
			cfg.Interceptors = map[string]InterceptorConfig{"auth": {Type: "require_credential"}}
		}, false},
		{"duplicate interceptor", []RouteConfig{{ID: "x", Method: "POST", Path: "/v1/x", Match: "exact", Parser: "x", Interceptors: []string{"auth", "auth"}}}, func(cfg *Config) {
			cfg.Interceptors = map[string]InterceptorConfig{"auth": {Type: "require_credential"}}
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Routes = test.routes
			if test.configure != nil {
				test.configure(&cfg)
			}
			err := Validate(cfg)
			if (err != nil) != test.wantError {
				t.Fatalf("Validate() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func testConfig() Config {
	cfg := Default()
	cfg.Listen = "127.0.0.1:18080"
	cfg.AdminListen = "127.0.0.1:18081"
	cfg.AdminToken = "test-token"
	return cfg
}
