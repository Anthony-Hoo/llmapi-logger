package config

const (
	DefaultListen        = "0.0.0.0:8080"
	DefaultAdminListen   = "127.0.0.1:8081"
	DefaultNewAPIURL     = "http://127.0.0.1:3000"
	DefaultMode          = "available"
	DefaultDBPath        = "./data/audit.db"
	DefaultKeyPath       = "./data/audit.key"
	DefaultRetentionDays = 30
)

// Config is the complete user-facing configuration for one audit-proxy
// process. Operational tuning values intentionally remain internal defaults.
type Config struct {
	Listen            string                       `yaml:"listen"`
	AdminListen       string                       `yaml:"admin_listen"`
	NewAPIURL         string                       `yaml:"newapi_url"`
	Mode              string                       `yaml:"mode"`
	DBPath            string                       `yaml:"db_path"`
	KeyPath           string                       `yaml:"key_path"`
	AdminToken        string                       `yaml:"admin_token"`
	RetentionDays     int                          `yaml:"retention_days"`
	NewAPITokenDBPath string                       `yaml:"newapi_token_db_path"`
	Interceptors      map[string]InterceptorConfig `yaml:"interceptors"`
	Routes            []RouteConfig                `yaml:"routes"`
}

// InterceptorConfig defines one named interceptor instance. Config is kept as
// raw values so the interceptor registry can pass it to the selected factory.
type InterceptorConfig struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config,omitempty"`
}

// RouteConfig is one explicitly enabled LLM API route.
type RouteConfig struct {
	ID           string   `yaml:"id"`
	Method       string   `yaml:"method"`
	Path         string   `yaml:"path"`
	Match        string   `yaml:"match"`
	Parser       string   `yaml:"parser"`
	Interceptors []string `yaml:"interceptors,omitempty"`
}

// Default returns the scalar defaults documented in
// doc/features/01-configuration-and-route-boundary.md. Routes and
// interceptors remain explicit whitelist configuration.
func Default() Config {
	return Config{
		Listen:        DefaultListen,
		AdminListen:   DefaultAdminListen,
		NewAPIURL:     DefaultNewAPIURL,
		Mode:          DefaultMode,
		DBPath:        DefaultDBPath,
		KeyPath:       DefaultKeyPath,
		RetentionDays: DefaultRetentionDays,
		Interceptors:  make(map[string]InterceptorConfig),
		Routes:        make([]RouteConfig, 0),
	}
}
