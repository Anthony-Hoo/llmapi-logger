package config

const (
	DefaultListen                          = "0.0.0.0:8080"
	DefaultAdminListen                     = "127.0.0.1:8081"
	DefaultNewAPIURL                       = "http://127.0.0.1:3000"
	DefaultNewAPIResponseHeaderTimeoutSecs = 300
	DefaultShutdownTimeoutSecs             = 30
	DefaultMode                            = "available"
	DefaultDBPath                          = "./data/audit.db"
	DefaultKeyPath                         = "./data/audit.key"
	DefaultRetentionDays                   = 30
)

// Config is the complete user-facing configuration for one audit-proxy
// process. Only deployment-critical upstream and lifecycle timeouts are
// exposed; storage and worker tuning values remain internal defaults.
type Config struct {
	Listen      string       `yaml:"listen"`
	AdminListen string       `yaml:"admin_listen"`
	NewAPI      NewAPIConfig `yaml:"newapi"`
	Mode        string       `yaml:"mode"`
	// DBPath is retained only for legacy fixture/import callers; YAML rejects db_path.
	DBPath                 string                       `yaml:"-"`
	DatabaseURL            string                       `yaml:"database_url"`
	KeyPath                string                       `yaml:"key_path"`
	AdminToken             string                       `yaml:"admin_token"`
	DeveloperLogin         DeveloperLoginConfig         `yaml:"developer_login"`
	ShutdownTimeoutSeconds int                          `yaml:"shutdown_timeout_seconds"`
	RetentionDays          int                          `yaml:"retention_days"`
	Insights               InsightsConfig               `yaml:"insights"`
	OrgReports             OrgReportsConfig             `yaml:"org_reports"`
	SessionAnalysis        SessionAnalysisConfig        `yaml:"session_analysis"`
	Interceptors           map[string]InterceptorConfig `yaml:"interceptors"`
	Routes                 []RouteConfig                `yaml:"routes"`
}

// InsightsConfig controls derived context and usage analysis
// (doc/features/20-context-insights.md). VocabularyFile optionally overrides
// the tool/agent vocabulary; startup only checks that it exists, its owner
// parses it. ContextWindows overrides the embedded per-model context windows.
//
// PricingFile is deprecated and ignored: cost now comes from NewAPI's actual
// billing (doc/features/21-newapi-billing.md). It still parses so old
// configurations start, and startup logs one warning when it is set.
type InsightsConfig struct {
	Enabled        bool             `yaml:"enabled"`
	PricingFile    string           `yaml:"pricing_file"`
	VocabularyFile string           `yaml:"vocabulary_file"`
	ContextWindows map[string]int64 `yaml:"context_windows"`
}

// OrgReportsConfig controls the optional organisation project reports
// (doc/features/23-org-project-reports.md). It is off by default; while off
// nothing is extracted, no job runs and every /api/v1/org route answers 404.
// Groups, projects and rules live in the database, never in YAML.
type OrgReportsConfig struct {
	Enabled bool `yaml:"enabled"`
	// Timezone is an IANA zone name; day and week boundaries are local to it.
	Timezone string `yaml:"timezone"`
	// WeekStart is monday or sunday.
	WeekStart string `yaml:"week_start"`
	// IdleGapSeconds merges request spans of one agent-tree root whose gap is
	// at most this many seconds.
	IdleGapSeconds int `yaml:"idle_gap_seconds"`
	// RankedClients are the agent clients whose active time enters the ranking.
	// Names are vocabulary client keys and are not checked against the loaded
	// vocabulary, so a client added later by an override can be listed now.
	RankedClients     []string                   `yaml:"ranked_clients"`
	Anomaly           OrgAnomalyConfig           `yaml:"anomaly"`
	LLMClassification OrgLLMClassificationConfig `yaml:"llm_classification"`
}

// OrgAnomalyConfig holds the per-week thresholds that flag a ranking row.
// Flags never exclude a row.
type OrgAnomalyConfig struct {
	MaxConcurrentRoots    int `yaml:"max_concurrent_roots"`
	MaxSingleRequestRoots int `yaml:"max_single_request_roots"`
}

// OrgLLMClassificationConfig is the switch the original M5 design reserved.
// That work became the top-level session_analysis section
// (doc/features/24-session-analysis.md); the switch is kept so existing
// configuration files still load, and must stay disabled.
type OrgLLMClassificationConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Org report defaults (doc/features/23-org-project-reports.md section 3).
const (
	DefaultOrgTimezone              = "Asia/Shanghai"
	DefaultOrgWeekStart             = "monday"
	DefaultOrgIdleGapSeconds        = 180
	DefaultOrgMaxConcurrentRoots    = 10
	DefaultOrgMaxSingleRequestRoots = 200
)

// DefaultOrgRankedClients returns a fresh copy of the default ranked clients.
func DefaultOrgRankedClients() []string {
	return []string{"codex", "claude_code", "opencode", "dsh", "pi", "zcode", "custom"}
}

// DefaultOrgReports returns the disabled section with every default filled.
func DefaultOrgReports() OrgReportsConfig {
	return OrgReportsConfig{
		Timezone:       DefaultOrgTimezone,
		WeekStart:      DefaultOrgWeekStart,
		IdleGapSeconds: DefaultOrgIdleGapSeconds,
		RankedClients:  DefaultOrgRankedClients(),
		Anomaly: OrgAnomalyConfig{
			MaxConcurrentRoots:    DefaultOrgMaxConcurrentRoots,
			MaxSingleRequestRoots: DefaultOrgMaxSingleRequestRoots,
		},
	}
}

// NewAPIConfig contains both the data-plane upstream settings and the
// optional administrator credential used for read-only global users and logs.
// AccessToken is never returned by the management API, persisted, or logged.
type NewAPIConfig struct {
	URL                          string `yaml:"url"`
	ProxyURL                     string `yaml:"proxy_url"`
	ResponseHeaderTimeoutSeconds int    `yaml:"response_header_timeout_seconds"`
	PreserveHost                 bool   `yaml:"preserve_host"`
	AccessToken                  string `yaml:"access_token"`
	UserID                       int64  `yaml:"user_id"`
}

// DeveloperLoginConfig controls the second management identity: a NewAPI user
// who signs in with their own API key and may only read the audits that key
// produced. It authenticates against newapi.url directly and therefore needs
// neither newapi.access_token nor newapi.user_id.
type DeveloperLoginConfig struct {
	Enabled bool `yaml:"enabled"`
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
		Listen:      DefaultListen,
		AdminListen: DefaultAdminListen,
		NewAPI: NewAPIConfig{
			URL:                          DefaultNewAPIURL,
			ResponseHeaderTimeoutSeconds: DefaultNewAPIResponseHeaderTimeoutSecs,
		},
		Mode:                   DefaultMode,
		DBPath:                 DefaultDBPath,
		KeyPath:                DefaultKeyPath,
		ShutdownTimeoutSeconds: DefaultShutdownTimeoutSecs,
		RetentionDays:          DefaultRetentionDays,
		Insights:               InsightsConfig{Enabled: true},
		OrgReports:             DefaultOrgReports(),
		SessionAnalysis:        defaultSessionAnalysis(),
		Interceptors:           make(map[string]InterceptorConfig),
		Routes:                 make([]RouteConfig, 0),
	}
}
