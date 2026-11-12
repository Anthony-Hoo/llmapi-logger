package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// SessionAnalysisConfig controls session-record analysis
// (doc/features/24-session-analysis.md). Everything is off by default; with
// the LLM part disabled the deterministic signals and input packs still run.
type SessionAnalysisConfig struct {
	Enabled            bool                     `yaml:"enabled"`
	RunAt              string                   `yaml:"run_at"`
	SessionIdleMinutes int                      `yaml:"session_idle_minutes"`
	L1SettleHours      int                      `yaml:"l1_settle_hours"`
	MinUserTurns       int                      `yaml:"min_user_turns"`
	MinActiveSeconds   int                      `yaml:"min_active_seconds"`
	VocabularyFile     string                   `yaml:"vocabulary_file"`
	Pack               SessionAnalysisPack      `yaml:"pack"`
	LLM                SessionAnalysisLLM       `yaml:"llm"`
	Compliance         SessionAnalysisCompliant `yaml:"compliance"`
}

// SessionAnalysisPack bounds the input pack handed to the local model.
type SessionAnalysisPack struct {
	MaxTokens int `yaml:"max_tokens"`
}

// SessionAnalysisLLM configures the local OpenAI-compatible model endpoint.
// APIKey is never logged or returned by any API.
type SessionAnalysisLLM struct {
	Enabled          bool   `yaml:"enabled"`
	BaseURL          string `yaml:"base_url"`
	Model            string `yaml:"model"`
	APIKey           string `yaml:"api_key"`
	AllowNonLocal    bool   `yaml:"allow_non_local"`
	StructuredOutput string `yaml:"structured_output"`
	ContextTokens    int    `yaml:"context_tokens"`
	DisableThinking  bool   `yaml:"disable_thinking"`
	MaxOutputTokens  int    `yaml:"max_output_tokens"`
	MaxConcurrency   int    `yaml:"max_concurrency"`
	TimeoutSeconds   int    `yaml:"timeout_seconds"`
	MaxSessionsRun   int    `yaml:"max_sessions_per_run"`
}

// SessionAnalysisCompliant is the compliance mode switch. The mode itself is
// not implemented yet (doc 24 section 10); enabling it is rejected.
type SessionAnalysisCompliant struct {
	Enabled bool `yaml:"enabled"`
}

// Session analysis defaults (doc 24 section 4).
const (
	DefaultSessionAnalysisRunAt        = "02:00"
	DefaultSessionIdleMinutes          = 120
	DefaultL1SettleHours               = 24
	DefaultSessionMinUserTurns         = 2
	DefaultSessionMinActiveSeconds     = 60
	DefaultSessionPackMaxTokens        = 6000
	DefaultSessionLLMBaseURL           = "http://127.0.0.1:11434/v1"
	DefaultSessionLLMStructuredOutput  = "json_schema"
	DefaultSessionLLMContextTokens     = 16384
	DefaultSessionLLMMaxOutputTokens   = 1500
	DefaultSessionLLMMaxConcurrency    = 1
	DefaultSessionLLMTimeoutSeconds    = 120
	DefaultSessionLLMMaxSessionsPerRun = 300
	// SessionPromptReserveTokens is the fixed-prefix budget (system prompt,
	// rules, schema and examples) the context check sets aside.
	SessionPromptReserveTokens = 2500
)

func defaultSessionAnalysis() SessionAnalysisConfig {
	return SessionAnalysisConfig{
		RunAt:              DefaultSessionAnalysisRunAt,
		SessionIdleMinutes: DefaultSessionIdleMinutes,
		L1SettleHours:      DefaultL1SettleHours,
		MinUserTurns:       DefaultSessionMinUserTurns,
		MinActiveSeconds:   DefaultSessionMinActiveSeconds,
		Pack:               SessionAnalysisPack{MaxTokens: DefaultSessionPackMaxTokens},
		LLM: SessionAnalysisLLM{
			BaseURL:          DefaultSessionLLMBaseURL,
			StructuredOutput: DefaultSessionLLMStructuredOutput,
			ContextTokens:    DefaultSessionLLMContextTokens,
			DisableThinking:  true,
			MaxOutputTokens:  DefaultSessionLLMMaxOutputTokens,
			MaxConcurrency:   DefaultSessionLLMMaxConcurrency,
			TimeoutSeconds:   DefaultSessionLLMTimeoutSeconds,
			MaxSessionsRun:   DefaultSessionLLMMaxSessionsPerRun,
		},
	}
}

// ParseRunAt returns the hour and minute of an "HH:MM" daily run time.
func ParseRunAt(value string) (int, int, error) {
	hourText, minuteText, ok := strings.Cut(value, ":")
	if !ok || len(hourText) != 2 || len(minuteText) != 2 {
		return 0, 0, fmt.Errorf("must be HH:MM, got %q", value)
	}
	hour, hourErr := strconv.Atoi(hourText)
	minute, minuteErr := strconv.Atoi(minuteText)
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("must be HH:MM, got %q", value)
	}
	return hour, minute, nil
}

func validateSessionAnalysis(cfg Config) error {
	analysis := cfg.SessionAnalysis
	if !analysis.Enabled {
		return nil
	}
	if !cfg.Insights.Enabled {
		return errors.New("session_analysis.enabled requires insights.enabled")
	}
	if _, _, err := ParseRunAt(analysis.RunAt); err != nil {
		return fmt.Errorf("session_analysis.run_at %w", err)
	}
	if analysis.SessionIdleMinutes < 5 || analysis.SessionIdleMinutes > 7*24*60 {
		return fmt.Errorf("session_analysis.session_idle_minutes must be between 5 and 10080, got %d", analysis.SessionIdleMinutes)
	}
	if analysis.L1SettleHours < 0 || analysis.L1SettleHours > 24*14 {
		return fmt.Errorf("session_analysis.l1_settle_hours must be between 0 and 336, got %d", analysis.L1SettleHours)
	}
	if analysis.MinUserTurns < 1 || analysis.MinUserTurns > 1000 {
		return fmt.Errorf("session_analysis.min_user_turns must be between 1 and 1000, got %d", analysis.MinUserTurns)
	}
	if analysis.MinActiveSeconds < 0 || analysis.MinActiveSeconds > 86400 {
		return fmt.Errorf("session_analysis.min_active_seconds must be between 0 and 86400, got %d", analysis.MinActiveSeconds)
	}
	if err := validateOptionalFile("session_analysis.vocabulary_file", analysis.VocabularyFile); err != nil {
		return err
	}
	if analysis.Pack.MaxTokens < 500 || analysis.Pack.MaxTokens > 200000 {
		return fmt.Errorf("session_analysis.pack.max_tokens must be between 500 and 200000, got %d", analysis.Pack.MaxTokens)
	}
	if analysis.Compliance.Enabled {
		return errors.New("session_analysis.compliance is not implemented yet and must stay disabled")
	}
	return validateSessionLLM(analysis)
}

// ValidateSessionAnalysisRuntime checks an enabled session_analysis section
// whose fields were replaced at run time (settings saved from the management
// UI) with the checks the configuration file gets, so the page can never store
// what the file would reject.
func ValidateSessionAnalysisRuntime(analysis SessionAnalysisConfig) error {
	analysis.Enabled = true
	return validateSessionAnalysis(Config{Insights: InsightsConfig{Enabled: true}, SessionAnalysis: analysis})
}

func validateSessionLLM(analysis SessionAnalysisConfig) error {
	llm := analysis.LLM
	if !llm.Enabled {
		return nil
	}
	if strings.TrimSpace(llm.Model) == "" {
		return errors.New("session_analysis.llm.model is required when the llm is enabled")
	}
	switch llm.StructuredOutput {
	case "json_schema", "json_object", "prompt":
	default:
		return fmt.Errorf("session_analysis.llm.structured_output must be json_schema, json_object or prompt, got %q", llm.StructuredOutput)
	}
	if llm.MaxOutputTokens < 100 || llm.MaxOutputTokens > 32768 {
		return fmt.Errorf("session_analysis.llm.max_output_tokens must be between 100 and 32768, got %d", llm.MaxOutputTokens)
	}
	if llm.ContextTokens < 2048 || llm.ContextTokens > 2_000_000 {
		return fmt.Errorf("session_analysis.llm.context_tokens must be between 2048 and 2000000, got %d", llm.ContextTokens)
	}
	if analysis.Pack.MaxTokens+SessionPromptReserveTokens+llm.MaxOutputTokens > llm.ContextTokens {
		return fmt.Errorf("session_analysis.pack.max_tokens + %d prompt tokens + llm.max_output_tokens exceeds llm.context_tokens", SessionPromptReserveTokens)
	}
	if llm.MaxConcurrency < 1 || llm.MaxConcurrency > 64 {
		return fmt.Errorf("session_analysis.llm.max_concurrency must be between 1 and 64, got %d", llm.MaxConcurrency)
	}
	if err := validateTimeoutSeconds("session_analysis.llm.timeout_seconds", llm.TimeoutSeconds); err != nil {
		return err
	}
	if llm.MaxSessionsRun < 1 || llm.MaxSessionsRun > 100000 {
		return fmt.Errorf("session_analysis.llm.max_sessions_per_run must be between 1 and 100000, got %d", llm.MaxSessionsRun)
	}
	if strings.IndexFunc(llm.APIKey, func(r rune) bool { return r == '\r' || r == '\n' }) >= 0 {
		return errors.New("session_analysis.llm.api_key must not contain line breaks")
	}
	parsed, err := url.Parse(llm.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("session_analysis.llm.base_url must be an http(s) URL without credentials, query or fragment")
	}
	if !llm.AllowNonLocal && !LocalModelHost(parsed.Hostname()) {
		return errors.New("session_analysis.llm.base_url must point to localhost, a loopback or a private address unless allow_non_local is true")
	}
	return nil
}

// LocalModelHost reports whether host is "localhost" or a literal loopback,
// RFC 1918, CGNAT (100.64.0.0/10) or IPv6 unique-local address. Host names
// other than localhost are rejected here; the dialer re-checks every resolved
// peer address at connect time.
func LocalModelHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return LocalModelAddress(address)
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// LocalModelAddress reports whether one peer address is allowed for the
// local model endpoint.
func LocalModelAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() {
		return false
	}
	return address.IsLoopback() || address.IsPrivate() || cgnatPrefix.Contains(address)
}

// LocalModelIP adapts LocalModelAddress to net.IP.
func LocalModelIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	return ok && LocalModelAddress(address)
}
