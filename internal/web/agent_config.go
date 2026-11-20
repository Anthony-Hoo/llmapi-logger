package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/uaguard"
)

// Configuration and directory reads on the facade (contract sections 4.3.6
// and 4.4). All of them are administrator-only in the registry (D12). Every
// modifiable object carries version, the decimal string of its last
// modification time; names, patterns and keywords are _untrusted because
// another administrator or agent may have written them.

// agentVersion is the version of an object last modified at ns; "0" for a
// settings section that was never saved.
func agentVersion(ns int64) string {
	return strconv.FormatInt(ns, 10)
}

type agentUARule struct {
	ID                        int64   `json:"id"`
	Version                   string  `json:"version"`
	NameUntrusted             string  `json:"name_untrusted"`
	Enabled                   bool    `json:"enabled"`
	ModelPatternUntrusted     string  `json:"model_pattern_untrusted"`
	UserAgentPatternUntrusted string  `json:"user_agent_pattern_untrusted"`
	CreatedAt                 *string `json:"created_at"`
	UpdatedAt                 *string `json:"updated_at"`
}

func agentUARules(rules []uaguard.Rule) []agentUARule {
	out := make([]agentUARule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, agentUARule{ID: rule.ID, Version: agentVersion(rule.UpdatedAtNS), NameUntrusted: rule.Name, Enabled: rule.Enabled,
			ModelPatternUntrusted: rule.ModelPattern, UserAgentPatternUntrusted: rule.UserAgentPattern,
			CreatedAt: agentTime(rule.CreatedAtNS), UpdatedAt: agentTime(rule.UpdatedAtNS)})
	}
	return out
}

type agentContentRule struct {
	ID                    int64    `json:"id"`
	Version               string   `json:"version"`
	NameUntrusted         string   `json:"name_untrusted"`
	Enabled               bool     `json:"enabled"`
	Action                string   `json:"action"`
	ModelPatternUntrusted string   `json:"model_pattern_untrusted"`
	ScanScopes            []string `json:"scan_scopes"`
	KeywordsUntrusted     []string `json:"keywords_untrusted"`
	CreatedAt             *string  `json:"created_at"`
	UpdatedAt             *string  `json:"updated_at"`
}

func agentContentRules(rules []contentpolicy.Rule) []agentContentRule {
	out := make([]agentContentRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, agentContentRule{ID: rule.ID, Version: agentVersion(rule.UpdatedAtNS), NameUntrusted: rule.Name,
			Enabled: rule.Enabled, Action: rule.Action, ModelPatternUntrusted: rule.ModelPattern,
			ScanScopes: append([]string{}, rule.ScanScopes...), KeywordsUntrusted: append([]string{}, rule.Keywords...),
			CreatedAt: agentTime(rule.CreatedAtNS), UpdatedAt: agentTime(rule.UpdatedAtNS)})
	}
	return out
}

type agentOrgGroup struct {
	ID            int64   `json:"id"`
	Version       string  `json:"version"`
	NameUntrusted string  `json:"name_untrusted"`
	Enabled       bool    `json:"enabled"`
	CreatedAt     *string `json:"created_at"`
	UpdatedAt     *string `json:"updated_at"`
}

type agentOrgRule struct {
	Kind             string `json:"kind"`
	PatternUntrusted string `json:"pattern_untrusted"`
}

type agentOrgProject struct {
	ID            int64          `json:"id"`
	Version       string         `json:"version"`
	NameUntrusted string         `json:"name_untrusted"`
	GroupID       *int64         `json:"group_id"`
	Enabled       bool           `json:"enabled"`
	Rules         []agentOrgRule `json:"rules"`
	CreatedAt     *string        `json:"created_at"`
	UpdatedAt     *string        `json:"updated_at"`
}

type agentOrgMember struct {
	UserID    int64   `json:"user_id"`
	Version   string  `json:"version"`
	GroupID   int64   `json:"group_id"`
	UpdatedAt *string `json:"updated_at"`
}

type agentOrgPrincipal struct {
	Kind      string  `json:"kind"`
	ID        int64   `json:"id"`
	Version   string  `json:"version"`
	Class     string  `json:"class"`
	UpdatedAt *string `json:"updated_at"`
}

type agentOrgSettings struct {
	IdleGapSeconds        int64    `json:"idle_gap_seconds"`
	RankedClients         []string `json:"ranked_clients"`
	MaxConcurrentRoots    int      `json:"max_concurrent_roots"`
	MaxSingleRequestRoots int      `json:"max_single_request_roots"`
}

type agentOrgConfig struct {
	Groups            []agentOrgGroup     `json:"groups"`
	Projects          []agentOrgProject   `json:"projects"`
	Members           []agentOrgMember    `json:"members"`
	Principals        []agentOrgPrincipal `json:"principals"`
	ServiceCandidates []int64             `json:"service_candidates"`
	Timezone          string              `json:"timezone"`
	WeekStart         string              `json:"week_start"`
	Settings          agentOrgSettings    `json:"settings"`
}

func agentOrgConfigOf(catalog orgreport.CatalogView, settings orgreport.PublicSettings) agentOrgConfig {
	out := agentOrgConfig{
		Groups: make([]agentOrgGroup, 0, len(catalog.Groups)), Projects: make([]agentOrgProject, 0, len(catalog.Projects)),
		Members: make([]agentOrgMember, 0, len(catalog.Members)), Principals: make([]agentOrgPrincipal, 0, len(catalog.Principals)),
		ServiceCandidates: append([]int64{}, catalog.ServiceCandidates...),
		Timezone:          settings.Timezone, WeekStart: settings.WeekStart,
		Settings: agentOrgSettings{IdleGapSeconds: settings.IdleGapSeconds, RankedClients: append([]string{}, settings.RankedClients...),
			MaxConcurrentRoots: settings.MaxConcurrentRoots, MaxSingleRequestRoots: settings.MaxSingleRequestRoots},
	}
	for _, group := range catalog.Groups {
		out.Groups = append(out.Groups, agentOrgGroupOf(group))
	}
	for _, project := range catalog.Projects {
		out.Projects = append(out.Projects, agentOrgProjectOf(project))
	}
	for _, member := range catalog.Members {
		out.Members = append(out.Members, agentOrgMemberOf(member))
	}
	for _, principal := range catalog.Principals {
		out.Principals = append(out.Principals, agentOrgPrincipalOf(principal))
	}
	return out
}

func agentOrgGroupOf(group orgreport.Group) agentOrgGroup {
	return agentOrgGroup{ID: group.ID, Version: agentVersion(group.UpdatedAtNS), NameUntrusted: group.Name,
		Enabled: group.Enabled, CreatedAt: agentTime(group.CreatedAtNS), UpdatedAt: agentTime(group.UpdatedAtNS)}
}

func agentOrgProjectOf(project orgreport.Project) agentOrgProject {
	rules := make([]agentOrgRule, 0, len(project.Rules))
	for _, rule := range project.Rules {
		rules = append(rules, agentOrgRule{Kind: rule.Kind, PatternUntrusted: rule.Pattern})
	}
	var groupID *int64
	if project.GroupID != nil {
		value := *project.GroupID
		groupID = &value
	}
	return agentOrgProject{ID: project.ID, Version: agentVersion(project.UpdatedAtNS),
		NameUntrusted: project.Name, GroupID: groupID, Enabled: project.Enabled, Rules: rules,
		CreatedAt: agentTime(project.CreatedAtNS), UpdatedAt: agentTime(project.UpdatedAtNS)}
}

func agentOrgMemberOf(member orgreport.Member) agentOrgMember {
	return agentOrgMember{UserID: member.UserID, Version: agentVersion(member.UpdatedAtNS),
		GroupID: member.GroupID, UpdatedAt: agentTime(member.UpdatedAtNS)}
}

func agentOrgPrincipalOf(principal orgreport.Principal) agentOrgPrincipal {
	return agentOrgPrincipal{Kind: principal.Kind, ID: principal.ID,
		Version: agentVersion(principal.UpdatedAtNS), Class: principal.Class, UpdatedAt: agentTime(principal.UpdatedAtNS)}
}

type agentWeeklySettingsValues struct {
	IdleGapSeconds        int      `json:"idle_gap_seconds"`
	RankedClients         []string `json:"ranked_clients"`
	MaxConcurrentRoots    int      `json:"max_concurrent_roots"`
	MaxSingleRequestRoots int      `json:"max_single_request_roots"`
}

func agentWeeklySettingsValuesOf(settings orgreport.EditableSettings) agentWeeklySettingsValues {
	return agentWeeklySettingsValues{IdleGapSeconds: settings.IdleGapSeconds, RankedClients: append([]string{}, settings.RankedClients...),
		MaxConcurrentRoots: settings.MaxConcurrentRoots, MaxSingleRequestRoots: settings.MaxSingleRequestRoots}
}

type agentClientOption struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type agentWeeklySettings struct {
	Version   string                    `json:"version"`
	Source    string                    `json:"source"`
	UpdatedAt *string                   `json:"updated_at"`
	Settings  agentWeeklySettingsValues `json:"settings"`
	File      agentWeeklySettingsValues `json:"file"`
	Timezone  string                    `json:"timezone"`
	WeekStart string                    `json:"week_start"`
	Clients   []agentClientOption       `json:"clients"`
}

func agentWeeklySettingsOf(view orgreport.SettingsView) agentWeeklySettings {
	out := agentWeeklySettings{Version: agentVersion(view.UpdatedNS), Source: view.Source, UpdatedAt: agentTime(view.UpdatedNS),
		Settings: agentWeeklySettingsValuesOf(view.Settings), File: agentWeeklySettingsValuesOf(view.File),
		Timezone: view.Timezone, WeekStart: view.WeekStart, Clients: make([]agentClientOption, 0, len(view.Clients))}
	for _, client := range view.Clients {
		out.Clients = append(out.Clients, agentClientOption{Key: client.Key, Label: client.Label})
	}
	return out
}

type agentLLMSettings struct {
	Enabled           bool   `json:"enabled"`
	BaseURL           string `json:"base_url"`
	Model             string `json:"model"`
	StructuredOutput  string `json:"structured_output"`
	ContextTokens     int    `json:"context_tokens"`
	DisableThinking   bool   `json:"disable_thinking"`
	MaxOutputTokens   int    `json:"max_output_tokens"`
	MaxConcurrency    int    `json:"max_concurrency"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	MaxSessionsPerRun int    `json:"max_sessions_per_run"`
}

type agentAnalysisSettingsValues struct {
	RunAt         string           `json:"run_at"`
	L1SettleHours int              `json:"l1_settle_hours"`
	LLM           agentLLMSettings `json:"llm"`
}

func agentAnalysisSettingsValuesOf(settings sessionanalysis.EditableSettings) agentAnalysisSettingsValues {
	llm := settings.LLM
	return agentAnalysisSettingsValues{RunAt: settings.RunAt, L1SettleHours: settings.L1SettleHours, LLM: agentLLMSettings{
		Enabled: llm.Enabled, BaseURL: llm.BaseURL, Model: llm.Model, StructuredOutput: llm.StructuredOutput,
		ContextTokens: llm.ContextTokens, DisableThinking: llm.DisableThinking, MaxOutputTokens: llm.MaxOutputTokens,
		MaxConcurrency: llm.MaxConcurrency, TimeoutSeconds: llm.TimeoutSeconds, MaxSessionsPerRun: llm.MaxSessionsRun,
	}}
}

type agentFileOnlySettings struct {
	AllowNonLocal       bool `json:"allow_non_local"`
	SessionIdleMinutes  int  `json:"session_idle_minutes"`
	MinUserTurns        int  `json:"min_user_turns"`
	MinActiveSeconds    int  `json:"min_active_seconds"`
	PackMaxTokens       int  `json:"pack_max_tokens"`
	PromptReserveTokens int  `json:"prompt_reserve_tokens"`
}

type agentAnalysisSettings struct {
	Version    string                      `json:"version"`
	Source     string                      `json:"source"`
	UpdatedAt  *string                     `json:"updated_at"`
	Settings   agentAnalysisSettingsValues `json:"settings"`
	APIKey     string                      `json:"api_key"`
	File       agentAnalysisSettingsValues `json:"file"`
	FileAPIKey bool                        `json:"file_api_key"`
	FileOnly   agentFileOnlySettings       `json:"file_only"`
	Running    bool                        `json:"running"`
}

func agentAnalysisSettingsOf(view sessionanalysis.SettingsView) agentAnalysisSettings {
	return agentAnalysisSettings{
		Version: agentVersion(view.UpdatedNS), Source: view.Source, UpdatedAt: agentTime(view.UpdatedNS),
		Settings: agentAnalysisSettingsValuesOf(view.Settings), APIKey: view.APIKey,
		File: agentAnalysisSettingsValuesOf(view.File), FileAPIKey: view.FileAPIKey,
		FileOnly: agentFileOnlySettings{AllowNonLocal: view.FileOnly.AllowNonLocal, SessionIdleMinutes: view.FileOnly.SessionIdleMinutes,
			MinUserTurns: view.FileOnly.MinUserTurns, MinActiveSeconds: view.FileOnly.MinActiveSeconds,
			PackMaxTokens: view.FileOnly.PackMaxTokens, PromptReserveTokens: view.FileOnly.PromptReserveTokens},
		Running: view.Running,
	}
}

// serveAgentConfigShow is GET /config/{kind} (administrators).
func (handler *managementHandler) serveAgentConfigShow(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	switch call.Params["kind"] {
	case "ua-rule":
		if handler.rules == nil {
			handler.writeAgentServiceFailure(writer, errAgentUnavailable, "")
			return
		}
		writeAgentRead(writer, map[string]any{"items": agentUARules(handler.rules.List())}, agentMetaOK(), true)
	case "content-rule":
		if handler.policies == nil || !handler.policies.Available() {
			handler.writeAgentServiceFailure(writer, errAgentUnavailable, "")
			return
		}
		writeAgentRead(writer, map[string]any{"items": agentContentRules(handler.policies.List())}, agentMetaOK(), true)
	case "org":
		if !handler.agentOrgReady(writer) {
			return
		}
		writeAgentRead(writer, agentOrgConfigOf(handler.org.Catalog(), handler.org.Settings()), agentMetaOK(), true)
	case "weekly-settings":
		if !handler.agentOrgReady(writer) {
			return
		}
		view, err := handler.org.EditableSettings(ctx)
		if err != nil {
			handler.writeAgentServiceFailure(writer, err, "")
			return
		}
		writeAgentRead(writer, agentWeeklySettingsOf(view), agentMetaOK(), false)
	case "analysis-settings":
		if handler.sessionAnalysisSettings == nil {
			agentModuleDisabled(writer, agentModuleSessionAnalysis)
			return
		}
		view, err := handler.sessionAnalysisSettings.Get(ctx)
		if err != nil {
			handler.writeAgentServiceFailure(writer, err, "")
			return
		}
		writeAgentRead(writer, agentAnalysisSettingsOf(view), agentMetaOK(), false)
	default:
		handler.writeAgentServiceFailure(writer, argNotAllowed("kind", agentapi.ConfigKinds), "")
	}
}

type agentCallerEntry struct {
	ID                   int64  `json:"id"`
	UsernameUntrusted    string `json:"username_untrusted"`
	DisplayNameUntrusted string `json:"display_name_untrusted"`
	Status               int    `json:"status"`
	GroupUntrusted       string `json:"group_untrusted"`
}

// serveAgentCallers is GET /callers (administrators).
func (handler *managementHandler) serveAgentCallers(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	items := []agentCallerEntry{}
	var refreshedAt *string
	if handler.users != nil {
		snapshot := handler.users.Snapshot()
		for _, user := range snapshot.Users {
			items = append(items, agentCallerEntry{ID: user.ID, UsernameUntrusted: user.Username, DisplayNameUntrusted: user.DisplayName,
				Status: user.Status, GroupUntrusted: user.Group})
		}
		if !snapshot.RefreshedAt.IsZero() {
			refreshedAt = agentTime(snapshot.RefreshedAt.UnixNano())
		}
	}
	writeAgentRead(writer, map[string]any{"items": items, "refreshed_at": refreshedAt}, agentMetaOK(), true)
}

type agentReady struct {
	Status        string `json:"status"`
	Database      string `json:"database"`
	EncryptionKey string `json:"encryption_key"`
	ParserQueue   int    `json:"parser_queue"`
	CallerQueue   int    `json:"caller_queue"`
}

// serveAgentStatus is GET /status (administrators): /healthz and /readyz in
// one read. not_ready is a result here, not an error.
func (handler *managementHandler) serveAgentStatus(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	status := handler.readyStatus(request.Context())
	meta := agentapi.Meta{State: status.Status, Complete: true}
	if status.Status == "not_ready" {
		meta.Complete, meta.IncompleteReason = false, "not_ready"
	}
	writeAgentRead(writer, map[string]any{"live": true, "ready": agentReady{
		Status: status.Status, Database: status.Database, EncryptionKey: status.EncryptionKey,
		ParserQueue: status.ParserQueue, CallerQueue: status.CallerQueue,
	}}, meta, false)
}

type agentPreview struct {
	Requests          int `json:"requests"`
	Identities        int `json:"identities"`
	Users             int `json:"users"`
	FromUnattributed  int `json:"from_unattributed"`
	FromOtherProjects int `json:"from_other_projects"`
}

// errAgentPreviewWeek is a week the service refused after the facade's check.
var errAgentPreviewWeek = argFormat("week", "the first day of a report week, YYYY-MM-DD")

// agentPreviewInput decodes the body of the project preview field by field,
// so a refusal names the field: an unknown key, a value of the wrong JSON
// type, no rule at all, or a week that is not a week start. The rules
// themselves are checked by the service.
func (handler *managementHandler) agentPreviewInput(writer http.ResponseWriter, request *http.Request) (orgreport.PreviewInput, error) {
	var input orgreport.PreviewInput
	request.Body = http.MaxBytesReader(writer, request.Body, maxOrgBodyBytes)
	decoder := json.NewDecoder(request.Body)
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return input, argInvalid("body", reasonInvalidFormat, "the body must be one JSON object with week, group_id, rules and project_id")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return input, argInvalid("body", reasonInvalidFormat, "the body must be exactly one JSON object")
	}
	allowed := agentBodyFields()["config.project-preview"]
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !contains(allowed, key) {
			return input, argInvalid(key, reasonUnknownParameter, "`"+key+"` is not a field of the preview; it takes "+strings.Join(allowed, ", ")).
				with("allowed", allowed)
		}
	}
	if raw, ok := fields["week"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &input.Week) != nil {
			return input, argFormat("week", "a YYYY-MM-DD string")
		}
		if failure := handler.agentWeekFailure(input.Week, "week"); failure != nil {
			return input, failure
		}
	}
	if raw, ok := fields["group_id"]; ok && string(raw) != "null" {
		var id int64
		if json.Unmarshal(raw, &id) != nil || id < 0 {
			return input, argFormat("group_id", "a project group id (a JSON number, at least 0) or null for the organization-wide project")
		}
		input.GroupID = &id
	}
	if raw, ok := fields["project_id"]; ok && string(raw) != "null" {
		if json.Unmarshal(raw, &input.ProjectID) != nil || input.ProjectID < 0 {
			return input, argFormat("project_id", "a project id (a JSON number, at least 0)")
		}
	}
	if raw, ok := fields["rules"]; ok && string(raw) != "null" {
		rules := json.NewDecoder(bytes.NewReader(raw))
		rules.DisallowUnknownFields()
		if rules.Decode(&input.Rules) != nil {
			return input, argFormat("rules", "a list of {kind, pattern} objects")
		}
	}
	if len(input.Rules) == 0 {
		return input, argInvalid("rules", reasonRequired, "at least one rule is required: `rules` is a list of {kind, pattern} with kind "+
			strings.Join([]string{orgreport.RuleRepoURL, orgreport.RuleRepoName, orgreport.RulePathGlob, orgreport.RuleAgentProject}, ", "))
	}
	return input, nil
}

// serveAgentProjectPreview is POST /config/project-preview (administrators,
// read tier: it persists nothing). The body is the web route's.
func (handler *managementHandler) serveAgentProjectPreview(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if !handler.agentOrgReady(writer) {
		return
	}
	if _, err := agentCallParams(request, call); err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	input, err := handler.agentPreviewInput(writer, request)
	if err != nil {
		handler.writeAgentServiceFailure(writer, err, "")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queryTimeout)
	defer cancel()
	result, err := handler.org.Preview(ctx, input)
	if err != nil {
		var invalid *orgreport.ValidationError
		if errors.As(err, &invalid) {
			// A rule the service refused: the same field and reason as
			// `config set --kind project` reports for it.
			handler.writeAgentWriteFailure(writer, err)
			return
		}
		handler.writeAgentServiceFailure(writer, asArgument(err, errAgentPreviewWeek), "")
		return
	}
	var project *int64
	if input.ProjectID > 0 {
		project = &input.ProjectID
	}
	writeAgentRead(writer, agentPreview{Requests: result.Requests, Identities: result.Identities, Users: result.Users,
		FromUnattributed: result.Unattributed, FromOtherProjects: result.OtherProject}, agentMetaOK(), false,
		handler.agentUnknownOrgObjects(input.GroupID, project)...)
}
