package insights

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed vocabulary_default.yaml
var defaultVocabularyYAML []byte

// Vocabulary is the configurable knowledge about agent clients and tools
// (doc/features/20-context-insights.md sections 5.7, 5.8 and 11). It is data
// only: the analyzer reads the tool, marker and file-operation parts, and the
// identity resolver reads Clients and SideRequests.
//
// Header names, tool names and tool-name prefixes are lower-cased by
// LoadVocabulary; matching against request headers and tool names must
// lower-case the candidate too.
type Vocabulary struct {
	// Clients maps a lower-cased client name (codex, claude_code, opencode, dsh,
	// custom or any name added by an override) to its rules. Resolve them in
	// OrderedClients order; the first client whose Detect rule matches wins.
	Clients map[string]ClientRule `yaml:"clients"`
	// InjectionMarkers are text prefixes that mark client-injected context.
	InjectionMarkers []string `yaml:"injection_markers"`
	// VolatileTextPrefixes mark text that changes on every request without the
	// context really changing; fingerprints use the prefix instead of the text.
	VolatileTextPrefixes []string `yaml:"volatile_text_prefixes"`
	// ToolKinds maps a lower-cased tool name to a ToolKind* constant.
	ToolKinds map[string]string `yaml:"tool_kinds"`
	// ToolKindPrefixes maps a lower-cased tool-name prefix to a ToolKind*
	// constant (default: "mcp__" -> mcp). Exact ToolKinds entries win.
	ToolKindPrefixes map[string]string `yaml:"tool_kind_prefixes"`
	// SpawnTools maps a lower-cased spawn tool name to the argument names that
	// carry the child agent prompt, in priority order.
	SpawnTools map[string][]string `yaml:"spawn_tools"`
	// SubagentPrefixes is fixed text some clients prepend to a child agent's
	// opening prompt; it is stripped before prompt comparison.
	SubagentPrefixes []string `yaml:"subagent_prefixes"`
	// SideRequests recognise non-agent requests (title, compaction) by body.
	SideRequests []SideRequestRule `yaml:"side_requests"`
	// FileOps drives file-activity extraction from response tool calls.
	FileOps FileOpRules `yaml:"file_ops"`
}

// ClientRule describes how to detect one client and read its agent identity
// from request headers (and, for some clients, body paths). Header lists are
// ordered: the first header present with a non-empty value wins.
type ClientRule struct {
	// Priority orders detection: lower values are tried first.
	Priority int          `yaml:"priority"`
	Detect   ClientDetect `yaml:"detect"`
	// RootHeaders carry the id shared by the whole agent tree.
	RootHeaders []string `yaml:"root_headers"`
	// NodeHeaders carry the id of this single agent.
	NodeHeaders []string `yaml:"node_headers"`
	// ParentHeaders carry the id of the direct parent agent.
	ParentHeaders []string `yaml:"parent_headers"`
	// NameHeaders carry a human-readable agent name (detail view only).
	NameHeaders []string `yaml:"name_headers"`
	// ParentBodyPaths are dot-separated JSON paths in the request body that
	// hold the parent id when no parent header is present.
	ParentBodyPaths []string `yaml:"parent_body_paths"`
	// NodeFallback "root" means: with no node header the request belongs to the
	// main agent whose node id is the root id. "" or "none" disables it.
	NodeFallback string `yaml:"node_fallback"`
	// ParentFallback "root" means: with a node header but no parent header the
	// parent is the main agent (the root id). "" or "none" disables it.
	ParentFallback string `yaml:"parent_fallback"`
	// RoleHeaders map request-class header values to roles, in order.
	RoleHeaders []RoleHeader `yaml:"role_headers"`
}

// ClientDetect lists the signals that identify a client. Any one matching
// signal is enough.
type ClientDetect struct {
	// UserAgentPrefixes are case-insensitive User-Agent prefixes.
	UserAgentPrefixes []string `yaml:"user_agent_prefixes"`
	// HeadersPresent matches when any listed header has a non-empty value.
	HeadersPresent []string `yaml:"headers_present"`
	// HeadersEqual maps header name -> value (case-insensitive equality).
	HeadersEqual map[string]string `yaml:"headers_equal"`
}

// RoleHeader maps the value of one request-class header to an agent role
// (Role* constant). Value keys are lower-cased; compare case-insensitively.
type RoleHeader struct {
	Header string            `yaml:"header"`
	Values map[string]string `yaml:"values"`
}

// SideRequestRule recognises a non-agent request. A rule matches when the
// first system text starts with any of SystemPrefixes, or the last user text
// contains any of LastUserContains.
type SideRequestRule struct {
	Role             string   `yaml:"role"`
	SystemPrefixes   []string `yaml:"system_prefixes"`
	LastUserContains []string `yaml:"last_user_contains"`
}

// FileOpRules configures file-operation extraction. Op is one of read, write,
// search, shell. Style selects argument parsing: "" (path only), write
// (content), edit (old/new), multi_edit (edits array), patch (unified or
// apply_patch diff), editor (str_replace_editor commands).
type FileOpRules struct {
	PathKeys    []string              `yaml:"path_keys"`
	OldKeys     []string              `yaml:"old_keys"`
	NewKeys     []string              `yaml:"new_keys"`
	ContentKeys []string              `yaml:"content_keys"`
	EditsKeys   []string              `yaml:"edits_keys"`
	PatchKeys   []string              `yaml:"patch_keys"`
	Tools       map[string]FileOpTool `yaml:"tools"`
}

// FileOpTool is the file-operation rule of one lower-cased tool name.
type FileOpTool struct {
	Op    string `yaml:"op"`
	Style string `yaml:"style"`
}

// defaultClientPriority orders clients added by an override that sets no
// priority: after the built-in native clients, before the generic custom one.
const defaultClientPriority = 50

var (
	knownToolKinds = map[string]bool{
		ToolKindFileRead: true, ToolKindFileWrite: true, ToolKindSearch: true,
		ToolKindShell: true, ToolKindSpawn: true, ToolKindMCP: true, ToolKindOther: true,
	}
	knownRoles = map[string]bool{
		RoleMain: true, RoleSubagent: true, RoleCompaction: true,
		RoleTitle: true, RoleReview: true, RoleAuxiliary: true,
	}
	knownFileOps    = map[string]bool{"read": true, "write": true, "search": true, "shell": true}
	knownFileStyles = map[string]bool{"": true, "write": true, "edit": true, "multi_edit": true, "patch": true, "editor": true}
)

// DefaultVocabulary returns a fresh copy of the built-in vocabulary.
func DefaultVocabulary() *Vocabulary {
	vocab, err := parseVocabulary(defaultVocabularyYAML, true)
	if err != nil {
		panic("insights: invalid embedded vocabulary: " + err.Error())
	}
	if err := vocab.normalizeAndValidate(); err != nil {
		panic("insights: invalid embedded vocabulary: " + err.Error())
	}
	return vocab
}

// LoadVocabulary returns the default vocabulary when path is empty, otherwise
// the default merged with the YAML file at path: maps merge by key, lists
// replace the default list when present, scalars replace when non-empty. The
// result is validated; unknown YAML keys are rejected.
func LoadVocabulary(path string) (*Vocabulary, error) {
	vocab := DefaultVocabulary()
	if strings.TrimSpace(path) == "" {
		return vocab, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("insights vocabulary: %w", err)
	}
	override, err := parseVocabulary(data, true)
	if err != nil {
		return nil, fmt.Errorf("insights vocabulary: %w", err)
	}
	if err := override.normalize(); err != nil {
		return nil, fmt.Errorf("insights vocabulary: %w", err)
	}
	vocab.merge(override)
	if err := vocab.normalizeAndValidate(); err != nil {
		return nil, fmt.Errorf("insights vocabulary: %w", err)
	}
	return vocab, nil
}

func parseVocabulary(data []byte, strict bool) (*Vocabulary, error) {
	var vocab Vocabulary
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(strict)
	if err := decoder.Decode(&vocab); err != nil {
		if errors.Is(err, io.EOF) {
			return &vocab, nil // empty override file
		}
		return nil, err
	}
	// A second document would otherwise be silently ignored.
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple YAML documents are not supported")
		}
		return nil, err
	}
	return &vocab, nil
}

func (vocab *Vocabulary) merge(override *Vocabulary) {
	if vocab.Clients == nil {
		vocab.Clients = map[string]ClientRule{}
	}
	for name, rule := range override.Clients {
		base, ok := vocab.Clients[name]
		if !ok {
			if rule.Priority == 0 {
				rule.Priority = defaultClientPriority
			}
			vocab.Clients[name] = rule
			continue
		}
		vocab.Clients[name] = mergeClient(base, rule)
	}
	if override.InjectionMarkers != nil {
		vocab.InjectionMarkers = override.InjectionMarkers
	}
	if override.VolatileTextPrefixes != nil {
		vocab.VolatileTextPrefixes = override.VolatileTextPrefixes
	}
	vocab.ToolKinds = mergeStringMap(vocab.ToolKinds, override.ToolKinds)
	vocab.ToolKindPrefixes = mergeStringMap(vocab.ToolKindPrefixes, override.ToolKindPrefixes)
	if vocab.SpawnTools == nil {
		vocab.SpawnTools = map[string][]string{}
	}
	for name, args := range override.SpawnTools {
		vocab.SpawnTools[name] = args
	}
	if override.SubagentPrefixes != nil {
		vocab.SubagentPrefixes = override.SubagentPrefixes
	}
	if override.SideRequests != nil {
		vocab.SideRequests = override.SideRequests
	}
	rules, other := &vocab.FileOps, override.FileOps
	replaceList(&rules.PathKeys, other.PathKeys)
	replaceList(&rules.OldKeys, other.OldKeys)
	replaceList(&rules.NewKeys, other.NewKeys)
	replaceList(&rules.ContentKeys, other.ContentKeys)
	replaceList(&rules.EditsKeys, other.EditsKeys)
	replaceList(&rules.PatchKeys, other.PatchKeys)
	if rules.Tools == nil {
		rules.Tools = map[string]FileOpTool{}
	}
	for name, tool := range other.Tools {
		rules.Tools[name] = tool
	}
}

func mergeClient(base, override ClientRule) ClientRule {
	if override.Priority != 0 {
		base.Priority = override.Priority
	}
	replaceList(&base.Detect.UserAgentPrefixes, override.Detect.UserAgentPrefixes)
	replaceList(&base.Detect.HeadersPresent, override.Detect.HeadersPresent)
	if len(override.Detect.HeadersEqual) != 0 {
		merged := map[string]string{}
		for key, value := range base.Detect.HeadersEqual {
			merged[key] = value
		}
		for key, value := range override.Detect.HeadersEqual {
			merged[key] = value
		}
		base.Detect.HeadersEqual = merged
	}
	replaceList(&base.RootHeaders, override.RootHeaders)
	replaceList(&base.NodeHeaders, override.NodeHeaders)
	replaceList(&base.ParentHeaders, override.ParentHeaders)
	replaceList(&base.NameHeaders, override.NameHeaders)
	replaceList(&base.ParentBodyPaths, override.ParentBodyPaths)
	if override.NodeFallback != "" {
		base.NodeFallback = override.NodeFallback
	}
	if override.ParentFallback != "" {
		base.ParentFallback = override.ParentFallback
	}
	if override.RoleHeaders != nil {
		base.RoleHeaders = override.RoleHeaders
	}
	return base
}

func replaceList(target *[]string, override []string) {
	if override != nil {
		*target = override
	}
}

func mergeStringMap(base, override map[string]string) map[string]string {
	if base == nil {
		base = map[string]string{}
	}
	for key, value := range override {
		base[key] = value
	}
	return base
}

// normalize lower-cases names and keys. It runs on overrides before merging so
// that "Read" in an override replaces the default "read".
func (vocab *Vocabulary) normalize() error {
	clients := make(map[string]ClientRule, len(vocab.Clients))
	for name, rule := range vocab.Clients {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if trimmed == "" {
			return errors.New("client name is empty")
		}
		rule.Detect.UserAgentPrefixes = lowerList(rule.Detect.UserAgentPrefixes)
		rule.Detect.HeadersPresent = lowerList(rule.Detect.HeadersPresent)
		if rule.Detect.HeadersEqual != nil {
			equal := make(map[string]string, len(rule.Detect.HeadersEqual))
			for header, value := range rule.Detect.HeadersEqual {
				equal[strings.ToLower(strings.TrimSpace(header))] = value
			}
			rule.Detect.HeadersEqual = equal
		}
		rule.RootHeaders = lowerList(rule.RootHeaders)
		rule.NodeHeaders = lowerList(rule.NodeHeaders)
		rule.ParentHeaders = lowerList(rule.ParentHeaders)
		rule.NameHeaders = lowerList(rule.NameHeaders)
		rule.NodeFallback = strings.ToLower(strings.TrimSpace(rule.NodeFallback))
		rule.ParentFallback = strings.ToLower(strings.TrimSpace(rule.ParentFallback))
		if rule.RoleHeaders != nil {
			roleHeaders := make([]RoleHeader, 0, len(rule.RoleHeaders))
			for _, roleHeader := range rule.RoleHeaders {
				roleHeader.Header = strings.ToLower(strings.TrimSpace(roleHeader.Header))
				values := make(map[string]string, len(roleHeader.Values))
				for value, role := range roleHeader.Values {
					values[strings.ToLower(strings.TrimSpace(value))] = strings.TrimSpace(role)
				}
				roleHeader.Values = values
				roleHeaders = append(roleHeaders, roleHeader)
			}
			rule.RoleHeaders = roleHeaders
		}
		clients[trimmed] = rule
	}
	vocab.Clients = clients
	vocab.ToolKinds = lowerKeys(vocab.ToolKinds)
	vocab.ToolKindPrefixes = lowerKeys(vocab.ToolKindPrefixes)
	if vocab.SpawnTools != nil {
		spawn := make(map[string][]string, len(vocab.SpawnTools))
		for name, args := range vocab.SpawnTools {
			spawn[strings.ToLower(strings.TrimSpace(name))] = args
		}
		vocab.SpawnTools = spawn
	}
	if vocab.FileOps.Tools != nil {
		tools := make(map[string]FileOpTool, len(vocab.FileOps.Tools))
		for name, tool := range vocab.FileOps.Tools {
			tool.Op = strings.ToLower(strings.TrimSpace(tool.Op))
			tool.Style = strings.ToLower(strings.TrimSpace(tool.Style))
			tools[strings.ToLower(strings.TrimSpace(name))] = tool
		}
		vocab.FileOps.Tools = tools
	}
	for index := range vocab.SideRequests {
		vocab.SideRequests[index].Role = strings.TrimSpace(vocab.SideRequests[index].Role)
	}
	return nil
}

func (vocab *Vocabulary) normalizeAndValidate() error {
	if err := vocab.normalize(); err != nil {
		return err
	}
	return vocab.validate()
}

func lowerList(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func lowerKeys(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return out
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
		case strings.ContainsRune("-_.!#$%&'*+^`|~", char):
		default:
			return false
		}
	}
	return true
}

func (vocab *Vocabulary) validate() error {
	headerList := func(owner, field string, names []string) error {
		for _, name := range names {
			if !validHeaderName(name) {
				return fmt.Errorf("%s: %s has invalid header name %q", owner, field, name)
			}
		}
		return nil
	}
	for name, rule := range vocab.Clients {
		owner := "client " + name
		if err := firstError(
			headerList(owner, "detect.headers_present", rule.Detect.HeadersPresent),
			headerList(owner, "root_headers", rule.RootHeaders),
			headerList(owner, "node_headers", rule.NodeHeaders),
			headerList(owner, "parent_headers", rule.ParentHeaders),
			headerList(owner, "name_headers", rule.NameHeaders),
		); err != nil {
			return err
		}
		for header := range rule.Detect.HeadersEqual {
			if !validHeaderName(header) {
				return fmt.Errorf("%s: detect.headers_equal has invalid header name %q", owner, header)
			}
		}
		for _, prefix := range rule.Detect.UserAgentPrefixes {
			if prefix == "" {
				return fmt.Errorf("%s: empty user_agent_prefixes entry", owner)
			}
		}
		for _, path := range rule.ParentBodyPaths {
			if strings.TrimSpace(path) == "" {
				return fmt.Errorf("%s: empty parent_body_paths entry", owner)
			}
		}
		for _, fallback := range []string{rule.NodeFallback, rule.ParentFallback} {
			if fallback != "" && fallback != "root" && fallback != "none" {
				return fmt.Errorf("%s: fallback must be root or none, got %q", owner, fallback)
			}
		}
		for _, roleHeader := range rule.RoleHeaders {
			if !validHeaderName(roleHeader.Header) {
				return fmt.Errorf("%s: role_headers has invalid header name %q", owner, roleHeader.Header)
			}
			for value, role := range roleHeader.Values {
				if value == "" {
					return fmt.Errorf("%s: role header %s has an empty value key", owner, roleHeader.Header)
				}
				if !knownRoles[role] {
					return fmt.Errorf("%s: role header %s maps %q to unknown role %q", owner, roleHeader.Header, value, role)
				}
			}
		}
	}
	for _, marker := range vocab.InjectionMarkers {
		if strings.TrimSpace(marker) == "" {
			return errors.New("injection_markers contains an empty marker")
		}
	}
	for _, prefix := range vocab.VolatileTextPrefixes {
		if strings.TrimSpace(prefix) == "" {
			return errors.New("volatile_text_prefixes contains an empty prefix")
		}
	}
	for name, kind := range vocab.ToolKinds {
		if name == "" || !knownToolKinds[kind] {
			return fmt.Errorf("tool_kinds: %q maps to unknown tool kind %q", name, kind)
		}
	}
	for prefix, kind := range vocab.ToolKindPrefixes {
		if prefix == "" || !knownToolKinds[kind] {
			return fmt.Errorf("tool_kind_prefixes: %q maps to unknown tool kind %q", prefix, kind)
		}
	}
	for name, args := range vocab.SpawnTools {
		if name == "" || len(args) == 0 {
			return fmt.Errorf("spawn_tools: %q needs at least one prompt argument name", name)
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return fmt.Errorf("spawn_tools: %q has an empty argument name", name)
			}
		}
	}
	for _, prefix := range vocab.SubagentPrefixes {
		if prefix == "" {
			return errors.New("subagent_prefixes contains an empty prefix")
		}
	}
	for _, rule := range vocab.SideRequests {
		if !knownRoles[rule.Role] {
			return fmt.Errorf("side_requests: unknown role %q", rule.Role)
		}
		if len(rule.SystemPrefixes)+len(rule.LastUserContains) == 0 {
			return fmt.Errorf("side_requests: role %q has no recognisers", rule.Role)
		}
		for _, text := range append(append([]string(nil), rule.SystemPrefixes...), rule.LastUserContains...) {
			if text == "" {
				return fmt.Errorf("side_requests: role %q has an empty recogniser", rule.Role)
			}
		}
	}
	for field, keys := range map[string][]string{
		"path_keys": vocab.FileOps.PathKeys, "old_keys": vocab.FileOps.OldKeys,
		"new_keys": vocab.FileOps.NewKeys, "content_keys": vocab.FileOps.ContentKeys,
		"edits_keys": vocab.FileOps.EditsKeys, "patch_keys": vocab.FileOps.PatchKeys,
	} {
		for _, key := range keys {
			if strings.TrimSpace(key) == "" {
				return fmt.Errorf("file_ops.%s contains an empty key", field)
			}
		}
	}
	for name, tool := range vocab.FileOps.Tools {
		if name == "" || !knownFileOps[tool.Op] {
			return fmt.Errorf("file_ops.tools: %q has unknown op %q", name, tool.Op)
		}
		if !knownFileStyles[tool.Style] {
			return fmt.Errorf("file_ops.tools: %q has unknown style %q", name, tool.Style)
		}
	}
	return nil
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// OrderedClients returns client names sorted by Priority then name.
func (vocab *Vocabulary) OrderedClients() []string {
	names := make([]string, 0, len(vocab.Clients))
	for name := range vocab.Clients {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		left, right := vocab.Clients[names[i]], vocab.Clients[names[j]]
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		return names[i] < names[j]
	})
	return names
}

// HeaderAllowlist returns the sorted, lower-cased union of every request
// header the vocabulary reads, plus user-agent. Callers store only these.
func (vocab *Vocabulary) HeaderAllowlist() []string {
	set := map[string]struct{}{"user-agent": {}}
	add := func(names ...string) {
		for _, name := range names {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				set[name] = struct{}{}
			}
		}
	}
	for _, rule := range vocab.Clients {
		add(rule.Detect.HeadersPresent...)
		for header := range rule.Detect.HeadersEqual {
			add(header)
		}
		add(rule.RootHeaders...)
		add(rule.NodeHeaders...)
		add(rule.ParentHeaders...)
		add(rule.NameHeaders...)
		for _, roleHeader := range rule.RoleHeaders {
			add(roleHeader.Header)
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ToolKind classifies a tool name: exact vocabulary entry, then prefix, then
// ToolKindOther.
func (vocab *Vocabulary) ToolKind(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if kind, ok := vocab.ToolKinds[lower]; ok {
		return kind
	}
	longest, kind := 0, ""
	for prefix, candidate := range vocab.ToolKindPrefixes {
		if strings.HasPrefix(lower, prefix) && len(prefix) > longest {
			longest, kind = len(prefix), candidate
		}
	}
	if kind != "" {
		return kind
	}
	return ToolKindOther
}

// StripSubagentPrefix removes the first matching SubagentPrefixes entry.
func (vocab *Vocabulary) StripSubagentPrefix(text string) string {
	for _, prefix := range vocab.SubagentPrefixes {
		if strings.HasPrefix(text, prefix) {
			return text[len(prefix):]
		}
	}
	return text
}
