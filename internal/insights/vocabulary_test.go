package insights

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeVocabulary(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vocabulary.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultVocabularyContent(t *testing.T) {
	vocab := DefaultVocabulary()
	if got := vocab.OrderedClients(); !slices.Equal(got, []string{"codex", "claude_code", "opencode", "dsh", "custom"}) {
		t.Fatalf("client order = %v", got)
	}
	custom := vocab.Clients["custom"]
	if !slices.Equal(custom.RootHeaders, []string{"x-agent-session-id"}) ||
		!slices.Equal(custom.NodeHeaders, []string{"x-agent-id"}) ||
		!slices.Equal(custom.ParentHeaders, []string{"x-agent-parent-id"}) ||
		!slices.Equal(custom.NameHeaders, []string{"x-agent-name"}) ||
		custom.RoleHeaders[0].Header != "x-agent-role" {
		t.Errorf("custom client = %+v", custom)
	}
	codex := vocab.Clients["codex"]
	if codex.RoleHeaders[0].Values["collab_spawn"] != RoleSubagent || codex.RoleHeaders[0].Values["compact"] != RoleCompaction ||
		codex.RoleHeaders[0].Values["review"] != RoleReview || codex.RoleHeaders[0].Values["memory_consolidation"] != RoleAuxiliary ||
		codex.NodeHeaders[0] != "thread-id" || codex.RootHeaders[0] != "session-id" || codex.ParentHeaders[0] != "x-codex-parent-thread-id" {
		t.Errorf("codex client = %+v", codex)
	}
	claude := vocab.Clients["claude_code"]
	classes := claude.RoleHeaders[0].Values
	if classes["side_reply"] != RoleAuxiliary || classes["workflow"] != RoleAuxiliary || classes["subagent"] != RoleSubagent ||
		claude.NodeFallback != "root" || claude.ParentFallback != "root" {
		t.Errorf("claude_code client = %+v", claude)
	}
	opencode := vocab.Clients["opencode"]
	if !slices.Equal(opencode.ParentHeaders, []string{"x-opencode-parent-session-id", "x-parent-session-id"}) {
		t.Errorf("opencode parents = %v", opencode.ParentHeaders)
	}
	if vocab.Clients["dsh"].RoleHeaders[0].Values["1"] != RoleCompaction {
		t.Errorf("dsh compact mapping = %+v", vocab.Clients["dsh"].RoleHeaders)
	}
	for _, marker := range []string{"<system-reminder>", "<environment_context>", "<user_instructions>", "<skill_content", "# AGENTS.md", "<user-prompt-submit-hook>"} {
		if !slices.Contains(vocab.InjectionMarkers, marker) {
			t.Errorf("missing marker %q", marker)
		}
	}
	kinds := map[string]string{
		"Read": ToolKindFileRead, "MultiEdit": ToolKindFileWrite, "NotebookEdit": ToolKindFileWrite, "Glob": ToolKindSearch,
		"Bash": ToolKindShell, "Agent": ToolKindSpawn, "Task": ToolKindSpawn, "exec_command": ToolKindShell,
		"apply_patch": ToolKindFileWrite, "spawn_agent": ToolKindSpawn, "subagent_fork": ToolKindSpawn,
		"str_replace_editor": ToolKindFileWrite, "mcp__srv__tool": ToolKindMCP, "unknown_tool": ToolKindOther,
	}
	for name, want := range kinds {
		if got := vocab.ToolKind(name); got != want {
			t.Errorf("ToolKind(%s) = %s, want %s", name, got, want)
		}
	}
	if got := vocab.SpawnTools["spawn_agent"]; got[0] != "message" {
		t.Errorf("spawn_agent args = %v", got)
	}
	if got := vocab.StripSubagentPrefix("You are a subagent spawned by another session.\nDo it"); got != "Do it" {
		t.Errorf("strip = %q", got)
	}
	if vocab.SideRequests[0].SystemPrefixes[0] != "You are a title generator" ||
		vocab.SideRequests[1].LastUserContains[0] != "You MUST use this format for your response" {
		t.Errorf("side requests = %+v", vocab.SideRequests)
	}
}

func TestDefaultVocabularyIsFreshCopy(t *testing.T) {
	first := DefaultVocabulary()
	first.ToolKinds["read"] = ToolKindShell
	first.InjectionMarkers[0] = "mutated"
	second := DefaultVocabulary()
	if second.ToolKinds["read"] != ToolKindFileRead || second.InjectionMarkers[0] != "<system-reminder>" {
		t.Error("DefaultVocabulary must return independent copies")
	}
}

func TestHeaderAllowlist(t *testing.T) {
	list := DefaultVocabulary().HeaderAllowlist()
	if !slices.IsSorted(list) {
		t.Errorf("allowlist not sorted: %v", list)
	}
	for _, name := range list {
		if name != strings.ToLower(name) {
			t.Errorf("header %q is not lower-case", name)
		}
	}
	for _, want := range []string{
		"user-agent", "session-id", "thread-id", "x-codex-parent-thread-id", "x-openai-subagent", "originator",
		"x-claude-code-session-id", "x-claude-code-agent-id", "x-claude-code-parent-agent-id", "x-claude-code-request-class", "x-app",
		"x-opencode-session-id", "x-opencode-parent-session-id", "x-parent-session-id", "x-opencode-client",
		"x-deepseek-harness-session-id", "x-deepseek-harness-compact",
		"x-agent-session-id", "x-agent-id", "x-agent-parent-id", "x-agent-role", "x-agent-name",
	} {
		if !slices.Contains(list, want) {
			t.Errorf("allowlist misses %q", want)
		}
	}
	if len(slices.Compact(slices.Clone(list))) != len(list) {
		t.Error("allowlist has duplicates")
	}
}

func TestLoadVocabularyEmptyPathIsDefault(t *testing.T) {
	vocab, err := LoadVocabulary("")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(vocab.HeaderAllowlist(), DefaultVocabulary().HeaderAllowlist()) {
		t.Error("empty path should return the defaults")
	}
}

func TestLoadVocabularyMerge(t *testing.T) {
	path := writeVocabulary(t, `
clients:
  Custom:
    node_headers: [X-My-Agent]
  extra:
    priority: 5
    detect:
      user_agent_prefixes: ["Extra/"]
    node_headers: [x-extra-id]
injection_markers: ["<mine>"]
tool_kinds:
  Read: search
  Fetch_URL: other
spawn_tools:
  delegate: [task]
file_ops:
  path_keys: [target]
  tools:
    OpenFile: {op: read}
`)
	vocab, err := LoadVocabulary(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := vocab.Clients["custom"].NodeHeaders; !slices.Equal(got, []string{"x-my-agent"}) {
		t.Errorf("client names are case-insensitive and merge field-wise: %v", got)
	}
	if got := vocab.Clients["extra"]; got.Priority != 5 || got.Detect.UserAgentPrefixes[0] != "extra/" {
		t.Errorf("extra client = %+v", got)
	}
	if got := vocab.OrderedClients(); got[0] != "extra" || got[1] != "codex" || got[len(got)-1] != "custom" || len(got) != 6 {
		t.Errorf("order = %v", got)
	}
	if !slices.Equal(vocab.InjectionMarkers, []string{"<mine>"}) {
		t.Errorf("markers = %v", vocab.InjectionMarkers)
	}
	if vocab.ToolKind("read") != ToolKindSearch || vocab.ToolKind("fetch_url") != ToolKindOther || vocab.ToolKind("bash") != ToolKindShell {
		t.Error("tool_kinds should merge by lower-cased key")
	}
	if len(vocab.SpawnTools) != 6 || vocab.SpawnTools["delegate"][0] != "task" {
		t.Errorf("spawn tools = %v", vocab.SpawnTools)
	}
	if !slices.Equal(vocab.FileOps.PathKeys, []string{"target"}) || !slices.Equal(vocab.FileOps.OldKeys, []string{"old_string", "old_str"}) {
		t.Errorf("file_ops keys = %+v", vocab.FileOps)
	}
	if vocab.FileOps.Tools["openfile"].Op != "read" || vocab.FileOps.Tools["grep"].Op != "search" {
		t.Errorf("file_ops tools = %+v", vocab.FileOps.Tools)
	}
	if !slices.Contains(vocab.HeaderAllowlist(), "x-extra-id") {
		t.Error("allowlist should include override headers")
	}
}

func TestLoadVocabularyFieldLevelClientMerge(t *testing.T) {
	path := writeVocabulary(t, `
clients:
  custom:
    node_headers: [X-My-Agent]
    name_headers: []
`)
	vocab, err := LoadVocabulary(path)
	if err != nil {
		t.Fatal(err)
	}
	custom := vocab.Clients["custom"]
	if !slices.Equal(custom.NodeHeaders, []string{"x-my-agent"}) {
		t.Errorf("node headers = %v", custom.NodeHeaders)
	}
	if len(custom.NameHeaders) != 0 {
		t.Errorf("empty list should replace: %v", custom.NameHeaders)
	}
	if !slices.Equal(custom.RootHeaders, []string{"x-agent-session-id"}) || custom.Priority != 100 ||
		len(custom.RoleHeaders) != 1 || !slices.Equal(custom.Detect.HeadersPresent, []string{"x-agent-id", "x-agent-session-id"}) {
		t.Errorf("untouched fields should keep defaults: %+v", custom)
	}
	allowlist := vocab.HeaderAllowlist()
	if !slices.Contains(allowlist, "x-my-agent") || slices.Contains(allowlist, "x-agent-name") {
		t.Errorf("allowlist = %v", allowlist)
	}
}

func TestLoadVocabularyEmptyFileKeepsDefaults(t *testing.T) {
	vocab, err := LoadVocabulary(writeVocabulary(t, "# nothing\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(vocab.Clients) != 5 || len(vocab.InjectionMarkers) != 6 {
		t.Errorf("defaults lost: %d clients, %d markers", len(vocab.Clients), len(vocab.InjectionMarkers))
	}
}

func TestLoadVocabularyValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown top-level key", "bogus: 1\n", "bogus"},
		{"unknown client key", "clients:\n  custom:\n    bogus: 1\n", "bogus"},
		{"unknown tool kind", "tool_kinds:\n  x: weird\n", "unknown tool kind"},
		{"unknown prefix kind", "tool_kind_prefixes:\n  pre_: weird\n", "unknown tool kind"},
		{"unknown role", "clients:\n  custom:\n    role_headers:\n      - header: x-r\n        values: {a: nope}\n", "unknown role"},
		{"empty header name", "clients:\n  custom:\n    node_headers: [\"\"]\n", "invalid header name"},
		{"bad header name", "clients:\n  custom:\n    node_headers: [\"x bad\"]\n", "invalid header name"},
		{"empty marker", "injection_markers: [\"  \"]\n", "empty marker"},
		{"empty ua prefix", "clients:\n  custom:\n    detect:\n      user_agent_prefixes: [\"\"]\n", "user_agent_prefixes"},
		{"bad fallback", "clients:\n  custom:\n    node_fallback: parent\n", "fallback"},
		{"spawn without args", "spawn_tools:\n  x: []\n", "prompt argument"},
		{"bad side role", "side_requests:\n  - role: nope\n    system_prefixes: [a]\n", "unknown role"},
		{"side without recogniser", "side_requests:\n  - role: title\n", "no recognisers"},
		{"bad file op", "file_ops:\n  tools:\n    x: {op: delete}\n", "unknown op"},
		{"bad file style", "file_ops:\n  tools:\n    x: {op: write, style: weird}\n", "unknown style"},
		{"empty file key", "file_ops:\n  path_keys: [\"\"]\n", "empty key"},
		{"not yaml", "clients: [\n", "yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadVocabulary(writeVocabulary(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
	if _, err := LoadVocabulary(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file should be an error")
	}
}

func TestExampleVocabularyLoads(t *testing.T) {
	vocab, err := LoadVocabulary(filepath.Join("..", "..", "configs", "insights-vocabulary.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	custom := vocab.Clients["custom"]
	if !slices.Equal(custom.NodeHeaders, []string{"x-myfw-agent"}) || !slices.Equal(custom.ParentHeaders, []string{"x-myfw-parent"}) {
		t.Errorf("custom client = %+v", custom)
	}
	allowlist := vocab.HeaderAllowlist()
	for _, want := range []string{"x-myfw-agent", "x-myfw-run", "x-myfw-kind", "x-myfw-label", "x-codex-parent-thread-id"} {
		if !slices.Contains(allowlist, want) {
			t.Errorf("allowlist misses %q", want)
		}
	}
	if slices.Contains(allowlist, "x-agent-id") {
		t.Error("renamed custom headers should leave the allowlist")
	}
	if vocab.ToolKind("run_tests") != ToolKindShell || vocab.FileOps.Tools["open_file"].Op != "read" {
		t.Error("example tool rules not applied")
	}
}
