package insights

import (
	"net/http"
	"strings"
	"testing"
)

func headerSet(pairs ...string) http.Header {
	headers := http.Header{}
	for index := 0; index+1 < len(pairs); index += 2 {
		headers.Add(pairs[index], pairs[index+1])
	}
	return headers
}

func TestIdentifyAgentReadsNativeAndCustomHeaders(t *testing.T) {
	t.Parallel()
	chat := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	long := strings.Repeat("x", maxAgentIDBytes+1)
	for _, tc := range []struct {
		name    string
		headers http.Header
		request []byte
		want    AgentIdentity
	}{
		{
			name:    "codex main",
			headers: headerSet("User-Agent", "codex_cli_rs/0.1 (test)", "originator", "codex_cli_rs", "session-id", "root-a", "thread-id", "root-a"),
			want:    AgentIdentity{Client: "codex", Role: RoleMain, RootID: "root-a", NodeID: "root-a", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name: "codex spawned child",
			headers: headerSet("User-Agent", "codex_cli_rs/0.1", "session-id", "root-a", "thread-id", "child-b",
				"x-codex-parent-thread-id", "root-a", "x-openai-subagent", "collab_spawn"),
			want: AgentIdentity{Client: "codex", Role: RoleSubagent, RootID: "root-a", NodeID: "child-b", ParentID: "root-a", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "codex parent from client_metadata",
			headers: headerSet("User-Agent", "codex_cli_rs/0.1", "session-id", "root-a", "thread-id", "child-b"),
			request: []byte(`{"input":[],"client_metadata":{"x-codex-parent-thread-id":"root-a"}}`),
			want:    AgentIdentity{Client: "codex", Role: RoleSubagent, RootID: "root-a", NodeID: "child-b", ParentID: "root-a", LinkSource: LinkBody, Confidence: 100},
		},
		{
			name:    "codex compaction stays auxiliary",
			headers: headerSet("User-Agent", "codex_cli_rs/0.1", "session-id", "root-a", "thread-id", "child-b", "x-codex-parent-thread-id", "root-a", "x-openai-subagent", "COMPACT"),
			want:    AgentIdentity{Client: "codex", Role: RoleCompaction, RootID: "root-a", NodeID: "child-b", ParentID: "root-a", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "claude code main falls back to the session root",
			headers: headerSet("User-Agent", "claude-cli/2.1.90 (external, cli)", "X-Claude-Code-Session-Id", "cc-root"),
			want:    AgentIdentity{Client: "claude_code", Role: RoleMain, RootID: "cc-root", NodeID: "cc-root", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "claude code agent without parent header hangs under main",
			headers: headerSet("User-Agent", "claude-cli/2.1.90", "X-Claude-Code-Session-Id", "cc-root", "X-Claude-Code-Agent-Id", "cc-agent"),
			want:    AgentIdentity{Client: "claude_code", Role: RoleSubagent, RootID: "cc-root", NodeID: "cc-agent", ParentID: "cc-root", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "claude code agent equal to the root is not its own parent",
			headers: headerSet("User-Agent", "claude-cli/2.1.90", "X-Claude-Code-Session-Id", "cc-root", "X-Claude-Code-Agent-Id", "cc-root"),
			want:    AgentIdentity{Client: "claude_code", Role: RoleMain, RootID: "cc-root", NodeID: "cc-root", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name: "claude code request class wins",
			headers: headerSet("User-Agent", "claude-cli/2.1.90", "X-Claude-Code-Session-Id", "cc-root", "X-Claude-Code-Agent-Id", "cc-agent",
				"X-Claude-Code-Parent-Agent-Id", "cc-mid", "X-Claude-Code-Request-Class", "compaction"),
			want: AgentIdentity{Client: "claude_code", Role: RoleCompaction, RootID: "cc-root", NodeID: "cc-agent", ParentID: "cc-mid", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "opencode under chatgpt auth sends originator but UA wins",
			headers: headerSet("User-Agent", "opencode/1.19.2", "originator", "opencode", "x-opencode-session-id", "oc-child", "x-parent-session-id", "oc-root"),
			want:    AgentIdentity{Client: "opencode", Role: RoleSubagent, NodeID: "oc-child", ParentID: "oc-root", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "dsh parent from session log",
			headers: headerSet("User-Agent", "deepseek-harness/0.3", "x-deepseek-harness-session-id", "dsh-child"),
			request: []byte(`{"messages":[],"dsh_session_log":{"header":{"parentSession":"dsh-root","origin":"subagent"}}}`),
			want:    AgentIdentity{Client: "dsh", Role: RoleSubagent, NodeID: "dsh-child", ParentID: "dsh-root", LinkSource: LinkBody, Confidence: 100},
		},
		{
			name:    "dsh parent path must hold a string",
			headers: headerSet("User-Agent", "deepseek-harness/0.3", "x-deepseek-harness-session-id", "dsh-child"),
			request: []byte(`{"dsh_session_log":{"header":{"parentSession":7}}}`),
			want:    AgentIdentity{Client: "dsh", Role: RoleMain, NodeID: "dsh-child", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "custom grandchild with name",
			headers: headerSet("X-Agent-Session-Id", "tree", "X-Agent-Id", "grandchild", "X-Agent-Parent-Id", "child", "X-Agent-Name", "researcher"),
			want:    AgentIdentity{Client: "custom", Role: RoleSubagent, RootID: "tree", NodeID: "grandchild", ParentID: "child", Name: "researcher", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "custom compaction role",
			headers: headerSet("X-Agent-Session-Id", "tree", "X-Agent-Id", "child", "X-Agent-Parent-Id", "tree", "X-Agent-Role", "Compaction"),
			want:    AgentIdentity{Client: "custom", Role: RoleCompaction, RootID: "tree", NodeID: "child", ParentID: "tree", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "oversized ids are ignored",
			headers: headerSet("X-Agent-Session-Id", long, "X-Agent-Id", "node", "X-Agent-Parent-Id", long),
			want:    AgentIdentity{Client: "custom", Role: RoleMain, NodeID: "node", LinkSource: LinkHeader, Confidence: 100},
		},
		{
			name:    "unknown client",
			headers: headerSet("User-Agent", "curl/8.0"),
			want:    AgentIdentity{Client: ClientUnknown, Role: RoleMain},
		},
		{
			name:    "unknown client title request",
			headers: headerSet("User-Agent", "curl/8.0"),
			request: []byte(`{"messages":[{"role":"system","content":"You are a title generator."},{"role":"user","content":"x"}]}`),
			want:    AgentIdentity{Client: ClientUnknown, Role: RoleTitle},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.request
			if request == nil {
				request = chat
			}
			got := IdentifyAgent(Input{Protocol: "openai", Endpoint: "chat_completions", Request: request, Headers: tc.headers}, nil)
			if got != tc.want {
				t.Fatalf("IdentifyAgent = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestIdentifyAgentSideRequestBeatsParent(t *testing.T) {
	t.Parallel()
	request := []byte(`{"messages":[{"role":"system","content":"You are a title generator. Reply briefly."},{"role":"user","content":"x"}]}`)
	got := IdentifyAgent(Input{Protocol: "openai", Endpoint: "chat_completions", Request: request,
		Headers: headerSet("User-Agent", "opencode/1.19.2", "x-opencode-session-id", "oc-child", "x-opencode-parent-session-id", "oc-root")}, nil)
	if got.Role != RoleTitle || got.ParentID != "oc-root" {
		t.Fatalf("IdentifyAgent = %+v, want a title request that keeps its parent", got)
	}
}

func TestAgentFingerprintsAreDomainSeparated(t *testing.T) {
	t.Parallel()
	fp := testFingerprinter{}
	if string(AgentFPR(fp, "custom", "a")) == string(AgentFPR(fp, "codex", "a")) {
		t.Fatal("agent tags must include the client")
	}
	if string(SyntheticAgentFPR(fp, "custom\x00a")) == string(AgentFPR(fp, "custom", "a")) {
		t.Fatal("synthetic tags must not collide with client tags")
	}
}
