package insights

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

func projectInput(protocol, endpoint string, headers map[string]string, body any) Input {
	encoded, _ := json.Marshal(body)
	header := http.Header{}
	for name, value := range headers {
		header.Set(name, value)
	}
	return Input{AuditID: "audit-1", Protocol: protocol, Endpoint: endpoint, Request: encoded, Headers: header}
}

func extract(t *testing.T, input Input) orgreport.Identity {
	t.Helper()
	extractor, err := NewProjectExtractor(nil)
	if err != nil {
		t.Fatal(err)
	}
	return extractor.Extract(input)
}

func codexTurnMetadata(workspaces map[string]map[string]string) string {
	value := map[string]any{"session_id": "s-1", "thread_id": "t-1", "turn_id": "u-1", "request_kind": "turn"}
	if workspaces != nil {
		spaces := map[string]any{}
		for root, remotes := range workspaces {
			spaces[root] = map[string]any{"associated_remote_urls": remotes, "latest_git_commit_hash": "0123abcd", "has_changes": true}
		}
		value["workspaces"] = spaces
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func codexBody(metadata string, cwd string) map[string]any {
	body := map[string]any{
		"model":        "model-example",
		"instructions": "You are a coding agent.",
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": []any{
				map[string]any{"type": "input_text", "text": "<environment_context>\n  <cwd>" + cwd + "</cwd>\n  <shell>bash</shell>\n</environment_context>"},
			}},
			map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "fix the tests"}}},
		},
	}
	if metadata != "" {
		body["client_metadata"] = map[string]any{"x-codex-turn-metadata": metadata}
	}
	return body
}

func TestCodexIdentityFromBodyTurnMetadata(t *testing.T) {
	metadata := codexTurnMetadata(map[string]map[string]string{
		`C:\Users\dev\src\Sample-Repo`: {"upstream": "https://git.example.com/forks/sample-repo.git", "origin": "git@git.example.com:team/sample-repo.git"},
	})
	identity := extract(t, projectInput("openai", "responses", map[string]string{"User-Agent": "codex_cli_rs/0.99"}, codexBody(metadata, `C:\Users\dev\src\Sample-Repo\pkg`)))
	want := orgreport.Identity{
		Source:  orgreport.SourceCodexTurnMetadata,
		Remotes: []string{"git.example.com/team/sample-repo", "git.example.com/forks/sample-repo"},
		Roots:   []string{"c:/users/dev/src/sample-repo"},
		Cwd:     "c:/users/dev/src/sample-repo/pkg",
	}
	if !reflect.DeepEqual(identity, want) {
		t.Fatalf("identity = %+v\nwant %+v", identity, want)
	}
}

func TestCodexHeaderIsOnlyAFallback(t *testing.T) {
	bodyMeta := codexTurnMetadata(map[string]map[string]string{"/home/dev/body-repo": {"origin": "https://git.example.com/team/body-repo"}})
	headerMeta := codexTurnMetadata(map[string]map[string]string{"/home/dev/header-repo": {"origin": "https://git.example.com/team/header-repo"}})
	headers := map[string]string{"User-Agent": "codex_cli_rs/0.99", "X-Codex-Turn-Metadata": headerMeta}
	identity := extract(t, projectInput("openai", "responses", headers, codexBody(bodyMeta, "/home/dev/body-repo")))
	if !reflect.DeepEqual(identity.Remotes, []string{"git.example.com/team/body-repo"}) {
		t.Fatalf("body must win: %+v", identity)
	}
	// A short body value (no workspaces) falls back to the header.
	shortBody := codexBody(codexTurnMetadata(nil), "/home/dev/header-repo/sub")
	identity = extract(t, projectInput("openai", "responses", headers, shortBody))
	if !reflect.DeepEqual(identity.Remotes, []string{"git.example.com/team/header-repo"}) || identity.Cwd != "/home/dev/header-repo/sub" {
		t.Fatalf("header fallback: %+v", identity)
	}
	// No workspaces anywhere: the environment context cwd remains.
	identity = extract(t, projectInput("openai", "responses", map[string]string{"User-Agent": "codex_cli_rs/0.99", "X-Codex-Turn-Metadata": codexTurnMetadata(nil)}, shortBody))
	if identity.Source != orgreport.SourceCwd || identity.Cwd != "/home/dev/header-repo/sub" || len(identity.Remotes) != 0 {
		t.Fatalf("cwd only: %+v", identity)
	}
	// Garbage JSON-in-string is ignored.
	identity = extract(t, projectInput("openai", "responses", map[string]string{"User-Agent": "codex_cli_rs/0.99"}, codexBody("{not json", "/srv/x")))
	if identity.Source != orgreport.SourceCwd {
		t.Fatalf("garbage metadata: %+v", identity)
	}
}

func TestOpenCodeIdentity(t *testing.T) {
	system := "You are opencode.\n<env>\n  Working directory: /home/dev/work/app/src\n  Workspace root folder: /home/dev/work/app\n  Is directory a git repo: yes\n  Platform: linux\n</env>"
	body := map[string]any{"model": "model-example", "messages": []any{
		map[string]any{"role": "system", "content": system},
		map[string]any{"role": "user", "content": "hello"},
	}}
	hash := orgreport.OpenCodeProjectHash("git.example.com/team/app")
	v2 := extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "opencode/2.1.0", "X-Opencode-Project": strings.ToUpper(hash)}, body))
	if v2.ProjectHash != hash || !reflect.DeepEqual(v2.Roots, []string{"/home/dev/work/app"}) || v2.Cwd != "/home/dev/work/app/src" || v2.Source != orgreport.SourceAgentHeader {
		t.Fatalf("v2 = %+v", v2)
	}
	// v1: no project header, no workspace root.
	v1Body := map[string]any{"model": "model-example", "messages": []any{
		map[string]any{"role": "system", "content": "<env>\n  Working directory: /home/dev/work/app\n</env>"},
		map[string]any{"role": "user", "content": "hello"},
	}}
	v1 := extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "opencode/1.18.40"}, v1Body))
	if v1.Source != orgreport.SourceCwd || v1.Cwd != "/home/dev/work/app" || len(v1.Roots) != 0 {
		t.Fatalf("v1 = %+v", v1)
	}
	// "global" or anything that is not a 40-hex id is not a project hash.
	global := extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "opencode/2.1.0", "X-Opencode-Project": "global"}, v1Body))
	if global.ProjectHash != "" {
		t.Fatalf("global = %+v", global)
	}
	// A title request carries no <env>: nothing but the header.
	title := extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "opencode/2.1.0"}, map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "system", "content": "You are a title generator."}, map[string]any{"role": "user", "content": "x"}}}))
	if !title.Empty() || title.Source != orgreport.SourceNone {
		t.Fatalf("title = %+v", title)
	}
}

func claudeMeta(text string) map[string]any {
	return map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": text}}}
}

func TestClaudeCodeAndZCodeIdentity(t *testing.T) {
	environment := "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n" +
		"Contents of D:\\work\\Sample\\CLAUDE.md (project instructions, checked into the codebase):\n\nrules here\n</system-reminder>"
	env := "# Environment\nYou have been invoked in the following environment:\n - Primary working directory: D:\\work\\Sample\\cmd\n - Is a git repository: true\n - Platform: win32"
	body := map[string]any{"model": "model-example", "system": []any{map[string]any{"type": "text", "text": "You are Claude Code."}}, "messages": []any{
		claudeMeta(environment), claudeMeta(env), claudeMeta("please refactor"),
	}}
	identity := extract(t, projectInput("anthropic", "messages", map[string]string{"User-Agent": "claude-cli/2.1.300"}, body))
	if identity.Cwd != "d:/work/sample/cmd" || !reflect.DeepEqual(identity.Roots, []string{"d:/work/sample"}) || identity.Source != orgreport.SourceRoot {
		t.Fatalf("claude = %+v", identity)
	}

	// An environment update later in the conversation wins.
	update := "# Environment update\n - Primary working directory: D:\\work\\Other (was D:\\work\\Sample\\cmd)"
	body["messages"] = append(body["messages"].([]any), claudeMeta(update))
	identity = extract(t, projectInput("anthropic", "messages", map[string]string{"User-Agent": "claude-cli/2.1.300"}, body))
	if identity.Cwd != "d:/work/other" {
		t.Fatalf("environment update = %+v", identity)
	}

	// ZCode uses the same block, possibly as a system message; its client is
	// unknown on this branch and the shared patterns still apply.
	zcode := map[string]any{"model": "model-example", "messages": []any{
		map[string]any{"role": "system", "content": "<system-reminder>\n - Primary working directory: /Users/dev/zc-project\n - Is a git repository: false\n</system-reminder>"},
		map[string]any{"role": "user", "content": "go"},
	}}
	identity = extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "ZCode/1.4.0"}, zcode))
	if identity.Cwd != "/users/dev/zc-project" || identity.Source != orgreport.SourceCwd {
		t.Fatalf("zcode = %+v", identity)
	}
}

func TestPiAndDshIdentity(t *testing.T) {
	pi := map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "system", "content": "You are pi.\n<project_instructions path=\"/home/dev/pi-repo/AGENTS.md\">\n...\n</project_instructions>\n<cwd>\n/home/dev/pi-repo/web\n</cwd>"},
		map[string]any{"role": "user", "content": "hi"},
	}}
	identity := extract(t, projectInput("openai", "chat_completions", map[string]string{"User-Agent": "pi/0.90"}, pi))
	if identity.Cwd != "/home/dev/pi-repo/web" || !reflect.DeepEqual(identity.Roots, []string{"/home/dev/pi-repo"}) {
		t.Fatalf("pi = %+v", identity)
	}
	old := map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "system", "content": "Current working directory: /home/dev/old-pi"},
		map[string]any{"role": "user", "content": "hi"},
	}}
	if identity := extract(t, projectInput("openai", "chat_completions", nil, old)); identity.Cwd != "/home/dev/old-pi" {
		t.Fatalf("old pi = %+v", identity)
	}

	native := map[string]any{"model": "m",
		"dsh_session_log": map[string]any{"session": map[string]any{"cwd": "/srv/dsh/repo", "parentSession": "p-1"}},
		"messages":        []any{map[string]any{"role": "user", "content": `Current working directory: "/srv/dsh/elsewhere".`}},
	}
	identity = extract(t, projectInput("anthropic", "messages", map[string]string{"User-Agent": "deepseek-harness/1.0"}, native))
	if identity.Cwd != "/srv/dsh/repo" {
		t.Fatalf("dsh native body path must win: %+v", identity)
	}
	viaPiAI := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": `Current working directory: "/srv/dsh/repo two".`}}}
	if identity := extract(t, projectInput("openai", "chat_completions", nil, viaPiAI)); identity.Cwd != "/srv/dsh/repo two" {
		t.Fatalf("dsh via pi-ai = %+v", identity)
	}
}

func TestDeclaredProjectWinsForAnyClient(t *testing.T) {
	body := codexBody("", "/home/dev/x")
	identity := extract(t, projectInput("openai", "responses", map[string]string{"User-Agent": "my-agent/1", "X-Agent-Project": "  Billing-Service "}, body))
	if identity.Declared != "Billing-Service" || identity.Source != orgreport.SourceDeclared || identity.Cwd != "/home/dev/x" {
		t.Fatalf("declared = %+v", identity)
	}
}

func TestToolResultsAreNeverScanned(t *testing.T) {
	body := map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "user", "content": "list it"},
		map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "shell", "arguments": "{}"}}}},
		map[string]any{"role": "tool", "tool_call_id": "c1", "content": "Working directory: /tmp/leak\n<cwd>/tmp/leak</cwd>"},
	}}
	if identity := extract(t, projectInput("openai", "chat_completions", nil, body)); !identity.Empty() {
		t.Fatalf("tool output became an identity: %+v", identity)
	}
}

func TestOnlyLeadingAndTrailingMessagesAreScanned(t *testing.T) {
	messages := []any{map[string]any{"role": "system", "content": "sys"}}
	for index := 0; index < 30; index++ {
		text := "step"
		if index == 15 {
			text = "<cwd>/middle/only</cwd>"
		}
		messages = append(messages, map[string]any{"role": "user", "content": text})
	}
	if identity := extract(t, projectInput("openai", "chat_completions", nil, map[string]any{"model": "m", "messages": messages})); !identity.Empty() {
		t.Fatalf("a middle message was scanned: %+v", identity)
	}
}

type recordingProjectStore struct{ rows []storage.ProjectIdentityRow }

func (store *recordingProjectStore) SaveProjectIdentity(_ context.Context, row storage.ProjectIdentityRow) error {
	store.rows = append(store.rows, row)
	return nil
}

func TestProjectRunnerStoresNoPlaintext(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{7}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingProjectStore{}
	runner, err := NewProjectRunner(store, cipher, nil, testFingerprinter{})
	if err != nil {
		t.Fatal(err)
	}
	metadata := codexTurnMetadata(map[string]map[string]string{"/home/dev/secret-repo": {"origin": "git@git.example.com:team/secret-repo.git"}})
	input := projectInput("openai", "responses", map[string]string{"User-Agent": "codex_cli_rs/0.99"}, codexBody(metadata, "/home/dev/secret-repo"))
	if err := runner.AnalyzeAudit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	row := store.rows[0]
	if row.Source != orgreport.SourceCodexTurnMetadata || !row.BodyScanned || row.Version != ProjectIdentityVersion {
		t.Fatalf("row = %+v", row)
	}
	for name, value := range map[string][]byte{"identity": row.IdentityFPR, "remote": row.RemoteFPR, "root": row.RootFPR, "cwd": row.CwdFPR} {
		if len(value) != storage.ProjectFingerprintSize {
			t.Fatalf("%s fingerprint length %d", name, len(value))
		}
	}
	for _, field := range [][]byte{row.IdentityFPR, row.RemoteFPR, row.RootFPR, row.CwdFPR, row.IdentityEnc, []byte(row.Source)} {
		if bytes.Contains(bytes.ToLower(field), []byte("secret-repo")) {
			t.Fatal("plaintext path or remote stored")
		}
	}
	aad, _ := ProjectIdentityAAD(row.AuditID, row.Version)
	plaintext, err := cipher.Decrypt(aad, row.IdentityEnc)
	if err != nil {
		t.Fatal(err)
	}
	var decoded orgreport.Identity
	if err := json.Unmarshal(plaintext, &decoded); err != nil || decoded.Remotes[0] != "git.example.com/team/secret-repo" {
		t.Fatalf("decrypted = %+v, %v", decoded, err)
	}
	if _, err := cipher.Decrypt([]byte("other\x00project_identity\x001"), row.IdentityEnc); err == nil {
		t.Fatal("identity ciphertext is not bound to its audit")
	}

	// A request without signals stores a none row and no ciphertext.
	empty := projectInput("openai", "chat_completions", nil, map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	empty.AuditID = "audit-2"
	if err := runner.AnalyzeAudit(context.Background(), empty); err != nil {
		t.Fatal(err)
	}
	if row := store.rows[1]; row.Source != orgreport.SourceNone || row.IdentityEnc != nil || row.IdentityFPR != nil {
		t.Fatalf("none row = %+v", row)
	}
}

func TestProjectVocabularyValidationAndAllowlist(t *testing.T) {
	vocab := DefaultVocabulary()
	allow := vocab.ProjectHeaderAllowlist()
	for _, name := range []string{"x-agent-project", "x-codex-turn-metadata", "x-opencode-project"} {
		found := false
		for _, candidate := range allow {
			found = found || candidate == name
		}
		if !found {
			t.Fatalf("allowlist %v misses %s", allow, name)
		}
	}
	for _, name := range vocab.HeaderAllowlist() {
		if name == "x-codex-turn-metadata" || name == "x-agent-project" {
			t.Fatal("project headers leaked into the insights allowlist; it must stay unchanged")
		}
	}
	for _, bad := range []string{
		"project:\n  text_patterns:\n    - {kind: cwd, pattern: 'no group'}\n",
		"project:\n  text_patterns:\n    - {kind: cwd, pattern: '(unclosed'}\n",
		"project:\n  text_patterns:\n    - {kind: opencode_project, pattern: '(x)'}\n",
		"project:\n  headers:\n    - {header: 'bad header', kind: declared}\n",
		"project:\n  headers:\n    - {header: x-a, kind: sideways}\n",
		"clients:\n  codex:\n    project_body_paths:\n      - {path: '', kind: cwd}\n",
	} {
		path := t.TempDir() + "/vocabulary.yaml"
		if err := writeFile(path, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVocabulary(path); err == nil {
			t.Fatalf("accepted invalid vocabulary %q", bad)
		}
	}
	// An override replaces the shared list.
	path := t.TempDir() + "/vocabulary.yaml"
	if err := writeFile(path, "project:\n  headers:\n    - {header: X-My-Project, kind: declared}\n"); err != nil {
		t.Fatal(err)
	}
	override, err := LoadVocabulary(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(override.Project.Headers) != 1 || override.Project.Headers[0].Header != "x-my-project" || len(override.Project.TextPatterns) == 0 {
		t.Fatalf("override project = %+v", override.Project)
	}
}

func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}
