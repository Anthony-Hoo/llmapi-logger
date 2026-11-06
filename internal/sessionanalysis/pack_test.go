package sessionanalysis

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/storage"
)

var packZone = time.FixedZone("UTC+8", 8*3600)

// rowsFor builds count requests of one node spaced evenly between start and
// end, with usage that sums to the given totals.
func rowsFor(prefix string, node, parent []byte, role, client, model string, count int, start, end time.Time, input, cacheRead, output int64) []storage.SessionAuditRow {
	rows := make([]storage.SessionAuditRow, 0, count)
	step := end.Sub(start) / time.Duration(count)
	for index := 0; index < count; index++ {
		at := start.Add(time.Duration(index) * step)
		ended := at.Add(step / 2).UnixNano()
		uncached := (input - cacheRead) / int64(count)
		cached := cacheRead / int64(count)
		out := output / int64(count)
		rows = append(rows, storage.SessionAuditRow{
			AuditID: prefix + "-" + string(rune('a'+index/26)) + string(rune('a'+index%26)), StartedAtNS: at.UnixNano(), EndedAtNS: &ended,
			APIKeyFPR: bytes.Repeat([]byte{1}, 32), Model: model, Protocol: "openai",
			UncachedInput: &uncached, CacheRead: &cached, Output: &out,
			AgentClient: client, AgentRole: role, AgentNodeFPR: node, AgentParentFPR: parent, AnalysisSessionID: "agt_" + prefix,
		})
	}
	return rows
}

func examplePack(t *testing.T, rows []storage.SessionAuditRow, views map[string]*conversation.Conversation, maxTokens int) (Pack, *Session, storage.SessionSignals) {
	t.Helper()
	session := build(t, rows, views)
	vocab, _ := testVocabularies(t)
	signals, _ := ComputeSignals(session, vocab, testFingerprinter{}, Thresholds{MinUserTurns: 1}, baseTime)
	pack := BuildSessionPack(session, signals, vocab, PackOptions{MaxTokens: maxTokens, Location: packZone})
	return pack, session, signals
}

// Example A of doc 24 section 6.11 (Codex, Responses).
func codexExample(t *testing.T) ([]storage.SessionAuditRow, map[string]*conversation.Conversation) {
	start := time.Date(2026, 11, 4, 6, 2, 0, 0, time.UTC)
	end := start.Add(68 * time.Minute)
	main := rowsFor("cx", nodeMain, nil, "main", "codex", "codex-large", 52, start, end, 2_600_000, 2_450_000, 36_000)
	child := rowsFor("cxs", nodeChild, nodeMain, "subagent", "codex", "codex-large", 10, start.Add(5*time.Minute), start.Add(15*time.Minute), 280_000, 260_000, 4_500)
	aux := rowsFor("cxa", nodeMain, nil, "compaction", "codex", "codex-large", 2, start.Add(30*time.Minute), start.Add(31*time.Minute), 20_000, 0, 500)
	main[0].TurnStart, main[20].TurnStart, main[40].TurnStart = true, true, true
	child[0].TurnStart = true
	rows := append(append(append([]storage.SessionAuditRow{}, main...), child...), aux...)
	mainView := convo(
		user("<environment_context>\n  <cwd>/work/orders-service</cwd>\n</environment_context>"),
		user("# AGENTS.md instructions for /work/orders-service\n\n- 提交前先跑 go test ./..."),
		user("给订单导出接口加上按日期过滤，参数 from/to，格式 YYYY-MM-DD，补单测"),
		call("s1", "exec_command", map[string]any{"cmd": "rg -n export internal"}),
		result("s1", "Process exited with code 0"),
		call("r1", "exec_command", map[string]any{"cmd": "sed -n 1,80p internal/export/handler.go"}),
		result("r1", "Process exited with code 0"),
		call("sp", "spawn_agent", map[string]any{"message": "检查仓库里其他导出接口是怎么做参数校验的，列出文件和做法"}),
		result("sp", `{"agent_id":"child"}`),
		call("w1", "apply_patch", "*** Begin Patch\n*** Update File: internal/export/handler.go\n@@\n+from\n*** End Patch"),
		result("w1", "Success."),
		call("t1", "exec_command", map[string]any{"cmd": "go test ./internal/export/..."}),
		result("t1", "Process exited with code 1\n--- FAIL: TestDateFilter"),
		call("w2", "apply_patch", "*** Begin Patch\n*** Update File: internal/export/handler.go\n@@\n+to\n*** End Patch"),
		result("w2", "Success."),
		call("t2", "exec_command", map[string]any{"cmd": "go test ./internal/export/..."}),
		result("t2", "Process exited with code 0"),
		msg{role: conversation.RoleAssistant, parts: []conversation.Part{conversation.Text("已实现 from/to 过滤，使用 time.Parse 按 UTC 解析，并补充了 3 个单测，go test 通过。")}},
		user("不对，日期要按 UTC+8 解析，不要用 UTC"),
		call("w3", "apply_patch", "*** Begin Patch\n*** Update File: internal/export/handler.go\n@@\n+loc\n*** End Patch"),
		result("w3", "apply_patch verification failed"),
		call("w4", "apply_patch", "*** Begin Patch\n*** Update File: internal/export/handler.go\n@@\n+loc2\n*** End Patch"),
		result("w4", "Success."),
		call("t3", "exec_command", map[string]any{"cmd": "go test ./internal/export/..."}),
		result("t3", "Process exited with code 1"),
		call("t4", "exec_command", map[string]any{"cmd": "go test ./internal/export/..."}),
		result("t4", "Process exited with code 0"),
		user("<turn_aborted>\nThe user interrupted.\n</turn_aborted>"),
		user("测试过了的话顺便更新一下 README 的接口说明"),
		call("w5", "apply_patch", "*** Begin Patch\n*** Update File: README.md\n@@\n+docs\n*** End Patch"),
		result("w5", "Success."),
		call("g1", "exec_command", map[string]any{"cmd": "git diff --stat"}),
		result("g1", "Process exited with code 0"),
		answer("已改为按 UTC+8 解析 from/to，新增跨日边界用例；README 的导出接口一节补充了参数说明和示例。"),
	)
	childView := convo(
		user("检查仓库里其他导出接口是怎么做参数校验的，列出文件和做法"),
		call("c1", "exec_command", map[string]any{"cmd": "rg -n validate"}),
		result("c1", "Process exited with code 0"),
		call("c2", "exec_command", map[string]any{"cmd": "cat internal/report/handler.go"}),
		result("c2", "Process exited with code 0"),
	)
	return rows, map[string]*conversation.Conversation{main[len(main)-1].AuditID: mainView, child[len(child)-1].AuditID: childView}
}

const codexGolden = `[会话] 类型=agent 客户端=Codex 模型=codex-large 时间=11-04 14:02–15:08 活跃1h7m 请求=64(52/10/2) 子Agent=1(深度1) 用户轮=3 输入≈2.9M 输出≈41k 缓存命中93%
[信号] 工具失败=3(最长连续1) 反复编辑=1个文件×4 结束前验证=否 用户中断=1 纠正=1 压缩=2
[U1] 给订单导出接口加上按日期过滤，参数 from/to，格式 YYYY-MM-DD，补单测
[T1] search → read → spawn(S1){search → read} → write(internal/export/handler.go) → shell:test(go test)(失败) → write(internal/export/handler.go) → shell:test(go test)
[S1 深度=1] 检查仓库里其他导出接口是怎么做参数校验的，列出文件和做法
[A→C2] 已实现 from/to 过滤，使用 time.Parse 按 UTC 解析，并补充了 3 个单测，go test 通过。
[C2] 不对，日期要按 UTC+8 解析，不要用 UTC
[T2] write(internal/export/handler.go)×2(失败1) → shell:test(go test)×2(失败1)
[U3] 测试过了的话顺便更新一下 README 的接口说明
[T3] write(README.md) → shell:git(diff)
[A] 已改为按 UTC+8 解析 from/to，新增跨日边界用例；README 的导出接口一节补充了参数说明和示例。`

func TestCodexExamplePackGolden(t *testing.T) {
	rows, views := codexExample(t)
	pack, session, _ := examplePack(t, rows, views, 6000)
	t.Logf("example A: %d estimated tokens", pack.Tokens)
	if pack.Text != codexGolden {
		t.Fatalf("pack differs:\n%s\n--- want ---\n%s", pack.Text, codexGolden)
	}
	main := session.MainNode()
	if pack.RefMap["U1"] != main.Turns[0].AuditID || pack.RefMap["C2"] != main.Turns[1].AuditID ||
		pack.RefMap["T3"] != main.Turns[2].AuditID || pack.RefMap["A"] != main.FinalID || pack.RefMap["S1"] == "" {
		t.Fatalf("refs = %+v", pack.RefMap)
	}
	if pack.RefMap["A→C2"] != main.Turns[0].AuditID {
		t.Fatalf("assistant-before-correction ref = %s", pack.RefMap["A→C2"])
	}
	if pack.Truncated || pack.Tokens != EstimateTokens(pack.Text) {
		t.Fatalf("truncated=%v tokens=%d", pack.Truncated, pack.Tokens)
	}
	// Nothing from the exclusion list (doc 24 section 6.9) reaches the pack.
	for _, excluded := range []string{"environment_context", "AGENTS.md", "提交前先跑", "turn_aborted", "TestDateFilter", "rg -n", "sed -n", "verification failed", "cmd"} {
		if strings.Contains(pack.Text, excluded) {
			t.Errorf("pack contains excluded %q", excluded)
		}
	}
}

// Example B (Claude Code, Anthropic Messages).
func claudeExample(t *testing.T) ([]storage.SessionAuditRow, map[string]*conversation.Conversation) {
	start := time.Date(2026, 11, 5, 2, 15, 0, 0, time.UTC)
	main := rowsFor("cc", nodeMain, nil, "main", "claude_code", "claude-main", 14, start, start.Add(34*time.Minute), 500_000, 440_000, 9_000)
	haiku := rowsFor("cch", nodeMain, nil, "main", "claude_code", "claude-haiku", 3, start.Add(time.Minute), start.Add(2*time.Minute), 10_000, 9_000, 600)
	child := rowsFor("ccs", nodeChild, nodeMain, "subagent", "claude_code", "claude-main", 5, start.Add(3*time.Minute), start.Add(6*time.Minute), 100_000, 88_000, 2_400)
	title := rowsFor("cct", nodeMain, nil, "title", "claude_code", "claude-haiku", 1, start, start.Add(time.Second), 300, 0, 20)
	main[0].TurnStart, main[5].TurnStart, main[10].TurnStart = true, true, true
	rows := append(append(append(append([]storage.SessionAuditRow{}, main...), haiku...), child...), title...)
	image := conversation.Unknown(map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "AAAA"}})
	mainView := convo(
		user("<system-reminder>\nContents of /work/web-console/CLAUDE.md (project instructions)\n</system-reminder>",
			"<command-message>review-pr is running…</command-message>\n<command-name>/review-pr</command-name>\n<command-args>42</command-args>"),
		call("b1", "Bash", map[string]any{"command": "gh pr diff 42"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "b1", Result: "diff --git a/x b/x"}}},
		call("k1", "Task", map[string]any{"subagent_type": "Explore", "prompt": "Find where the PR changes the toolbar layout and list affected components."}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "k1", Result: "Toolbar.tsx"}}},
		call("r1", "Read", map[string]any{"file_path": "/work/web-console/src/components/Toolbar.tsx"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "r1", Result: "export function Toolbar()"}}},
		msg{role: conversation.RoleUser, parts: []conversation.Part{image, conversation.Text("这个按钮在窄屏下错位了，见截图，修一下")}},
		call("e1", "Edit", map[string]any{"file_path": "src/styles/global.css", "old_string": "a", "new_string": "b"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "e1", Result: "updated"}}},
		call("b2", "Bash", map[string]any{"command": "npm test"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "b2", Result: "Exit code 1\nFAIL src/Toolbar.test.tsx"}}},
		msg{role: conversation.RoleAssistant, parts: []conversation.Part{conversation.Text("我在 global.css 中把 .btn 的 flex-shrink 改为 0，并调整了媒体查询断点。")}},
		user("别改全局样式，只改这个组件"),
		call("e2", "Edit", map[string]any{"file_path": "src/styles/global.css", "old_string": "b", "new_string": "a"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "e2", Result: "updated"}}},
		call("e3", "Edit", map[string]any{"file_path": "src/components/Toolbar.tsx", "old_string": "c", "new_string": "d"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "e3", Result: "updated"}}},
		call("b3", "Bash", map[string]any{"command": "npm test"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "b3", Result: "Tests passed"}}},
		answer("已撤回 global.css 的改动，改为在 Toolbar 组件内用局部样式处理窄屏换行，npm test 通过。"),
	)
	childView := convo(
		user("Find where the PR changes the toolbar layout and list affected components."),
		call("g1", "Grep", map[string]any{"pattern": "toolbar"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "g1", Result: "src/a.tsx"}}},
		call("g2", "Read", map[string]any{"file_path": "/work/web-console/src/a.tsx"}),
		msg{role: conversation.RoleUser, parts: []conversation.Part{{Type: conversation.PartToolResult, ToolCallID: "g2", Result: "x"}}},
	)
	return rows, map[string]*conversation.Conversation{main[len(main)-1].AuditID: mainView, child[len(child)-1].AuditID: childView}
}

const claudeGolden = `[会话] 类型=agent 客户端=Claude Code 模型=claude-main(+claude-haiku 14%) 时间=11-05 10:15–10:46 活跃33m 请求=23(17/5/1) 子Agent=1(深度1) 用户轮=3 输入≈610k 输出≈12k 缓存命中88%
[信号] 工具失败=1(最长连续1) 结束前验证=是 纠正=1
[U1] [命令 /review-pr] 42
[T1] shell:git(gh) → spawn(S1){search → read} → read
[S1 深度=1] Find where the PR changes the toolbar layout and list affected components.
[U2] [图片 image/png] 这个按钮在窄屏下错位了，见截图，修一下
[T2] write(src/styles/global.css) → shell:test(npm test)(失败)
[A→C3] 我在 global.css 中把 .btn 的 flex-shrink 改为 0，并调整了媒体查询断点。
[C3] 别改全局样式，只改这个组件
[T3] write(src/styles/global.css) → write(src/components/Toolbar.tsx) → shell:test(npm test)
[A] 已撤回 global.css 的改动，改为在 Toolbar 组件内用局部样式处理窄屏换行，npm test 通过。`

func TestClaudeCodeExamplePackGolden(t *testing.T) {
	rows, views := claudeExample(t)
	pack, _, _ := examplePack(t, rows, views, 6000)
	t.Logf("example B: %d estimated tokens", pack.Tokens)
	if pack.Text != claudeGolden {
		t.Fatalf("pack differs:\n%s\n--- want ---\n%s", pack.Text, claudeGolden)
	}
	for _, excluded := range []string{"system-reminder", "CLAUDE.md", "command-message", "AAAA", "diff --git", "Toolbar.test"} {
		if strings.Contains(pack.Text, excluded) {
			t.Errorf("pack contains excluded %q", excluded)
		}
	}
}

// Example C (plain chat/completions) with a pasted log.
func TestChatExamplePackAndDigest(t *testing.T) {
	start := time.Date(2026, 11, 5, 12, 31, 0, 0, time.UTC)
	rows := rowsFor("ch", nodeMain, nil, "main", "unknown", "gpt-chat-small", 3, start, start.Add(13*time.Minute), 9_000, 0, 2_000)
	rows[0].TurnStart, rows[1].TurnStart, rows[2].TurnStart = true, true, true
	logLines := make([]string, 0, 120)
	for index := 0; index < 120; index++ {
		logLines = append(logLines, "2026/11/05 20:30:01 [error] 1234#0: upstream timed out while reading response header from upstream, client: 192.0.2.10")
	}
	view := convo(
		msg{role: conversation.RoleSystem, parts: []conversation.Part{conversation.Text("You are a helpful assistant.")}},
		user("帮我把下面这段报错翻译一下并说明原因\n"+strings.Join(logLines, "\n")),
		msg{role: conversation.RoleAssistant, parts: []conversation.Part{conversation.Text("这是反向代理读取上游响应头超时。")}},
		user("那 upstream 超时一般怎么调？"),
		msg{role: conversation.RoleAssistant, parts: []conversation.Part{conversation.Text("调大 proxy_read_timeout。")}},
		user("顺便推荐几部周末看的电影"),
		answer("以下是几部适合周末观看的电影：……"),
	)
	pack, session, signals := examplePack(t, rows, map[string]*conversation.Conversation{rows[2].AuditID: view}, 6000)
	t.Logf("example C: %d estimated tokens", pack.Tokens)
	if session.Kind != KindChat || signals.ErrorPastes != 1 {
		t.Fatalf("kind=%s pastes=%d", session.Kind, signals.ErrorPastes)
	}
	if strings.Contains(pack.Text, "[T") || strings.Contains(pack.Text, "helpful assistant") {
		t.Fatalf("chat pack has tool lines or the system prompt:\n%s", pack.Text)
	}
	// The 900+300 rune cap of the first turn may cut one kept log line.
	if !strings.Contains(pack.Text, "[…省略 110 行日志…]") || strings.Count(pack.Text, "upstream timed out") < 9 {
		t.Fatalf("pasted log not shortened:\n%s", pack.Text)
	}
	if !strings.HasPrefix(pack.Text, "[会话] 类型=聊天 客户端=unknown 模型=gpt-chat-small 时间=11-05 20:31–20:39 活跃11m 请求=3 用户轮=3") {
		t.Fatalf("header:\n%s", pack.Text)
	}

	vocab, _ := testVocabularies(t)
	items := []DigestItem{
		{AuditID: "d3", StartedNS: start.Add(5 * time.Hour).UnixNano(), Text: "写一封请假邮件，下周三下午，抄送 someone@example.com", Model: "gpt-chat-small"},
		{AuditID: "d1", StartedNS: start.Add(-3 * time.Hour).UnixNano(), Text: "用 SQL 写一个按月统计订单数的查询", Model: "gpt-chat-small"},
		{AuditID: "d2", StartedNS: start.Add(-time.Hour).UnixNano(), Text: "Kubernetes 里 readinessProbe 和 livenessProbe 的区别", Model: "gpt-chat-small"},
	}
	digest := BuildDigestPack("unknown", items, vocab, PackOptions{MaxTokens: 6000, Location: packZone})
	want := "[会话] 类型=聊天汇总 客户端=unknown 模型=gpt-chat-small 时间=11-05 17:31–11-06 01:31 会话=3\n" +
		"[U1 17:31] 用 SQL 写一个按月统计订单数的查询\n" +
		"[U2 19:31] Kubernetes 里 readinessProbe 和 livenessProbe 的区别\n" +
		"[U3 01:31] 写一封请假邮件，下周三下午，抄送 [REDACTED:contact]"
	if digest.Text != want {
		t.Fatalf("digest:\n%s\n--- want ---\n%s", digest.Text, want)
	}
	if digest.RefMap["U1"] != "d1" || digest.RefMap["U3"] != "d3" {
		t.Fatalf("digest refs = %+v", digest.RefMap)
	}
}

func TestPackBudgetDropsMiddleTurnsNewestKept(t *testing.T) {
	parts := []msg{user("第一轮：整体目标是重构导出模块，" + strings.Repeat("背景说明。", 100))}
	for index := 2; index <= 12; index++ {
		parts = append(parts, user("第"+string(rune('0'+index%10))+"轮补充："+strings.Repeat("细节内容。", 60)))
	}
	parts = append(parts, user("最后一轮：收尾并提交"), answer("完成"))
	rows := make([]storage.SessionAuditRow, 0, 13)
	for index := 0; index < 13; index++ {
		rows = append(rows, auditRow("b"+string(rune('a'+index)), baseTime.Add(time.Duration(index)*time.Minute), nodeMain, "main", true))
	}
	pack, _, _ := examplePack(t, rows, map[string]*conversation.Conversation{rows[12].AuditID: convo(parts...)}, 1200)
	if !pack.Truncated || pack.Tokens > 1200 {
		t.Fatalf("truncated=%v tokens=%d", pack.Truncated, pack.Tokens)
	}
	if !strings.Contains(pack.Text, "截断=是") || !strings.Contains(pack.Text, "[U1]") || !strings.Contains(pack.Text, "[U13] 最后一轮") || !strings.Contains(pack.Text, "[A] 完成") {
		t.Fatalf("mandatory lines missing:\n%s", pack.Text)
	}
	if !strings.Contains(pack.Text, "[…省略 U2–") {
		t.Fatalf("no placeholder for dropped turns:\n%s", pack.Text)
	}
	// Newest middle turns survive before older ones.
	if strings.Contains(pack.Text, "[U2]") && !strings.Contains(pack.Text, "[U12]") {
		t.Fatalf("older turn kept before newer:\n%s", pack.Text)
	}
	for label := range pack.RefMap {
		if !strings.Contains(pack.Text, "["+label+"]") && !strings.Contains(pack.Text, "["+label+" ") {
			t.Errorf("ref %s points at a dropped line", label)
		}
	}
	// The first turn is capped at 900 + 300 runes.
	first := strings.SplitN(strings.SplitN(pack.Text, "[U1] ", 2)[1], "\n", 2)[0]
	if n := len([]rune(first)); n > 1201 {
		t.Fatalf("first turn has %d runes", n)
	}
}

func TestRedactionCoversEverySecretCategory(t *testing.T) {
	vocab, _ := testVocabularies(t)
	samples := map[string]string{
		"private_key":         "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
		"cloud_key":           "AKIA" + strings.Repeat("Z", 16),
		"vcs_token":           "ghp_" + strings.Repeat("b2", 18),
		"api_key":             "sk-" + strings.Repeat("x", 24),
		"jwt":                 "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12),
		"connection_string":   "postgres://app:" + "hunter22" + "@db.example.com/x",
		"password_assignment": "password=" + "Sup3rS3cret",
	}
	for category, sample := range samples {
		got := vocab.Redact("值是 " + sample + " 结束")
		if strings.Contains(got, sample) || !strings.Contains(got, "[REDACTED:"+category+"]") {
			t.Errorf("%s: %q", category, got)
		}
	}
	if got := vocab.Redact("call 13812345678 or mail a.b@example.com"); strings.Contains(got, "13812345678") || strings.Contains(got, "example.com") {
		t.Errorf("contacts: %q", got)
	}
}

func TestEstimateTokens(t *testing.T) {
	if got := EstimateTokens("中文四字"); got != 4 {
		t.Fatalf("cjk = %d", got)
	}
	if got := EstimateTokens("abcdefgh"); got != 2 {
		t.Fatalf("ascii = %d", got)
	}
	if got := EstimateTokens("中a"); got != 2 {
		t.Fatalf("mixed = %d", got)
	}
}

// The design document shows examples A and B verbatim (doc 24 section 6.11).
func TestDesignDocShowsTheGoldenPacks(t *testing.T) {
	doc, err := os.ReadFile("../../doc/features/24-session-analysis.md")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")
	for name, golden := range map[string]string{"A": codexGolden, "B": claudeGolden} {
		if !strings.Contains(text, golden) {
			t.Errorf("doc 24 section 6.11 example %s differs from the golden pack", name)
		}
	}
}
