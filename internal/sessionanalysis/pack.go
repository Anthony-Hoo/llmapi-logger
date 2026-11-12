package sessionanalysis

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"llmapi-logger/internal/storage"
)

// Pack is the input pack of one session or chat digest (doc 24 section 6).
// Text is sensitive and must be encrypted before storage; RefMap maps every
// line label to the audit that carries it.
type Pack struct {
	Text      string
	RefMap    map[string]string
	Tokens    int
	Truncated bool
}

// Hash returns the hex SHA-256 of the pack text, the facet cache key part.
func (pack Pack) Hash() string {
	sum := sha256.Sum256([]byte(pack.Text))
	return fmt.Sprintf("%x", sum[:])
}

// Per-line limits in runes (doc 24 section 6.7).
const (
	capFirstHead   = 900
	capFirstTail   = 300
	capCorrection  = 400
	capBeforeFix   = 200
	capLast        = 600
	capMiddle      = 300
	capTask        = 300
	capFinalHead   = 200
	capFinalTail   = 400
	capDigestQuest = 300
	maxSegmentToks = 40
	keepSegHead    = 15
	keepSegTail    = 20
	maxDigestItems = 20
	pasteMinLines  = 15
	fenceMinLines  = 40
	pasteKeepLines = 5
)

var builtinClientLabels = map[string]string{
	"codex": "Codex", "claude_code": "Claude Code", "opencode": "OpenCode", "dsh": "DSH",
	"custom": "自定义", "pi": "pi", "zcode": "ZCode",
}

// EstimateTokens counts a CJK rune as one token and four other characters as
// one token (doc 24 section 6.8).
func EstimateTokens(text string) int {
	cjk, other := 0, 0
	for _, r := range text {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) || (r >= 0x3000 && r <= 0x303f) || (r >= 0xff00 && r <= 0xffef) {
			cjk++
			continue
		}
		other++
	}
	return cjk + (other+3)/4
}

// PackOptions tune pack building.
type PackOptions struct {
	MaxTokens    int
	Location     *time.Location
	ClientLabels map[string]string
	// Project is the value of the session line's project field; empty (org
	// reports off, or no booking yet) omits the field.
	Project string
}

func (options PackOptions) clientLabel(client string) string {
	if client == "" {
		return "unknown"
	}
	if label := options.ClientLabels[client]; label != "" {
		return label
	}
	if label := builtinClientLabels[client]; label != "" {
		return label
	}
	return client
}

// headTail keeps the first head and last tail runes of text.
func headTail(text string, head, tail int) string {
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) <= head+tail {
		return text
	}
	runes := []rune(text)
	if tail == 0 {
		return string(runes[:head]) + "…"
	}
	if head == 0 {
		return "…" + string(runes[len(runes)-tail:])
	}
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

// compressPastes shortens pasted logs, stack traces and long code fences to
// their first and last lines (doc 24 section 6.3 step 7).
func (vocab *Vocabulary) compressPastes(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) < pasteMinLines {
		return text
	}
	out := make([]string, 0, len(lines))
	for index := 0; index < len(lines); {
		if strings.HasPrefix(strings.TrimSpace(lines[index]), "```") {
			end := index + 1
			for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), "```") {
				end++
			}
			body := end - index - 1
			if body >= fenceMinLines {
				out = append(out, lines[index:index+1+pasteKeepLines]...)
				out = append(out, fmt.Sprintf("[…省略 %d 行…]", body-2*pasteKeepLines))
				closing := end
				if closing >= len(lines) {
					closing = len(lines) - 1
				}
				out = append(out, lines[end-pasteKeepLines:closing+1]...)
				index = closing + 1
				continue
			}
		}
		out = append(out, lines[index])
		index++
	}
	if len(out) != len(lines) {
		return strings.Join(out, "\n")
	}
	// No long fence: an unfenced block of many lines that carries error
	// output is a pasted log.
	if !vocab.isErrorPaste(text) {
		return text
	}
	first := 0
	for first < len(lines) && !vocab.lineLooksLikeLog(lines[first]) {
		first++
	}
	if len(lines)-first < pasteMinLines {
		return text
	}
	kept := append([]string{}, lines[:first+pasteKeepLines]...)
	kept = append(kept, fmt.Sprintf("[…省略 %d 行日志…]", len(lines)-first-2*pasteKeepLines))
	kept = append(kept, lines[len(lines)-pasteKeepLines:]...)
	return strings.Join(kept, "\n")
}

func (vocab *Vocabulary) lineLooksLikeLog(line string) bool {
	for _, pattern := range vocab.errors {
		if pattern.MatchString(line) {
			return true
		}
	}
	trimmed := strings.TrimSpace(line)
	return len(trimmed) > 0 && (trimmed[0] >= '0' && trimmed[0] <= '9' || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "at "))
}

// Redact replaces secrets and contact details (doc 24 section 6.10).
func (vocab *Vocabulary) Redact(text string) string {
	for _, group := range vocab.secrets {
		for _, pattern := range group.patterns {
			text = pattern.ReplaceAllString(text, "[REDACTED:"+group.name+"]")
		}
	}
	for _, pattern := range vocab.contacts {
		text = pattern.ReplaceAllString(text, "[REDACTED:contact]")
	}
	return text
}

func formatCount(value int64) string {
	switch {
	case value < 1000:
		return strconv.FormatInt(value, 10)
	case value < 10_000:
		return strings.TrimSuffix(strconv.FormatFloat(float64(value)/1000, 'f', 1, 64), ".0") + "k"
	case value < 1_000_000:
		return strconv.FormatInt((value+500)/1000, 10) + "k"
	default:
		return strings.TrimSuffix(strconv.FormatFloat(float64(value)/1_000_000, 'f', 1, 64), ".0") + "M"
	}
}

func formatActive(ns int64) string {
	seconds := ns / int64(time.Second)
	switch {
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%dm", (seconds+30)/60)
	default:
		return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600+30)/60)
	}
}

func formatSpan(firstNS, lastNS int64, location *time.Location) string {
	first, last := time.Unix(0, firstNS).In(location), time.Unix(0, lastNS).In(location)
	if first.Format("01-02") == last.Format("01-02") {
		return first.Format("01-02 15:04") + "–" + last.Format("15:04")
	}
	return first.Format("01-02 15:04") + "–" + last.Format("01-02 15:04")
}

// modelSummary renders the main model and up to two others with their share.
func modelSummary(rows []storage.SessionAuditRow) string {
	counts := map[string]int{}
	total := 0
	for _, row := range rows {
		if row.Model == "" || isAuxiliary(row.AgentRole) {
			continue
		}
		counts[row.Model]++
		total++
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) == 0 {
		return "unknown"
	}
	out := names[0]
	others := make([]string, 0, 2)
	for _, name := range names[1:] {
		if len(others) == 2 {
			break
		}
		others = append(others, fmt.Sprintf("%s %d%%", name, (counts[name]*100+total/2)/total))
	}
	if len(others) != 0 {
		out += "(+" + strings.Join(others, ", +") + ")"
	}
	return out
}

func sessionHeader(session *Session, signals storage.SessionSignals, options PackOptions, truncated bool) string {
	kind := "agent"
	if session.Kind == KindChat {
		kind = "聊天"
	}
	parts := []string{
		"类型=" + kind,
		"客户端=" + options.clientLabel(session.Client),
	}
	if options.Project != "" {
		parts = append(parts, "项目="+options.Project)
	}
	parts = append(parts,
		"模型="+modelSummary(session.Rows),
		"时间="+formatSpan(signals.FirstNS, signals.LastNS, options.Location)+" 活跃"+formatActive(signals.ActiveNS))
	if session.Kind == KindAgent {
		parts = append(parts,
			fmt.Sprintf("请求=%d(%d/%d/%d)", signals.Requests, signals.MainRequests, signals.SubRequests, signals.AuxRequests),
			fmt.Sprintf("子Agent=%d(深度%d)", signals.Subagents, signals.MaxDepth))
	} else {
		parts = append(parts, fmt.Sprintf("请求=%d", signals.Requests))
	}
	parts = append(parts, fmt.Sprintf("用户轮=%d", signals.UserTurns),
		"输入≈"+formatCount(signals.InputTokens), "输出≈"+formatCount(signals.OutputTokens))
	if signals.InputTokens > 0 && signals.CacheReadTokens > 0 {
		parts = append(parts, fmt.Sprintf("缓存命中%d%%", (signals.CacheReadTokens*100+signals.InputTokens/2)/signals.InputTokens))
	}
	if truncated {
		parts = append(parts, "截断=是")
	}
	return "[会话] " + strings.Join(parts, " ")
}

var dangerNames = map[string]string{
	"destructive_delete": "破坏性删除", "force_push": "强制推送", "remote_script": "远程脚本",
	"credential_read": "读取凭据", "exfiltrate": "外传文件",
}

func signalLine(signals storage.SessionSignals) string {
	parts := make([]string, 0, 12)
	if signals.ToolFailures > 0 {
		parts = append(parts, fmt.Sprintf("工具失败=%d(最长连续%d)", signals.ToolFailures, signals.MaxFailureStreak))
	}
	if signals.Loops > 0 {
		parts = append(parts, fmt.Sprintf("重复调用=%d处(最长%d次)", signals.Loops, signals.MaxLoopLength))
	}
	if signals.ThrashFiles > 0 {
		parts = append(parts, fmt.Sprintf("反复编辑=%d个文件×%d", signals.ThrashFiles, signals.MaxFileWrites))
	}
	switch signals.Verified {
	case "yes":
		parts = append(parts, "结束前验证=是")
	case "no":
		parts = append(parts, "结束前验证=否")
	}
	if signals.ErrorPastes > 0 {
		parts = append(parts, fmt.Sprintf("报错回贴=%d", signals.ErrorPastes))
	}
	if signals.Interrupts > 0 {
		parts = append(parts, fmt.Sprintf("用户中断=%d", signals.Interrupts))
	}
	if signals.Corrections > 0 {
		parts = append(parts, fmt.Sprintf("纠正=%d", signals.Corrections))
	}
	if signals.Compactions > 0 {
		parts = append(parts, fmt.Sprintf("压缩=%d", signals.Compactions))
	}
	if signals.LengthStops > 0 {
		parts = append(parts, fmt.Sprintf("长度截断=%d", signals.LengthStops))
	}
	if signals.UpstreamErrors > 0 {
		parts = append(parts, fmt.Sprintf("上游错误=%d", signals.UpstreamErrors))
	}
	if signals.HeavyModel {
		parts = append(parts, "重模型候选")
	}
	if counts := decodeCounts(signals.DangerCounts); len(counts) != 0 {
		names := make([]string, 0, len(counts))
		for key := range counts {
			name := dangerNames[key]
			if name == "" {
				name = key
			}
			names = append(names, name)
		}
		sort.Strings(names)
		parts = append(parts, "危险命令="+strings.Join(names, "、"))
	}
	if counts := decodeCounts(signals.SecretCounts); len(counts) != 0 {
		var total int64
		for _, count := range counts {
			total += count
		}
		parts = append(parts, fmt.Sprintf("疑似密钥=%d", total))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[信号] " + strings.Join(parts, " ")
}

// callToken is the [T] token of one call without its status.
func callToken(call ToolCall) string {
	switch call.Kind {
	case "write":
		if len(call.Paths) == 0 {
			return "write"
		}
		return "write(" + displayPath(call.Paths[0]) + ")"
	case "shell":
		return "shell:" + call.Class + "(" + call.Label + ")"
	case "mcp":
		return "mcp:" + call.Class
	case "other":
		return "other:" + call.Label
	default:
		return call.Kind
	}
}

// displayPath keeps a relative path, and only the file name of an absolute
// one (no repository root is known here).
func displayPath(path string) string {
	path = strings.ReplaceAll(path, `\`, "/")
	if strings.HasPrefix(path, "/") || (len(path) > 2 && path[1] == ':') {
		return baseName(path)
	}
	return strings.TrimPrefix(path, "./")
}

type tokenGroup struct {
	base    string
	count   int
	failed  int
	unknown int
	nested  string
}

func (group tokenGroup) String() string {
	out := group.base
	if group.nested != "" {
		out += "{" + group.nested + "}"
	}
	if group.count > 1 {
		out += "×" + strconv.Itoa(group.count)
	}
	status := make([]string, 0, 2)
	switch {
	case group.failed > 0 && group.count == 1:
		status = append(status, "失败")
	case group.failed > 0:
		status = append(status, "失败"+strconv.Itoa(group.failed))
	}
	switch {
	case group.unknown > 0 && group.count == 1:
		status = append(status, "?")
	case group.unknown > 0:
		status = append(status, "?"+strconv.Itoa(group.unknown))
	}
	if len(status) != 0 {
		out += "(" + strings.Join(status, ",") + ")"
	}
	return out
}

// renderCalls run-length encodes calls into " → "-joined tokens. spawn calls
// expand their child one level (depth counts levels already expanded).
func renderCalls(session *Session, calls []ToolCall, labels map[int]string, depth int) string {
	groups := make([]tokenGroup, 0, len(calls))
	for _, call := range calls {
		base := callToken(call)
		nested := ""
		if call.Kind == "spawn" {
			label := labels[call.Child]
			if label == "" {
				label = "?"
			}
			base = "spawn(" + label + ")"
			if call.Child >= 0 && call.Child < len(session.Nodes) {
				child := session.Nodes[call.Child]
				if depth == 0 {
					nested = renderCalls(session, child.Calls, labels, depth+1)
				} else {
					nested = fmt.Sprintf("子Agent 共 %d 步", len(child.Calls))
				}
			}
		}
		if last := len(groups) - 1; last >= 0 && groups[last].base == base && nested == "" && groups[last].nested == "" {
			groups[last].count++
			if call.Status == StatusFailed {
				groups[last].failed++
			} else if call.Status == StatusUnknown {
				groups[last].unknown++
			}
			continue
		}
		group := tokenGroup{base: base, count: 1, nested: nested}
		if call.Status == StatusFailed {
			group.failed = 1
		} else if call.Status == StatusUnknown {
			group.unknown = 1
		}
		groups = append(groups, group)
	}
	tokens := make([]string, 0, len(groups))
	for _, group := range groups {
		tokens = append(tokens, group.String())
	}
	if len(tokens) > maxSegmentToks {
		omitted := len(tokens) - keepSegHead - keepSegTail
		kept := append(append([]string{}, tokens[:keepSegHead]...), fmt.Sprintf("…(省略 %d 步)…", omitted))
		tokens = append(kept, tokens[len(tokens)-keepSegTail:]...)
	}
	return strings.Join(tokens, " → ")
}

// packLine is one labelled line with its priority group.
type packLine struct {
	text     string
	turn     int // user turn index the line belongs to, -1 for header lines
	priority int // lower survives longer
}

// Priority groups (doc 24 section 6.8).
const (
	prioHeader = iota
	prioFirst
	prioCorrection
	prioLast
	prioTask
	prioMiddle
)

// BuildSessionPack assembles the input pack of one eligible session.
func BuildSessionPack(session *Session, signals storage.SessionSignals, vocab *Vocabulary, options PackOptions) Pack {
	if options.Location == nil {
		options.Location = time.Local
	}
	main := session.MainNode()
	refs := map[string]string{}
	lines := make([]packLine, 0, 16)
	if main == nil {
		return Pack{}
	}
	childLabels := map[int]string{}
	nextChild := 1
	for _, call := range flatten(session, session.Main, 0) {
		if call.Kind == "spawn" && call.Child >= 0 {
			if _, ok := childLabels[call.Child]; !ok {
				childLabels[call.Child] = "S" + strconv.Itoa(nextChild)
				nextChild++
			}
		}
	}
	turns := main.Turns
	segments := make([][]ToolCall, len(turns))
	for _, call := range main.Calls {
		turn := call.Turn
		if turn < 0 {
			turn = 0
		}
		if turn < len(segments) {
			segments[turn] = append(segments[turn], call)
		}
	}
	last := len(turns) - 1
	for index, turn := range turns {
		number := strconv.Itoa(index + 1)
		label := "U" + number
		priority := prioMiddle
		text := vocab.compressPastes(turn.Text)
		switch {
		case index == 0:
			priority = prioFirst
			text = headTail(text, capFirstHead, capFirstTail)
		case turn.Correction:
			priority = prioCorrection
			label = "C" + number
			text = headTail(text, capCorrection, 0)
		case index == last:
			priority = prioLast
			text = headTail(text, capLast, 0)
		default:
			text = headTail(text, capMiddle, 0)
		}
		if len(turn.Images) != 0 {
			text = strings.Join(turn.Images, " ") + " " + text
		}
		if turn.Correction && strings.TrimSpace(turn.AssistantBefore) != "" {
			before := "A→C" + number
			lines = append(lines, packLine{text: "[" + before + "] " + headTail(turn.AssistantBefore, 0, capBeforeFix), turn: index, priority: prioCorrection})
			if index > 0 {
				refs[before] = turns[index-1].AuditID
			}
		}
		lines = append(lines, packLine{text: "[" + label + "] " + text, turn: index, priority: priority})
		refs[label] = turn.AuditID
		if len(segments[index]) != 0 {
			segmentLabel := "T" + number
			lines = append(lines, packLine{text: "[" + segmentLabel + "] " + renderCalls(session, segments[index], childLabels, 0), turn: index, priority: priority})
			refs[segmentLabel] = turn.AuditID
			for _, call := range segments[index] {
				if call.Kind != "spawn" || call.Child < 0 || call.Child >= len(session.Nodes) {
					continue
				}
				child := session.Nodes[call.Child]
				childLabel := childLabels[call.Child]
				if child.Task == "" || childLabel == "" {
					continue
				}
				lines = append(lines, packLine{
					text: fmt.Sprintf("[%s 深度=%d] %s", childLabel, child.Depth, headTail(child.Task, capTask, 0)),
					turn: index, priority: prioTask,
				})
				refs[childLabel] = child.TaskAudit
			}
		}
	}
	if final := strings.TrimSpace(main.Final); final != "" {
		lines = append(lines, packLine{text: "[A] " + headTail(final, capFinalHead, capFinalTail), turn: last, priority: prioLast})
		refs["A"] = main.FinalID
	}
	return finishPack(session, signals, vocab, options, lines, refs)
}

// finishPack applies redaction and the token budget, dropping middle turns
// newest first and leaving a placeholder for each dropped run.
func finishPack(session *Session, signals storage.SessionSignals, vocab *Vocabulary, options PackOptions, lines []packLine, refs map[string]string) Pack {
	for index := range lines {
		lines[index].text = vocab.Redact(lines[index].text)
	}
	signalText := signalLine(signals)
	render := func(dropped map[int]bool, truncated bool) string {
		out := []string{sessionHeader(session, signals, options, truncated)}
		if signalText != "" {
			out = append(out, signalText)
		}
		gapStart, gapEnd := -1, -1
		flush := func() {
			if gapStart >= 0 {
				out = append(out, fmt.Sprintf("[…省略 U%d–U%d，共 %d 轮…]", gapStart+1, gapEnd+1, gapEnd-gapStart+1))
				gapStart = -1
			}
		}
		for _, line := range lines {
			if line.turn >= 0 && dropped[line.turn] && line.priority == prioMiddle {
				if gapStart < 0 {
					gapStart = line.turn
				}
				gapEnd = line.turn
				continue
			}
			flush()
			out = append(out, line.text)
		}
		flush()
		return strings.Join(out, "\n")
	}
	maxTokens := options.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 6000
	}
	middle := make([]int, 0)
	seen := map[int]bool{}
	for _, line := range lines {
		if line.priority == prioMiddle && !seen[line.turn] {
			seen[line.turn] = true
			middle = append(middle, line.turn)
		}
	}
	dropped := map[int]bool{}
	text := render(dropped, false)
	if EstimateTokens(text) <= maxTokens {
		return Pack{Text: text, RefMap: keptRefs(refs, dropped), Tokens: EstimateTokens(text)}
	}
	// Keep middle turns newest first while they fit.
	for _, turn := range middle {
		dropped[turn] = true
	}
	for index := len(middle) - 1; index >= 0; index-- {
		delete(dropped, middle[index])
		if EstimateTokens(render(dropped, true)) > maxTokens {
			dropped[middle[index]] = true
			break
		}
	}
	text = render(dropped, true)
	if EstimateTokens(text) > maxTokens {
		text = cutToBudget(text, maxTokens)
	}
	return Pack{Text: text, RefMap: keptRefs(refs, dropped), Tokens: EstimateTokens(text), Truncated: true}
}

func keptRefs(refs map[string]string, dropped map[int]bool) map[string]string {
	out := make(map[string]string, len(refs))
	for label, audit := range refs {
		if audit == "" {
			continue
		}
		// Only U and T lines of middle turns are ever dropped.
		if label[0] == 'U' || label[0] == 'T' {
			if number, err := strconv.Atoi(label[1:]); err == nil && dropped[number-1] {
				continue
			}
		}
		out[label] = audit
	}
	return out
}

// cutToBudget drops whole lines from the end (keeping the first two) until
// the text fits.
func cutToBudget(text string, maxTokens int) string {
	lines := strings.Split(text, "\n")
	for len(lines) > 2 && EstimateTokens(strings.Join(lines, "\n")) > maxTokens-10 {
		lines = lines[:len(lines)-1]
	}
	joined := strings.Join(lines, "\n") + "\n[…超出预算，后续省略…]"
	for EstimateTokens(joined) > maxTokens && utf8.RuneCountInString(joined) > 10 {
		runes := []rune(joined)
		joined = string(runes[:len(runes)*9/10])
	}
	return joined
}

// DigestItem is one single-turn chat of a digest pack.
type DigestItem struct {
	SessionKey []byte
	AuditID    string
	StartedNS  int64
	Text       string
	Model      string
}

// BuildDigestPack assembles one chat digest pack (doc 24 section 6.2).
func BuildDigestPack(client string, items []DigestItem, vocab *Vocabulary, options PackOptions) Pack {
	if options.Location == nil {
		options.Location = time.Local
	}
	if len(items) == 0 {
		return Pack{}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].StartedNS < items[j].StartedNS })
	models := map[string]int{}
	for _, item := range items {
		if item.Model != "" {
			models[item.Model]++
		}
	}
	header := fmt.Sprintf("[会话] 类型=聊天汇总 客户端=%s 模型=%s 时间=%s 会话=%d",
		options.clientLabel(client), topModel(models), formatSpan(items[0].StartedNS, items[len(items)-1].StartedNS, options.Location), len(items))
	lines := []string{header}
	refs := map[string]string{}
	for index, item := range items {
		label := "U" + strconv.Itoa(index+1)
		at := time.Unix(0, item.StartedNS).In(options.Location).Format("15:04")
		text := vocab.Redact(headTail(vocab.compressPastes(item.Text), capDigestQuest, 0))
		lines = append(lines, "["+label+" "+at+"] "+text)
		refs[label] = item.AuditID
	}
	text := strings.Join(lines, "\n")
	pack := Pack{Text: text, RefMap: refs, Tokens: EstimateTokens(text)}
	if options.MaxTokens > 0 && pack.Tokens > options.MaxTokens {
		pack.Text = cutToBudget(text, options.MaxTokens)
		pack.Tokens, pack.Truncated = EstimateTokens(pack.Text), true
	}
	return pack
}

// EncodeRefMap renders a ref map as compact sorted JSON.
func EncodeRefMap(refs map[string]string) string {
	encoded, err := json.Marshal(refs)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// chatClient returns the analysis client key of a chat session.
func chatClient(session *Session) string {
	if session.Client == "" {
		return "unknown"
	}
	return session.Client
}
