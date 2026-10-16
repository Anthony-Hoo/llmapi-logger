package insights

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

// Fingerprint domain labels. Every tag is a keyed HMAC supplied by the caller.
const (
	DomainItem    = "insights/item"
	DomainSystem  = "insights/system"
	DomainTools   = "insights/tools"
	DomainSession = "insights/session"
	DomainHint    = "insights/hint"
)

const (
	maxDetailItems = 2000
	maxItemFPRs    = 20000
	maxHintBlocks  = 8
)

var defaultVocabulary = sync.OnceValue(DefaultVocabulary)

// Analyze derives the context analysis of one audit. It fills everything
// except Agent, SpawnHintFPRs and ChildHintFPRs, which the identity resolver
// owns. A nil vocab means the built-in vocabulary (shared; do not mutate).
//
// An error is returned only when the request body is not parseable as a JSON
// object for a supported protocol; any other defect degrades to a best-effort
// Analysis.
//
// SessionKeyFPR is a partial key: for the explicit source it covers
// protocol and the body-supplied id, for the inferred source protocol, system
// fingerprint and first user item. The caller mixes the api key fingerprint in
// before using it as a session identity (doc section 3.3).
func Analyze(input Input, vocab *Vocabulary, fp Fingerprinter) (Analysis, error) {
	if fp == nil {
		return Analysis{}, errors.New("insights: fingerprinter is required")
	}
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	request, err := parseRequest(input, vocab)
	if err != nil {
		return Analysis{}, err
	}
	analysis := Analysis{
		Version:         AnalysisVersion,
		Model:           firstNonEmpty(input.RequestModel, input.ResponseModel),
		Usage:           input.Usage,
		MaxOutputTokens: maxOutputTokens(request.root),
		FirstEventNS:    input.FirstEventNS,
	}
	if input.FirstEventNS != nil && input.LastEventNS != nil && *input.LastEventNS >= *input.FirstEventNS {
		generation := *input.LastEventNS - *input.FirstEventNS
		analysis.GenerationNS = &generation
	}

	items := request.items
	fprs := make([][]byte, len(items))
	hexFPRs := make([]string, 0, min(len(items), maxItemFPRs))
	var systemCanons []json.RawMessage
	for index, item := range items {
		analysis.Estimate.add(item.Category, item.Tokens)
		analysis.Counts.Items++
		switch {
		case item.Kind == "tool_def":
			analysis.Counts.ToolDefs++
		case item.Kind == "tool_result":
			analysis.Counts.ToolResults++
		case item.Category == CategoryMedia:
			analysis.Counts.Media++
		}
		fprs[index] = fp.Fingerprint(DomainItem, item.canon)
		if index < maxItemFPRs {
			hexFPRs = append(hexFPRs, hex.EncodeToString(fprs[index]))
		}
		if item.Category == CategorySystem {
			systemCanons = append(systemCanons, json.RawMessage(item.canon))
		}
	}
	if len(systemCanons) != 0 {
		analysis.SystemFPR = fp.Fingerprint(DomainSystem, canonicalJSON(systemCanons))
	}
	if request.toolsCanon != nil {
		analysis.ToolsFPR = fp.Fingerprint(DomainTools, request.toolsCanon)
	}
	if n := len(items); n != 0 {
		last := items[n-1]
		analysis.TurnStart = last.Category == CategoryUser && last.Kind == "text"
	}

	protocol := strings.ToLower(input.Protocol)
	if id := explicitSessionID(request.root); id != "" {
		analysis.SessionKeyFPR = fp.Fingerprint(DomainSession, []byte(protocol+"\x00"+id))
		analysis.SessionKeySource = SessionLinkExplicit
	} else if first := firstUserItem(items); first >= 0 {
		key := append([]byte(protocol+"\x00"), analysis.SystemFPR...)
		key = append(append(key, 0), fprs[first]...)
		analysis.SessionKeyFPR = fp.Fingerprint(DomainSession, key)
		analysis.SessionKeySource = SessionLinkInferred
	}

	detailItems := make([]Item, 0, min(len(items), maxDetailItems))
	for _, item := range items {
		if len(detailItems) == maxDetailItems {
			analysis.Detail.Truncated = true
			break
		}
		detailItems = append(detailItems, item.Item)
	}
	tools := request.tools
	if tools == nil {
		tools = []ToolDef{}
	}
	analysis.Detail.Items = detailItems
	analysis.Detail.Tools = tools
	analysis.Detail.FileOps = []FileOp{}
	analysis.Detail.ItemFPRs = hexFPRs
	if len(items) > maxItemFPRs {
		analysis.Detail.Truncated = true
	}

	analysis.applyResponse(input, vocab)
	return analysis, nil
}

func firstUserItem(items []ctxItem) int {
	fallback := -1
	for index, item := range items {
		switch item.Category {
		case CategoryUser:
			return index
		case CategoryInjected:
			if fallback < 0 {
				fallback = index
			}
		}
	}
	return fallback
}

// explicitSessionID reads a client-declared session id from the request body:
// metadata.{session_id,conversation_id,thread_id}, or a Claude Code
// metadata.user_id that is a JSON object (or the legacy "..._session_<id>").
func explicitSessionID(root map[string]any) string {
	metadata := asMap(root["metadata"])
	for _, key := range []string{"session_id", "conversation_id", "thread_id"} {
		if value := strings.TrimSpace(asString(metadata[key])); value != "" {
			return value
		}
	}
	userID := strings.TrimSpace(asString(metadata["user_id"]))
	if userID == "" {
		return ""
	}
	if strings.HasPrefix(userID, "{") {
		if value, err := decodeJSON([]byte(userID)); err == nil {
			return strings.TrimSpace(asString(asMap(value)["session_id"]))
		}
		return ""
	}
	if index := strings.LastIndex(userID, "_session_"); index >= 0 {
		return strings.TrimSpace(userID[index+len("_session_"):])
	}
	return ""
}

// SpawnPrompts returns the child prompts of the spawn-tool calls in this
// response (vocabulary SpawnTools), trimmed of surrounding whitespace. The
// identity resolver fingerprints them with HintFPR.
func SpawnPrompts(input Input, vocab *Vocabulary) []string {
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	var prompts []string
	for _, call := range responseToolCalls(input.Conversation) {
		argNames, ok := vocab.SpawnTools[strings.ToLower(call.name)]
		if !ok {
			continue
		}
		if prompt := strings.TrimSpace(firstString(parseArgs(call.args), argNames)); prompt != "" {
			prompts = append(prompts, prompt)
		}
	}
	return prompts
}

// OpeningUserTexts returns the text blocks of the first user message of the
// request (at most eight, trimmed). When a block starts with a vocabulary
// SubagentPrefixes entry, the stripped text follows it as an extra candidate.
// The identity resolver fingerprints them with HintFPR to match SpawnPrompts.
func OpeningUserTexts(input Input, vocab *Vocabulary) []string {
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	request, err := parseRequest(input, vocab)
	if err != nil {
		return nil
	}
	var texts []string
	msg := -1
	blocks := 0
	for _, item := range request.items {
		if msg < 0 {
			if item.Role != "user" || (item.Category != CategoryUser && item.Category != CategoryInjected) {
				continue
			}
			msg = item.msg
		}
		if item.msg != msg {
			break
		}
		if item.Kind != "text" || blocks == maxHintBlocks {
			continue
		}
		blocks++
		text := strings.TrimSpace(item.text)
		texts = append(texts, text)
		if stripped := strings.TrimSpace(vocab.StripSubagentPrefix(item.text)); stripped != text {
			texts = append(texts, stripped)
		}
	}
	return texts
}

// HintFPR fingerprints a spawn prompt or opening text for content matching.
func HintFPR(fp Fingerprinter, text string) []byte {
	return fp.Fingerprint(DomainHint, []byte(strings.TrimSpace(text)))
}

// SideRequestRole returns the Role* constant of the first vocabulary
// SideRequests rule the request matches (for example the OpenCode title
// generator or compaction trailer), or "" for an ordinary request.
func SideRequestRole(input Input, vocab *Vocabulary) string {
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	request, err := parseRequest(input, vocab)
	if err != nil {
		return ""
	}
	firstSystem, lastUser := "", ""
	haveSystem := false
	for _, item := range request.items {
		switch {
		case item.Category == CategorySystem && item.Kind == "system" && !haveSystem:
			firstSystem, haveSystem = strings.TrimLeft(item.text, " \t\r\n"), true
		case item.Category == CategoryUser && item.Kind == "text":
			lastUser = item.text
		}
	}
	for _, rule := range vocab.SideRequests {
		for _, prefix := range rule.SystemPrefixes {
			if haveSystem && strings.HasPrefix(firstSystem, prefix) {
				return rule.Role
			}
		}
		for _, needle := range rule.LastUserContains {
			if lastUser != "" && strings.Contains(lastUser, needle) {
				return rule.Role
			}
		}
	}
	return ""
}
