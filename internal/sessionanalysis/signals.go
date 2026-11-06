package sessionanalysis

import (
	"bytes"
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

// SignalVersion is bumped whenever stored signals would change for the same
// evidence; rows of an older version are recomputed by the next batch.
const SignalVersion = 1

// activeGapNS merges request intervals into one active block (doc 23 6.1).
const activeGapNS = int64(180 * time.Second)

// Thresholds of a session that gets an input pack (doc 24 section 5.1).
type Thresholds struct {
	MinUserTurns     int
	MinActiveSeconds int
}

// Skip reasons recorded in session_signals.skip_reason.
const (
	SkipBelowThreshold = "below_threshold"
	SkipSingleTurnChat = "single_turn_chat"
	SkipNoContent      = "content_unavailable"
	SkipNoAgent        = "no_agent_identity"
)

// ComputeSignals derives the L0 signals and sentence fingerprints of one
// built session.
func ComputeSignals(session *Session, vocab *Vocabulary, fp Fingerprinter, thresholds Thresholds, now time.Time) (storage.SessionSignals, []storage.SessionTextFPR) {
	rows := session.Rows
	signals := storage.SessionSignals{
		SessionKey:    append([]byte(nil), session.Key...),
		Kind:          session.Kind,
		Client:        session.Client,
		FirstNS:       rows[0].StartedAtNS,
		SignalVersion: SignalVersion,
		ComputedAtNS:  now.UnixNano(),
		Verified:      "no_writes",
	}
	modelCounts := map[string]int{}
	var cost float64
	billed := false
	compactionRows, compactionFlags := int64(0), int64(0)
	for _, row := range rows {
		signals.Requests++
		switch {
		case isAuxiliary(row.AgentRole):
			signals.AuxRequests++
			if row.AgentRole == insights.RoleCompaction {
				compactionRows++
			}
		case row.AgentRole == insights.RoleSubagent:
			signals.SubRequests++
		default:
			signals.MainRequests++
			if row.Model != "" {
				modelCounts[row.Model]++
			}
		}
		if row.StartedAtNS > signals.LastNS || signals.LastAuditID == "" {
			signals.LastNS, signals.LastAuditID = row.StartedAtNS, row.AuditID
		}
		if signals.APIKeyFPR == nil && len(row.APIKeyFPR) != 0 {
			signals.APIKeyFPR = append([]byte(nil), row.APIKeyFPR...)
		}
		if signals.NewAPIUserID == nil && row.NewAPIUserID != nil {
			signals.NewAPIUserID = row.NewAPIUserID
		}
		if signals.NewAPITokenID == nil && row.NewAPITokenID != nil {
			signals.NewAPITokenID = row.NewAPITokenID
		}
		if signals.MainSessionID == "" && row.AgentRole != insights.RoleSubagent && !isAuxiliary(row.AgentRole) {
			signals.MainSessionID = row.AnalysisSessionID
		}
		signals.InputTokens += value(row.UncachedInput) + value(row.CacheRead) + value(row.CacheWrite)
		signals.CacheReadTokens += value(row.CacheRead)
		signals.OutputTokens += value(row.Output)
		if row.Quota != nil && row.QuotaPerUnit != nil && *row.QuotaPerUnit > 0 {
			cost += float64(*row.Quota) / *row.QuotaPerUnit
			billed = true
		}
		if row.EventFlags&insights.EventCompaction != 0 {
			compactionFlags++
		}
		if row.EventFlags&insights.EventModelSwitch != 0 {
			signals.ModelSwitches++
		}
		if row.StopReason == insights.StopLength {
			signals.LengthStops++
		}
		if (row.StatusCode != nil && *row.StatusCode >= 400) || row.ErrorType != "" || row.UpstreamErrorCls != "" {
			signals.UpstreamErrors++
		}
	}
	if billed {
		signals.CostUSD = &cost
	}
	signals.Compactions = compactionRows
	if signals.Compactions == 0 {
		signals.Compactions = compactionFlags
	}
	signals.MainModel = topModel(modelCounts)
	signals.ActiveNS = activeNS(rows)

	main := session.MainNode()
	for _, node := range session.Nodes {
		if node.Role == insights.RoleSubagent || node != main {
			signals.Subagents++
		}
		if int64(node.Depth) > signals.MaxDepth {
			signals.MaxDepth = int64(node.Depth)
		}
		signals.Interrupts += int64(node.Interrupt)
	}
	danger, secrets := map[string]int64{}, map[string]int64{}
	userTexts := make([]string, 0)
	if main != nil {
		signals.UserTurns = int64(len(main.Turns))
		for _, turn := range main.Turns {
			if turn.Correction {
				signals.Corrections++
			}
			if turn.ErrorPaste {
				signals.ErrorPastes++
			}
			vocab.secretMatches(turn.Text, secrets)
			userTexts = append(userTexts, turn.Text)
		}
	}
	for _, node := range session.Nodes {
		nodeSignals(node, vocab, fp, &signals, danger, secrets)
	}
	if main != nil {
		signals.Verified = verification(session, session.Main)
	}
	signals.DangerCounts = encodeCounts(danger)
	signals.SecretCounts = encodeCounts(secrets)
	signals.HeavyModel = vocab.heavyModel(signals.MainModel, signals.OutputTokens, signals.ToolCalls)

	switch {
	case len(session.Nodes) == 0:
		signals.SkipReason = SkipNoAgent
	case main == nil || !main.Loaded:
		signals.SkipReason = SkipNoContent
	case session.Kind == KindChat && signals.UserTurns == 1:
		signals.SkipReason = SkipSingleTurnChat
	case signals.UserTurns < int64(thresholds.MinUserTurns) || signals.ActiveNS < int64(thresholds.MinActiveSeconds)*int64(time.Second):
		signals.SkipReason = SkipBelowThreshold
	default:
		signals.Eligible = true
	}

	fprs := make([]storage.SessionTextFPR, 0)
	for _, tag := range sentenceFingerprints(fp, userTexts, maxUserFPRs) {
		fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceUser, FPR: tag, APIKeyFPR: signals.APIKeyFPR, SeenAtNS: signals.LastNS})
	}
	if main != nil {
		for _, tag := range sentenceFingerprints(fp, main.Rules, maxRuleFPRs) {
			fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceInjectedRules, FPR: tag, APIKeyFPR: signals.APIKeyFPR, SeenAtNS: signals.LastNS})
		}
	}
	return signals, fprs
}

func value(pointer *int64) int64 {
	if pointer == nil {
		return 0
	}
	return *pointer
}

func topModel(counts map[string]int) string {
	best, bestCount := "", 0
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if counts[name] > bestCount {
			best, bestCount = name, counts[name]
		}
	}
	return best
}

// activeNS sums request intervals merged across gaps of at most activeGapNS.
func activeNS(rows []storage.SessionAuditRow) int64 {
	type interval struct{ start, end int64 }
	intervals := make([]interval, 0, len(rows))
	for _, row := range rows {
		end := row.StartedAtNS
		if row.EndedAtNS != nil && *row.EndedAtNS > end {
			end = *row.EndedAtNS
		}
		intervals = append(intervals, interval{row.StartedAtNS, end})
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
	var total int64
	blockStart, blockEnd := intervals[0].start, intervals[0].end
	for _, current := range intervals[1:] {
		if current.start <= blockEnd+activeGapNS {
			if current.end > blockEnd {
				blockEnd = current.end
			}
			continue
		}
		total += blockEnd - blockStart
		blockStart, blockEnd = current.start, current.end
	}
	return total + blockEnd - blockStart
}

// nodeSignals adds one agent's tool-call signals.
func nodeSignals(node *Node, vocab *Vocabulary, fp Fingerprinter, signals *storage.SessionSignals, danger, secrets map[string]int64) {
	streak := int64(0)
	var previous []byte
	run := int64(0)
	closeRun := func() {
		if run >= int64(vocab.loopMinRepeats) {
			signals.Loops++
			if run > signals.MaxLoopLength {
				signals.MaxLoopLength = run
			}
		}
	}
	writes := map[string][]int{}
	for index := range node.Calls {
		call := &node.Calls[index]
		signals.ToolCalls++
		switch call.Status {
		case StatusFailed:
			signals.ToolFailures++
			streak++
			if streak > signals.MaxFailureStreak {
				signals.MaxFailureStreak = streak
			}
		case StatusOK:
			streak = 0
		default:
			signals.ToolUnknown++
		}
		if fp != nil {
			call.ArgFPR = fp.Fingerprint(domainToolCall, []byte(strings.ToLower(call.Name)+"\x00"+strings.TrimSpace(call.arguments)))
		}
		if previous != nil && bytes.Equal(previous, call.ArgFPR) {
			run++
		} else {
			closeRun()
			run = 1
		}
		previous = call.ArgFPR
		if call.Kind == "shell" && call.Command != "" {
			for _, category := range vocab.dangerCategories(call.Command) {
				danger[category]++
			}
		}
		if call.Result != "" {
			vocab.secretMatches(truncateRunes(call.Result, 65536), secrets)
		}
		if call.Kind == "write" {
			for _, path := range call.Paths {
				writes[path] = append(writes[path], index)
			}
		}
	}
	closeRun()
	for _, indexes := range writes {
		if int64(len(indexes)) > signals.MaxFileWrites {
			signals.MaxFileWrites = int64(len(indexes))
		}
		if len(indexes) < vocab.thrashMinWrites {
			continue
		}
		for between := indexes[0] + 1; between < indexes[len(indexes)-1]; between++ {
			if node.Calls[between].Status == StatusFailed {
				signals.ThrashFiles++
				break
			}
		}
	}
}

// verification reports whether a test, lint or build command ran after the
// last file write, walking spawned agents in place.
func verification(session *Session, root int) string {
	sequence := flatten(session, root, 0)
	lastWrite := -1
	for index, call := range sequence {
		if call.Kind == "write" {
			lastWrite = index
		}
	}
	if lastWrite < 0 {
		return "no_writes"
	}
	for _, call := range sequence[lastWrite+1:] {
		if call.Kind == "shell" && (call.Class == "test" || call.Class == "lint" || call.Class == "build") {
			return "yes"
		}
	}
	return "no"
}

func flatten(session *Session, index, depth int) []*ToolCall {
	node := session.Nodes[index]
	out := make([]*ToolCall, 0, len(node.Calls))
	for callIndex := range node.Calls {
		call := &node.Calls[callIndex]
		if call.Child >= 0 && depth < maxNodeDepth {
			out = append(out, flatten(session, call.Child, depth+1)...)
		}
		out = append(out, call)
	}
	return out
}

func (vocab *Vocabulary) heavyModel(model string, output, toolCalls int64) bool {
	model = strings.ToLower(model)
	if model == "" {
		return false
	}
	for _, heavy := range vocab.heavyModels {
		if strings.Contains(model, heavy) {
			return output < vocab.heavyMaxOutput && toolCalls < vocab.heavyMaxTools
		}
	}
	return false
}
