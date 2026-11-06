package sessionanalysis

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"unicode"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/storage"
)

// ConversationLoader returns the decrypted conversation of one audit: the
// verified turn graph for OpenAI records, the encrypted parser conversation
// otherwise.
type ConversationLoader interface {
	SessionConversation(ctx context.Context, auditID string) (*conversation.Conversation, error)
}

// Limits on how much content one session may load.
const (
	maxNodesLoaded      = 40
	maxSnapshotsPerNode = 6
	maxSnapshotFallback = 2
	maxNodeDepth        = 10
)

// Session is one analysed agent-tree root.
type Session struct {
	Key        []byte
	Rows       []storage.SessionAuditRow
	Nodes      []*Node
	Main       int
	Kind       string
	Client     string
	Truncated  bool
	LoadFailed int
	Unloaded   int
}

// Session kinds.
const (
	KindAgent = "agent"
	KindChat  = "chat"
)

// isAuxiliary reports whether a request is a compaction, title, review or
// other side request rather than agent work.
func isAuxiliary(role string) bool {
	switch role {
	case insights.RoleCompaction, insights.RoleTitle, insights.RoleReview, insights.RoleAuxiliary:
		return true
	}
	return false
}

// BuildSession groups the session's requests by agent, loads the minimum
// set of conversation snapshots per agent and extracts user turns and tool
// calls. A nil loader builds the request structure only.
func BuildSession(ctx context.Context, key []byte, rows []storage.SessionAuditRow, truncated bool, loader ConversationLoader, vocab *Vocabulary, insightsVocab *insights.Vocabulary) (*Session, error) {
	if len(rows) == 0 {
		return nil, errors.New("sessionanalysis: empty session")
	}
	session := &Session{Key: key, Rows: rows, Truncated: truncated, Main: -1}
	byKey := map[string]int{}
	nodeRows := map[int][]storage.SessionAuditRow{}
	for _, row := range rows {
		if isAuxiliary(row.AgentRole) || len(row.AgentNodeFPR) == 0 {
			continue
		}
		nodeKey := hex.EncodeToString(row.AgentNodeFPR)
		index, ok := byKey[nodeKey]
		if !ok {
			index = len(session.Nodes)
			byKey[nodeKey] = index
			session.Nodes = append(session.Nodes, &Node{Key: nodeKey, Role: insights.RoleMain, Parent: -1, FirstNS: row.StartedAtNS})
		}
		node := session.Nodes[index]
		if row.AgentRole == insights.RoleSubagent {
			node.Role = insights.RoleSubagent
		}
		if node.ParentKey == "" && len(row.AgentParentFPR) != 0 {
			node.ParentKey = hex.EncodeToString(row.AgentParentFPR)
		}
		nodeRows[index] = append(nodeRows[index], row)
	}
	session.Client = sessionClient(rows)
	if len(session.Nodes) == 0 {
		session.Kind = KindChat
		return session, nil
	}
	session.linkNodes(byKey, nodeRows)
	if loader != nil {
		order := session.loadOrder()
		for position, index := range order {
			if position >= maxNodesLoaded {
				session.Unloaded++
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			session.loadNode(ctx, index, nodeRows[index], loader, vocab, insightsVocab)
		}
		session.assignChildren()
	}
	session.Kind = KindChat
	if session.Client != "" && session.Client != "unknown" {
		session.Kind = KindAgent
	}
	for _, node := range session.Nodes {
		if len(node.Calls) != 0 || node.Role == insights.RoleSubagent {
			session.Kind = KindAgent
		}
	}
	return session, nil
}

func sessionClient(rows []storage.SessionAuditRow) string {
	counts := map[string]int{}
	best, bestCount := "", 0
	for _, row := range rows {
		if row.AgentClient == "" {
			continue
		}
		counts[row.AgentClient]++
		if counts[row.AgentClient] > bestCount {
			best, bestCount = row.AgentClient, counts[row.AgentClient]
		}
	}
	return best
}

// linkNodes picks the main agent and computes parents and depths.
func (session *Session) linkNodes(byKey map[string]int, nodeRows map[int][]storage.SessionAuditRow) {
	best, bestRows := -1, -1
	for index, node := range session.Nodes {
		if parent, ok := byKey[node.ParentKey]; ok && parent != index {
			node.Parent = parent
			continue
		}
		if node.Role == insights.RoleMain && len(nodeRows[index]) > bestRows {
			best, bestRows = index, len(nodeRows[index])
		}
	}
	if best < 0 {
		best = 0
		for index, node := range session.Nodes {
			if node.FirstNS < session.Nodes[best].FirstNS {
				best = index
			}
		}
		session.Nodes[best].Parent = -1
	}
	session.Main = best
	for index, node := range session.Nodes {
		if index != best && node.Parent < 0 {
			node.Parent = best // an orphan agent hangs under the main agent
		}
	}
	for _, node := range session.Nodes {
		depth, cursor := 0, node
		for cursor.Parent >= 0 && depth < maxNodeDepth {
			depth++
			cursor = session.Nodes[cursor.Parent]
		}
		node.Depth = depth
	}
}

// loadOrder lists node indexes main first, then by first request.
func (session *Session) loadOrder() []int {
	order := make([]int, 0, len(session.Nodes))
	for index := range session.Nodes {
		order = append(order, index)
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i] == session.Main || order[j] == session.Main {
			return order[i] == session.Main
		}
		return session.Nodes[order[i]].FirstNS < session.Nodes[order[j]].FirstNS
	})
	return order
}

// snapshotIndexes returns the rows whose request holds a complete history:
// the request just before each detected compaction and the last request.
func snapshotIndexes(rows []storage.SessionAuditRow) []int {
	indexes := make([]int, 0, 2)
	for index := 0; index+1 < len(rows); index++ {
		if rows[index+1].EventFlags&insights.EventCompaction != 0 {
			indexes = append(indexes, index)
		}
	}
	indexes = append(indexes, len(rows)-1)
	if len(indexes) > maxSnapshotsPerNode {
		indexes = indexes[len(indexes)-maxSnapshotsPerNode:]
	}
	return indexes
}

func (session *Session) loadNode(ctx context.Context, index int, rows []storage.SessionAuditRow, loader ConversationLoader, vocab *Vocabulary, insightsVocab *insights.Vocabulary) {
	node := session.Nodes[index]
	snapshots := snapshotIndexes(rows)
	segments := make([]segment, 0, len(snapshots))
	for position, snapshot := range snapshots {
		last := position == len(snapshots)-1
		var loaded *conversation.Conversation
		auditID := ""
		for attempt := 0; attempt <= maxSnapshotFallback && snapshot-attempt >= 0; attempt++ {
			candidate := rows[snapshot-attempt]
			view, err := loader.SessionConversation(ctx, candidate.AuditID)
			if err == nil && view != nil {
				loaded, auditID = view, candidate.AuditID
				break
			}
		}
		if loaded == nil {
			session.LoadFailed++
			continue
		}
		seg := extractSegment(loaded, vocab, insightsVocab, last)
		if last {
			node.FinalID = auditID
		}
		segments = append(segments, seg)
	}
	if len(segments) == 0 {
		return
	}
	node.Loaded = true
	mergeSegments(node, segments)
	for callIndex := range node.Calls {
		classifyCall(&node.Calls[callIndex], vocab, insightsVocab)
	}
	turnAudits := make([]storage.SessionAuditRow, 0)
	for _, row := range rows {
		if row.TurnStart {
			turnAudits = append(turnAudits, row)
		}
	}
	for turnIndex := range node.Turns {
		row := rows[len(rows)-1]
		if len(turnAudits) != 0 {
			position := turnIndex
			if position >= len(turnAudits) {
				position = len(turnAudits) - 1
			}
			row = turnAudits[position]
		}
		node.Turns[turnIndex].AuditID = row.AuditID
		node.Turns[turnIndex].StartedNS = row.StartedAtNS
	}
	if node.Role == insights.RoleSubagent || index != session.Main && node.Parent >= 0 {
		if len(node.Turns) != 0 {
			node.Task = stripPrefixes(node.Turns[0].Text, insightsVocab)
			node.TaskAudit = node.Turns[0].AuditID
		}
		node.Turns = nil // a parent agent's follow-ups are not user input
		for callIndex := range node.Calls {
			node.Calls[callIndex].Turn = -1
		}
		return
	}
	for turnIndex := range node.Turns {
		turn := &node.Turns[turnIndex]
		turn.Correction = turnIndex > 0 && vocab.isCorrection(turn.Text)
		turn.ErrorPaste = vocab.isErrorPaste(turn.Text)
	}
}

func stripPrefixes(text string, insightsVocab *insights.Vocabulary) string {
	if insightsVocab == nil {
		return text
	}
	for _, prefix := range insightsVocab.SubagentPrefixes {
		text = strings.TrimPrefix(text, prefix)
	}
	return strings.TrimSpace(text)
}

// mergeSegments joins the snapshots of one agent. Later snapshots repeat the
// user turns a compaction kept and, when compaction was misdetected, the whole
// history: user turns are consumed against earlier ones and tool calls are
// deduplicated by call id.
func mergeSegments(node *Node, segments []segment) {
	firstIndex := map[string][]int{}
	seenCalls := map[string]bool{}
	for position, seg := range segments {
		if position == 0 {
			node.Rules = seg.rules
		}
		if seg.interrupts > node.Interrupt {
			node.Interrupt = seg.interrupts
		}
		mapped := make([]int, len(seg.turns))
		consumed := map[string]int{}
		for turnIndex, turn := range seg.turns {
			key := normalizeSentence(turn.Text)
			if prior := firstIndex[key]; consumed[key] < len(prior) {
				mapped[turnIndex] = prior[consumed[key]]
				consumed[key]++
				continue
			}
			mapped[turnIndex] = len(node.Turns)
			firstIndex[key] = append(firstIndex[key], len(node.Turns))
			consumed[key]++
			node.Turns = append(node.Turns, turn)
		}
		for _, call := range seg.calls {
			if call.ID != "" {
				if seenCalls[call.ID] {
					continue
				}
				seenCalls[call.ID] = true
			}
			if call.Turn >= 0 && call.Turn < len(mapped) {
				call.Turn = mapped[call.Turn]
			} else if call.Turn >= 0 {
				call.Turn = len(node.Turns) - 1
			}
			node.Calls = append(node.Calls, call)
		}
		if seg.final != "" {
			node.Final = seg.final
		}
	}
}

// assignChildren pairs each agent's spawn calls with its child agents in
// start order.
func (session *Session) assignChildren() {
	for index, node := range session.Nodes {
		if node.Parent >= 0 {
			session.Nodes[node.Parent].Children = append(session.Nodes[node.Parent].Children, index)
		}
	}
	for _, node := range session.Nodes {
		sort.SliceStable(node.Children, func(i, j int) bool {
			return session.Nodes[node.Children[i]].FirstNS < session.Nodes[node.Children[j]].FirstNS
		})
		next := 0
		for callIndex := range node.Calls {
			if node.Calls[callIndex].Kind == "spawn" && next < len(node.Children) {
				node.Calls[callIndex].Child = node.Children[next]
				next++
			}
		}
	}
}

// isCorrection applies the correction vocabulary to one user turn.
func (vocab *Vocabulary) isCorrection(text string) bool {
	trimmed := strings.ToLower(strings.TrimLeftFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || (unicode.IsPunct(r) && r != '[')
	}))
	if hasAnyPrefix(trimmed, vocab.correctionPrefix) {
		return true
	}
	return containsAny(truncateRunes(trimmed, 30), vocab.correctionPhrases)
}

// isErrorPaste reports a user turn that carries error output or a stack trace
// of at least three lines.
func (vocab *Vocabulary) isErrorPaste(text string) bool {
	if strings.Count(text, "\n") < 2 {
		return false
	}
	for _, pattern := range vocab.errors {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// MainNode returns the main agent, or nil for a session without agents.
func (session *Session) MainNode() *Node {
	if session.Main < 0 || session.Main >= len(session.Nodes) {
		return nil
	}
	return session.Nodes[session.Main]
}
