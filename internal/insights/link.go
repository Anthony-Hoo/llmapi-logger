package insights

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// Linking places one analysed audit into its session and agent tree
// (doc/features/20-context-insights.md sections 3.3, 5.4 and 5.8). It reads
// earlier analysis rows but never writes them: a parent that arrives late is
// joined by fingerprint at query time.

const (
	// Session ids carry this many hex digits of their fingerprint.
	sessionIDHexDigits = 24
	agentSessionPrefix = "agt_"
	keySessionPrefix   = "ses_"

	// inferredPrevCandidates bounds the prefix comparison for explicit and
	// inferred sessions, which may interleave parallel conversations.
	inferredPrevCandidates = 8

	// Compaction: the context shrank by at least 30% from at least 8k tokens.
	compactionMinPrevEstimate = 8000
	compactionKeepPercent     = 70

	// Content matching only looks this far back for the parent's spawn call.
	contentMatchWindowNS = int64(24 * 60 * 60 * 1e9)
	// A content link is inferred; a match on a prefix-stripped opener is less
	// certain than one on the opener as sent.
	contentLinkConfidence         = 70
	contentLinkStrippedConfidence = 60
)

// LinkStore is the narrow read surface of the linker, implemented by
// *sqlite.Store.
type LinkStore interface {
	LatestAgentRootFPR(ctx context.Context, nodeFPR []byte, excludeAuditID string) ([]byte, error)
	HasEarlierAnalysisStep(ctx context.Context, sessionID string, startedAtNS int64, auditID string) (bool, error)
	ListAnalysisPrevCandidates(ctx context.Context, sessionID string, startedAtNS int64, auditID string, limit int) ([]sqlite.AnalysisLinkCandidate, error)
	MatchSpawnHints(ctx context.Context, hintFPRs [][]byte, apiKeyFPR []byte, fromNS, toNS int64, excludeAuditID string) ([]sqlite.SpawnHintMatch, error)
}

// DetailCodec seals a Detail for storage and opens earlier rows' details.
// Open receives the stored row's analysis_version because it is part of the
// AAD.
type DetailCodec interface {
	SealDetail(auditID string, detail Detail) ([]byte, error)
	OpenDetail(auditID string, version int, sealed []byte) (Detail, error)
}

// CipherDetailCodec encrypts Detail JSON with the audit cipher under AAD
// (audit_id, "analysis_detail", analysis_version).
type CipherDetailCodec struct {
	Cipher security.Cipher
}

func detailAAD(auditID string, version int) ([]byte, error) {
	return security.AAD(auditID, "analysis_detail", strconv.Itoa(version))
}

// SealDetail encrypts detail for the current AnalysisVersion. The plaintext
// JSON is cleared before returning.
func (codec CipherDetailCodec) SealDetail(auditID string, detail Detail) ([]byte, error) {
	if codec.Cipher == nil {
		return nil, errors.New("insights: nil detail cipher")
	}
	aad, err := detailAAD(auditID, AnalysisVersion)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(detail)
	if err != nil {
		return nil, fmt.Errorf("insights: encode detail: %w", err)
	}
	defer clear(plaintext)
	return codec.Cipher.Encrypt(aad, plaintext)
}

// OpenDetail decrypts and decodes one stored detail blob.
func (codec CipherDetailCodec) OpenDetail(auditID string, version int, sealed []byte) (Detail, error) {
	if codec.Cipher == nil {
		return Detail{}, errors.New("insights: nil detail cipher")
	}
	if len(sealed) == 0 {
		return Detail{}, errors.New("insights: empty detail")
	}
	aad, err := detailAAD(auditID, version)
	if err != nil {
		return Detail{}, err
	}
	plaintext, err := codec.Cipher.Decrypt(aad, sealed)
	if err != nil {
		return Detail{}, fmt.Errorf("insights: decrypt detail: %w", err)
	}
	defer clear(plaintext)
	var detail Detail
	if err := json.Unmarshal(plaintext, &detail); err != nil {
		return Detail{}, fmt.Errorf("insights: decode detail: %w", err)
	}
	return detail, nil
}

// Linker turns an Analysis and AgentIdentity into the stored row.
type Linker struct {
	store LinkStore
	fp    Fingerprinter
	codec DetailCodec
	vocab *Vocabulary
}

// NewLinker validates its collaborators. A nil vocab means the built-in one.
func NewLinker(store LinkStore, fp Fingerprinter, codec DetailCodec, vocab *Vocabulary) (*Linker, error) {
	if store == nil || fp == nil || codec == nil {
		return nil, errors.New("insights: linker needs a store, fingerprinter and detail codec")
	}
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	return &Linker{store: store, fp: fp, codec: codec, vocab: vocab}, nil
}

// LinkInput is everything the linker needs about one audit.
type LinkInput struct {
	Meta         sqlite.AnalysisAuditMeta
	Protocol     string
	Analysis     Analysis
	Identity     AgentIdentity
	SpawnPrompts []string      // SpawnPrompts of this response
	OpeningHints []OpeningHint // OpeningUserHints of this request
	AnalyzedAtNS int64
}

// Link resolves the session, previous step, events and agent tree position of
// one audit and returns the row to save, with Detail sealed.
//
// Rules, in order:
//
//  1. Node, parent and root tags come from the identity's raw ids
//     (AgentFPR over client ‖ 0x00 ‖ id).
//  2. analysis_session_id: a client node id gives "agt_"+24 hex of the node
//     tag (link agent); else the OpenAI turn conversation (link
//     conversation); else HMAC(insights/session, api_key_fpr ‖ SessionKeyFPR)
//     gives "ses_"+24 hex (link explicit or inferred); else none.
//  3. A row without a client node but with a session gets the synthetic node
//     SyntheticAgentFPR(analysis_session_id), so every agent is addressable
//     by agent_node_fpr.
//  4. prev_audit_id is the latest earlier main/subagent step of the session;
//     explicit and inferred sessions pick, among the last eight, the one with
//     the longest common item prefix.
//  5. A synthetic node without its own parent inherits a content link from
//     its previous step; otherwise the first step of such a session may be
//     content matched to a unique parent spawn call.
//  6. agent_root_fpr: the explicit root header; else the parent's stored root;
//     else the parent tag; else the node tag.
func (linker *Linker) Link(ctx context.Context, in LinkInput) (sqlite.AnalysisRow, error) {
	if linker == nil {
		return sqlite.AnalysisRow{}, errors.New("insights: nil linker")
	}
	analysis, identity, meta := in.Analysis, in.Identity, in.Meta
	if meta.AuditID == "" {
		return sqlite.AnalysisRow{}, errors.New("insights: link input without audit id")
	}
	client := firstNonEmpty(identity.Client, ClientUnknown)
	identity.Client = client

	var nodeFPR, parentFPR, explicitRoot []byte
	if identity.NodeID != "" {
		nodeFPR = AgentFPR(linker.fp, client, identity.NodeID)
	}
	if identity.ParentID != "" {
		parentFPR = AgentFPR(linker.fp, client, identity.ParentID)
	}
	if identity.RootID != "" {
		explicitRoot = AgentFPR(linker.fp, client, identity.RootID)
	}

	var sessionID, sessionLink string
	switch {
	case nodeFPR != nil:
		sessionID, sessionLink = agentSessionPrefix+hex.EncodeToString(nodeFPR)[:sessionIDHexDigits], SessionLinkAgent
	case meta.ConversationID != nil && *meta.ConversationID != "":
		sessionID, sessionLink = *meta.ConversationID, SessionLinkConversation
	case len(analysis.SessionKeyFPR) != 0:
		key := append(append([]byte(nil), meta.APIKeyFPR...), analysis.SessionKeyFPR...)
		tag := linker.fp.Fingerprint(DomainSession, key)
		sessionID, sessionLink = keySessionPrefix+hex.EncodeToString(tag)[:sessionIDHexDigits], analysis.SessionKeySource
	}
	if nodeFPR == nil && sessionID != "" {
		nodeFPR = SyntheticAgentFPR(linker.fp, sessionID)
	}

	first := true
	var prev *sqlite.AnalysisLinkCandidate
	var prevDetail *Detail
	if sessionID != "" {
		earlier, err := linker.store.HasEarlierAnalysisStep(ctx, sessionID, meta.StartedAtNS, meta.AuditID)
		if err != nil {
			return sqlite.AnalysisRow{}, err
		}
		first = !earlier
		if earlier {
			prev, prevDetail, err = linker.choosePrev(ctx, sessionID, sessionLink, meta, analysis.Detail.ItemFPRs)
			if err != nil {
				return sqlite.AnalysisRow{}, err
			}
		}
	}

	row := sqlite.AnalysisRow{
		AuditID:         meta.AuditID,
		AnalysisVersion: analysis.Version,
		AnalyzedAtNS:    in.AnalyzedAtNS,
		Protocol:        in.Protocol,
		Model:           optionalText(analysis.Model),
		StartedAtNS:     meta.StartedAtNS,
		UncachedInput:   analysis.Usage.UncachedInput,
		CacheRead:       analysis.Usage.CacheRead,
		CacheWrite:      analysis.Usage.CacheWrite,
		Output:          analysis.Usage.Output,
		Reasoning:       analysis.Usage.Reasoning,
		MaxOutputTokens: analysis.MaxOutputTokens,
		EstSystem:       analysis.Estimate.System,
		EstTools:        analysis.Estimate.Tools,
		EstUser:         analysis.Estimate.User,
		EstInjected:     analysis.Estimate.Injected,
		EstAssistant:    analysis.Estimate.Assistant,
		EstReasoning:    analysis.Estimate.Reasoning,
		EstToolResult:   analysis.Estimate.ToolResult,
		EstMedia:        analysis.Estimate.Media,
		Items:           analysis.Counts.Items,
		ToolDefs:        analysis.Counts.ToolDefs,
		ToolResults:     analysis.Counts.ToolResults,
		Media:           analysis.Counts.Media,
		StopReason:      optionalText(analysis.StopReason),
		RespKinds:       analysis.ResponseKinds,
		RespToolCalls:   analysis.ResponseToolCalls,
		TurnStart:       analysis.TurnStart,
		SystemFPR:       analysis.SystemFPR,
		ToolsFPR:        analysis.ToolsFPR,
		FirstEventNS:    analysis.FirstEventNS,
		GenerationNS:    analysis.GenerationNS,
	}
	if row.AnalysisVersion == 0 {
		row.AnalysisVersion = AnalysisVersion
	}
	if counts, err := toolKindCountsJSON(analysis.ToolKindCounts); err == nil {
		row.ToolKindCounts = counts
	}
	if sessionID != "" {
		row.AnalysisSessionID, row.SessionLink = optionalText(sessionID), optionalText(sessionLink)
	}
	if prev != nil {
		row.PrevAuditID = optionalText(prev.AuditID)
		row.EventFlags, row.AppendedItems, row.RemovedItems = diffEvents(analysis, prev, prevDetail)
	}

	// Content links: inherit from the previous step of the same session, or
	// match the first step against a parent's spawn call. Steps of a session
	// share one node, so a link found on the first step holds for the rest.
	var contentRoot []byte
	contentLinked := false
	if identity.ParentID == "" && prev != nil && prev.AgentLinkSource != nil &&
		*prev.AgentLinkSource == LinkContent && len(prev.AgentParentFPR) != 0 {
		parentFPR, contentRoot, contentLinked = prev.AgentParentFPR, prev.AgentRootFPR, true
		identity.LinkSource = LinkContent
		identity.Confidence = contentLinkConfidence
		if prev.AgentLinkConfidence != nil {
			identity.Confidence = *prev.AgentLinkConfidence
		}
	} else if identity.ParentID == "" && first && !auxiliaryRole(identity.Role) && linker.contentMatchApplies(identity) {
		match, confidence, err := linker.matchParent(ctx, meta, in.OpeningHints)
		if err != nil {
			return sqlite.AnalysisRow{}, err
		}
		if match != nil {
			parentFPR = match.AgentNodeFPR
			if len(parentFPR) == 0 && match.AnalysisSessionID != nil {
				parentFPR = SyntheticAgentFPR(linker.fp, *match.AnalysisSessionID)
			}
			if len(parentFPR) != 0 && !bytes.Equal(parentFPR, nodeFPR) {
				contentRoot, contentLinked = match.AgentRootFPR, true
				identity.LinkSource, identity.Confidence = LinkContent, confidence
			} else {
				parentFPR = nil
			}
		}
	}
	if contentLinked && identity.Role == RoleMain {
		identity.Role = RoleSubagent
	}

	rootFPR := explicitRoot
	switch {
	case rootFPR != nil:
	case contentLinked:
		rootFPR = contentRoot
		if len(rootFPR) == 0 {
			rootFPR = parentFPR
		}
	case parentFPR != nil:
		stored, err := linker.store.LatestAgentRootFPR(ctx, parentFPR, meta.AuditID)
		if err != nil {
			return sqlite.AnalysisRow{}, err
		}
		rootFPR = parentFPR
		if len(stored) != 0 {
			rootFPR = stored
		}
	default:
		rootFPR = nodeFPR
	}

	row.AgentClient = optionalText(client)
	row.AgentRole = optionalText(firstNonEmpty(identity.Role, RoleMain))
	row.AgentNodeFPR, row.AgentParentFPR, row.AgentRootFPR = nodeFPR, parentFPR, rootFPR
	row.AgentLinkSource = optionalText(identity.LinkSource)
	if identity.LinkSource != "" {
		confidence := identity.Confidence
		row.AgentLinkConfidence = &confidence
	}
	for _, prompt := range in.SpawnPrompts {
		row.SpawnHints = append(row.SpawnHints, HintFPR(linker.fp, prompt))
	}

	detail := analysis.Detail
	detail.Agent = identity
	sealed, err := linker.codec.SealDetail(meta.AuditID, detail)
	if err != nil {
		return sqlite.AnalysisRow{}, err
	}
	row.DetailEnc = sealed
	return row, nil
}

// choosePrev picks the previous step and opens its detail once. A detail that
// cannot be opened leaves only the fingerprint-level events computable.
func (linker *Linker) choosePrev(ctx context.Context, sessionID, sessionLink string, meta sqlite.AnalysisAuditMeta, itemFPRs []string) (*sqlite.AnalysisLinkCandidate, *Detail, error) {
	limit := 1
	if sessionLink == SessionLinkExplicit || sessionLink == SessionLinkInferred {
		limit = inferredPrevCandidates
	}
	candidates, err := linker.store.ListAnalysisPrevCandidates(ctx, sessionID, meta.StartedAtNS, meta.AuditID, limit)
	if err != nil || len(candidates) == 0 {
		return nil, nil, err
	}
	if limit == 1 {
		chosen := candidates[0]
		if detail, err := linker.codec.OpenDetail(chosen.AuditID, chosen.AnalysisVersion, chosen.DetailEnc); err == nil {
			return &chosen, &detail, nil
		}
		return &chosen, nil, nil
	}
	// Candidates arrive newest first, so a strict improvement is required to
	// prefer an older one.
	best, bestPrefix := -1, -1
	var bestDetail *Detail
	for index := range candidates {
		detail, err := linker.codec.OpenDetail(candidates[index].AuditID, candidates[index].AnalysisVersion, candidates[index].DetailEnc)
		if err != nil {
			continue
		}
		if prefix := commonPrefix(itemFPRs, detail.ItemFPRs); prefix > bestPrefix {
			best, bestPrefix, bestDetail = index, prefix, &detail
		}
	}
	if best < 0 {
		return &candidates[0], nil, nil
	}
	return &candidates[best], bestDetail, nil
}

// diffEvents compares this step with its previous step (doc section 5.4).
func diffEvents(analysis Analysis, prev *sqlite.AnalysisLinkCandidate, prevDetail *Detail) (int, *int, *int) {
	flags := 0
	if prev.Model != nil && *prev.Model != "" && analysis.Model != "" && *prev.Model != analysis.Model {
		flags |= EventModelSwitch
	}
	if prev.SystemFPR != nil && analysis.SystemFPR != nil && !bytes.Equal(prev.SystemFPR, analysis.SystemFPR) {
		flags |= EventSystemChanged
	}
	if prev.ToolsFPR != nil && analysis.ToolsFPR != nil && !bytes.Equal(prev.ToolsFPR, analysis.ToolsFPR) {
		flags |= EventToolsChanged
	}
	if prevDetail == nil {
		return flags, nil, nil
	}
	current := analysis.Detail
	prefix := commonPrefix(current.ItemFPRs, prevDetail.ItemFPRs)
	appended := len(current.ItemFPRs) - prefix
	removed := len(prevDetail.ItemFPRs) - prefix

	estimate := analysis.Estimate.Sum()
	compaction := removed > 0 && prev.EstimateTotal >= compactionMinPrevEstimate &&
		estimate*100 <= prev.EstimateTotal*compactionKeepPercent
	if compaction {
		flags |= EventCompaction
	} else if removed > 0 {
		// Items, unlike ItemFPRs, may be capped; only compare indexes both
		// sides still describe.
		for index := prefix; index < len(prevDetail.ItemFPRs); index++ {
			if index >= len(prevDetail.Items) || index >= len(current.Items) {
				break
			}
			if prevDetail.Items[index].Category == CategoryToolResult && current.Items[index].Tokens < prevDetail.Items[index].Tokens {
				flags |= EventPrune
				break
			}
		}
	}
	for index := prefix; index < len(current.ItemFPRs) && index < len(current.Items); index++ {
		if current.Items[index].Category == CategoryInjected {
			flags |= EventInjected
			break
		}
	}
	return flags, &appended, &removed
}

func commonPrefix(left, right []string) int {
	count := 0
	for count < len(left) && count < len(right) && left[count] == right[count] {
		count++
	}
	return count
}

// contentMatchApplies reports whether the request has no way of naming its
// parent itself: an unknown client, no node id, or a client without any
// parent mechanism.
func (linker *Linker) contentMatchApplies(identity AgentIdentity) bool {
	if identity.Client == ClientUnknown || identity.NodeID == "" {
		return true
	}
	rule, ok := linker.vocab.Clients[identity.Client]
	if !ok {
		return true
	}
	return len(rule.ParentHeaders) == 0 && len(rule.ParentBodyPaths) == 0 && rule.ParentFallback != "root"
}

// matchParent looks up spawn hints of the same api key within the window
// before this request. Only exactly one distinct parent audit links.
func (linker *Linker) matchParent(ctx context.Context, meta sqlite.AnalysisAuditMeta, hints []OpeningHint) (*sqlite.SpawnHintMatch, int, error) {
	if len(meta.APIKeyFPR) == 0 || len(hints) == 0 {
		return nil, 0, nil
	}
	stripped := map[string]bool{}
	fprs := make([][]byte, 0, len(hints))
	for _, hint := range hints {
		if hint.Text == "" {
			continue
		}
		tag := HintFPR(linker.fp, hint.Text)
		key := string(tag)
		if previous, seen := stripped[key]; seen {
			// The same text as sent and as stripped counts as sent.
			stripped[key] = previous && hint.Stripped
			continue
		}
		stripped[key] = hint.Stripped
		fprs = append(fprs, tag)
	}
	if len(fprs) == 0 {
		return nil, 0, nil
	}
	matches, err := linker.store.MatchSpawnHints(ctx, fprs, meta.APIKeyFPR, meta.StartedAtNS-contentMatchWindowNS, meta.StartedAtNS, meta.AuditID)
	if err != nil || len(matches) == 0 {
		return nil, 0, err
	}
	var chosen *sqlite.SpawnHintMatch
	viaOriginal := false
	for index := range matches {
		match := &matches[index]
		if chosen != nil && chosen.AuditID != match.AuditID {
			return nil, 0, nil
		}
		chosen = match
		if !stripped[string(match.HintFPR)] {
			viaOriginal = true
		}
	}
	if viaOriginal {
		return chosen, contentLinkConfidence, nil
	}
	return chosen, contentLinkStrippedConfidence, nil
}

func toolKindCountsJSON(counts map[string]int) (string, error) {
	if len(counts) == 0 {
		return "{}", nil
	}
	encoded, err := json.Marshal(counts)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func optionalText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
