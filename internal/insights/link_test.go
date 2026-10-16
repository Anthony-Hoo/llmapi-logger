package insights

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"llmapi-logger/internal/storage/sqlite"
)

// fakeLinkRow is one stored analysis row with the api key of its audit.
type fakeLinkRow struct {
	candidate sqlite.AnalysisLinkCandidate
	session   string
	apiKey    []byte
	detail    Detail
}

type fakeSpawnHint struct {
	auditID string
	hint    []byte
	node    []byte
	root    []byte
	session string
	apiKey  []byte
}

// fakeLinkStore mirrors the same-api-key contract of the sqlite reader: NULL
// (nil) only matches NULL.
type fakeLinkStore struct {
	rows  []fakeLinkRow
	hints []fakeSpawnHint
}

func (store *fakeLinkStore) LatestAgentRootFPR(_ context.Context, nodeFPR, apiKeyFPR []byte, excludeAuditID string) ([]byte, error) {
	var best *fakeLinkRow
	for index := range store.rows {
		row := &store.rows[index]
		if !bytes.Equal(row.candidate.AgentNodeFPR, nodeFPR) || row.candidate.AuditID == excludeAuditID || !sameKey(row.apiKey, apiKeyFPR) {
			continue
		}
		if best == nil || row.candidate.StartedAtNS > best.candidate.StartedAtNS {
			best = row
		}
	}
	if best == nil {
		return nil, nil
	}
	return best.candidate.AgentRootFPR, nil
}

func (store *fakeLinkStore) HasEarlierAnalysisStep(_ context.Context, sessionID string, apiKeyFPR []byte, startedAtNS int64, auditID string) (bool, error) {
	for _, row := range store.rows {
		if row.session == sessionID && sameKey(row.apiKey, apiKeyFPR) && row.candidate.StartedAtNS < startedAtNS {
			return true, nil
		}
	}
	return false, nil
}

func (store *fakeLinkStore) ListAnalysisPrevCandidates(_ context.Context, sessionID string, apiKeyFPR []byte, startedAtNS int64, auditID string, limit int) ([]sqlite.AnalysisLinkCandidate, error) {
	var found []sqlite.AnalysisLinkCandidate
	for index := len(store.rows) - 1; index >= 0; index-- {
		row := store.rows[index]
		if row.session == sessionID && sameKey(row.apiKey, apiKeyFPR) && row.candidate.StartedAtNS < startedAtNS && len(found) < limit {
			found = append(found, row.candidate)
		}
	}
	return found, nil
}

func (store *fakeLinkStore) MatchSpawnHints(_ context.Context, hintFPRs [][]byte, apiKeyFPR []byte, fromNS, toNS int64, excludeAuditID string) ([]sqlite.SpawnHintMatch, error) {
	var matches []sqlite.SpawnHintMatch
	if len(apiKeyFPR) == 0 {
		return matches, nil
	}
	for _, hint := range store.hints {
		if hint.auditID == excludeAuditID || !bytes.Equal(hint.apiKey, apiKeyFPR) {
			continue
		}
		for _, want := range hintFPRs {
			if bytes.Equal(want, hint.hint) {
				session := hint.session
				matches = append(matches, sqlite.SpawnHintMatch{
					AuditID: hint.auditID, HintFPR: hint.hint, AgentNodeFPR: hint.node,
					AgentRootFPR: hint.root, AnalysisSessionID: &session,
				})
			}
		}
	}
	return matches, nil
}

func sameKey(left, right []byte) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == 0 && len(right) == 0
	}
	return bytes.Equal(left, right)
}

// fakeDetailCodec stores details by audit id instead of encrypting them.
type fakeDetailCodec struct {
	store *fakeLinkStore
}

func (codec fakeDetailCodec) SealDetail(string, Detail) ([]byte, error) { return []byte("sealed"), nil }

func (codec fakeDetailCodec) OpenDetail(auditID string, _ int, _ []byte) (Detail, error) {
	for _, row := range codec.store.rows {
		if row.candidate.AuditID == auditID {
			return row.detail, nil
		}
	}
	return Detail{}, errors.New("unknown detail")
}

func newTestLinker(t *testing.T, store *fakeLinkStore, vocab *Vocabulary) *Linker {
	t.Helper()
	linker, err := NewLinker(store, testFingerprinter{}, fakeDetailCodec{store: store}, vocab)
	if err != nil {
		t.Fatal(err)
	}
	return linker
}

func testKey(value byte) []byte { return bytes.Repeat([]byte{value}, sqlite.AnalysisFingerprintSize) }

func TestLinkNeverChoosesPrevOfAnotherAPIKey(t *testing.T) {
	t.Parallel()
	keyA, keyB := testKey(0xa1), testKey(0xb2)
	const session = "conv-shared"
	store := &fakeLinkStore{rows: []fakeLinkRow{{
		candidate: sqlite.AnalysisLinkCandidate{AuditID: "audit-a", AnalysisVersion: AnalysisVersion, StartedAtNS: 100},
		session:   session,
		apiKey:    keyA,
		detail:    Detail{ItemFPRs: []string{"i1", "i2", "i3"}},
	}}}
	linker := newTestLinker(t, store, nil)
	conversationID := session
	link := func(apiKey []byte) sqlite.AnalysisRow {
		t.Helper()
		row, err := linker.Link(context.Background(), LinkInput{
			Meta: sqlite.AnalysisAuditMeta{
				AuditID: "audit-b", StartedAtNS: 200, APIKeyFPR: apiKey, ConversationID: &conversationID,
			},
			Protocol: "openai",
			Analysis: Analysis{Detail: Detail{ItemFPRs: []string{"i1", "x2"}}},
			Identity: AgentIdentity{Client: ClientUnknown, Role: RoleMain},
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}

	other := link(keyB)
	if other.PrevAuditID != nil || other.AppendedItems != nil || other.RemovedItems != nil || other.EventFlags != 0 {
		t.Fatalf("cross-key row inherited a predecessor: prev=%v appended=%v removed=%v flags=%d",
			other.PrevAuditID, other.AppendedItems, other.RemovedItems, other.EventFlags)
	}
	if none := link(nil); none.PrevAuditID != nil {
		t.Fatalf("a NULL key matched a keyed predecessor: %v", *none.PrevAuditID)
	}
	same := link(keyA)
	if same.PrevAuditID == nil || *same.PrevAuditID != "audit-a" || same.AppendedItems == nil || *same.AppendedItems != 1 ||
		same.RemovedItems == nil || *same.RemovedItems != 2 {
		t.Fatalf("same-key row lost its predecessor: %+v", same)
	}
}

func TestLinkNeverInheritsRootOfAnotherAPIKey(t *testing.T) {
	t.Parallel()
	keyA, keyB := testKey(0xa1), testKey(0xb2)
	parentFPR := AgentFPR(testFingerprinter{}, "claude_code", "parent-id")
	foreignRoot := testKey(0x77)
	store := &fakeLinkStore{rows: []fakeLinkRow{{
		candidate: sqlite.AnalysisLinkCandidate{
			AuditID: "audit-parent", AnalysisVersion: AnalysisVersion, StartedAtNS: 100,
			AgentNodeFPR: parentFPR, AgentRootFPR: foreignRoot,
		},
		session: "agt_parent",
		apiKey:  keyA,
	}}}
	linker := newTestLinker(t, store, nil)
	link := func(apiKey []byte) sqlite.AnalysisRow {
		t.Helper()
		row, err := linker.Link(context.Background(), LinkInput{
			Meta:     sqlite.AnalysisAuditMeta{AuditID: "audit-child", StartedAtNS: 200, APIKeyFPR: apiKey},
			Protocol: "anthropic",
			Identity: AgentIdentity{
				Client: "claude_code", Role: RoleSubagent, NodeID: "child-id", ParentID: "parent-id",
				LinkSource: LinkHeader, Confidence: 100,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	if row := link(keyB); !bytes.Equal(row.AgentRootFPR, parentFPR) {
		t.Fatalf("root of another key's parent row was inherited: %x", row.AgentRootFPR)
	}
	if row := link(keyA); !bytes.Equal(row.AgentRootFPR, foreignRoot) {
		t.Fatalf("same-key parent root not inherited: %x", row.AgentRootFPR)
	}
}

func TestLinkContentMatchesSubagentWithoutParentHeader(t *testing.T) {
	t.Parallel()
	key := testKey(0xa1)
	parentNode, parentRoot := testKey(0x31), testKey(0x32)
	prompt := "investigate the failing build"
	store := &fakeLinkStore{hints: []fakeSpawnHint{{
		auditID: "audit-parent", hint: HintFPR(testFingerprinter{}, prompt), node: parentNode,
		root: parentRoot, session: "agt_parent", apiKey: key,
	}}}
	linker := newTestLinker(t, store, nil)
	link := func(identity AgentIdentity) sqlite.AnalysisRow {
		t.Helper()
		row, err := linker.Link(context.Background(), LinkInput{
			Meta:         sqlite.AnalysisAuditMeta{AuditID: "audit-child", StartedAtNS: 200, APIKeyFPR: key},
			Protocol:     "openai",
			Identity:     identity,
			OpeningHints: []OpeningHint{{Text: prompt}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}

	// Older Codex: thread-id and x-openai-subagent: collab_spawn, but no
	// x-codex-parent-thread-id.
	child := link(AgentIdentity{
		Client: "codex", Role: RoleSubagent, NodeID: "child-thread", RootID: "",
		LinkSource: LinkHeader, Confidence: 100,
	})
	if child.AgentLinkSource == nil || *child.AgentLinkSource != LinkContent || !bytes.Equal(child.AgentParentFPR, parentNode) ||
		!bytes.Equal(child.AgentRootFPR, parentRoot) || child.AgentLinkConfidence == nil || *child.AgentLinkConfidence != contentLinkConfidence {
		t.Fatalf("old Codex child not content linked: source=%v parent=%x root=%x", child.AgentLinkSource, child.AgentParentFPR, child.AgentRootFPR)
	}

	// A main request of a known client with a node id is a root: it never runs
	// content matching, even when its opener equals a spawn prompt.
	main := link(AgentIdentity{
		Client: "claude_code", Role: RoleMain, NodeID: "session-root", RootID: "session-root",
		LinkSource: LinkHeader, Confidence: 100,
	})
	if main.AgentParentFPR != nil || (main.AgentLinkSource != nil && *main.AgentLinkSource == LinkContent) {
		t.Fatalf("main request was content linked: source=%v parent=%x", main.AgentLinkSource, main.AgentParentFPR)
	}
}
