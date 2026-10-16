package sqlite

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func openLinkReaderStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func saveLinkRow(t *testing.T, store *Store, auditID string, startedAt int64, apiKey []byte, mutate func(*AnalysisRow)) {
	t.Helper()
	ended := startedAt + 10
	insertRetentionAudit(t, store, auditID, startedAt, &ended, ParseOK, false)
	if apiKey != nil {
		if _, err := store.writerDB.Exec(`UPDATE audit_records SET api_key_fpr = ? WHERE audit_id = ?`, apiKey, auditID); err != nil {
			t.Fatal(err)
		}
	}
	row := testAnalysisRow(auditID, startedAt)
	row.SpawnHints = nil
	if mutate != nil {
		mutate(&row)
	}
	if err := store.SaveAnalysis(context.Background(), row); err != nil {
		t.Fatal(err)
	}
}

func TestLinkReaderSessionCandidatesSkipAuxiliarySteps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openLinkReaderStore(t)
	role := func(value string) func(*AnalysisRow) {
		return func(row *AnalysisRow) { row.AgentRole = &value }
	}
	saveLinkRow(t, store, "audit-a", 100, nil, role("main"))
	saveLinkRow(t, store, "audit-b", 200, nil, role("compaction"))
	saveLinkRow(t, store, "audit-c", 300, nil, role("subagent"))
	saveLinkRow(t, store, "audit-d", 300, nil, role("main")) // same start: ordered after audit-c
	session := *testAnalysisRow("", 0).AnalysisSessionID

	candidates, err := store.ListAnalysisPrevCandidates(ctx, session, 300, "audit-d", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].AuditID != "audit-c" || candidates[1].AuditID != "audit-a" {
		t.Fatalf("candidates = %+v", candidates)
	}
	if candidates[0].EstimateTotal != 920 || candidates[0].AnalysisVersion != 1 || len(candidates[0].DetailEnc) == 0 {
		t.Fatalf("candidate fields = %+v", candidates[0])
	}
	earlier, err := store.HasEarlierAnalysisStep(ctx, session, 100, "audit-a")
	if err != nil || earlier {
		t.Fatalf("HasEarlierAnalysisStep(first) = %v, %v", earlier, err)
	}
	// An auxiliary step still counts as an earlier step of the session.
	earlier, err = store.HasEarlierAnalysisStep(ctx, session, 250, "audit-z")
	if err != nil || !earlier {
		t.Fatalf("HasEarlierAnalysisStep(later) = %v, %v", earlier, err)
	}
}

func TestLinkReaderLatestRootAndMeta(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openLinkReaderStore(t)
	node := bytes.Repeat([]byte{0x22}, AnalysisFingerprintSize)
	rootOld := bytes.Repeat([]byte{0x41}, AnalysisFingerprintSize)
	rootNew := bytes.Repeat([]byte{0x42}, AnalysisFingerprintSize)
	saveLinkRow(t, store, "audit-old", 100, nil, func(row *AnalysisRow) { row.AgentRootFPR = rootOld })
	saveLinkRow(t, store, "audit-new", 200, nil, func(row *AnalysisRow) { row.AgentRootFPR = rootNew })

	root, err := store.LatestAgentRootFPR(ctx, node, "")
	if err != nil || !bytes.Equal(root, rootNew) {
		t.Fatalf("LatestAgentRootFPR = %x, %v", root, err)
	}
	// A recomputed row never reads its own previous root.
	root, err = store.LatestAgentRootFPR(ctx, node, "audit-new")
	if err != nil || !bytes.Equal(root, rootOld) {
		t.Fatalf("LatestAgentRootFPR excluding self = %x, %v", root, err)
	}
	root, err = store.LatestAgentRootFPR(ctx, bytes.Repeat([]byte{0x99}, AnalysisFingerprintSize), "")
	if err != nil || root != nil {
		t.Fatalf("LatestAgentRootFPR unknown = %x, %v", root, err)
	}

	meta, err := store.LoadAnalysisAuditMeta(ctx, "audit-new")
	if err != nil {
		t.Fatal(err)
	}
	if meta.StartedAtNS != 200 || meta.EndedAtNS == nil || *meta.EndedAtNS != 210 || meta.APIKeyFPR != nil ||
		meta.FirstEventAtNS != nil || meta.ConversationID != nil {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestLinkReaderSpawnHintsMatchOnlyTheSameKeyInWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := openLinkReaderStore(t)
	keyA := bytes.Repeat([]byte{0xa1}, AnalysisFingerprintSize)
	keyB := bytes.Repeat([]byte{0xb2}, AnalysisFingerprintSize)
	hint := bytes.Repeat([]byte{0x31}, AnalysisFingerprintSize)
	withHint := func(row *AnalysisRow) { row.SpawnHints = [][]byte{hint} }
	saveLinkRow(t, store, "parent-a", 1000, keyA, withHint)
	saveLinkRow(t, store, "parent-b", 1000, keyB, withHint)
	saveLinkRow(t, store, "parent-null", 1000, nil, withHint)
	saveLinkRow(t, store, "parent-old", 10, keyA, withHint)

	matches, err := store.MatchSpawnHints(ctx, [][]byte{hint}, keyA, 500, 2000, "child")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].AuditID != "parent-a" || !bytes.Equal(matches[0].HintFPR, hint) ||
		matches[0].AnalysisSessionID == nil || len(matches[0].AgentNodeFPR) != AnalysisFingerprintSize {
		t.Fatalf("matches = %+v", matches)
	}
	// A missing key never matches, not even rows whose key is also NULL.
	matches, err = store.MatchSpawnHints(ctx, [][]byte{hint}, nil, 0, 2000, "child")
	if err != nil || len(matches) != 0 {
		t.Fatalf("matches without key = %+v, %v", matches, err)
	}
	matches, err = store.MatchSpawnHints(ctx, [][]byte{hint}, keyA, 500, 2000, "parent-a")
	if err != nil || len(matches) != 0 {
		t.Fatalf("matches excluding self = %+v, %v", matches, err)
	}
}
