package postgres

import (
	"bytes"
	"context"
	"llmapi-logger/internal/storage"
	"testing"
)

func TestAnalysisDetailAtomicPrefixesAndRetention(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"detail-one", "detail-two", "detail-failed"} {
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
	}
	node := func(v byte, parent []byte) storage.AnalysisDetailObject {
		return storage.AnalysisDetailObject{Hash: bytes.Repeat([]byte{v}, 32), ParentHash: parent, PayloadEnc: []byte{v, 1, 2}}
	}
	root := node(1, nil)
	one := node(2, root.Hash)
	two := node(3, root.Hash)
	row := testAnalysisRow("detail-one", 100)
	row.DetailRoot = one.Hash
	row.DetailObjects = []storage.AnalysisDetailObject{root, one}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	row = testAnalysisRow("detail-two", 200)
	row.DetailRoot = two.Hash
	row.DetailObjects = []storage.AnalysisDetailObject{two}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	read, err := store.LoadAnalysis(ctx, row.AuditID)
	if err != nil || !bytes.Equal(read.DetailRoot, two.Hash) {
		t.Fatalf("root: %+v %v", read, err)
	}
	chain, err := store.LoadAnalysisDetailChain(ctx, two.Hash, 2)
	if err != nil || len(chain) != 2 || !bytes.Equal(chain[1].Hash, root.Hash) {
		t.Fatalf("chain=%+v err=%v", chain, err)
	}
	orphan := node(4, nil)
	bad := node(5, bytes.Repeat([]byte{99}, 32))
	row = testAnalysisRow("detail-failed", 300)
	row.DetailRoot = bad.Hash
	row.DetailObjects = []storage.AnalysisDetailObject{orphan, bad}
	if err := store.SaveAnalysis(ctx, row); err == nil {
		t.Fatal("dangling parent accepted")
	}
	found, err := store.ExistingAnalysisDetailObjects(ctx, [][]byte{orphan.Hash, bad.Hash})
	if err != nil || len(found) != 0 {
		t.Fatalf("failed save leaked nodes: %v %v", found, err)
	}
	for _, auditID := range []string{"detail-one", "detail-two"} {
		tx, err := store.writerConn.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		roots, err := selectAnalysisDetailRoots(tx, []string{auditID})
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec(`DELETE FROM audit_records WHERE audit_id=$1`, auditID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := pruneAnalysisDetailChains(tx, roots); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := store.readerDB.QueryRow(`SELECT count(*) FROM analysis_detail_objects`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		expected := 0
		if auditID == "detail-one" {
			expected = 2
		}
		if count != expected {
			t.Fatalf("GC %s: nodes=%d want=%d", auditID, count, expected)
		}
	}
}

func countAnalysisDetailObjects(t *testing.T, store *Store) int {
	t.Helper()
	var count int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM analysis_detail_objects`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSaveAnalysisPrunesReplacedDetailRoot(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if err := store.BeginAudit(ctx, testAudit("recomputed")); err != nil {
		t.Fatal(err)
	}
	for _, b := range []byte{10, 11} {
		hash := bytes.Repeat([]byte{b}, 32)
		row := testAnalysisRow("recomputed", 100)
		row.DetailRoot = hash
		row.DetailObjects = []storage.AnalysisDetailObject{{Hash: hash, PayloadEnc: []byte{b}}}
		if err := store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	// The replaced root is released by the save itself, before any retention pass.
	if count := countAnalysisDetailObjects(t, store); count != 1 {
		t.Fatalf("replaced prefix count=%d", count)
	}
	found, err := store.ExistingAnalysisDetailObjects(ctx, [][]byte{bytes.Repeat([]byte{11}, 32)})
	if err != nil || len(found) != 1 {
		t.Fatalf("current root missing: %v %v", found, err)
	}
	if _, err := store.DeleteExpired(ctx, 1, 1, 1); err != nil {
		t.Fatal(err)
	}
	if count := countAnalysisDetailObjects(t, store); count != 1 {
		t.Fatalf("retention changed current prefixes: %d", count)
	}
}

func TestSaveAnalysisKeepsSharedPrefixWhenRootIsReplaced(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"shared-a", "shared-b"} {
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
	}
	node := func(v byte, parent []byte) storage.AnalysisDetailObject {
		return storage.AnalysisDetailObject{Hash: bytes.Repeat([]byte{v}, 32), ParentHash: parent, PayloadEnc: []byte{v}}
	}
	head := node(20, nil)
	mid := node(21, head.Hash)
	leafA := node(22, mid.Hash)
	leafB := node(23, mid.Hash)
	save := func(auditID string, root []byte, objects ...storage.AnalysisDetailObject) {
		t.Helper()
		row := testAnalysisRow(auditID, 100)
		row.DetailRoot = root
		row.DetailObjects = objects
		if err := store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	save("shared-a", leafA.Hash, head, mid, leafA)
	save("shared-b", leafB.Hash, head, mid, leafB)
	// Re-analysis of shared-a points its root at the shared middle node: only
	// its old leaf is released; nodes still reachable from either row stay.
	save("shared-a", mid.Hash)
	if count := countAnalysisDetailObjects(t, store); count != 3 {
		t.Fatalf("nodes after re-analysis=%d want=3", count)
	}
	found, err := store.ExistingAnalysisDetailObjects(ctx, [][]byte{leafA.Hash})
	if err != nil || len(found) != 0 {
		t.Fatalf("replaced leaf kept: %v %v", found, err)
	}
	// A root that another analysis also uses is not pruned.
	save("shared-b", mid.Hash)
	if count := countAnalysisDetailObjects(t, store); count != 2 {
		t.Fatalf("nodes after second re-analysis=%d want=2", count)
	}
	save("shared-a", nil)
	save("shared-b", nil)
	if count := countAnalysisDetailObjects(t, store); count != 0 {
		t.Fatalf("nodes after clearing roots=%d want=0", count)
	}
}

func TestRetentionPrunesOnlyChainsOfDeletedAudits(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	finish := func(auditID string, endedAtNS int64) {
		t.Helper()
		audit := testAudit(auditID)
		audit.StartedAtNS = endedAtNS - 1
		if err := store.BeginAudit(ctx, audit); err != nil {
			t.Fatal(err)
		}
		if err := store.FinishAudit(ctx, AuditFinish{
			AuditID: auditID, EndedAtNS: endedAtNS, ForwardStatus: ForwardCompleted,
			CaptureStatus: CaptureComplete, ParseStatus: ParsePending,
		}); err != nil {
			t.Fatal(err)
		}
	}
	finish("expired-deep", 2)
	finish("kept", 100)
	// A long chain exercises the level-by-level walk toward the chain head.
	const depth = 1200
	hashOf := func(prefix byte, i int) []byte {
		hash := bytes.Repeat([]byte{prefix}, 32)
		hash[30], hash[31] = byte(i>>8), byte(i)
		return hash
	}
	var objects []storage.AnalysisDetailObject
	var parent []byte
	for i := 0; i < depth; i++ {
		hash := hashOf(0x40, i)
		objects = append(objects, storage.AnalysisDetailObject{Hash: hash, ParentHash: parent, PayloadEnc: []byte{1}})
		parent = hash
	}
	row := testAnalysisRow("expired-deep", 1)
	row.DetailRoot = parent
	row.DetailObjects = objects
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	keptRoot := hashOf(0x50, 0)
	row = testAnalysisRow("kept", 99)
	row.DetailRoot = keptRoot
	row.DetailObjects = []storage.AnalysisDetailObject{{Hash: keptRoot, PayloadEnc: []byte{2}}}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	result, err := store.DeleteExpired(ctx, 50, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedAudits != 1 {
		t.Fatalf("deleted audits = %d", result.DeletedAudits)
	}
	if count := countAnalysisDetailObjects(t, store); count != 1 {
		t.Fatalf("nodes after retention=%d want=1", count)
	}
	found, err := store.ExistingAnalysisDetailObjects(ctx, [][]byte{keptRoot})
	if err != nil || len(found) != 1 {
		t.Fatalf("retention removed a kept audit's root: %v %v", found, err)
	}
}

func TestPruneAnalysisDetailChainsAcrossStatementBatches(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	// More released roots than one prune statement binds, all hanging off two
	// shared parents, so candidates and returned parents span several batches.
	roots := gcBatchSize + 137
	parents := [][]byte{bytes.Repeat([]byte{0x70}, 32), bytes.Repeat([]byte{0x71}, 32)}
	for _, parent := range parents {
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO analysis_detail_objects(hash,parent_hash,payload_enc) VALUES ($1,NULL,$2)`, parent, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	var released [][]byte
	for i := 0; i < roots; i++ {
		hash := bytes.Repeat([]byte{0x72}, 32)
		hash[30], hash[31] = byte(i>>8), byte(i)
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO analysis_detail_objects(hash,parent_hash,payload_enc) VALUES ($1,$2,$3)`, hash, parents[i%2], []byte{2}); err != nil {
			t.Fatal(err)
		}
		released = append(released, hash, hash) // duplicates are ignored
	}
	tx, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pruneAnalysisDetailChains(tx, released); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count := countAnalysisDetailObjects(t, store); count != 0 {
		t.Fatalf("nodes after batched prune=%d want=0", count)
	}
}
