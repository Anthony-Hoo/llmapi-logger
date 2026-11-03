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
		if _, err := tx.Exec(`DELETE FROM audit_records WHERE audit_id=$1`, auditID); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := garbageCollectAnalysisDetails(tx); err != nil {
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

func TestRetentionCollectsReplacedAnalysisWithoutExpiredAudits(t *testing.T) {
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
	if _, err := store.DeleteExpired(ctx, 1, 1, 1); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.readerDB.QueryRow(`SELECT count(*) FROM analysis_detail_objects`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replaced prefix count=%d err=%v", count, err)
	}
}
