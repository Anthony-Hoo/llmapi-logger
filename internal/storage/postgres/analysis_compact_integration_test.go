package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/security"
)

func TestCompactInsightsActualPostgresGrowth(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x64}, security.KeySize)
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := security.NewAnalysisFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	codec := insights.CipherDetailCodec{Cipher: cipher, Store: store, Fingerprinter: fp}
	detail := insights.Detail{Tools: []insights.ToolDef{{Name: "fixture-tool", Tokens: 20}}}
	previous := int64(0)
	legacyBytes := 0
	var latest AnalysisRow
	for i := 1; i <= 128; i++ {
		id := fmt.Sprintf("compact-growth-%03d", i)
		if err := store.BeginAudit(ctx, testAudit(id)); err != nil {
			t.Fatal(err)
		}
		detail.Items = append(detail.Items, insights.Item{Index: i - 1, Category: insights.CategoryUser, Kind: "text", Tokens: 256, Summary: fmt.Sprintf("message %04d %s", i, strings.Repeat("x", 148))})
		detail.ItemFPRs = append(detail.ItemFPRs, fmt.Sprintf("%064x", i))
		row := testAnalysisRow(id, int64(i)*100)
		row.AnalysisVersion = insights.AnalysisVersion
		row.DetailEnc, row.DetailRoot, row.DetailObjects, err = codec.SealDetailRow(ctx, id, detail)
		if err != nil {
			t.Fatal(err)
		}
		if i > 1 && len(row.DetailObjects) != 1 {
			t.Fatalf("turn %d regenerated %d objects", i, len(row.DetailObjects))
		}
		if err := store.SaveAnalysis(ctx, row); err != nil {
			t.Fatal(err)
		}
		plain, _ := json.Marshal(detail)
		legacyBytes += len(plain) + security.NonceSize + 16
		latest = row
		if i == 16 || i == 32 || i == 64 || i == 128 {
			loaded, err := store.LoadAnalysis(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(loaded.DetailRoot, row.DetailRoot) {
				t.Fatal("stored root differs")
			}
			got, err := codec.OpenDetailContext(ctx, id, loaded.AnalysisVersion, loaded.DetailEnc)
			if err != nil || !reflect.DeepEqual(got, detail) {
				t.Fatalf("turn %d roundtrip: %v", i, err)
			}
			var objects int
			var bytesStored int64
			if err := store.readerDB.QueryRowContext(ctx, `SELECT count(*) FROM analysis_detail_objects`).Scan(&objects); err != nil {
				t.Fatal(err)
			}
			if err := store.readerDB.QueryRowContext(ctx, `SELECT (SELECT coalesce(sum(octet_length(detail_enc)+octet_length(detail_root)),0) FROM audit_analysis) + (SELECT coalesce(sum(octet_length(hash)+coalesce(octet_length(parent_hash),0)+octet_length(payload_enc)),0) FROM analysis_detail_objects)`).Scan(&bytesStored); err != nil {
				t.Fatal(err)
			}
			t.Logf("turns=%d nodes=%d persisted_payload_bytes=%d legacy_snapshot_bytes=%d", i, objects, bytesStored, legacyBytes)
			if objects != i+1 {
				t.Fatalf("turn %d objects=%d", i, objects)
			}
			if previous > 0 && bytesStored > previous*22/10 {
				t.Fatalf("nonlinear persisted growth %d -> %d", previous, bytesStored)
			}
			if i == 128 && int64(legacyBytes) < bytesStored*10 {
				t.Fatal("expected >10x payload reduction")
			}
			previous = bytesStored
		}
	}
	// Replaying the exact successful analysis is safe despite randomized AES
	// nonces; immutable node identity is canonical plaintext, not ciphertext.
	latest.DetailEnc, latest.DetailRoot, latest.DetailObjects, err = codec.SealDetailRow(ctx, latest.AuditID, detail)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest.DetailObjects) != 0 {
		t.Fatal("idempotent replay regenerated objects")
	}
	if err := store.SaveAnalysis(ctx, latest); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.readerDB.QueryRowContext(ctx, `SELECT count(*) FROM analysis_detail_objects`).Scan(&count); err != nil || count != 129 {
		t.Fatalf("replay count %d err %v", count, err)
	}
}
