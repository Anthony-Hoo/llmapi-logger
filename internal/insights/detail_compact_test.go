package insights

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

type memoryDetailStore struct {
	objects map[string]storage.AnalysisDetailObject
	loads   int
}

func (s *memoryDetailStore) ExistingAnalysisDetailObjects(ctx context.Context, hashes [][]byte) (map[string]bool, error) {
	r := map[string]bool{}
	for _, h := range hashes {
		_, r[string(h)] = s.objects[string(h)]
	}
	return r, ctx.Err()
}
func (s *memoryDetailStore) LoadAnalysisDetailChain(ctx context.Context, root []byte, limit int) ([]storage.AnalysisDetailObject, error) {
	s.loads++
	var result []storage.AnalysisDetailObject
	for len(root) != 0 && len(result) < limit {
		n, ok := s.objects[string(root)]
		if !ok {
			break
		}
		result = append(result, n)
		root = n.ParentHash
	}
	return result, ctx.Err()
}
func compactTestCodec(t *testing.T) (CipherDetailCodec, *memoryDetailStore) {
	t.Helper()
	key := bytes.Repeat([]byte{3}, 32)
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := security.NewAnalysisFingerprinter(key)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryDetailStore{objects: map[string]storage.AnalysisDetailObject{}}
	return CipherDetailCodec{Cipher: cipher, Store: store, Fingerprinter: fp}, store
}
func saveDetail(t *testing.T, codec CipherDetailCodec, s *memoryDetailStore, id string, d Detail) ([]byte, []byte, int) {
	t.Helper()
	sealed, root, nodes, err := codec.SealDetailRow(context.Background(), id, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		s.objects[string(n.Hash)] = n
	}
	return sealed, root, len(nodes)
}
func TestCompactDetailRoundTripAndReuse(t *testing.T) {
	codec, store := compactTestCodec(t)
	for i, want := range []Detail{{}, {Items: []Item{}, ItemFPRs: []string{}, Tools: []ToolDef{}}, {Items: []Item{{Index: 0, Summary: "private", Tokens: 42}}, ItemFPRs: []string{"private keyed hash"}, Tools: []ToolDef{{Name: "private tool", Tokens: 99}}, Agent: AgentIdentity{Name: "private agent"}, FileOps: []FileOp{{Path: "private path"}}, Truncated: true}} {
		id := fmt.Sprint(i)
		sealed, root, count := saveDetail(t, codec, store, id, want)
		got, err := codec.OpenDetailContext(context.Background(), id, AnalysisVersion, sealed)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d roundtrip got %#v want %#v error %v", i, got, want, err)
		}
		_, again, nodes, err := codec.SealDetailRow(context.Background(), id, want)
		if err != nil || !bytes.Equal(root, again) || len(nodes) != 0 {
			t.Fatalf("reuse failed: %d initial %d err %v", len(nodes), count, err)
		}
		// Query does not need the HMAC key: authenticated node identities and
		// parent references prevent node substitution; writer additionally hashes.
		queryCodec := codec
		queryCodec.Fingerprinter = nil
		if _, err := queryCodec.OpenDetailContext(context.Background(), id, AnalysisVersion, sealed); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCompactDetailGrowthIsIncremental(t *testing.T) {
	codec, store := compactTestCodec(t)
	var detail Detail
	detail.Tools = []ToolDef{{Name: "fixture-tool", Tokens: 20}}
	total := 0
	legacyTotal := 0
	previous := 0
	for i := 1; i <= 128; i++ {
		detail.Items = append(detail.Items, Item{Index: i - 1, Category: CategoryUser, Kind: "text", Tokens: 256, Summary: fmt.Sprintf("message %04d %s", i, strings.Repeat("x", 148))})
		detail.ItemFPRs = append(detail.ItemFPRs, fmt.Sprintf("%064x", i))
		sealed, _, nodes, err := codec.SealDetailRow(context.Background(), fmt.Sprint(i), detail)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 && i != 1 {
			t.Fatalf("turn %d persisted %d nodes", i, len(nodes))
		}
		legacy, _ := json.Marshal(detail)
		legacyTotal += len(legacy) + security.NonceSize + 16
		total += len(sealed) + 32
		for _, n := range nodes {
			store.objects[string(n.Hash)] = n
			total += len(n.Hash) + len(n.ParentHash) + len(n.PayloadEnc)
		}
		got, err := codec.OpenDetailContext(context.Background(), fmt.Sprint(i), AnalysisVersion, sealed)
		if err != nil || !reflect.DeepEqual(got, detail) {
			t.Fatalf("turn %d roundtrip %v", i, err)
		}
		if i == 16 || i == 32 || i == 64 || i == 128 {
			t.Logf("turns=%d objects=%d total_bytes=%d legacy_snapshot_bytes=%d", i, len(store.objects), total, legacyTotal)
			if previous > 0 && total > previous*22/10 {
				t.Fatalf("nonlinear growth: %d -> %d", previous, total)
			}
			previous = total
		}
	}
	if legacyTotal < total*10 {
		t.Fatalf("expected >10x reduction at128: legacy=%d compact=%d", legacyTotal, total)
	}
	if len(store.objects) != 129 {
		t.Fatalf("objects %d", len(store.objects))
	}
}
func TestCompactDetailCapsAndCorruption(t *testing.T) {
	codec, store := compactTestCodec(t)
	detail := Detail{Items: make([]Item, maxDetailItems), ItemFPRs: make([]string, maxItemFPRs)}
	for i := range detail.Items {
		detail.Items[i] = Item{Index: i, Summary: "summary"}
	}
	for i := range detail.ItemFPRs {
		detail.ItemFPRs[i] = fmt.Sprintf("%064x", i)
	}
	sealed, root, _ := saveDetail(t, codec, store, "cap", detail)
	got, err := codec.OpenDetailContext(context.Background(), "cap", AnalysisVersion, sealed)
	if err != nil || !reflect.DeepEqual(got, detail) {
		t.Fatalf("cap roundtrip %v", err)
	}
	node := store.objects[string(root)]
	node.ParentHash = bytes.Repeat([]byte{9}, 32)
	store.objects[string(root)] = node
	if _, err := codec.OpenDetailContext(context.Background(), "cap", AnalysisVersion, sealed); err == nil {
		t.Fatal("changed parent accepted")
	}
	delete(store.objects, string(root))
	if _, err := codec.OpenDetailContext(context.Background(), "cap", AnalysisVersion, sealed); err == nil {
		t.Fatal("missing node accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := codec.SealDetailRow(ctx, "cancel", Detail{}); err == nil {
		t.Fatal("cancel ignored")
	}
	detail.ItemFPRs = append(detail.ItemFPRs, "too many")
	if _, _, _, err := codec.SealDetailRow(context.Background(), "limit", detail); err == nil {
		t.Fatal("limit ignored")
	}
}

func TestCompactMetadataDoesNotLoadHistory(t *testing.T) {
	codec, store := compactTestCodec(t)
	detail := Detail{Agent: AgentIdentity{Name: "node name"}, Items: []Item{{Index: 0, Summary: "private history"}}, ItemFPRs: []string{"fingerprint"}}
	sealed, root, _ := saveDetail(t, codec, store, "metadata", detail)
	delete(store.objects, string(root))
	metadata, err := codec.OpenDetailMetadata(context.Background(), "metadata", AnalysisVersion, sealed)
	if err != nil || metadata.Agent.Name != detail.Agent.Name || len(metadata.Items) != 0 || store.loads != 0 {
		t.Fatalf("metadata unexpectedly loaded history: %v loads %d", err, store.loads)
	}
	if _, err := codec.OpenDetailContext(context.Background(), "metadata", AnalysisVersion, sealed); err == nil {
		t.Fatal("full read accepted missing node")
	}
}
func TestCompactDetailRejectsTamperedNodesAndCycles(t *testing.T) {
	codec, store := compactTestCodec(t)
	sealed, root, _ := saveDetail(t, codec, store, "tamper", Detail{Items: []Item{{Index: 0, Summary: "a"}, {Index: 1, Summary: "b"}}})
	original := store.objects[string(root)]
	broken := original
	broken.PayloadEnc = append([]byte(nil), broken.PayloadEnc...)
	broken.PayloadEnc[len(broken.PayloadEnc)-1] ^= 1
	store.objects[string(root)] = broken
	if _, err := codec.OpenDetailContext(context.Background(), "tamper", AnalysisVersion, sealed); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	cycle := original
	cycle.ParentHash = root
	store.objects[string(root)] = cycle
	if _, err := codec.OpenDetailContext(context.Background(), "tamper", AnalysisVersion, sealed); err == nil {
		t.Fatal("cycle accepted")
	}
	store.objects[string(root)] = original
	sibling := Detail{Items: []Item{{Index: 0, Summary: "different"}, {Index: 1, Summary: "b"}}}
	_, siblingRoot, _ := saveDetail(t, codec, store, "sibling", sibling)
	swapped := store.objects[string(siblingRoot)]
	swapped.Hash = root
	store.objects[string(root)] = swapped
	if _, err := codec.OpenDetailContext(context.Background(), "tamper", AnalysisVersion, sealed); err == nil {
		t.Fatal("node substitution accepted")
	}
}
func TestCompactDivergencePreservesEarlierRoots(t *testing.T) {
	codec, store := compactTestCodec(t)
	first := Detail{Items: []Item{{Index: 0, Summary: "same"}, {Index: 1, Summary: "old"}}, ItemFPRs: []string{"same", "old"}}
	a, _, _ := saveDetail(t, codec, store, "a", first)
	next := Detail{Items: []Item{{Index: 0, Summary: "same"}, {Index: 1, Summary: "new"}}, ItemFPRs: []string{"same", "new"}}
	b, _, added := saveDetail(t, codec, store, "b", next)
	if added != 1 {
		t.Fatalf("divergent suffix added %d nodes", added)
	}
	for id, pair := range map[string]struct {
		sealed []byte
		want   Detail
	}{"a": {a, first}, "b": {b, next}} {
		got, err := codec.OpenDetailContext(context.Background(), id, AnalysisVersion, pair.sealed)
		if err != nil || !reflect.DeepEqual(got, pair.want) {
			t.Fatalf("branch %s: %v", id, err)
		}
	}
}
