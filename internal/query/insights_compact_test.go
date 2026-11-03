package query

import (
	"bytes"
	"context"
	"errors"
	"llmapi-logger/internal/insights"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
	"testing"
)

type compactQueryStore struct {
	*sqlite.Store
	objects map[string]storage.AnalysisDetailObject
	loads   int
}

func (s *compactQueryStore) ExistingAnalysisDetailObjects(ctx context.Context, hashes [][]byte) (map[string]bool, error) {
	found := map[string]bool{}
	for _, h := range hashes {
		_, found[string(h)] = s.objects[string(h)]
	}
	return found, ctx.Err()
}
func (s *compactQueryStore) LoadAnalysisDetailChain(ctx context.Context, root []byte, limit int) ([]storage.AnalysisDetailObject, error) {
	s.loads++
	var nodes []storage.AnalysisDetailObject
	for len(root) != 0 && len(nodes) < limit {
		node, ok := s.objects[string(root)]
		if !ok {
			break
		}
		nodes = append(nodes, node)
		root = node.ParentHash
	}
	return nodes, ctx.Err()
}

func TestCompactCompositionAuthorizesBeforeNodeAccess(t *testing.T) {
	fixture := newInsightsFixture(t, nil)
	ctx := context.Background()
	fixture.seed(stepSeed{id: "compact", key: keyOwn, uncached: i64(5)})
	store := &compactQueryStore{Store: fixture.store, objects: map[string]storage.AnalysisDetailObject{}}
	fp, err := security.NewAnalysisFingerprinter(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	codec := insights.CipherDetailCodec{Cipher: fixture.cipher, Store: store, Fingerprinter: fp}
	detail := insights.Detail{Items: []insights.Item{{Index: 0, Category: insights.CategoryUser, Tokens: 5, Summary: "private context"}}, ItemFPRs: []string{"private fingerprint"}, Agent: insights.AgentIdentity{Name: "private agent"}}
	sealed, _, nodes, err := codec.SealDetailRow(ctx, "compact", detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		store.objects[string(node.Hash)] = node
	}
	row, err := fixture.store.LoadAnalysis(ctx, "compact")
	if err != nil {
		t.Fatal(err)
	}
	row.DetailEnc = sealed
	row.AnalysisVersion = insights.AnalysisVersion
	if err := fixture.store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
	fixture.service.store = store
	if _, err := fixture.service.Composition(ctx, "compact", scopeFor(fingerprint(0xee))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope read: %v", err)
	}
	if store.loads != 0 {
		t.Fatalf("unauthorized read loaded %d chains", store.loads)
	}
	got, err := fixture.service.Composition(ctx, "compact", scopeFor(keyOwn))
	if err != nil || len(got.Items) != 1 || got.Items[0].Summary != "private context" {
		t.Fatalf("authorized composition: %#v %v", got, err)
	}
	if store.loads != 1 {
		t.Fatalf("expected one bounded chain query, got %d", store.loads)
	}
	name, err := fixture.service.agentName(ctx, "compact")
	if err != nil || name != "private agent" || store.loads != 1 {
		t.Fatalf("agent metadata inflated history: %q %v loads%d", name, err, store.loads)
	}
}
