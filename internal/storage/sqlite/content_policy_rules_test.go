package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"llmapi-logger/internal/contentpolicy"
)

func contentPolicyTestRule(id int64, name string, timestamp int64) contentpolicy.Rule {
	return contentpolicy.Rule{
		ID:           id,
		Name:         name,
		Enabled:      true,
		Action:       contentpolicy.ActionBlock,
		ModelPattern: `^gpt`,
		ScanScopes:   []string{contentpolicy.ScopeSystem, contentpolicy.ScopeLatestUser},
		Keywords:     []string{"cyber", "忽略之前的指令"},
		CreatedAtNS:  timestamp,
		UpdatedAtNS:  timestamp,
	}
}

func TestContentPolicyRulesPersistAcrossRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, path := openTestStore(t)

	// Migration 010 installs no seed rule: an empty table means no interception.
	rules, err := store.ListContentPolicyRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("seed content policy rules = %+v", rules)
	}

	first := contentPolicyTestRule(1, "first", 100)
	created, err := store.CreateContentPolicyRule(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(created, first) {
		t.Fatalf("created rule = %+v, want %+v", created, first)
	}
	second := contentPolicyTestRule(2, "second", 200)
	if _, err := store.CreateContentPolicyRule(ctx, second); err != nil {
		t.Fatal(err)
	}

	updated := first
	updated.Name = "first updated"
	updated.Enabled = false
	updated.Action = contentpolicy.ActionDryRun
	updated.ModelPattern = `(?i)^claude`
	updated.ScanScopes = []string{contentpolicy.ScopeLatestUser}
	updated.Keywords = []string{"updated keyword"}
	updated.UpdatedAtNS = 300
	if _, err := store.UpdateContentPolicyRule(ctx, updated); err != nil {
		t.Fatal(err)
	}
	rules, err = store.ListContentPolicyRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []contentpolicy.Rule{updated, second}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules before restart = %+v, want %+v", rules, want)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	rules, err = reopened.ListContentPolicyRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules after restart = %+v, want %+v", rules, want)
	}
}

func TestContentPolicyRuleNotFoundErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)

	rule := contentPolicyTestRule(1, "existing", 100)
	if _, err := store.CreateContentPolicyRule(ctx, rule); err != nil {
		t.Fatal(err)
	}

	if _, err := store.UpdateContentPolicyRule(ctx, contentPolicyTestRule(99, "missing", 100)); !errors.Is(err, contentpolicy.ErrNotFound) {
		t.Fatalf("update missing rule error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteContentPolicyRule(ctx, 99); !errors.Is(err, contentpolicy.ErrNotFound) {
		t.Fatalf("delete missing rule error = %v, want ErrNotFound", err)
	}
	rules, err := store.ListContentPolicyRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != 1 || rules[0].Name != "existing" {
		t.Fatalf("failed update/delete changed rules: %+v", rules)
	}

	if err := store.DeleteContentPolicyRule(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteContentPolicyRule(ctx, 1); !errors.Is(err, contentpolicy.ErrNotFound) {
		t.Fatalf("second delete error = %v, want ErrNotFound", err)
	}
	rules, err = store.ListContentPolicyRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("deleted rule still listed: %+v", rules)
	}
	// Isolated not-found errors must not be reported as writer health failures.
	if !store.Healthy() {
		t.Fatal("not-found operations made the store unhealthy")
	}
}

func TestWriterIsolatesContentPolicyDeleteNotFoundFromBatch(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	first := writeRequest{
		kind: writeCreateContentPolicyRule,
		data: contentPolicyTestRule(1, "first", 100),
		ack:  make(chan error, 1),
	}
	missing := writeRequest{
		kind: writeDeleteContentPolicyRule,
		data: int64(999),
		ack:  make(chan error, 1),
	}
	second := writeRequest{
		kind: writeCreateContentPolicyRule,
		data: contentPolicyTestRule(2, "second", 200),
		ack:  make(chan error, 1),
	}
	batch := []writeRequest{first, missing, second}
	// Run a dedicated writer loop so all three operations deterministically
	// share one batch, independent of scheduler timing and the 5 ms window.
	writer := &Store{writerDB: store.writerDB, queue: make(chan writeRequest, len(batch)), done: make(chan struct{})}
	for _, request := range batch {
		writer.queue <- request
	}
	close(writer.queue)
	writer.runWriter()

	if err := <-first.ack; err != nil {
		t.Fatalf("create before failed delete rolled back: %v", err)
	}
	if err := <-missing.ack; !errors.Is(err, contentpolicy.ErrNotFound) {
		t.Fatalf("delete missing rule error = %v, want ErrNotFound", err)
	}
	if err := <-second.ack; err != nil {
		t.Fatalf("create after failed delete rolled back: %v", err)
	}
	if !writer.healthy.Load() {
		t.Fatal("isolated not-found delete changed writer health")
	}
	assertTableCount(t, store.readerDB, "content_policy_rules", 2)
	rules, err := store.ListContentPolicyRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].ID != 1 || rules[1].ID != 2 {
		t.Fatalf("rules after isolated delete failure = %+v", rules)
	}
}
