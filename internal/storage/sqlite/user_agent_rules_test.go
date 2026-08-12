package sqlite

import (
	"context"
	"errors"
	"testing"

	"llmapi-logger/internal/uaguard"
)

func TestUserAgentRulesPersistAcrossRestart(t *testing.T) {
	store, path := openTestStore(t)
	service, err := uaguard.New(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	rules := service.List()
	if len(rules) != 1 || rules[0].ID != 1 || !rules[0].Enabled || rules[0].ModelPattern != "^gpt" || rules[0].UserAgentPattern != "Codex Desktop" {
		t.Fatalf("default rules = %+v", rules)
	}

	updated, err := service.Update(context.Background(), 1, uaguard.RuleInput{
		Name: "updated default", Enabled: false, ModelPattern: `(?i)^gpt`, UserAgentPattern: `Desktop`,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), uaguard.RuleInput{
		Name: "second", Enabled: true, ModelPattern: `^other`, UserAgentPattern: `Approved`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID <= updated.ID {
		t.Fatalf("created ID = %d, updated ID = %d", created.ID, updated.ID)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reloaded, err := uaguard.New(context.Background(), reopened)
	if err != nil {
		t.Fatal(err)
	}
	rules = reloaded.List()
	if len(rules) != 2 || rules[0].Enabled || rules[0].ModelPattern != `(?i)^gpt` || rules[1].ID != created.ID {
		t.Fatalf("reloaded rules = %+v", rules)
	}
	if err := reloaded.Delete(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Delete(context.Background(), created.ID); !errors.Is(err, uaguard.ErrNotFound) {
		t.Fatalf("second delete error = %v", err)
	}
}
