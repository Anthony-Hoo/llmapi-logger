package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

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
		data: policyRulePointer(contentPolicyTestRule(1, "first", 100)),
		ack:  make(chan error, 1),
	}
	missing := writeRequest{
		kind: writeDeleteContentPolicyRule,
		data: int64(999),
		ack:  make(chan error, 1),
	}
	second := writeRequest{
		kind: writeCreateContentPolicyRule,
		data: policyRulePointer(contentPolicyTestRule(2, "second", 200)),
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

func policyRulePointer(rule contentpolicy.Rule) *contentpolicy.Rule { return &rule }

func TestPolicyIDsNeverReuseAfterUpdateAndRestart(t *testing.T) {
	ctx := context.Background()
	store, path := openTestStore(t)
	service, err := contentpolicy.New(ctx, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := contentpolicy.RuleInput{Name: "rule", Enabled: true, Keywords: []string{"blocked"}}
	first, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(ctx, first.ID, input); err != nil {
		t.Fatal(err)
	}
	third, err := service.Create(ctx, input)
	if err != nil || third.ID <= second.ID {
		t.Fatalf("third=%+v err=%v", third, err)
	}
	if err := service.Delete(ctx, third.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	service, err = contentpolicy.New(ctx, reopened, nil)
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := service.Create(ctx, input)
	if err != nil || fourth.ID <= third.ID {
		t.Fatalf("fourth=%+v err=%v", fourth, err)
	}
}

// Hold the real writer queue until cancellation, then let its real transaction
// commit. No timing assumption about the normal batch collection window.
func TestAcceptedPolicyWritesPublishDespiteCallerCancellation(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			store, _ := openTestStore(t)
			if operation != "create" {
				if _, err := store.CreateContentPolicyRule(ctx, contentPolicyTestRule(1, "old", 100)); err != nil {
					t.Fatal(err)
				}
			}
			writer := &Store{writerDB: store.writerDB, readerDB: store.readerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
			service, err := contentpolicy.New(ctx, writer, nil)
			if err != nil {
				t.Fatal(err)
			}
			requestCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				input := contentpolicy.RuleInput{Name: "new", Enabled: true, Keywords: []string{"blocked"}}
				var err error
				switch operation {
				case "create":
					_, err = service.Create(requestCtx, input)
				case "update":
					_, err = service.Update(requestCtx, 1, input)
				case "delete":
					err = service.Delete(requestCtx, 1)
				}
				done <- err
			}()
			var request writeRequest
			select {
			case request = <-writer.queue:
			case <-time.After(time.Second):
				t.Fatal("write was not queued")
			}
			cancel()
			select {
			case err := <-done:
				t.Fatalf("accepted write returned before definitive result: %v", err)
			default:
			}
			writer.queue <- request
			close(writer.queue)
			go writer.runWriter()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("policy write hung")
			}
			<-writer.done
			persisted, err := store.ListContentPolicyRules(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(service.List(), persisted) {
				t.Fatalf("snapshot=%+v persisted=%+v", service.List(), persisted)
			}
			if operation != "delete" && (len(persisted) != 1 || persisted[0].Name != "new") {
				t.Fatalf("persisted=%+v", persisted)
			}
		})
	}
}

func TestExpiredQueuedPolicyCannotCommitLater(t *testing.T) {
	store, _ := openTestStore(t)
	writer := &Store{writerDB: store.writerDB, queue: make(chan writeRequest, 1), done: make(chan struct{})}
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- writer.submitPolicyUntil(context.Background(), writeRequest{kind: writeCreateContentPolicyRule, data: policyRulePointer(contentPolicyTestRule(0, "expired", 100))}, operation)
	}()
	var request writeRequest
	select {
	case request = <-writer.queue:
	case <-time.After(time.Second):
		t.Fatal("not queued")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired queued write hung")
	}
	writer.queue <- request
	close(writer.queue)
	writer.runWriter()
	assertTableCount(t, store.readerDB, "content_policy_rules", 0)
}

func TestPolicyMigrationPreservesIDsAndAllocatesAboveExisting(t *testing.T) {
	ctx := context.Background()
	store, path := openTestStore(t)
	// Recreate the deployed pre-012 table, with a noncontiguous stable identity.
	legacy, err := migrationFiles.ReadFile("migrations/010_content_policy_rules.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.writerDB.Exec("DROP TABLE content_policy_rules; DELETE FROM schema_migrations WHERE version=12;" + string(legacy)); err != nil {
		t.Fatal(err)
	}
	_, err = store.writerDB.Exec(`INSERT INTO content_policy_rules VALUES (7,'legacy',1,'block','','["latest_user"]','["blocked"]',100,100)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rules, err := reopened.ListContentPolicyRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].ID != 7 {
		t.Fatalf("rules=%+v err=%v", rules, err)
	}
	if err := reopened.DeleteContentPolicyRule(ctx, 7); err != nil {
		t.Fatal(err)
	}
	created, err := reopened.CreateContentPolicyRule(ctx, contentPolicyTestRule(7, "new", 200))
	if err != nil || created.ID <= 7 {
		t.Fatalf("created=%+v err=%v", created, err)
	}
}

func TestExecutingPolicyDeadlineDoesNotHangOrAffectAuditWrites(t *testing.T) {
	store, _ := openTestStore(t)
	// Occupy the sole write connection so the policy has started but cannot begin
	// a transaction. Its independent deadline must still release its caller.
	connection, err := store.writerDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &Store{writerDB: store.writerDB, queue: make(chan writeRequest, 2), done: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- writer.submitPolicyUntil(context.Background(), writeRequest{kind: writeCreateContentPolicyRule, data: policyRulePointer(contentPolicyTestRule(0, "expired", 100))}, operation)
	}()
	var request writeRequest
	select {
	case request = <-writer.queue:
	case <-time.After(time.Second):
		t.Fatal("not queued")
	}
	writer.queue <- request
	record := testAudit("after-expired-policy")
	record.Defaults()
	audit := writeRequest{kind: writeBeginAudit, data: record, ack: make(chan error, 1)}
	writer.queue <- audit
	close(writer.queue)
	go writer.runWriter()
	deadline := time.After(time.Second)
	for request.policy.state.Load() != 1 {
		select {
		case <-deadline:
			t.Fatal("policy never started")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("started policy ignored deadline")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-audit.ack:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated audit write hung")
	}
	<-writer.done
	assertTableCount(t, store.readerDB, "content_policy_rules", 0)
	assertTableCount(t, store.readerDB, "audit_records", 1)
}
