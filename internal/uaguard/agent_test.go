package uaguard

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// rowRepository keeps rows like a database and counts writes, so a test can
// prove a refused or check-only call wrote nothing.
type rowRepository struct {
	mu     sync.Mutex
	rows   map[int64]Rule
	nextID int64
	writes int
}

func newRowRepository(rules ...Rule) *rowRepository {
	repository := &rowRepository{rows: map[int64]Rule{}, nextID: 1}
	for _, rule := range rules {
		repository.rows[rule.ID] = rule
		if rule.ID >= repository.nextID {
			repository.nextID = rule.ID + 1
		}
	}
	return repository
}

func (repository *rowRepository) ListUserAgentRules(context.Context) ([]Rule, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.sorted(), nil
}

func (repository *rowRepository) sorted() []Rule {
	rules := make([]Rule, 0, len(repository.rows))
	for _, rule := range repository.rows {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func (repository *rowRepository) snapshot() []Rule {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.sorted()
}

func (repository *rowRepository) CreateUserAgentRule(_ context.Context, rule Rule) (Rule, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	rule.ID = repository.nextID
	repository.nextID++
	repository.rows[rule.ID] = rule
	return rule, nil
}

func (repository *rowRepository) UpdateUserAgentRule(_ context.Context, rule Rule) (Rule, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	if _, ok := repository.rows[rule.ID]; !ok {
		return Rule{}, ErrNotFound
	}
	repository.rows[rule.ID] = rule
	return rule, nil
}

func (repository *rowRepository) DeleteUserAgentRule(_ context.Context, id int64) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	delete(repository.rows, id)
	return nil
}

// frozenService pins the clock, so only the version bump keeps two writes
// apart.
func frozenService(t *testing.T) (*Service, *rowRepository) {
	t.Helper()
	repository := newRowRepository(DefaultRule(100), Rule{
		ID: 2, Name: "deepseek", Enabled: true, ModelPattern: `^deepseek`, UserAgentPattern: ` Approved `, CreatedAtNS: 50, UpdatedAtNS: 60,
	})
	service, err := New(context.Background(), repository)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(0, 1000) }
	return service, repository
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }

func asMap(t *testing.T, rule Rule) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestPatchChangesOnlyTheGivenField(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	before, _ := service.Get(2)

	// The regression this exists for: a whole-object replace that omits
	// enabled disables the rule. A patch that sets only the name must not.
	patched, err := service.Patch(ctx, 2, before.Version(), RulePatch{Name: stringPtr("  renamed  ")})
	if err != nil {
		t.Fatal(err)
	}
	beforeFields, afterFields := asMap(t, before), asMap(t, patched)
	for field, value := range beforeFields {
		switch field {
		case "name":
			if afterFields[field] != "renamed" {
				t.Fatalf("name = %v", afterFields[field])
			}
		case "updated_at_ns":
			if patched.Version() <= before.Version() {
				t.Fatalf("version did not advance: %d -> %d", before.Version(), patched.Version())
			}
		default:
			if !reflect.DeepEqual(afterFields[field], value) {
				t.Fatalf("%s changed from %v to %v", field, value, afterFields[field])
			}
		}
	}
	if !patched.Enabled || patched.UserAgentPattern != " Approved " {
		t.Fatalf("patched = %+v", patched)
	}
	if got, _ := service.Get(2); !reflect.DeepEqual(got, patched) {
		t.Fatalf("published %+v, returned %+v", got, patched)
	}
	if row := repository.snapshot()[1]; !reflect.DeepEqual(row, patched) {
		t.Fatalf("stored %+v, returned %+v", row, patched)
	}

	// enabled alone, then a second write at the same clock reading: versions
	// must still differ.
	disabled, err := service.Patch(ctx, 2, patched.Version(), RulePatch{Enabled: boolPtr(false)})
	if err != nil || disabled.Enabled || disabled.Name != "renamed" || disabled.Version() == patched.Version() {
		t.Fatalf("disabled = %+v, %v", disabled, err)
	}
}

func TestPatchRefusesAStaleVersionAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	before := service.List()
	rows := repository.snapshot()
	snapshot := service.current.Load()

	for _, version := range []int64{59, 61, AnyVersion, 0} {
		if _, err := service.Patch(ctx, 2, version, RulePatch{Enabled: boolPtr(false)}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("patch at %d = %v", version, err)
		}
		if err := service.DeleteIfVersion(ctx, 2, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("delete at %d = %v", version, err)
		}
	}
	if _, err := service.Patch(ctx, 99, 60, RulePatch{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rule = %v", err)
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.snapshot(), rows) || service.current.Load() != snapshot || !reflect.DeepEqual(service.List(), before) {
		t.Fatal("a refused write changed something")
	}
}

func TestChecksMatchTheRealWriteAndChangeNothing(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	rows := repository.snapshot()
	snapshot := service.current.Load()
	patch := RulePatch{Name: stringPtr(" checked "), ModelPattern: stringPtr(`(?i)^deep`)}

	planned, err := service.CheckPatch(2, 60, patch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckPatch(2, AnyVersion, patch); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CheckPatch(2, 59, patch); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale check = %v", err)
	}
	deleted, err := service.CheckDelete(2, 60)
	if err != nil || deleted.ID != 2 {
		t.Fatalf("check delete = %+v, %v", deleted, err)
	}
	created, err := service.CheckCreate(RulePatch{Name: stringPtr("new"), Enabled: boolPtr(true), ModelPattern: stringPtr("^m"), UserAgentPattern: stringPtr("^c")}, CreateOptions{})
	if err != nil || created.After.ID != 0 || created.After.CreatedAtNS != 0 || len(created.Changed) != 4 {
		t.Fatalf("check create = %+v, %v", created, err)
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.snapshot(), rows) || service.current.Load() != snapshot || service.current.Load().nextID != 3 {
		t.Fatal("a check changed the database, the snapshot or the next id")
	}

	applied, err := service.Patch(ctx, 2, 60, patch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(planned.Before, rows[1]) || !reflect.DeepEqual(planned.Changed, []string{"name", "model_pattern"}) {
		t.Fatalf("planned = %+v", planned)
	}
	want := planned.After
	want.UpdatedAtNS = applied.UpdatedAtNS
	if !reflect.DeepEqual(applied, want) || planned.After.UpdatedAtNS != 60 {
		t.Fatalf("applied %+v, planned %+v", applied, planned.After)
	}

	made, err := service.CreateFromPatch(ctx, RulePatch{Name: stringPtr("new"), Enabled: boolPtr(true), ModelPattern: stringPtr("^m"), UserAgentPattern: stringPtr("^c")}, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want = created.After
	want.ID, want.CreatedAtNS, want.UpdatedAtNS = made.ID, made.CreatedAtNS, made.UpdatedAtNS
	if !reflect.DeepEqual(made, want) || made.ID != 3 {
		t.Fatalf("created %+v, planned %+v", made, created.After)
	}
}

func TestAWebEditBetweenCheckAndPatchConflicts(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	planned, err := service.CheckPatch(2, AnyVersion, RulePatch{Enabled: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	// The web form resubmits the same values; only the version moves.
	current := planned.Before
	if _, err := service.Update(ctx, 2, RuleInput{Name: current.Name, Enabled: current.Enabled, ModelPattern: current.ModelPattern, UserAgentPattern: current.UserAgentPattern}); err != nil {
		t.Fatal(err)
	}
	rows := repository.snapshot()
	if _, err := service.Patch(ctx, 2, planned.Before.Version(), RulePatch{Enabled: boolPtr(false)}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("patch after a web edit = %v", err)
	}
	if err := service.DeleteIfVersion(ctx, 2, planned.Before.Version()); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("delete after a web edit = %v", err)
	}
	if !reflect.DeepEqual(repository.snapshot(), rows) {
		t.Fatal("refused write changed the database")
	}
}

func TestDeleteIfVersion(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	if err := service.DeleteIfVersion(ctx, 2, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(2); !errors.Is(err, ErrNotFound) || len(repository.snapshot()) != 1 {
		t.Fatalf("rule 2 still present: %v", err)
	}
	if err := service.DeleteIfVersion(ctx, 2, 60); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestCreateRefusesADuplicateNameWithTheExistingID(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenService(t)
	patch := RulePatch{Name: stringPtr("  deepseek "), Enabled: boolPtr(true), ModelPattern: stringPtr("^x"), UserAgentPattern: stringPtr("^y")}
	for _, call := range []func() error{
		func() error {
			_, err := service.CheckCreate(patch, CreateOptions{RejectDuplicateName: true})
			return err
		},
		func() error {
			_, err := service.CreateFromPatch(ctx, patch, CreateOptions{RejectDuplicateName: true})
			return err
		},
	} {
		err := call()
		var exists *AlreadyExistsError
		if !errors.Is(err, ErrAlreadyExists) || !errors.As(err, &exists) || exists.ID != 2 {
			t.Fatalf("duplicate = %v", err)
		}
	}
	if repository.writes != 0 {
		t.Fatal("a refused create wrote")
	}
	// A different case is a different name, and without the option the
	// existing behaviour (duplicates allowed) is kept.
	if _, err := service.CreateFromPatch(ctx, RulePatch{Name: stringPtr("DeepSeek"), Enabled: boolPtr(true), ModelPattern: stringPtr("^x"), UserAgentPattern: stringPtr("^y")}, CreateOptions{RejectDuplicateName: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateFromPatch(ctx, patch, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, RuleInput{Name: "deepseek", Enabled: true, ModelPattern: "^x", UserAgentPattern: "^y"}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateFromPatchRequiresEveryField(t *testing.T) {
	service, _ := frozenService(t)
	_, err := service.CheckCreate(RulePatch{Name: stringPtr("n"), ModelPattern: stringPtr("^m"), UserAgentPattern: stringPtr("^c")}, CreateOptions{})
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.Field != "enabled" || invalid.Reason != ReasonRequired || !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("missing enabled = %v", err)
	}
}

func TestValidationErrorsNameTheFieldAndKeepTheirText(t *testing.T) {
	service, _ := frozenService(t)
	cases := []struct {
		patch  RulePatch
		field  string
		reason string
		text   string
	}{
		{RulePatch{Name: stringPtr("   ")}, "name", ReasonEmpty, "invalid user agent rule: rule name is required and must be at most 128 bytes"},
		{RulePatch{ModelPattern: stringPtr("[")}, "model_pattern", ReasonInvalidRegexp, "invalid user agent rule: invalid model regular expression"},
		{RulePatch{UserAgentPattern: stringPtr(" ")}, "user_agent_pattern", ReasonEmpty, "invalid user agent rule: user agent pattern is required and must be at most 2048 bytes"},
		{RulePatch{UserAgentPattern: stringPtr("(")}, "user_agent_pattern", ReasonInvalidRegexp, "invalid user agent rule: invalid user agent regular expression"},
	}
	for _, test := range cases {
		_, err := service.CheckPatch(2, 60, test.patch)
		var invalid *ValidationError
		if !errors.As(err, &invalid) || invalid.Field != test.field || invalid.Reason != test.reason || err.Error() != test.text || !errors.Is(err, ErrInvalidRule) {
			t.Fatalf("%+v = %v (%+v)", test.patch, err, invalid)
		}
		// The web entry fails with the same text.
		rule, _ := service.Get(2)
		input := RuleInput{Name: rule.Name, Enabled: rule.Enabled, ModelPattern: rule.ModelPattern, UserAgentPattern: rule.UserAgentPattern}
		merged := mergePatch(rule, test.patch)
		input.Name, input.ModelPattern, input.UserAgentPattern = merged.Name, merged.ModelPattern, merged.UserAgentPattern
		if _, err := service.Update(context.Background(), 2, input); err == nil || err.Error() != test.text {
			t.Fatalf("web update = %v, want %q", err, test.text)
		}
	}
}

func TestRulePatchDecodesStrictly(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{"enabled":false,"priority":1}`))
	decoder.DisallowUnknownFields()
	var patch RulePatch
	if err := decoder.Decode(&patch); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &patch); err != nil || patch.Enabled == nil || *patch.Enabled || patch.Name != nil {
		t.Fatalf("patch = %+v, %v", patch, err)
	}
}
