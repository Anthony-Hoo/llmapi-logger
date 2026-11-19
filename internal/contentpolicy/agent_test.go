package contentpolicy

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

// rowRepository keeps rows like a database and counts writes.
type rowRepository struct {
	mu     sync.Mutex
	rows   map[int64]Rule
	nextID int64
	writes int
}

func newRowRepository(rules ...Rule) *rowRepository {
	repository := &rowRepository{rows: map[int64]Rule{}, nextID: 1}
	for _, rule := range rules {
		repository.rows[rule.ID] = cloneRule(rule)
		if rule.ID >= repository.nextID {
			repository.nextID = rule.ID + 1
		}
	}
	return repository
}

func (repository *rowRepository) ListContentPolicyRules(context.Context) ([]Rule, error) {
	return repository.snapshot(), nil
}

func (repository *rowRepository) snapshot() []Rule {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	rules := make([]Rule, 0, len(repository.rows))
	for _, rule := range repository.rows {
		rule := rule
		// Keep a nil list nil: a stored JSON null decodes to nil.
		if rule.ScanScopes != nil {
			rule.ScanScopes = append([]string{}, rule.ScanScopes...)
		}
		rule.Keywords = append([]string(nil), rule.Keywords...)
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func (repository *rowRepository) CreateContentPolicyRule(_ context.Context, rule Rule) (Rule, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	rule.ID = repository.nextID
	repository.nextID++
	repository.rows[rule.ID] = cloneRule(rule)
	return rule, nil
}

func (repository *rowRepository) UpdateContentPolicyRule(_ context.Context, rule Rule) (Rule, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	if _, ok := repository.rows[rule.ID]; !ok {
		return Rule{}, ErrNotFound
	}
	repository.rows[rule.ID] = cloneRule(rule)
	return rule, nil
}

func (repository *rowRepository) DeleteContentPolicyRule(_ context.Context, id int64) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.writes++
	delete(repository.rows, id)
	return nil
}

func storedRule() Rule {
	return Rule{
		ID: 7, Name: "secrets", Enabled: true, Action: ActionDryRun, ModelPattern: `^gpt`,
		ScanScopes: []string{ScopeLatestUser, ScopeToolResults}, Keywords: []string{"Password", "api key"},
		CreatedAtNS: 50, UpdatedAtNS: 60,
	}
}

func frozenPolicyService(t *testing.T, rules ...Rule) (*Service, *rowRepository) {
	t.Helper()
	if len(rules) == 0 {
		rules = []Rule{storedRule()}
	}
	repository := newRowRepository(rules...)
	service, err := New(context.Background(), repository, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(0, 1000) }
	return service, repository
}

func strPtr(value string) *string        { return &value }
func boolPtr(value bool) *bool           { return &value }
func listPtr(values ...string) *[]string { return &values }

func fieldsOf(t *testing.T, rule Rule) map[string]any {
	t.Helper()
	encoded, _ := json.Marshal(rule)
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestPolicyPatchChangesOnlyTheGivenField(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name  string
		set   RulePatch
		field string
	}{
		{"enabled", RulePatch{Enabled: boolPtr(false)}, "enabled"},
		{"name", RulePatch{Name: strPtr(" renamed ")}, "name"},
		{"action", RulePatch{Action: strPtr(ActionBlock)}, "action"},
		{"model_pattern", RulePatch{ModelPattern: strPtr("  ^claude ")}, "model_pattern"},
		{"keywords", RulePatch{Keywords: listPtr("x")}, "keywords"},
		{"scan_scopes", RulePatch{ScanScopes: listPtr(ScopeSystem)}, "scan_scopes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, repository := frozenPolicyService(t)
			before, _ := service.Get(7)
			patched, err := service.Patch(ctx, 7, before.Version(), RuleChange{Set: test.set})
			if err != nil {
				t.Fatal(err)
			}
			beforeFields, afterFields := fieldsOf(t, before), fieldsOf(t, patched)
			for field, value := range beforeFields {
				if field == test.field || field == "updated_at_ns" {
					continue
				}
				if !reflect.DeepEqual(afterFields[field], value) {
					t.Fatalf("%s changed from %v to %v", field, value, afterFields[field])
				}
			}
			if reflect.DeepEqual(afterFields[test.field], beforeFields[test.field]) || patched.Version() <= before.Version() {
				t.Fatalf("%s did not change: %+v", test.field, patched)
			}
			if patched.Name != strings.TrimSpace(patched.Name) || patched.ModelPattern != strings.TrimSpace(patched.ModelPattern) {
				t.Fatalf("form trimming not applied: %+v", patched)
			}
			if stored := repository.snapshot()[0]; !reflect.DeepEqual(stored, patched) {
				t.Fatalf("stored %+v, returned %+v", stored, patched)
			}
		})
	}
}

func TestPolicyStaleVersionIsRefusedAndNothingChanges(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenPolicyService(t)
	rows, snapshot := repository.snapshot(), service.current.Load()
	for _, version := range []int64{59, 61, AnyVersion} {
		if _, err := service.Patch(ctx, 7, version, RuleChange{Set: RulePatch{Enabled: boolPtr(false)}}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("patch at %d = %v", version, err)
		}
		if err := service.DeleteIfVersion(ctx, 7, version); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("delete at %d = %v", version, err)
		}
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.snapshot(), rows) || service.current.Load() != snapshot {
		t.Fatal("a refused write changed something")
	}
}

func TestPolicyChecksMatchTheRealWriteAndChangeNothing(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenPolicyService(t)
	rows, snapshot := repository.snapshot(), service.current.Load()
	change := RuleChange{
		Set:    RulePatch{Name: strPtr("checked")},
		Add:    RuleListEdit{Keywords: []string{"token"}, ScanScopes: []string{ScopeSystem}},
		Remove: RuleListEdit{Keywords: []string{" PASSWORD "}},
	}
	planned, err := service.CheckPatch(7, 60, change)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := service.CheckDelete(7, AnyVersion)
	if err != nil || !reflect.DeepEqual(deleted, rows[0]) {
		t.Fatalf("check delete = %+v, %v", deleted, err)
	}
	create := RulePatch{Name: strPtr(" new "), Enabled: boolPtr(true), Action: strPtr(ActionBlock), Keywords: listPtr("a", "A ", "b")}
	plannedCreate, err := service.CheckCreate(create, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if repository.writes != 0 || !reflect.DeepEqual(repository.snapshot(), rows) || service.current.Load() != snapshot {
		t.Fatal("a check changed the database or the snapshot")
	}
	if want := []string{"name", "scan_scopes", "keywords"}; !reflect.DeepEqual(planned.Changed, want) {
		t.Fatalf("changed = %v", planned.Changed)
	}
	if !reflect.DeepEqual(planned.After.Keywords, []string{"api key", "token"}) ||
		!reflect.DeepEqual(planned.After.ScanScopes, []string{ScopeLatestUser, ScopeToolResults, ScopeSystem}) {
		t.Fatalf("planned after = %+v", planned.After)
	}

	applied, err := service.Patch(ctx, 7, 60, change)
	if err != nil {
		t.Fatal(err)
	}
	want := planned.After
	want.UpdatedAtNS = applied.UpdatedAtNS
	if !reflect.DeepEqual(applied, want) || planned.After.UpdatedAtNS != 60 {
		t.Fatalf("applied %+v, planned %+v", applied, planned.After)
	}

	made, err := service.CreateFromPatch(ctx, create, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want = plannedCreate.After
	want.ID, want.CreatedAtNS, want.UpdatedAtNS = made.ID, made.CreatedAtNS, made.UpdatedAtNS
	if !reflect.DeepEqual(made, want) || plannedCreate.After.ID != 0 || made.Name != "new" ||
		!reflect.DeepEqual(made.Keywords, []string{"a", "b"}) || !reflect.DeepEqual(made.ScanScopes, AllScanScopes) {
		t.Fatalf("created %+v, planned %+v", made, plannedCreate.After)
	}
}

func TestPolicyListEdits(t *testing.T) {
	service, _ := frozenPolicyService(t)
	cases := []struct {
		name     string
		change   RuleChange
		keywords []string
		scopes   []string
		reason   string
		field    string
	}{
		{name: "add a keyword differing only by case and spaces is a no-op",
			change: RuleChange{Add: RuleListEdit{Keywords: []string{"  PASSWORD "}}}, keywords: []string{"Password", "api key"}},
		{name: "remove matches by trimmed lower case",
			change: RuleChange{Remove: RuleListEdit{Keywords: []string{"API KEY  "}}}, keywords: []string{"Password"}},
		{name: "add then normalise",
			change: RuleChange{Add: RuleListEdit{Keywords: []string{" new one "}}}, keywords: []string{"Password", "api key", "new one"}},
		{name: "remove an absent keyword",
			change: RuleChange{Remove: RuleListEdit{Keywords: []string{"nope"}}}, field: "keywords", reason: ReasonNotPresent},
		{name: "removing every keyword fails validation",
			change: RuleChange{Remove: RuleListEdit{Keywords: []string{"password", "api key"}}}, field: "keywords", reason: ReasonEmpty},
		{name: "add and remove the same keyword",
			change: RuleChange{Add: RuleListEdit{Keywords: []string{"x"}}, Remove: RuleListEdit{Keywords: []string{" X"}}}, field: "keywords", reason: ReasonAddAndRemove},
		{name: "set and add the same list",
			change: RuleChange{Set: RulePatch{Keywords: listPtr("a")}, Add: RuleListEdit{Keywords: []string{"b"}}}, field: "keywords", reason: ReasonConflictingEdit},
		{name: "set and remove scopes",
			change: RuleChange{Set: RulePatch{ScanScopes: listPtr(ScopeSystem)}, Remove: RuleListEdit{ScanScopes: []string{ScopeLatestUser}}}, field: "scan_scopes", reason: ReasonConflictingEdit},
		{name: "scope add is exact after trimming",
			change: RuleChange{Add: RuleListEdit{ScanScopes: []string{" " + ScopeToolResults, ScopeAssistant}}}, scopes: []string{ScopeLatestUser, ScopeToolResults, ScopeAssistant}},
		{name: "scope remove",
			change: RuleChange{Remove: RuleListEdit{ScanScopes: []string{ScopeLatestUser}}}, scopes: []string{ScopeToolResults}},
		{name: "scope compare is case sensitive",
			change: RuleChange{Remove: RuleListEdit{ScanScopes: []string{"LATEST_USER"}}}, field: "scan_scopes", reason: ReasonNotPresent},
		{name: "unknown scope",
			change: RuleChange{Add: RuleListEdit{ScanScopes: []string{"everything"}}}, field: "scan_scopes", reason: ReasonInvalidValue},
		{name: "removing every scope is an empty list, not all scopes",
			change: RuleChange{Remove: RuleListEdit{ScanScopes: []string{ScopeLatestUser, ScopeToolResults}}}, field: "scan_scopes", reason: ReasonEmpty},
		{name: "setting an empty scope list is refused",
			change: RuleChange{Set: RulePatch{ScanScopes: listPtr()}}, field: "scan_scopes", reason: ReasonEmpty},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			diff, err := service.CheckPatch(7, 60, test.change)
			if test.reason != "" {
				var invalid *ValidationError
				if !errors.As(err, &invalid) || invalid.Field != test.field || invalid.Reason != test.reason || !errors.Is(err, ErrInvalidRule) {
					t.Fatalf("err = %v (%+v)", err, invalid)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.keywords != nil && !reflect.DeepEqual(diff.After.Keywords, test.keywords) {
				t.Fatalf("keywords = %q", diff.After.Keywords)
			}
			if test.scopes != nil && !reflect.DeepEqual(diff.After.ScanScopes, test.scopes) {
				t.Fatalf("scopes = %q", diff.After.ScanScopes)
			}
		})
	}
}

// A stored rule without scan scopes (a JSON null column) is shown by the web
// edit form with all seven ticked; an edit that does not touch the scopes
// saves all seven, and add/remove start from all seven.
func TestPolicyEmptyStoredScopesAreSubstituted(t *testing.T) {
	ctx := context.Background()
	legacy := storedRule()
	legacy.ScanScopes = nil
	service, repository := frozenPolicyService(t, legacy)
	if stored := repository.snapshot()[0]; stored.ScanScopes != nil {
		t.Fatalf("fixture lost its nil scopes: %+v", stored)
	}

	diff, err := service.CheckPatch(7, 60, RuleChange{Set: RulePatch{Enabled: boolPtr(false)}})
	if err != nil || !diff.ScopesSubstituted || !reflect.DeepEqual(diff.After.ScanScopes, AllScanScopes) {
		t.Fatalf("diff = %+v, %v", diff, err)
	}
	diff, err = service.CheckPatch(7, 60, RuleChange{Remove: RuleListEdit{ScanScopes: []string{ScopeSystem}}})
	if err != nil || !diff.ScopesSubstituted || !reflect.DeepEqual(diff.After.ScanScopes, AllScanScopes[1:]) {
		t.Fatalf("remove from substituted = %+v, %v", diff, err)
	}
	diff, err = service.CheckPatch(7, 60, RuleChange{Set: RulePatch{ScanScopes: listPtr(ScopeSystem)}})
	if err != nil || diff.ScopesSubstituted {
		t.Fatalf("explicit scopes = %+v, %v", diff, err)
	}
	patched, err := service.Patch(ctx, 7, 60, RuleChange{Set: RulePatch{Enabled: boolPtr(false)}})
	if err != nil || !reflect.DeepEqual(patched.ScanScopes, AllScanScopes) || !reflect.DeepEqual(repository.snapshot()[0].ScanScopes, AllScanScopes) {
		t.Fatalf("patched = %+v, %v", patched, err)
	}
}

func TestPolicyWebEditBetweenCheckAndPatchConflicts(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenPolicyService(t)
	planned, err := service.CheckPatch(7, AnyVersion, RuleChange{Set: RulePatch{Enabled: boolPtr(false)}})
	if err != nil {
		t.Fatal(err)
	}
	current := planned.Before
	if _, err := service.Update(ctx, 7, RuleInput{Name: current.Name, Enabled: current.Enabled, Action: current.Action, ModelPattern: current.ModelPattern, ScanScopes: current.ScanScopes, Keywords: current.Keywords}); err != nil {
		t.Fatal(err)
	}
	rows := repository.snapshot()
	if _, err := service.Patch(ctx, 7, current.Version(), RuleChange{Set: RulePatch{Enabled: boolPtr(false)}}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("patch after a web edit = %v", err)
	}
	if !reflect.DeepEqual(repository.snapshot(), rows) {
		t.Fatal("refused patch wrote")
	}
}

func TestPolicyCreateDuplicateAndRequiredFields(t *testing.T) {
	ctx := context.Background()
	service, repository := frozenPolicyService(t)
	duplicate := RulePatch{Name: strPtr(" secrets "), Enabled: boolPtr(true), Action: strPtr(ActionBlock), Keywords: listPtr("k")}
	for _, call := range []func() error{
		func() error {
			_, err := service.CheckCreate(duplicate, CreateOptions{RejectDuplicateName: true})
			return err
		},
		func() error {
			_, err := service.CreateFromPatch(ctx, duplicate, CreateOptions{RejectDuplicateName: true})
			return err
		},
	} {
		var exists *AlreadyExistsError
		if err := call(); !errors.Is(err, ErrAlreadyExists) || !errors.As(err, &exists) || exists.ID != 7 {
			t.Fatalf("duplicate = %v", err)
		}
	}
	if repository.writes != 0 {
		t.Fatal("a refused create wrote")
	}
	_, err := service.CheckCreate(RulePatch{Name: strPtr("n"), Enabled: boolPtr(true), Keywords: listPtr("k")}, CreateOptions{})
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.Field != "action" || invalid.Reason != ReasonRequired {
		t.Fatalf("missing action = %v", err)
	}
	if _, err := service.Create(ctx, RuleInput{Name: "secrets", Keywords: []string{"k"}}); err != nil {
		t.Fatalf("web create no longer allows a duplicate name: %v", err)
	}
}

func TestPolicyValidationErrorsKeepTheirText(t *testing.T) {
	service, _ := frozenPolicyService(t)
	for _, test := range []struct {
		set    RulePatch
		field  string
		reason string
		text   string
	}{
		{RulePatch{Name: strPtr(" ")}, "name", ReasonEmpty, "invalid content policy rule: name is required and must be at most 128 bytes"},
		{RulePatch{Action: strPtr("allow")}, "action", ReasonInvalidValue, "invalid content policy rule: action must be block or dry_run"},
		{RulePatch{ModelPattern: strPtr("(")}, "model_pattern", ReasonInvalidRegexp, "invalid content policy rule: invalid model regular expression"},
		{RulePatch{Keywords: listPtr("a\nb")}, "keywords", ReasonInvalidCharacter, "invalid content policy rule: a keyword must be a single line"},
	} {
		_, err := service.CheckPatch(7, 60, RuleChange{Set: test.set})
		var invalid *ValidationError
		if !errors.As(err, &invalid) || invalid.Field != test.field || invalid.Reason != test.reason || err.Error() != test.text {
			t.Fatalf("%+v = %v", test.set, err)
		}
	}
	// The web entry keeps the same text, including for the case only the
	// service rejects (the form trims it).
	_, err := service.Update(context.Background(), 7, RuleInput{Name: "n", ModelPattern: " ^x", Keywords: []string{"k"}})
	var invalid *ValidationError
	if err == nil || err.Error() != "invalid content policy rule: model pattern must not have surrounding whitespace and must be at most 2048 bytes" ||
		!errors.As(err, &invalid) || invalid.Reason != ReasonSurroundingWhitespace {
		t.Fatalf("web update = %v", err)
	}
}

func TestPolicyChangeDecodesStrictly(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{"keywords":["a"],"name":"x"}`))
	decoder.DisallowUnknownFields()
	var add RuleListEdit
	if err := decoder.Decode(&add); err == nil {
		t.Fatal("a scalar field was accepted as a list edit")
	}
}

func TestPolicyExplicitEmptyActionIsRefused(t *testing.T) {
	service, _ := frozenPolicyService(t)
	for _, call := range []func() error{
		func() error {
			_, err := service.CheckPatch(7, 60, RuleChange{Set: RulePatch{Action: strPtr(" ")}})
			return err
		},
		func() error {
			_, err := service.CheckCreate(RulePatch{Name: strPtr("n"), Enabled: boolPtr(true), Action: strPtr(""), Keywords: listPtr("k")}, CreateOptions{})
			return err
		},
	} {
		var invalid *ValidationError
		if err := call(); !errors.As(err, &invalid) || invalid.Field != "action" || invalid.Reason != ReasonInvalidValue {
			t.Fatalf("empty action = %v", err)
		}
	}
	// The web route keeps defaulting an empty action to block.
	if rule, err := service.Create(context.Background(), RuleInput{Name: "web", Keywords: []string{"k"}}); err != nil || rule.Action != ActionBlock {
		t.Fatalf("web create = %+v, %v", rule, err)
	}
}

func TestPolicyVersionsNeverRepeat(t *testing.T) {
	ctx := context.Background()
	service, _ := frozenPolicyService(t)
	seen := map[int64]bool{60: true}
	rule, _ := service.Get(7)
	for range 3 {
		var err error
		rule, err = service.Patch(ctx, 7, rule.Version(), RuleChange{})
		if err != nil || seen[rule.Version()] {
			t.Fatalf("version %d repeated (%v)", rule.Version(), err)
		}
		seen[rule.Version()] = true
	}
	if err := service.DeleteIfVersion(ctx, 7, rule.Version()); err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateFromPatch(ctx, RulePatch{Name: strPtr("n"), Enabled: boolPtr(true), Action: strPtr(ActionBlock), Keywords: listPtr("k")}, CreateOptions{})
	if err != nil || seen[created.Version()] {
		t.Fatalf("created version %d repeated (%v)", created.Version(), err)
	}
}
