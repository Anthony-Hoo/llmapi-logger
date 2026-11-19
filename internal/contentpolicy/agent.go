package contentpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Entry points for callers that edit one field at a time (the agent facade,
// doc/features/25-agent-access.md section 8.2). The web routes replace a
// whole rule; these merge only the fields given, refuse to write over a
// change made since the caller read the rule, and can run every check without
// saving. The merged rule goes through normalizeInput and compileRule and the
// same commit path as Create, Update and Delete.
//
// They also do what the web form does in the browser before it submits
// (contract section 4.7), so a rule saved here equals one saved from the
// page: name and model_pattern are trimmed, and a stored rule whose
// scan_scopes list is empty is edited as if all seven scopes were selected.

// AnyVersion makes a Check… entry skip the version comparison. The writing
// entries never accept it, because no rule has a negative version.
const AnyVersion int64 = -1

var (
	// ErrVersionConflict means the rule changed since the caller read the
	// version it passed. Nothing was written.
	ErrVersionConflict = errors.New("content policy rule changed since it was read")
	// ErrAlreadyExists is matched by *AlreadyExistsError.
	ErrAlreadyExists = errors.New("a content policy rule with this name already exists")
)

// AlreadyExistsError is returned when CreateOptions.RejectDuplicateName finds
// a rule with the same trimmed name. ID lets a caller that retried after a
// timeout find the rule its first attempt created.
type AlreadyExistsError struct {
	ID int64
}

func (err *AlreadyExistsError) Error() string { return ErrAlreadyExists.Error() }

// Is makes errors.Is(err, ErrAlreadyExists) hold.
func (err *AlreadyExistsError) Is(target error) bool { return target == ErrAlreadyExists }

// Version returns the rule's version: its last-modified time in Unix
// nanoseconds (UpdatedAtNS). Every write stamps a value greater than any
// version a rule currently holds (Service.timestamp), so two successive
// writes never leave the same version.
func (rule Rule) Version() int64 { return rule.UpdatedAtNS }

// RulePatch names the scalar fields to change and the lists to replace as a
// whole; a nil field keeps its value. A list set to an empty slice is
// submitted empty (and scan_scopes then fails validation, as an empty list
// does on the web route). It has one field per editable column and nothing
// else, so decoding into it with DisallowUnknownFields rejects an unknown
// field. The JSON names are the web API's.
type RulePatch struct {
	Name         *string   `json:"name,omitempty"`
	Enabled      *bool     `json:"enabled,omitempty"`
	Action       *string   `json:"action,omitempty"`
	ModelPattern *string   `json:"model_pattern,omitempty"`
	ScanScopes   *[]string `json:"scan_scopes,omitempty"`
	Keywords     *[]string `json:"keywords,omitempty"`
}

// RuleListEdit lists elements to add to or remove from the two list fields.
// Elements compare the way normalisation compares them: keywords trimmed and
// case-insensitive, scan scopes trimmed and exact. Adding an element already
// present is a no-op; removing one that is absent is a *ValidationError
// (ReasonNotPresent), so a mistyped value is not silently ignored.
type RuleListEdit struct {
	ScanScopes []string `json:"scan_scopes,omitempty"`
	Keywords   []string `json:"keywords,omitempty"`
}

// RuleChange is one patch: fields to set, list elements to add and remove.
// A list may not be both set and edited in one change.
type RuleChange struct {
	Set    RulePatch
	Add    RuleListEdit
	Remove RuleListEdit
}

// CreateOptions adjusts CreateFromPatch and CheckCreate.
type CreateOptions struct {
	// RejectDuplicateName refuses the new rule when a rule with the same name
	// (both trimmed, compared exactly) exists, with an *AlreadyExistsError.
	// Create itself keeps allowing duplicates, as the web page does.
	RejectDuplicateName bool
}

// RuleDiff is what a write did or would do. Before is the zero Rule for a
// create and After the zero Rule for a delete. Changed lists the JSON names of
// the editable fields whose value differs. ScopesSubstituted reports that the
// stored rule had no scan scopes and all seven were used in their place.
//
// A Check… entry allocates nothing: After of a planned create has ID 0 and
// zero timestamps, and After of a planned update keeps Before's UpdatedAtNS
// (the real write stamps a new version). Every other field is what the real
// write stores.
type RuleDiff struct {
	Before            Rule     `json:"before"`
	After             Rule     `json:"after"`
	Changed           []string `json:"changed"`
	ScopesSubstituted bool     `json:"scopes_substituted"`
}

// Get returns one active rule.
func (service *Service) Get(id int64) (Rule, error) {
	for _, rule := range service.List() {
		if rule.ID == id {
			return rule, nil
		}
	}
	return Rule{}, ErrNotFound
}

// CheckCreate runs every check CreateFromPatch runs, without saving.
func (service *Service) CheckCreate(patch RulePatch, options CreateOptions) (RuleDiff, error) {
	if !service.Available() {
		return RuleDiff{}, ErrUnavailable
	}
	rule, err := prepareCreate(service.List(), patch, options)
	if err != nil {
		return RuleDiff{}, err
	}
	rule.CreatedAtNS, rule.UpdatedAtNS = 0, 0
	return diffOf(Rule{}, rule, false), nil
}

// CreateFromPatch creates a rule from a patch in which name, enabled, action
// and keywords are required (a missing one is a *ValidationError with
// ReasonRequired), so the caller does not inherit the service default action
// "block" by omission. scan_scopes may be omitted: all seven, as on the form.
func (service *Service) CreateFromPatch(ctx context.Context, patch RulePatch, options CreateOptions) (Rule, error) {
	if !service.Available() {
		return Rule{}, ErrUnavailable
	}
	if ctx == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rule, err := prepareCreate(service.List(), patch, options)
	if err != nil {
		return Rule{}, err
	}
	now := service.timestamp()
	rule.CreatedAtNS, rule.UpdatedAtNS = now, now
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitCreate(ctx, rule)
}

func prepareCreate(rules []Rule, patch RulePatch, options CreateOptions) (Rule, error) {
	for _, required := range []struct {
		field   string
		missing bool
	}{
		{"name", patch.Name == nil}, {"enabled", patch.Enabled == nil},
		{"action", patch.Action == nil}, {"keywords", patch.Keywords == nil},
	} {
		if required.missing {
			return Rule{}, invalidField(required.field, ReasonRequired, required.field+" is required")
		}
	}
	rule, _, err := mergeChange(Rule{CreatedAtNS: 1, UpdatedAtNS: 1, ScanScopes: nil}, RuleChange{Set: patch}, false)
	if err != nil {
		return Rule{}, err
	}
	if options.RejectDuplicateName {
		for _, existing := range rules {
			if strings.TrimSpace(existing.Name) == rule.Name {
				return Rule{}, &AlreadyExistsError{ID: existing.ID}
			}
		}
	}
	return rule, nil
}

// CheckPatch runs every check Patch runs, without saving. expectedVersion may
// be AnyVersion.
func (service *Service) CheckPatch(id, expectedVersion int64, change RuleChange) (RuleDiff, error) {
	if !service.Available() {
		return RuleDiff{}, ErrUnavailable
	}
	rules := service.List()
	index, err := findVersion(rules, id, expectedVersion)
	if err != nil {
		return RuleDiff{}, err
	}
	after, substituted, err := mergeChange(rules[index], change, true)
	if err != nil {
		return RuleDiff{}, err
	}
	return diffOf(rules[index], after, substituted), nil
}

// Patch merges change into rule id and saves it, only when the rule's version
// still equals expectedVersion; otherwise ErrVersionConflict and nothing is
// written. Fields the change does not name keep their stored value.
func (service *Service) Patch(ctx context.Context, id, expectedVersion int64, change RuleChange) (Rule, error) {
	if !service.Available() {
		return Rule{}, ErrUnavailable
	}
	if ctx == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rules := service.List()
	index, err := findVersion(rules, id, exact(expectedVersion))
	if err != nil {
		return Rule{}, err
	}
	rule, _, err := mergeChange(rules[index], change, true)
	if err != nil {
		return Rule{}, err
	}
	rule.UpdatedAtNS = service.timestamp()
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitUpdate(ctx, rules, index, rule)
}

// CheckDelete reports the rule DeleteIfVersion would remove. expectedVersion
// may be AnyVersion.
func (service *Service) CheckDelete(id, expectedVersion int64) (Rule, error) {
	if !service.Available() {
		return Rule{}, ErrUnavailable
	}
	rules := service.List()
	index, err := findVersion(rules, id, expectedVersion)
	if err != nil {
		return Rule{}, err
	}
	return rules[index], nil
}

// DeleteIfVersion deletes rule id only when its version still equals
// expectedVersion.
func (service *Service) DeleteIfVersion(ctx context.Context, id, expectedVersion int64) error {
	if !service.Available() {
		return ErrUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("contentpolicy: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rules := service.List()
	index, err := findVersion(rules, id, exact(expectedVersion))
	if err != nil {
		return err
	}
	return service.commitDelete(ctx, rules, index, id)
}

func exact(version int64) int64 {
	if version < 0 {
		return -2
	}
	return version
}

func findVersion(rules []Rule, id, expectedVersion int64) (int, error) {
	for index := range rules {
		if rules[index].ID != id {
			continue
		}
		if expectedVersion != AnyVersion && rules[index].UpdatedAtNS != expectedVersion {
			return -1, ErrVersionConflict
		}
		return index, nil
	}
	return -1, ErrNotFound
}

// mergeChange applies a change to a stored rule and normalises the result
// with normalizeInput, as Update does. substitute enables the form's
// empty-scope substitution (an edit of a stored rule); the returned flag says
// whether it happened. The result keeps the stored id and timestamps and has
// passed compileRule.
func mergeChange(current Rule, change RuleChange, substitute bool) (Rule, bool, error) {
	rule := cloneRule(current)
	set := change.Set
	substituted := false
	if substitute && len(rule.ScanScopes) == 0 && set.ScanScopes == nil {
		rule.ScanScopes = DefaultScanScopes()
		substituted = true
	}
	if set.ScanScopes != nil && (len(change.Add.ScanScopes) > 0 || len(change.Remove.ScanScopes) > 0) {
		return Rule{}, false, invalidField("scan_scopes", ReasonConflictingEdit, "a list cannot be both replaced and edited")
	}
	if set.Keywords != nil && (len(change.Add.Keywords) > 0 || len(change.Remove.Keywords) > 0) {
		return Rule{}, false, invalidField("keywords", ReasonConflictingEdit, "a list cannot be both replaced and edited")
	}
	if set.Name != nil {
		rule.Name = *set.Name
	}
	if set.Enabled != nil {
		rule.Enabled = *set.Enabled
	}
	if set.Action != nil {
		// normalizeInput turns an empty action into "block", the web
		// form's default; an explicit empty action here is a mistake, not a
		// request to start blocking.
		if strings.TrimSpace(*set.Action) == "" {
			return Rule{}, false, invalidField("action", ReasonInvalidValue, "action must be block or dry_run")
		}
		rule.Action = *set.Action
	}
	if set.ModelPattern != nil {
		rule.ModelPattern = *set.ModelPattern
	}
	if set.ScanScopes != nil {
		rule.ScanScopes = append([]string{}, (*set.ScanScopes)...)
	}
	if set.Keywords != nil {
		rule.Keywords = append([]string{}, (*set.Keywords)...)
	}
	// What the form trims before it submits.
	rule.Name, rule.ModelPattern = strings.TrimSpace(rule.Name), strings.TrimSpace(rule.ModelPattern)

	var err error
	if rule.ScanScopes, err = editList("scan_scopes", rule.ScanScopes, change.Add.ScanScopes, change.Remove.ScanScopes, strings.TrimSpace); err != nil {
		return Rule{}, false, err
	}
	if rule.Keywords, err = editList("keywords", rule.Keywords, change.Add.Keywords, change.Remove.Keywords, keywordKey); err != nil {
		return Rule{}, false, err
	}
	normalized, err := normalizeInput(RuleInput{
		Name: rule.Name, Enabled: rule.Enabled, Action: rule.Action, ModelPattern: rule.ModelPattern,
		ScanScopes: rule.ScanScopes, Keywords: rule.Keywords,
	})
	if err != nil {
		return Rule{}, false, err
	}
	rule.Name, rule.Enabled, rule.Action, rule.ModelPattern = normalized.Name, normalized.Enabled, normalized.Action, normalized.ModelPattern
	rule.ScanScopes, rule.Keywords = normalized.ScanScopes, normalized.Keywords
	if _, err := compileRule(rule); err != nil {
		return Rule{}, false, err
	}
	return rule, substituted, nil
}

// keywordKey is how normalizeKeywords compares keywords.
func keywordKey(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

// editList removes, then adds, elements by key. The result is never nil, so
// an edit that empties a list reaches validation as an empty list rather
// than as "absent" (which normalizeScopes would turn into all scopes).
func editList(field string, list, add, remove []string, key func(string) string) ([]string, error) {
	out := append([]string{}, list...)
	if len(add) == 0 && len(remove) == 0 {
		if list == nil {
			return nil, nil
		}
		return out, nil
	}
	adding := map[string]bool{}
	for _, value := range add {
		adding[key(value)] = true
	}
	for _, value := range remove {
		wanted := key(value)
		if adding[wanted] {
			return nil, invalidField(field, ReasonAddAndRemove, "an element cannot be both added and removed")
		}
		kept := out[:0:0]
		for _, element := range out {
			if key(element) != wanted {
				kept = append(kept, element)
			}
		}
		if len(kept) == len(out) {
			return nil, invalidField(field, ReasonNotPresent, "an element to remove is not in the list")
		}
		out = kept
	}
	for _, value := range add {
		present := false
		for _, element := range out {
			if key(element) == key(value) {
				present = true
				break
			}
		}
		if !present {
			out = append(out, value)
		}
	}
	return out, nil
}

func diffOf(before, after Rule, substituted bool) RuleDiff {
	changed := []string{}
	if before.Name != after.Name {
		changed = append(changed, "name")
	}
	if before.Enabled != after.Enabled {
		changed = append(changed, "enabled")
	}
	if before.Action != after.Action {
		changed = append(changed, "action")
	}
	if before.ModelPattern != after.ModelPattern {
		changed = append(changed, "model_pattern")
	}
	if !sameStrings(before.ScanScopes, after.ScanScopes) {
		changed = append(changed, "scan_scopes")
	}
	if !sameStrings(before.Keywords, after.Keywords) {
		changed = append(changed, "keywords")
	}
	return RuleDiff{Before: before, After: after, Changed: changed, ScopesSubstituted: substituted}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Stable reasons of a ValidationError.
const (
	ReasonEmpty                 = "empty"
	ReasonTooLong               = "too_long"
	ReasonTooMany               = "too_many"
	ReasonInvalidCharacter      = "invalid_character"
	ReasonInvalidValue          = "invalid_value"
	ReasonInvalidRegexp         = "invalid_regexp"
	ReasonSurroundingWhitespace = "surrounding_whitespace"
	ReasonRequired              = "required"
	ReasonConflictingEdit       = "set_and_edited"
	ReasonAddAndRemove          = "added_and_removed"
	ReasonNotPresent            = "not_present"
)

// ValidationError says which field of a rule failed and why. Field is the
// JSON name of the field ("" for a fault of the stored row itself), Reason
// one of the Reason… constants and Message the safe sentence the error has
// always carried; it never contains a submitted keyword. It unwraps to
// ErrInvalidRule and its text is unchanged, so the web handler's mapping does
// not change.
type ValidationError struct {
	Field   string
	Reason  string
	Message string
}

func (err *ValidationError) Error() string { return ErrInvalidRule.Error() + ": " + err.Message }

// Unwrap makes errors.Is(err, ErrInvalidRule) hold.
func (err *ValidationError) Unwrap() error { return ErrInvalidRule }

func invalidField(field, reason, message string) error {
	return &ValidationError{Field: field, Reason: reason, Message: message}
}
