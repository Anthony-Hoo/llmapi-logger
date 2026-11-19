package uaguard

import (
	"context"
	"errors"
	"strings"
)

// Entry points for callers that edit one field at a time (the agent facade,
// doc/features/25-agent-access.md section 8.2). The web routes replace a
// whole rule; these merge only the fields given, refuse to write over a
// change made since the caller read the rule, and can run every check without
// saving. They reuse compileRule and the commit path of Create, Update and
// Delete, so a rule saved here is exactly what the web form would save.

// AnyVersion makes a Check… entry skip the version comparison: a plan that
// has not been given an expected version yet. The writing entries never
// accept it, because no rule has a negative version.
const AnyVersion int64 = -1

var (
	// ErrVersionConflict means the rule changed (or was replaced) since the
	// caller read the version it passed. Nothing was written.
	ErrVersionConflict = errors.New("user agent rule changed since it was read")
	// ErrAlreadyExists is matched by *AlreadyExistsError, which carries the id
	// of the rule with the same name.
	ErrAlreadyExists = errors.New("a user agent rule with this name already exists")
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
// nanoseconds (UpdatedAtNS). Every write gives a rule a value greater than any
// version currently held by any rule (see Service.timestamp), so two
// successive writes never leave the same version.
func (rule Rule) Version() int64 { return rule.UpdatedAtNS }

// RulePatch names the fields to change; a nil field keeps its value. It has a
// field per editable column and nothing else, so a caller that decodes its
// input into it with json.Decoder.DisallowUnknownFields cannot set an unknown
// field silently. The JSON names are the ones the web API uses.
type RulePatch struct {
	Name             *string `json:"name,omitempty"`
	Enabled          *bool   `json:"enabled,omitempty"`
	ModelPattern     *string `json:"model_pattern,omitempty"`
	UserAgentPattern *string `json:"user_agent_pattern,omitempty"`
}

// CreateOptions adjusts CreateFromPatch and CheckCreate.
type CreateOptions struct {
	// RejectDuplicateName refuses the new rule when a rule with the same name
	// (both trimmed, compared exactly) exists, with an *AlreadyExistsError.
	// Create itself keeps allowing duplicates, as the web page does, and so
	// does the agent facade, which shows RuleDiff.SameName in its plan
	// instead of setting this.
	RejectDuplicateName bool
}

// RuleDiff is what a write did or would do. Before is the zero Rule for a
// create and After the zero Rule for a delete. Changed lists the JSON names of
// the editable fields whose value differs.
//
// A Check… entry allocates nothing: After of a planned create has ID 0 and
// zero timestamps, and After of a planned update keeps Before's UpdatedAtNS
// (the real write stamps a new version). Every other field is what the real
// write stores.
type RuleDiff struct {
	Before  Rule     `json:"before"`
	After   Rule     `json:"after"`
	Changed []string `json:"changed"`
	// SameName lists, for a planned create, the ids of the rules that already
	// have the new rule's name (both trimmed, compared exactly). A create is
	// not refused for it, as the web form does not refuse it; the caller shows
	// it so that a duplicate is a decision, not an accident.
	SameName []int64 `json:"same_name,omitempty"`
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
	if service == nil {
		return RuleDiff{}, errors.New("uaguard: nil service")
	}
	rules := service.List()
	rule, err := service.prepareCreate(rules, patch, options)
	if err != nil {
		return RuleDiff{}, err
	}
	rule.ID, rule.CreatedAtNS, rule.UpdatedAtNS = 0, 0, 0
	diff := diffOf(Rule{}, rule)
	for _, existing := range rules {
		if strings.TrimSpace(existing.Name) == rule.Name {
			diff.SameName = append(diff.SameName, existing.ID)
		}
	}
	return diff, nil
}

// CreateFromPatch creates a rule from a patch in which every field is
// required (a missing one is a *ValidationError with ReasonRequired), so the
// caller states enabled explicitly instead of inheriting a form default.
func (service *Service) CreateFromPatch(ctx context.Context, patch RulePatch, options CreateOptions) (Rule, error) {
	if service == nil {
		return Rule{}, errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return Rule{}, errors.New("uaguard: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rule, err := service.prepareCreate(service.List(), patch, options)
	if err != nil {
		return Rule{}, err
	}
	now := service.timestamp()
	rule.CreatedAtNS, rule.UpdatedAtNS = now, now
	if current := service.current.Load(); current != nil {
		rule.ID = current.nextID
	}
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitCreate(ctx, rule)
}

// prepareCreate is the shared, side-effect free half of a create. The new
// rule carries placeholder timestamps so the full validation can run.
func (service *Service) prepareCreate(rules []Rule, patch RulePatch, options CreateOptions) (Rule, error) {
	for _, required := range []struct {
		field   string
		missing bool
	}{
		{"name", patch.Name == nil}, {"enabled", patch.Enabled == nil},
		{"model_pattern", patch.ModelPattern == nil}, {"user_agent_pattern", patch.UserAgentPattern == nil},
	} {
		if required.missing {
			return Rule{}, invalidField(required.field, ReasonRequired, required.field+" is required")
		}
	}
	rule := mergePatch(Rule{CreatedAtNS: 1, UpdatedAtNS: 1}, patch)
	if _, err := compileRule(rule); err != nil {
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
func (service *Service) CheckPatch(id, expectedVersion int64, patch RulePatch) (RuleDiff, error) {
	if service == nil {
		return RuleDiff{}, errors.New("uaguard: nil service")
	}
	rules := service.List()
	index, err := findVersion(rules, id, expectedVersion)
	if err != nil {
		return RuleDiff{}, err
	}
	after := mergePatch(rules[index], patch)
	if _, err := compileRule(after); err != nil {
		return RuleDiff{}, err
	}
	return diffOf(rules[index], after), nil
}

// Patch merges the given fields into rule id and saves it, only when the
// rule's version still equals expectedVersion; otherwise ErrVersionConflict
// and nothing is written. The merged rule goes through the same validation
// and the same persist-then-publish path as Update.
func (service *Service) Patch(ctx context.Context, id, expectedVersion int64, patch RulePatch) (Rule, error) {
	if service == nil {
		return Rule{}, errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return Rule{}, errors.New("uaguard: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rules := service.List()
	index, err := findVersion(rules, id, exact(expectedVersion))
	if err != nil {
		return Rule{}, err
	}
	rule := mergePatch(rules[index], patch)
	rule.UpdatedAtNS = service.timestamp()
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitUpdate(ctx, rules, index, rule)
}

// CheckDelete reports the rule DeleteIfVersion would remove. expectedVersion
// may be AnyVersion.
func (service *Service) CheckDelete(id, expectedVersion int64) (Rule, error) {
	if service == nil {
		return Rule{}, errors.New("uaguard: nil service")
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
	if service == nil {
		return errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return errors.New("uaguard: nil context")
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

// exact turns AnyVersion into a value no rule has, so a writing entry never
// skips the comparison.
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

// mergePatch applies the patch the way Update applies a RuleInput: the name
// is trimmed, the patterns are kept as given (surrounding spaces are part of a
// regular expression, and the web form does not trim them either).
func mergePatch(rule Rule, patch RulePatch) Rule {
	if patch.Name != nil {
		rule.Name = *patch.Name
	}
	if patch.Enabled != nil {
		rule.Enabled = *patch.Enabled
	}
	if patch.ModelPattern != nil {
		rule.ModelPattern = *patch.ModelPattern
	}
	if patch.UserAgentPattern != nil {
		rule.UserAgentPattern = *patch.UserAgentPattern
	}
	rule.Name = strings.TrimSpace(rule.Name)
	return rule
}

func diffOf(before, after Rule) RuleDiff {
	changed := []string{}
	if before.Name != after.Name {
		changed = append(changed, "name")
	}
	if before.Enabled != after.Enabled {
		changed = append(changed, "enabled")
	}
	if before.ModelPattern != after.ModelPattern {
		changed = append(changed, "model_pattern")
	}
	if before.UserAgentPattern != after.UserAgentPattern {
		changed = append(changed, "user_agent_pattern")
	}
	return RuleDiff{Before: before, After: after, Changed: changed}
}

// Stable reasons of a ValidationError.
const (
	ReasonEmpty            = "empty"
	ReasonTooLong          = "too_long"
	ReasonInvalidCharacter = "invalid_character"
	ReasonInvalidRegexp    = "invalid_regexp"
	ReasonRequired         = "required"
)

// ValidationError says which field of a rule failed and why. Field is the
// JSON name of the field, Reason one of the Reason… constants, Message the
// safe sentence the error has always carried (it never contains the submitted
// value). It unwraps to ErrInvalidRule and its text is unchanged, so the web
// handler's mapping does not change.
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
