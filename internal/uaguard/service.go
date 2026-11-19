// Package uaguard provides dynamically configurable model and User-Agent
// allow rules for matched LLM API requests.
package uaguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/interceptor"
)

const (
	MaxPatternBytes = 2048
	MaxNameBytes    = 128

	InterceptorID = "user_agent_policy"
	BlockCode     = "user_agent_not_allowed"
)

var (
	ErrInvalidRule = errors.New("invalid user agent rule")
	ErrNotFound    = errors.New("user agent rule not found")
)

// Rule is the persisted public representation of one User-Agent policy.
type Rule struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	ModelPattern     string `json:"model_pattern"`
	UserAgentPattern string `json:"user_agent_pattern"`
	CreatedAtNS      int64  `json:"created_at_ns,string"`
	UpdatedAtNS      int64  `json:"updated_at_ns,string"`
}

// RuleInput is accepted by create and update operations.
type RuleInput struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	ModelPattern     string `json:"model_pattern"`
	UserAgentPattern string `json:"user_agent_pattern"`
}

// Repository persists rules in the same local database as audit evidence.
type Repository interface {
	ListUserAgentRules(context.Context) ([]Rule, error)
	CreateUserAgentRule(context.Context, Rule) (Rule, error)
	UpdateUserAgentRule(context.Context, Rule) (Rule, error)
	DeleteUserAgentRule(context.Context, int64) error
}

// RuleSet is the stable surface shared by the data-plane interceptor and the
// authenticated management API.
type RuleSet interface {
	interceptor.Interceptor
	List() []Rule
	Create(context.Context, RuleInput) (Rule, error)
	Update(context.Context, int64, RuleInput) (Rule, error)
	Delete(context.Context, int64) error
}

type compiledRule struct {
	rule      Rule
	model     *regexp.Regexp
	userAgent *regexp.Regexp
}

type snapshot struct {
	rules  []compiledRule
	public []Rule
	nextID int64
}

// Service owns the current compiled rule snapshot. Updates are serialized,
// persisted first, and then atomically published to request handlers.
type Service struct {
	repository Repository
	mu         sync.Mutex
	current    atomic.Pointer[snapshot]
	now        func() time.Time
}

// New loads and compiles persisted rules. A nil repository is supported for
// degraded audit mode and starts with the same default rule in memory.
func New(ctx context.Context, repository Repository) (*Service, error) {
	if ctx == nil {
		return nil, errors.New("uaguard: nil context")
	}
	service := &Service{repository: repository, now: time.Now}
	rules := []Rule{DefaultRule(time.Now().UnixNano())}
	if repository != nil {
		persisted, err := repository.ListUserAgentRules(ctx)
		if err != nil {
			return nil, fmt.Errorf("uaguard: load rules: %w", err)
		}
		rules = persisted
	}
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return nil, fmt.Errorf("uaguard: compile persisted rules: %w", err)
	}
	service.current.Store(compiled)
	return service, nil
}

// DefaultRule returns the initial enabled policy installed by the migration.
func DefaultRule(timestamp int64) Rule {
	if timestamp <= 0 {
		timestamp = 1
	}
	return Rule{
		ID:               1,
		Name:             "GPT models require Codex clients",
		Enabled:          true,
		ModelPattern:     "^gpt",
		UserAgentPattern: "^(codex-tui|Codex Desktop)",
		CreatedAtNS:      timestamp,
		UpdatedAtNS:      timestamp,
	}
}

// Requirements declares the bounded body buffer needed to read the model.
func (*Service) Requirements() interceptor.Requirements {
	return interceptor.Requirements{NeedsBody: true, MaxBodyBytes: interceptor.MaxBodyBytes}
}

// Check allows requests that do not match an enabled model rule. Every
// enabled rule matching the model must also match the inbound User-Agent.
func (service *Service) Check(_ context.Context, request interceptor.RequestView) (interceptor.Decision, error) {
	current := service.current.Load()
	if current == nil || len(current.rules) == 0 {
		return interceptor.Decision{Allow: true}, nil
	}
	model := request.PathParams()["model"]
	if body, ok := request.Body(); ok && body.Len() > 0 {
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(body.Open()).Decode(&payload); err == nil && payload.Model != "" {
			model = payload.Model
		}
	}
	if model == "" {
		return interceptor.Decision{Allow: true}, nil
	}
	userAgent := strings.Join(request.Headers().Values("User-Agent"), "\n")
	for _, rule := range current.rules {
		if !rule.rule.Enabled || !rule.model.MatchString(model) {
			continue
		}
		if !rule.userAgent.MatchString(userAgent) {
			return interceptor.Decision{
				StatusCode: http.StatusUnauthorized,
				BlockCode:  BlockCode,
			}, nil
		}
	}
	return interceptor.Decision{Allow: true}, nil
}

// List returns an immutable copy of the active public rules.
func (service *Service) List() []Rule {
	if service == nil {
		return []Rule{}
	}
	current := service.current.Load()
	if current == nil {
		return []Rule{}
	}
	return append([]Rule(nil), current.public...)
}

// Create validates, persists, and atomically activates one rule.
func (service *Service) Create(ctx context.Context, input RuleInput) (Rule, error) {
	if service == nil {
		return Rule{}, errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return Rule{}, errors.New("uaguard: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	current := service.current.Load()
	now := service.timestamp()
	rule := Rule{
		Name:             strings.TrimSpace(input.Name),
		Enabled:          input.Enabled,
		ModelPattern:     input.ModelPattern,
		UserAgentPattern: input.UserAgentPattern,
		CreatedAtNS:      now,
		UpdatedAtNS:      now,
	}
	if current != nil {
		rule.ID = current.nextID
	}
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitCreate(ctx, rule)
}

// commitCreate persists a validated new rule and publishes it. The caller
// holds service.mu.
func (service *Service) commitCreate(ctx context.Context, rule Rule) (Rule, error) {
	var err error
	if service.repository != nil {
		rule, err = service.repository.CreateUserAgentRule(ctx, rule)
		if err != nil {
			return Rule{}, err
		}
	}
	rules := service.List()
	rules = append(rules, rule)
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return Rule{}, err
	}
	service.current.Store(compiled)
	return rule, nil
}

// Update replaces one rule and publishes it immediately after persistence.
func (service *Service) Update(ctx context.Context, id int64, input RuleInput) (Rule, error) {
	if service == nil {
		return Rule{}, errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return Rule{}, errors.New("uaguard: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rules := service.List()
	index := -1
	for candidate := range rules {
		if rules[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 {
		return Rule{}, ErrNotFound
	}
	rule := rules[index]
	rule.Name = strings.TrimSpace(input.Name)
	rule.Enabled = input.Enabled
	rule.ModelPattern = input.ModelPattern
	rule.UserAgentPattern = input.UserAgentPattern
	rule.UpdatedAtNS = service.timestamp()
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	return service.commitUpdate(ctx, rules, index, rule)
}

// commitUpdate persists a validated replacement of rules[index] and publishes
// the result. The caller holds service.mu.
func (service *Service) commitUpdate(ctx context.Context, rules []Rule, index int, rule Rule) (Rule, error) {
	if service.repository != nil {
		persisted, err := service.repository.UpdateUserAgentRule(ctx, rule)
		if err != nil {
			return Rule{}, err
		}
		rule = persisted
	}
	rules[index] = rule
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return Rule{}, err
	}
	service.current.Store(compiled)
	return rule, nil
}

// Delete removes one rule and immediately publishes the reduced snapshot.
func (service *Service) Delete(ctx context.Context, id int64) error {
	if service == nil {
		return errors.New("uaguard: nil service")
	}
	if ctx == nil {
		return errors.New("uaguard: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	rules := service.List()
	index := -1
	for candidate := range rules {
		if rules[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 {
		return ErrNotFound
	}
	return service.commitDelete(ctx, rules, index, id)
}

// commitDelete persists the removal of rules[index] and publishes the reduced
// snapshot. The caller holds service.mu.
func (service *Service) commitDelete(ctx context.Context, rules []Rule, index int, id int64) error {
	if service.repository != nil {
		if err := service.repository.DeleteUserAgentRule(ctx, id); err != nil {
			return err
		}
	}
	rules = append(rules[:index], rules[index+1:]...)
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return err
	}
	service.current.Store(compiled)
	return nil
}

func (service *Service) timestamp() int64 {
	now := service.now().UnixNano()
	current := service.current.Load()
	if current != nil {
		for _, rule := range current.public {
			if now <= rule.UpdatedAtNS {
				now = rule.UpdatedAtNS + 1
			}
		}
	}
	return now
}

func compileSnapshot(rules []Rule) (*snapshot, error) {
	result := &snapshot{
		rules:  make([]compiledRule, 0, len(rules)),
		public: make([]Rule, 0, len(rules)),
		nextID: 1,
	}
	seen := make(map[int64]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID <= 0 {
			return nil, errors.New("uaguard: rule id must be positive")
		}
		if _, exists := seen[rule.ID]; exists {
			return nil, errors.New("uaguard: duplicate rule id")
		}
		seen[rule.ID] = struct{}{}
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", rule.ID, err)
		}
		result.rules = append(result.rules, compiled)
		result.public = append(result.public, rule)
		if rule.ID >= result.nextID {
			result.nextID = rule.ID + 1
		}
	}
	return result, nil
}

// compileRule validates and compiles one rule. Its errors are
// *ValidationError values whose text is exactly the "%w: message" form
// earlier releases returned, so callers that only test errors.Is(err,
// ErrInvalidRule) see no difference.
func compileRule(rule Rule) (compiledRule, error) {
	switch {
	case rule.Name == "":
		return compiledRule{}, invalidField("name", ReasonEmpty, "rule name is required and must be at most 128 bytes")
	case len(rule.Name) > MaxNameBytes:
		return compiledRule{}, invalidField("name", ReasonTooLong, "rule name is required and must be at most 128 bytes")
	case strings.ContainsRune(rule.Name, '\x00'):
		return compiledRule{}, invalidField("name", ReasonInvalidCharacter, "rule name is required and must be at most 128 bytes")
	}
	if err := checkPattern("model_pattern", rule.ModelPattern, "model pattern is required and must be at most 2048 bytes"); err != nil {
		return compiledRule{}, err
	}
	if err := checkPattern("user_agent_pattern", rule.UserAgentPattern, "user agent pattern is required and must be at most 2048 bytes"); err != nil {
		return compiledRule{}, err
	}
	model, err := regexp.Compile(rule.ModelPattern)
	if err != nil {
		return compiledRule{}, invalidField("model_pattern", ReasonInvalidRegexp, "invalid model regular expression")
	}
	userAgent, err := regexp.Compile(rule.UserAgentPattern)
	if err != nil {
		return compiledRule{}, invalidField("user_agent_pattern", ReasonInvalidRegexp, "invalid user agent regular expression")
	}
	return compiledRule{rule: rule, model: model, userAgent: userAgent}, nil
}

func checkPattern(field, pattern, message string) error {
	if strings.TrimSpace(pattern) == "" {
		return invalidField(field, ReasonEmpty, message)
	}
	if len(pattern) > MaxPatternBytes {
		return invalidField(field, ReasonTooLong, message)
	}
	return nil
}
