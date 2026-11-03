package contentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/interceptor"
)

// capturedRule is the immutable request-time representation of one rule.
type capturedRule struct {
	rule    Rule
	model   *regexp.Regexp
	scopes  map[string]struct{}
	matcher *matcher
}

func (rule capturedRule) applies(model string) bool {
	if rule.model == nil {
		return true
	}
	return model != "" && rule.model.MatchString(model)
}

func (rule capturedRule) matches(segments []segment) bool {
	for _, item := range segments {
		if _, ok := rule.scopes[item.Scope]; !ok {
			continue
		}
		if rule.matcher.Match(item.Text) {
			return true
		}
	}
	return false
}

type snapshot struct {
	rules  []capturedRule
	public []Rule
	nextID int64
}

// Service owns the compiled rule snapshot. It is the interceptor instance and
// the management surface used by the web layer.
type Service struct {
	repository Repository
	logger     *slog.Logger
	mu         sync.Mutex
	current    atomic.Pointer[snapshot]
	now        func() time.Time
}

// New loads and compiles persisted rules. A nil repository is supported for
// degraded audit mode and starts with an empty snapshot (no interception).
func New(ctx context.Context, repository Repository, logger *slog.Logger) (*Service, error) {
	if ctx == nil {
		return nil, fmt.Errorf("contentpolicy: nil context")
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &Service{repository: repository, logger: logger, now: time.Now}
	rules := []Rule{}
	if repository != nil {
		persisted, err := repository.ListContentPolicyRules(ctx)
		if err != nil {
			return nil, fmt.Errorf("contentpolicy: load rules: %w", err)
		}
		rules = persisted
	}
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return nil, fmt.Errorf("contentpolicy: compile persisted rules: %w", err)
	}
	service.current.Store(compiled)
	return service, nil
}

// Requirements declares the same bounded body buffer as the dynamic UA
// interceptor so large requests are not rejected by the engine's 413 path.
func (*Service) Requirements() interceptor.Requirements {
	return interceptor.Requirements{NeedsBody: true, MaxBodyBytes: interceptor.MaxBodyBytes}
}

// Check evaluates the enabled rules against the selected request text. It
// never mutates the request and never returns an error for unparseable or
// oversized bodies: the policy fails open with a stable diagnostic code.
func (service *Service) Check(ctx context.Context, request interceptor.RequestView) (interceptor.Decision, error) {
	if service == nil {
		return interceptor.Decision{Allow: true}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current := service.current.Load()
	if current == nil || len(current.rules) == 0 {
		return interceptor.Decision{Allow: true}, nil
	}
	body, ok := request.Body()
	if !ok || body.Len() <= 0 {
		return interceptor.Decision{Allow: true}, nil
	}
	if encoding := normalizedEncoding(request.Headers().Get("Content-Encoding")); encoding != "" {
		service.skip(ctx, request.RouteID, "content_policy_encoded", "content policy scan skipped because the request body is content-encoded")
		return interceptor.Decision{Allow: true}, nil
	}
	if body.Len() > MaxScanBodyBytes {
		service.skip(ctx, request.RouteID, "content_policy_body_too_large", "content policy scan skipped because the request body exceeds the scan limit")
		return interceptor.Decision{Allow: true}, nil
	}

	model := request.PathParams()["model"]
	if model == "" {
		model = readRequestModel(body)
	}
	applicable := false
	for index := range current.rules {
		if current.rules[index].rule.Enabled && current.rules[index].applies(model) {
			applicable = true
			break
		}
	}
	if !applicable {
		return interceptor.Decision{Allow: true}, nil
	}

	data, err := io.ReadAll(io.LimitReader(body.Open(), MaxScanBodyBytes+1))
	if err != nil {
		service.skip(ctx, request.RouteID, "content_policy_body_read_error", "content policy scan skipped because the buffered request body could not be read")
		return interceptor.Decision{Allow: true}, nil
	}
	if int64(len(data)) > MaxScanBodyBytes {
		service.skip(ctx, request.RouteID, "content_policy_body_too_large", "content policy scan skipped because the request body exceeds the scan limit")
		return interceptor.Decision{Allow: true}, nil
	}

	segments, err := extractRequest(request.Parser, data)
	if err != nil {
		code := "content_policy_unparseable"
		message := "content policy scan skipped because the request body is not a JSON object"
		if err == errUnsupportedParser {
			code = "content_policy_unsupported_parser"
			message = "content policy scan skipped because the route parser is not supported"
		}
		service.skip(ctx, request.RouteID, code, message)
		return interceptor.Decision{Allow: true}, nil
	}

	for index := range current.rules {
		rule := &current.rules[index]
		if !rule.rule.Enabled || !rule.applies(model) {
			continue
		}
		if !rule.matches(segments) {
			continue
		}
		if rule.rule.Action == ActionDryRun {
			service.logger.InfoContext(ctx, "content policy dry run match",
				"route_id", request.RouteID,
				"policy_rule_id", rule.rule.ID,
			)
			continue
		}
		service.logger.InfoContext(ctx, "content policy match",
			"route_id", request.RouteID,
			"policy_rule_id", rule.rule.ID,
		)
		return interceptor.Decision{StatusCode: RejectStatusCode, BlockCode: BlockCode}, nil
	}
	return interceptor.Decision{Allow: true}, nil
}

func readRequestModel(body interceptor.BodyView) string {
	decoder := json.NewDecoder(body.Open())
	var payload struct {
		Model string `json:"model"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.Model)
}

func normalizedEncoding(value string) string {
	encoding := strings.ToLower(strings.TrimSpace(value))
	if encoding == "" || encoding == "identity" {
		return ""
	}
	return encoding
}

func (service *Service) skip(ctx context.Context, routeID, code, message string) {
	service.logger.WarnContext(ctx, message, "route_id", routeID, "error_code", code)
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
	rules := make([]Rule, 0, len(current.public))
	for _, rule := range current.public {
		rules = append(rules, cloneRule(rule))
	}
	return rules
}

// Create validates, persists, and atomically activates one rule.
func (service *Service) Create(ctx context.Context, input RuleInput) (Rule, error) {
	if service == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil service")
	}
	if ctx == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	normalized, err := normalizeInput(input)
	if err != nil {
		return Rule{}, err
	}
	current := service.current.Load()
	now := service.timestamp()
	rule := Rule{
		Name:         normalized.Name,
		Enabled:      normalized.Enabled,
		Action:       normalized.Action,
		ModelPattern: normalized.ModelPattern,
		ScanScopes:   normalized.ScanScopes,
		Keywords:     normalized.Keywords,
		CreatedAtNS:  now,
		UpdatedAtNS:  now,
	}
	if current != nil {
		rule.ID = current.nextID
	}
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	if service.repository != nil {
		rule, err = service.repository.CreateContentPolicyRule(ctx, rule)
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
	return cloneRule(rule), nil
}

// Update replaces one rule and publishes it immediately after persistence.
func (service *Service) Update(ctx context.Context, id int64, input RuleInput) (Rule, error) {
	if service == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil service")
	}
	if ctx == nil {
		return Rule{}, fmt.Errorf("contentpolicy: nil context")
	}
	service.mu.Lock()
	defer service.mu.Unlock()

	normalized, err := normalizeInput(input)
	if err != nil {
		return Rule{}, err
	}
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
	rule.Name = normalized.Name
	rule.Enabled = normalized.Enabled
	rule.Action = normalized.Action
	rule.ModelPattern = normalized.ModelPattern
	rule.ScanScopes = normalized.ScanScopes
	rule.Keywords = normalized.Keywords
	rule.UpdatedAtNS = service.timestamp()
	if _, err := compileRule(rule); err != nil {
		return Rule{}, err
	}
	if service.repository != nil {
		persisted, err := service.repository.UpdateContentPolicyRule(ctx, rule)
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
	return cloneRule(rule), nil
}

// Delete removes one rule and immediately publishes the reduced snapshot.
func (service *Service) Delete(ctx context.Context, id int64) error {
	if service == nil {
		return fmt.Errorf("contentpolicy: nil service")
	}
	if ctx == nil {
		return fmt.Errorf("contentpolicy: nil context")
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
	if service.repository != nil {
		if err := service.repository.DeleteContentPolicyRule(ctx, id); err != nil {
			return err
		}
	}
	rules = append(rules[:index], rules[index+1:]...)
	compiled, err := compileSnapshot(rules)
	if err != nil {
		return err
	}
	// Keep ids monotonic even when the highest rule is deleted; a later rule
	// must not reuse an id that historical audits may still reference.
	if previous := service.current.Load(); previous != nil && previous.nextID > compiled.nextID {
		compiled.nextID = previous.nextID
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
		rules:  make([]capturedRule, 0, len(rules)),
		public: make([]Rule, 0, len(rules)),
		nextID: 1,
	}
	seen := make(map[int64]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID <= 0 {
			return nil, fmt.Errorf("%w: rule id must be positive", ErrInvalidRule)
		}
		if _, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate rule id", ErrInvalidRule)
		}
		seen[rule.ID] = struct{}{}
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", rule.ID, err)
		}
		result.rules = append(result.rules, compiled)
		result.public = append(result.public, cloneRule(rule))
		if rule.ID >= result.nextID {
			result.nextID = rule.ID + 1
		}
	}
	return result, nil
}

func compileRule(rule Rule) (capturedRule, error) {
	name := rule.Name
	if name == "" || len(name) > MaxNameBytes || strings.ContainsRune(name, '\x00') {
		return capturedRule{}, fmt.Errorf("%w: name is required and must be at most %d bytes", ErrInvalidRule, MaxNameBytes)
	}
	if !ValidAction(rule.Action) {
		return capturedRule{}, fmt.Errorf("%w: action must be block or dry_run", ErrInvalidRule)
	}
	if strings.TrimSpace(rule.ModelPattern) != rule.ModelPattern || len(rule.ModelPattern) > MaxModelPatternBytes {
		return capturedRule{}, fmt.Errorf("%w: model pattern must not have surrounding whitespace and must be at most %d bytes", ErrInvalidRule, MaxModelPatternBytes)
	}
	var model *regexp.Regexp
	if rule.ModelPattern != "" {
		compiled, err := regexp.Compile(rule.ModelPattern)
		if err != nil {
			return capturedRule{}, fmt.Errorf("%w: invalid model regular expression", ErrInvalidRule)
		}
		model = compiled
	}

	scopes, err := normalizeScopes(rule.ScanScopes)
	if err != nil {
		return capturedRule{}, err
	}
	keywords, err := normalizeKeywords(rule.Keywords)
	if err != nil {
		return capturedRule{}, err
	}
	if len(keywords) == 0 {
		return capturedRule{}, fmt.Errorf("%w: at least one keyword is required", ErrInvalidRule)
	}
	scopeJSON, err := json.Marshal(scopes)
	if err != nil || len(scopeJSON) > MaxScanScopesJSON {
		return capturedRule{}, fmt.Errorf("%w: scan scopes are too large", ErrInvalidRule)
	}
	keywordJSON, err := json.Marshal(keywords)
	if err != nil || len(keywordJSON) > MaxKeywordsJSONBytes {
		return capturedRule{}, fmt.Errorf("%w: keywords exceed the size limit", ErrInvalidRule)
	}
	if rule.CreatedAtNS <= 0 || rule.UpdatedAtNS < rule.CreatedAtNS {
		return capturedRule{}, fmt.Errorf("%w: invalid rule timestamps", ErrInvalidRule)
	}
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	return capturedRule{
		rule:    cloneRule(rule),
		model:   model,
		scopes:  scopeSet,
		matcher: newMatcher(keywords),
	}, nil
}

func normalizeInput(input RuleInput) (RuleInput, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > MaxNameBytes || strings.ContainsRune(name, '\x00') {
		return RuleInput{}, fmt.Errorf("%w: name is required and must be at most %d bytes", ErrInvalidRule, MaxNameBytes)
	}
	action := strings.TrimSpace(input.Action)
	if action == "" {
		action = ActionBlock
	}
	if !ValidAction(action) {
		return RuleInput{}, fmt.Errorf("%w: action must be block or dry_run", ErrInvalidRule)
	}
	modelPattern := input.ModelPattern
	if strings.TrimSpace(modelPattern) != modelPattern || len(modelPattern) > MaxModelPatternBytes {
		return RuleInput{}, fmt.Errorf("%w: model pattern must not have surrounding whitespace and must be at most %d bytes", ErrInvalidRule, MaxModelPatternBytes)
	}
	scopes, err := normalizeScopes(input.ScanScopes)
	if err != nil {
		return RuleInput{}, err
	}
	keywords, err := normalizeKeywords(input.Keywords)
	if err != nil {
		return RuleInput{}, err
	}
	if len(keywords) == 0 {
		return RuleInput{}, fmt.Errorf("%w: at least one keyword is required", ErrInvalidRule)
	}
	scopeJSON, err := json.Marshal(scopes)
	if err != nil || len(scopeJSON) > MaxScanScopesJSON {
		return RuleInput{}, fmt.Errorf("%w: scan scopes are too large", ErrInvalidRule)
	}
	keywordJSON, err := json.Marshal(keywords)
	if err != nil || len(keywordJSON) > MaxKeywordsJSONBytes {
		return RuleInput{}, fmt.Errorf("%w: keywords exceed the size limit", ErrInvalidRule)
	}
	return RuleInput{
		Name:         name,
		Enabled:      input.Enabled,
		Action:       action,
		ModelPattern: modelPattern,
		ScanScopes:   scopes,
		Keywords:     keywords,
	}, nil
}

func normalizeScopes(values []string) ([]string, error) {
	if values == nil {
		return DefaultScanScopes(), nil
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: at least one scan scope is required", ErrInvalidRule)
	}
	scopes := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		scope := strings.TrimSpace(value)
		if scope == "" || !ValidScanScope(scope) {
			return nil, fmt.Errorf("%w: unknown scan scope", ErrInvalidRule)
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 || len(scopes) > len(AllScanScopes) {
		return nil, fmt.Errorf("%w: invalid scan scope count", ErrInvalidRule)
	}
	return scopes, nil
}

func normalizeKeywords(values []string) ([]string, error) {
	if len(values) > MaxKeywords {
		return nil, fmt.Errorf("%w: at most %d keywords are allowed", ErrInvalidRule, MaxKeywords)
	}
	keywords := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		keyword := strings.TrimSpace(value)
		if keyword == "" {
			continue
		}
		if len(keyword) > MaxKeywordBytes {
			return nil, fmt.Errorf("%w: a keyword exceeds %d bytes", ErrInvalidRule, MaxKeywordBytes)
		}
		if strings.ContainsRune(keyword, '\x00') {
			return nil, fmt.Errorf("%w: a keyword contains NUL", ErrInvalidRule)
		}
		if strings.ContainsAny(keyword, "\r\n") {
			return nil, fmt.Errorf("%w: a keyword must be a single line", ErrInvalidRule)
		}
		key := strings.ToLower(keyword)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		keywords = append(keywords, keyword)
	}
	if len(keywords) > MaxKeywords {
		return nil, fmt.Errorf("%w: at most %d keywords are allowed", ErrInvalidRule, MaxKeywords)
	}
	return keywords, nil
}

func cloneRule(rule Rule) Rule {
	rule.ScanScopes = append([]string(nil), rule.ScanScopes...)
	rule.Keywords = append([]string(nil), rule.Keywords...)
	return rule
}

var _ interceptor.Interceptor = (*Service)(nil)
var _ RuleSet = (*Service)(nil)
