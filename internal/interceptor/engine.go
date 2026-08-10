package interceptor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/routing"
)

const (
	chainBlockedBy      = "interceptor_chain"
	chainErrorBlockCode = "interceptor_invalid_chain"
	checkErrorBlockCode = "interceptor_error"
	checkPanicBlockCode = "interceptor_panic"
	invalidDecisionCode = "interceptor_invalid_decision"
	bodyReadErrorCode   = "interceptor_body_read_error"
)

var blockCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

var errCheckPanicked = errors.New("interceptor: check panicked")

// Result is the engine's forwarding decision. Internal is intended for local
// diagnostics only and must never be returned in an HTTP response.
type Result struct {
	Allowed    bool
	Cancelled  bool
	StatusCode int
	BlockedBy  string
	BlockCode  string
	Internal   error
}

type compiledInterceptor struct {
	id           string
	interceptor  Interceptor
	requirements Requirements
}

type compiledRoute struct {
	interceptorIDs []string
	chain          []compiledInterceptor
	maxBodyBytes   int64
}

// Engine contains immutable, precompiled route chains and is safe for
// concurrent request evaluation.
type Engine struct {
	routes map[string]compiledRoute
}

// NewEngine builds an engine with the first-party registry.
func NewEngine(definitions map[string]config.InterceptorConfig, routes []config.RouteConfig) (*Engine, error) {
	return NewEngineWithRegistry(NewDefaultRegistry(), definitions, routes)
}

// NewEngineWithRegistry builds an engine with an explicit registry. It is
// useful for adding local interceptors without implicit global registration.
func NewEngineWithRegistry(registry *Registry, definitions map[string]config.InterceptorConfig, routes []config.RouteConfig) (*Engine, error) {
	factories := registry.snapshot()
	if factories == nil {
		return nil, fmt.Errorf("interceptor: nil registry")
	}

	instances := make(map[string]compiledInterceptor, len(definitions))
	definitionIDs := make([]string, 0, len(definitions))
	for id := range definitions {
		definitionIDs = append(definitionIDs, id)
	}
	sort.Strings(definitionIDs)

	for _, id := range definitionIDs {
		if id == "" {
			return nil, fmt.Errorf("interceptor: empty instance id")
		}
		definition := definitions[id]
		factory, exists := factories[definition.Type]
		if !exists {
			return nil, fmt.Errorf("interceptor %q: unknown type %q", id, definition.Type)
		}

		instance, err := callFactory(factory, id, cloneAnyMap(definition.Config))
		if err != nil {
			return nil, fmt.Errorf("interceptor %q: %w", id, err)
		}
		if instance == nil {
			return nil, fmt.Errorf("interceptor %q: factory returned nil", id)
		}

		requirements, err := readRequirements(instance)
		if err != nil {
			return nil, fmt.Errorf("interceptor %q: %w", id, err)
		}
		instances[id] = compiledInterceptor{
			id:           id,
			interceptor:  instance,
			requirements: requirements,
		}
	}

	compiledRoutes := make(map[string]compiledRoute, len(routes))
	for _, route := range routes {
		if route.ID == "" {
			return nil, fmt.Errorf("interceptor: route has empty id")
		}
		if _, exists := compiledRoutes[route.ID]; exists {
			return nil, fmt.Errorf("interceptor: duplicate route id %q", route.ID)
		}

		compiled := compiledRoute{
			interceptorIDs: append([]string(nil), route.Interceptors...),
			chain:          make([]compiledInterceptor, 0, len(route.Interceptors)),
		}
		for _, id := range route.Interceptors {
			instance, exists := instances[id]
			if !exists {
				return nil, fmt.Errorf("interceptor: route %q references unknown interceptor %q", route.ID, id)
			}
			compiled.chain = append(compiled.chain, instance)
			if instance.requirements.MaxBodyBytes > compiled.maxBodyBytes {
				compiled.maxBodyBytes = instance.requirements.MaxBodyBytes
			}
		}
		compiledRoutes[route.ID] = compiled
	}

	return &Engine{routes: compiledRoutes}, nil
}

// Evaluate executes the route's fixed chain in configuration order. It never
// writes a response; the caller maps Result to the fixed public JSON envelope.
func (e *Engine) Evaluate(ctx context.Context, req *http.Request, match routing.Match) Result {
	if e == nil || req == nil {
		return unavailableResult(chainBlockedBy, chainErrorBlockCode, errors.New("interceptor: nil engine or request"))
	}
	if ctx == nil {
		ctx = req.Context()
	}

	route, exists := e.routes[match.RouteID]
	if !exists {
		return unavailableResult(chainBlockedBy, chainErrorBlockCode, fmt.Errorf("interceptor: unknown matched route %q", match.RouteID))
	}
	if !equalStrings(route.interceptorIDs, match.InterceptorIDs) {
		return unavailableResult(chainBlockedBy, chainErrorBlockCode, fmt.Errorf("interceptor: route %q chain does not match compiled configuration", match.RouteID))
	}
	if err := ctx.Err(); err != nil {
		return cancelledResult("", err)
	}

	view := snapshotRequest(req, match)
	var body *BodyView
	bodyRead := false

	for _, item := range route.chain {
		if err := ctx.Err(); err != nil {
			return cancelledResult(item.id, err)
		}

		if item.requirements.NeedsBody && !bodyRead {
			buffered, err := readAndReplayBody(req, route.maxBodyBytes)
			if err != nil {
				if isCancellation(ctx, err) {
					return cancelledResult(item.id, cancellationError(ctx, err))
				}
				return unavailableResult(item.id, bodyReadErrorCode, fmt.Errorf("interceptor: request body read failed: %w", err))
			}
			body = &BodyView{data: buffered}
			bodyRead = true
		}

		if item.requirements.NeedsBody {
			if body.Len() > item.requirements.MaxBodyBytes {
				return Result{
					StatusCode: http.StatusRequestEntityTooLarge,
					BlockedBy:  item.id,
					BlockCode:  "body_too_large",
				}
			}
			view.body = body
		} else {
			view.body = nil
		}

		decision, err := callCheck(ctx, item.interceptor, view)
		if err != nil {
			if isCancellation(ctx, err) {
				return cancelledResult(item.id, cancellationError(ctx, err))
			}
			if errors.Is(err, errCheckPanicked) {
				return unavailableResult(item.id, checkPanicBlockCode, err)
			}
			return unavailableResult(item.id, checkErrorBlockCode, err)
		}
		if err := validateDecision(decision); err != nil {
			return unavailableResult(item.id, invalidDecisionCode, err)
		}
		if !decision.Allow {
			return Result{
				StatusCode: decision.StatusCode,
				BlockedBy:  item.id,
				BlockCode:  decision.BlockCode,
			}
		}
	}

	return Result{Allowed: true}
}

func snapshotRequest(req *http.Request, match routing.Match) RequestView {
	view := RequestView{
		RouteID:       match.RouteID,
		Method:        req.Method,
		Host:          req.Host,
		ContentLength: req.ContentLength,
		headers:       req.Header.Clone(),
		pathParams:    cloneStrings(match.PathParams),
	}
	if req.URL != nil {
		view.EscapedPath = req.URL.EscapedPath()
		view.query = cloneValues(req.URL.Query())
	}
	return view
}

func readAndReplayBody(req *http.Request, maxBytes int64) (buffered []byte, err error) {
	if req.Body == nil {
		return nil, nil
	}

	original := req.Body
	defer func() {
		if recovered := recover(); recovered != nil {
			buffered = nil
			err = errors.New("interceptor: request body reader panicked")
		}
	}()
	defer func() {
		_ = original.Close()
	}()

	buffered, err = io.ReadAll(io.LimitReader(original, maxBytes+1))
	if err != nil {
		buffered = nil
		return nil, err
	}

	req.Body = io.NopCloser(bytes.NewReader(buffered))
	return buffered, nil
}

func validateDecision(decision Decision) error {
	if decision.Allow {
		if decision.StatusCode != 0 || decision.BlockCode != "" {
			return errors.New("interceptor: invalid allow decision")
		}
		return nil
	}

	if decision.StatusCode < 400 || decision.StatusCode > 499 {
		return errors.New("interceptor: invalid reject status")
	}
	if !blockCodePattern.MatchString(decision.BlockCode) {
		return errors.New("interceptor: invalid reject block code")
	}
	return nil
}

func validateRequirements(requirements Requirements) error {
	if !requirements.NeedsBody {
		if requirements.MaxBodyBytes != 0 {
			return errors.New("metadata interceptor declares a body limit")
		}
		return nil
	}
	if requirements.MaxBodyBytes < MinBodyBytes || requirements.MaxBodyBytes > MaxBodyBytes {
		return fmt.Errorf("body limit must be between %d and %d", MinBodyBytes, MaxBodyBytes)
	}
	return nil
}

func readRequirements(instance Interceptor) (requirements Requirements, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("requirements panicked")
		}
	}()
	requirements = instance.Requirements()
	if validationErr := validateRequirements(requirements); validationErr != nil {
		return Requirements{}, validationErr
	}
	return requirements, nil
}

func callFactory(factory Factory, id string, raw map[string]any) (instance Interceptor, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("factory panicked")
		}
	}()
	return factory(id, raw)
}

func callCheck(ctx context.Context, instance Interceptor, request RequestView) (decision Decision, err error) {
	defer func() {
		if recover() != nil {
			err = errCheckPanicked
		}
	}()
	return instance.Check(ctx, request)
}

func unavailableResult(blockedBy, blockCode string, err error) Result {
	return Result{
		StatusCode: http.StatusServiceUnavailable,
		BlockedBy:  blockedBy,
		BlockCode:  blockCode,
		Internal:   err,
	}
}

func cancelledResult(_ string, err error) Result {
	return Result{
		Cancelled: true,
		Internal:  err,
	}
}

func isCancellation(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func cancellationError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func equalStrings(left, right []string) bool {
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

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
