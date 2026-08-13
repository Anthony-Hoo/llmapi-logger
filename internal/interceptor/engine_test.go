package interceptor

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/config"
	"llmapi-logger/internal/routing"
)

type testInterceptor struct {
	requirements Requirements
	check        func(context.Context, RequestView) (Decision, error)
}

func (i testInterceptor) Requirements() Requirements {
	return i.requirements
}

func (i testInterceptor) Check(ctx context.Context, request RequestView) (Decision, error) {
	if i.check == nil {
		return Decision{Allow: true}, nil
	}
	return i.check(ctx, request)
}

type panicRequirements struct{}

func (panicRequirements) Requirements() Requirements {
	panic("requirements secret")
}

func (panicRequirements) Check(context.Context, RequestView) (Decision, error) {
	return Decision{Allow: true}, nil
}

func TestEngineExecutesInOrderAndShortCircuits(t *testing.T) {
	t.Parallel()

	var calls []string
	registry := NewRegistry()
	mustRegister(t, registry, "ordered", func(id string, _ map[string]any) (Interceptor, error) {
		return testInterceptor{check: func(context.Context, RequestView) (Decision, error) {
			calls = append(calls, id)
			if id == "reject" {
				return Decision{StatusCode: http.StatusForbidden, BlockCode: "policy_denied"}, nil
			}
			return Decision{Allow: true}, nil
		}}, nil
	})

	engine := mustEngine(t, registry,
		map[string]config.InterceptorConfig{
			"first":  {Type: "ordered"},
			"reject": {Type: "ordered"},
			"last":   {Type: "ordered"},
		},
		testRoute("route", "first", "reject", "last"),
	)
	request := newRequest(t, []byte("not read"))
	result := engine.Evaluate(request.Context(), request, testMatch("route", "first", "reject", "last"))

	if result.Allowed || result.StatusCode != http.StatusForbidden || result.BlockedBy != "reject" || result.BlockCode != "policy_denied" || result.Internal != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	if want := []string{"first", "reject"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestMetadataChainDoesNotReadBody(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	mustRegister(t, registry, "metadata", func(string, map[string]any) (Interceptor, error) {
		return testInterceptor{check: func(_ context.Context, request RequestView) (Decision, error) {
			if _, ok := request.Body(); ok {
				t.Fatal("metadata interceptor received body")
			}
			return Decision{StatusCode: http.StatusUnauthorized, BlockCode: "missing_metadata"}, nil
		}}, nil
	})
	engine := mustEngine(t, registry,
		map[string]config.InterceptorConfig{"metadata": {Type: "metadata"}},
		testRoute("route", "metadata"),
	)
	body := &panicReadCloser{}
	request := newRequestWithBody(t, body, -1)

	result := engine.Evaluate(request.Context(), request, testMatch("route", "metadata"))
	if result.StatusCode != http.StatusUnauthorized || result.BlockedBy != "metadata" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if body.closed {
		t.Fatal("metadata-only chain closed the request body")
	}
	if request.Body != body {
		t.Fatal("metadata-only chain replaced the request body")
	}
}

func TestRequestViewCopiesCannotMutateRequestOrLaterInterceptor(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	mustRegister(t, registry, "copy", func(id string, _ map[string]any) (Interceptor, error) {
		return testInterceptor{check: func(_ context.Context, request RequestView) (Decision, error) {
			headers := request.Headers()
			query := request.Query()
			params := request.PathParams()
			if id == "mutate" {
				headers.Set("Authorization", "changed")
				query.Set("key", "changed")
				params["model"] = "changed"
				return Decision{Allow: true}, nil
			}
			if got := headers.Get("Authorization"); got != "Bearer original" {
				return Decision{}, fmt.Errorf("header changed to %q", got)
			}
			if got := query.Get("key"); got != "original-query" {
				return Decision{}, fmt.Errorf("query changed to %q", got)
			}
			if got := params["model"]; got != "original-model" {
				return Decision{}, fmt.Errorf("path param changed to %q", got)
			}
			return Decision{Allow: true}, nil
		}}, nil
	})
	engine := mustEngine(t, registry,
		map[string]config.InterceptorConfig{
			"mutate":  {Type: "copy"},
			"observe": {Type: "copy"},
		},
		testRoute("route", "mutate", "observe"),
	)
	request := newRequest(t, nil)
	request.Header.Set("Authorization", "Bearer original")
	request.URL.RawQuery = "key=original-query"
	match := testMatch("route", "mutate", "observe")
	match.PathParams = map[string]string{"model": "original-model"}

	result := engine.Evaluate(request.Context(), request, match)
	if !result.Allowed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer original" {
		t.Fatalf("request header changed to %q", got)
	}
	if got := request.URL.Query().Get("key"); got != "original-query" {
		t.Fatalf("request query changed to %q", got)
	}
	if got := match.PathParams["model"]; got != "original-model" {
		t.Fatalf("matcher path params changed to %q", got)
	}
}

func TestBodyChainBuffersOnceAndReplaysExactBytes(t *testing.T) {
	t.Parallel()

	gzipBytes := func() []byte {
		var output bytes.Buffer
		writer := gzip.NewWriter(&output)
		if _, err := writer.Write([]byte(`{"compressed":true}`)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return output.Bytes()
	}()

	tests := []struct {
		name          string
		body          []byte
		contentLength int64
	}{
		{name: "json", body: []byte(`{"model":"gpt"}`), contentLength: int64(len(`{"model":"gpt"}`))},
		{name: "gzip", body: gzipBytes, contentLength: int64(len(gzipBytes))},
		{name: "multipart", body: []byte("--boundary\r\nContent-Disposition: form-data; name=x\r\n\r\ny\r\n--boundary--\r\n"), contentLength: -1},
		{name: "binary", body: []byte{0x00, 0xff, 0x80, 0x01, 0x00}, contentLength: -1},
		{name: "unknown-length", body: []byte("streamed bytes"), contentLength: -1},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			registry := NewRegistry()
			var checks int
			mustRegister(t, registry, "body", func(string, map[string]any) (Interceptor, error) {
				return testInterceptor{
					requirements: Requirements{NeedsBody: true, MaxBodyBytes: MinBodyBytes},
					check: func(_ context.Context, request RequestView) (Decision, error) {
						view, ok := request.Body()
						if !ok {
							return Decision{}, errors.New("body view missing")
						}
						first, err := io.ReadAll(view.Open())
						if err != nil {
							return Decision{}, err
						}
						second, err := io.ReadAll(view.Open())
						if err != nil {
							return Decision{}, err
						}
						if !bytes.Equal(first, test.body) || !bytes.Equal(second, test.body) || view.Len() != int64(len(test.body)) {
							return Decision{}, errors.New("body view differs from inbound bytes")
						}
						checks++
						return Decision{Allow: true}, nil
					},
				}, nil
			})
			engine := mustEngine(t, registry,
				map[string]config.InterceptorConfig{
					"body-one": {Type: "body"},
					"body-two": {Type: "body"},
				},
				testRoute("route", "body-one", "body-two"),
			)
			original := &trackingReadCloser{reader: bytes.NewReader(test.body)}
			request := newRequestWithBody(t, original, test.contentLength)
			request.TransferEncoding = []string{"chunked"}

			result := engine.Evaluate(request.Context(), request, testMatch("route", "body-one", "body-two"))
			if !result.Allowed {
				t.Fatalf("unexpected result: %+v", result)
			}
			if checks != 2 {
				t.Fatalf("body checks = %d, want 2", checks)
			}
			if original.bytesRead != len(test.body) || original.closeCalls != 1 {
				t.Fatalf("original read=%d close=%d, want read=%d close=1", original.bytesRead, original.closeCalls, len(test.body))
			}
			replayed, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replayed, test.body) {
				t.Fatalf("replayed body differs: %x != %x", replayed, test.body)
			}
			if request.ContentLength != test.contentLength {
				t.Fatalf("ContentLength = %d, want %d", request.ContentLength, test.contentLength)
			}
			if !reflect.DeepEqual(request.TransferEncoding, []string{"chunked"}) {
				t.Fatalf("TransferEncoding changed: %v", request.TransferEncoding)
			}
		})
	}
}

func TestBodyLimitBoundaryAndBoundedRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		size           int
		contentLength  int64
		wantAllowed    bool
		wantReadBytes  int
		wantStatusCode int
	}{
		{name: "at-limit", size: int(MinBodyBytes), contentLength: MinBodyBytes, wantAllowed: true, wantReadBytes: int(MinBodyBytes)},
		{name: "limit-plus-one-unknown-length", size: int(MinBodyBytes + 1), contentLength: -1, wantReadBytes: int(MinBodyBytes + 1), wantStatusCode: http.StatusRequestEntityTooLarge},
		{name: "bounded-prefix-unknown-length", size: int(MinBodyBytes + 4096), contentLength: -1, wantReadBytes: int(MinBodyBytes + 1), wantStatusCode: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			definitions := map[string]config.InterceptorConfig{
				"limit": {Type: "max_body_bytes", Config: map[string]any{"max_bytes": MinBodyBytes}},
			}
			engine, err := NewEngine(definitions, []config.RouteConfig{testRoute("route", "limit")})
			if err != nil {
				t.Fatal(err)
			}
			originalBytes := bytes.Repeat([]byte{0xa5}, test.size)
			original := &trackingReadCloser{reader: bytes.NewReader(originalBytes)}
			request := newRequestWithBody(t, original, test.contentLength)

			result := engine.Evaluate(request.Context(), request, testMatch("route", "limit"))
			if result.Allowed != test.wantAllowed || result.StatusCode != test.wantStatusCode {
				t.Fatalf("unexpected result: %+v", result)
			}
			if !test.wantAllowed && (result.BlockedBy != "limit" || result.BlockCode != "body_too_large" || result.Internal != nil) {
				t.Fatalf("unexpected rejection: %+v", result)
			}
			if original.bytesRead != test.wantReadBytes || original.closeCalls != 1 {
				t.Fatalf("original read=%d close=%d, want read=%d close=1", original.bytesRead, original.closeCalls, test.wantReadBytes)
			}
			if request.ContentLength != test.contentLength {
				t.Fatalf("ContentLength = %d, want %d", request.ContentLength, test.contentLength)
			}
		})
	}
}

func TestBodyAboveGlobalLimitIsRejectedWithoutReading(t *testing.T) {
	t.Parallel()

	definitions := map[string]config.InterceptorConfig{
		"limit": {Type: "max_body_bytes", Config: map[string]any{"max_bytes": MaxBodyBytes}},
	}
	engine, err := NewEngine(definitions, []config.RouteConfig{testRoute("route", "limit")})
	if err != nil {
		t.Fatal(err)
	}
	original := &trackingReadCloser{reader: strings.NewReader("not read")}
	request := newRequestWithBody(t, original, MaxBodyBytes+1)

	result := engine.Evaluate(request.Context(), request, testMatch("route", "limit"))
	if result.StatusCode != http.StatusRequestEntityTooLarge || result.BlockedBy != "limit" || result.BlockCode != "body_too_large" || result.Internal != nil {
		t.Fatalf("unexpected result: %+v", result)
	}
	if original.bytesRead != 0 {
		t.Fatalf("oversized body read %d bytes, want 0", original.bytesRead)
	}
}

func TestRouteMaximumIsSharedButEachInterceptorLimitIsEnforced(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	var smallCalled bool
	mustRegister(t, registry, "small", func(string, map[string]any) (Interceptor, error) {
		return testInterceptor{
			requirements: Requirements{NeedsBody: true, MaxBodyBytes: MinBodyBytes},
			check: func(context.Context, RequestView) (Decision, error) {
				smallCalled = true
				return Decision{Allow: true}, nil
			},
		}, nil
	})
	mustRegister(t, registry, "large", func(string, map[string]any) (Interceptor, error) {
		return testInterceptor{requirements: Requirements{NeedsBody: true, MaxBodyBytes: 2 * MinBodyBytes}}, nil
	})
	engine := mustEngine(t, registry,
		map[string]config.InterceptorConfig{
			"small": {Type: "small"},
			"large": {Type: "large"},
		},
		testRoute("route", "small", "large"),
	)
	payload := bytes.Repeat([]byte("x"), int(MinBodyBytes+1))
	original := &trackingReadCloser{reader: bytes.NewReader(payload)}
	request := newRequestWithBody(t, original, -1)

	result := engine.Evaluate(request.Context(), request, testMatch("route", "small", "large"))
	if result.StatusCode != http.StatusRequestEntityTooLarge || result.BlockedBy != "small" || result.BlockCode != "body_too_large" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if smallCalled {
		t.Fatal("interceptor Check ran after its body limit was exceeded")
	}
	if original.bytesRead != len(payload) {
		t.Fatalf("shared route buffer read %d bytes, want %d", original.bytesRead, len(payload))
	}
}

func TestEngineFailureClassification(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("check failed")
	tests := []struct {
		name      string
		check     func(context.Context, RequestView) (Decision, error)
		wantCode  string
		wantError error
	}{
		{
			name: "error",
			check: func(context.Context, RequestView) (Decision, error) {
				return Decision{}, sentinel
			},
			wantCode:  checkErrorBlockCode,
			wantError: sentinel,
		},
		{
			name: "panic",
			check: func(context.Context, RequestView) (Decision, error) {
				panic("do not leak this")
			},
			wantCode:  checkPanicBlockCode,
			wantError: errCheckPanicked,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registry := NewRegistry()
			mustRegister(t, registry, "failure", func(string, map[string]any) (Interceptor, error) {
				return testInterceptor{check: test.check}, nil
			})
			engine := mustEngine(t, registry,
				map[string]config.InterceptorConfig{"guard": {Type: "failure"}},
				testRoute("route", "guard"),
			)
			request := newRequest(t, nil)

			result := engine.Evaluate(request.Context(), request, testMatch("route", "guard"))
			if result.StatusCode != http.StatusServiceUnavailable || result.BlockedBy != "guard" || result.BlockCode != test.wantCode || result.Allowed || result.Cancelled {
				t.Fatalf("unexpected result: %+v", result)
			}
			if !errors.Is(result.Internal, test.wantError) {
				t.Fatalf("Internal = %v, want %v", result.Internal, test.wantError)
			}
		})
	}
}

func TestInvalidDecisionsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		decision Decision
	}{
		{name: "zero"},
		{name: "allow-with-status", decision: Decision{Allow: true, StatusCode: http.StatusOK}},
		{name: "allow-with-code", decision: Decision{Allow: true, BlockCode: "unexpected"}},
		{name: "reject-with-2xx", decision: Decision{StatusCode: http.StatusOK, BlockCode: "rejected"}},
		{name: "reject-with-5xx", decision: Decision{StatusCode: http.StatusServiceUnavailable, BlockCode: "rejected"}},
		{name: "reject-without-code", decision: Decision{StatusCode: http.StatusBadRequest}},
		{name: "reject-with-unstable-code", decision: Decision{StatusCode: http.StatusBadRequest, BlockCode: "Not-Stable"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registry := NewRegistry()
			mustRegister(t, registry, "decision", func(string, map[string]any) (Interceptor, error) {
				return testInterceptor{check: func(context.Context, RequestView) (Decision, error) {
					return test.decision, nil
				}}, nil
			})
			engine := mustEngine(t, registry,
				map[string]config.InterceptorConfig{"guard": {Type: "decision"}},
				testRoute("route", "guard"),
			)
			request := newRequest(t, nil)

			result := engine.Evaluate(request.Context(), request, testMatch("route", "guard"))
			if result.StatusCode != http.StatusServiceUnavailable || result.BlockedBy != "guard" || result.BlockCode != invalidDecisionCode || result.Internal == nil {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestBodyReadFailureAndCancellation(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	mustRegister(t, registry, "body", func(string, map[string]any) (Interceptor, error) {
		return testInterceptor{requirements: Requirements{NeedsBody: true, MaxBodyBytes: MinBodyBytes}}, nil
	})
	engine := mustEngine(t, registry,
		map[string]config.InterceptorConfig{"guard": {Type: "body"}},
		testRoute("route", "guard"),
	)

	t.Run("ordinary-error", func(t *testing.T) {
		sentinel := errors.New("read failed")
		body := &errorReadCloser{err: sentinel}
		request := newRequestWithBody(t, body, -1)
		result := engine.Evaluate(request.Context(), request, testMatch("route", "guard"))
		if result.StatusCode != http.StatusServiceUnavailable || result.BlockedBy != "guard" || result.BlockCode != bodyReadErrorCode || !errors.Is(result.Internal, sentinel) || result.Cancelled {
			t.Fatalf("unexpected result: %+v", result)
		}
		if !body.closed {
			t.Fatal("failed body reader was not closed")
		}
	})

	t.Run("reader-cancelled", func(t *testing.T) {
		body := &errorReadCloser{err: context.Canceled}
		request := newRequestWithBody(t, body, -1)
		result := engine.Evaluate(request.Context(), request, testMatch("route", "guard"))
		assertCancelled(t, result)
	})

	t.Run("context-cancelled-before-chain", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := newRequest(t, nil).WithContext(ctx)
		result := engine.Evaluate(ctx, request, testMatch("route", "guard"))
		assertCancelled(t, result)
	})

	t.Run("check-cancelled", func(t *testing.T) {
		cancelRegistry := NewRegistry()
		mustRegister(t, cancelRegistry, "cancel", func(string, map[string]any) (Interceptor, error) {
			return testInterceptor{check: func(context.Context, RequestView) (Decision, error) {
				return Decision{}, context.Canceled
			}}, nil
		})
		cancelEngine := mustEngine(t, cancelRegistry,
			map[string]config.InterceptorConfig{"guard": {Type: "cancel"}},
			testRoute("route", "guard"),
		)
		request := newRequest(t, nil)
		result := cancelEngine.Evaluate(request.Context(), request, testMatch("route", "guard"))
		assertCancelled(t, result)
	})
}

func TestEngineRejectsUnknownOrChangedCompiledChain(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(
		map[string]config.InterceptorConfig{"credential": {Type: "require_credential"}},
		[]config.RouteConfig{testRoute("route", "credential")},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := newRequest(t, nil)

	for _, match := range []routing.Match{
		testMatch("unknown"),
		testMatch("route"),
		testMatch("route", "credential", "extra"),
	} {
		result := engine.Evaluate(request.Context(), request, match)
		if result.StatusCode != http.StatusServiceUnavailable || result.BlockedBy != chainBlockedBy || result.BlockCode != chainErrorBlockCode || result.Internal == nil {
			t.Fatalf("match %+v produced %+v", match, result)
		}
	}

	var nilEngine *Engine
	result := nilEngine.Evaluate(request.Context(), request, testMatch("route", "credential"))
	if result.StatusCode != http.StatusServiceUnavailable || result.BlockedBy != chainBlockedBy || result.BlockCode != chainErrorBlockCode {
		t.Fatalf("nil engine produced %+v", result)
	}
}

func TestEngineSupportsConcurrentEvaluation(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(
		map[string]config.InterceptorConfig{"credential": {Type: "require_credential"}},
		[]config.RouteConfig{testRoute("route", "credential")},
	)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 64
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := newRequest(t, nil)
			request.Header.Set("Authorization", "Bearer token")
			result := engine.Evaluate(request.Context(), request, testMatch("route", "credential"))
			if !result.Allowed {
				errorsFound <- fmt.Errorf("unexpected result: %+v", result)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestEngineConstructionValidation(t *testing.T) {
	t.Parallel()

	t.Run("nil-registry", func(t *testing.T) {
		if _, err := NewEngineWithRegistry(nil, nil, nil); err == nil {
			t.Fatal("expected nil registry error")
		}
	})

	t.Run("unknown-type", func(t *testing.T) {
		if _, err := NewEngineWithRegistry(NewRegistry(), map[string]config.InterceptorConfig{"x": {Type: "missing"}}, nil); err == nil {
			t.Fatal("expected unknown type error")
		}
	})

	t.Run("unknown-route-reference", func(t *testing.T) {
		if _, err := NewEngineWithRegistry(NewRegistry(), nil, []config.RouteConfig{testRoute("route", "missing")}); err == nil {
			t.Fatal("expected unknown route reference error")
		}
	})

	t.Run("duplicate-route", func(t *testing.T) {
		if _, err := NewEngineWithRegistry(NewRegistry(), nil, []config.RouteConfig{testRoute("route"), testRoute("route")}); err == nil {
			t.Fatal("expected duplicate route error")
		}
	})

	t.Run("nil-instance", func(t *testing.T) {
		registry := NewRegistry()
		mustRegister(t, registry, "nil", func(string, map[string]any) (Interceptor, error) { return nil, nil })
		if _, err := NewEngineWithRegistry(registry, map[string]config.InterceptorConfig{"x": {Type: "nil"}}, nil); err == nil {
			t.Fatal("expected nil instance error")
		}
	})

	t.Run("factory-panic", func(t *testing.T) {
		registry := NewRegistry()
		mustRegister(t, registry, "panic", func(string, map[string]any) (Interceptor, error) { panic("factory secret") })
		if _, err := NewEngineWithRegistry(registry, map[string]config.InterceptorConfig{"x": {Type: "panic"}}, nil); err == nil || strings.Contains(err.Error(), "factory secret") {
			t.Fatalf("unexpected factory error: %v", err)
		}
	})

	t.Run("requirements-panic", func(t *testing.T) {
		registry := NewRegistry()
		mustRegister(t, registry, "panic", func(string, map[string]any) (Interceptor, error) { return panicRequirements{}, nil })
		if _, err := NewEngineWithRegistry(registry, map[string]config.InterceptorConfig{"x": {Type: "panic"}}, nil); err == nil || strings.Contains(err.Error(), "requirements secret") {
			t.Fatalf("unexpected requirements error: %v", err)
		}
	})

	invalidRequirements := []Requirements{
		{MaxBodyBytes: MinBodyBytes},
		{NeedsBody: true, MaxBodyBytes: MinBodyBytes - 1},
		{NeedsBody: true, MaxBodyBytes: MaxBodyBytes + 1},
	}
	for index, requirements := range invalidRequirements {
		index, requirements := index, requirements
		t.Run(fmt.Sprintf("invalid-requirements-%d", index), func(t *testing.T) {
			registry := NewRegistry()
			mustRegister(t, registry, "invalid", func(string, map[string]any) (Interceptor, error) {
				return testInterceptor{requirements: requirements}, nil
			})
			if _, err := NewEngineWithRegistry(registry, map[string]config.InterceptorConfig{"x": {Type: "invalid"}}, nil); err == nil {
				t.Fatal("expected invalid requirements error")
			}
		})
	}
}

func assertCancelled(t *testing.T, result Result) {
	t.Helper()
	if !result.Cancelled || result.Allowed || result.StatusCode != 0 || result.BlockedBy != "" || result.BlockCode != "" || result.Internal == nil {
		t.Fatalf("unexpected cancellation result: %+v", result)
	}
}

func mustRegister(t *testing.T, registry *Registry, typeName string, factory Factory) {
	t.Helper()
	if err := registry.Register(typeName, factory); err != nil {
		t.Fatal(err)
	}
}

func mustEngine(t *testing.T, registry *Registry, definitions map[string]config.InterceptorConfig, route config.RouteConfig) *Engine {
	t.Helper()
	engine, err := NewEngineWithRegistry(registry, definitions, []config.RouteConfig{route})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func testRoute(id string, interceptorIDs ...string) config.RouteConfig {
	return config.RouteConfig{ID: id, Interceptors: append([]string(nil), interceptorIDs...)}
}

func testMatch(id string, interceptorIDs ...string) routing.Match {
	return routing.Match{RouteID: id, InterceptorIDs: append([]string(nil), interceptorIDs...)}
}

func newRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://audit.test/v1/messages?existing=value", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func newRequestWithBody(t *testing.T, body io.ReadCloser, contentLength int64) *http.Request {
	t.Helper()
	request := newRequest(t, nil)
	request.Body = body
	request.ContentLength = contentLength
	return request
}

type trackingReadCloser struct {
	reader     io.Reader
	bytesRead  int
	closeCalls int
}

func (r *trackingReadCloser) Read(target []byte) (int, error) {
	read, err := r.reader.Read(target)
	r.bytesRead += read
	return read, err
}

func (r *trackingReadCloser) Close() error {
	r.closeCalls++
	return nil
}

type panicReadCloser struct {
	closed bool
}

func (*panicReadCloser) Read([]byte) (int, error) {
	panic("body was read")
}

func (r *panicReadCloser) Close() error {
	r.closed = true
	return nil
}

type errorReadCloser struct {
	err    error
	closed bool
}

func (r *errorReadCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *errorReadCloser) Close() error {
	r.closed = true
	return nil
}
