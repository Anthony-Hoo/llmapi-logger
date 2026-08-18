package interceptor

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"llmapi-logger/internal/security"
)

type requireCredential struct{}

func newRequireCredential(_ string, raw map[string]any) (Interceptor, error) {
	if len(raw) != 0 {
		return nil, fmt.Errorf("require_credential: unknown configuration fields")
	}
	return requireCredential{}, nil
}

func (requireCredential) Requirements() Requirements {
	return Requirements{}
}

func (requireCredential) Check(_ context.Context, request RequestView) (Decision, error) {
	if security.HasCredential(request.Headers(), request.Query()) {
		return Decision{Allow: true}, nil
	}

	return Decision{
		StatusCode: http.StatusUnauthorized,
		BlockCode:  "credential_required",
	}, nil
}

type maxBodyBytes struct {
	maxBytes int64
}

func newMaxBodyBytes(_ string, raw map[string]any) (Interceptor, error) {
	if len(raw) != 1 {
		return nil, fmt.Errorf("max_body_bytes: config must contain only max_bytes")
	}

	value, exists := raw["max_bytes"]
	if !exists {
		return nil, fmt.Errorf("max_body_bytes: max_bytes is required")
	}
	maxBytes, ok := exactInt64(value)
	if !ok || maxBytes < MinBodyBytes || maxBytes > MaxBodyBytes {
		return nil, fmt.Errorf("max_body_bytes: max_bytes must be between %d and %d", MinBodyBytes, MaxBodyBytes)
	}

	return maxBodyBytes{maxBytes: maxBytes}, nil
}

func (m maxBodyBytes) Requirements() Requirements {
	return Requirements{NeedsBody: true, MaxBodyBytes: m.maxBytes}
}

func (maxBodyBytes) Check(_ context.Context, _ RequestView) (Decision, error) {
	// Engine.Evaluate enforces each interceptor's declared bound before Check.
	return Decision{Allow: true}, nil
}

func exactInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		if uint64(number) > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case uint8:
		return int64(number), true
	case uint16:
		return int64(number), true
	case uint32:
		return int64(number), true
	case uint64:
		if number > math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	case float32:
		converted := int64(number)
		return converted, float32(converted) == number
	case float64:
		converted := int64(number)
		return converted, float64(converted) == number
	default:
		return 0, false
	}
}
