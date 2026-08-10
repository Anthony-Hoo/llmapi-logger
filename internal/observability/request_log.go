package observability

import (
	"context"
	"log/slog"
	"regexp"
	"time"
)

const RequestCompletedMessage = "llm request completed"

var stableCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// RequestCompletion contains only the allowlisted scalar fields that may be
// written to the per-LLM-request completion log.
type RequestCompletion struct {
	AuditID       string
	RouteID       string
	Protocol      string
	Method        string
	EscapedPath   string
	StatusCode    int
	Duration      time.Duration
	TTFT          time.Duration
	ForwardStatus string
	CaptureStatus string
	ParseStatus   string
	BlockedBy     string
	BlockCode     string
	ErrorCode     string
}

// LogRequestCompleted emits one fixed-message record. It never receives an
// http.Request or an error, so Header values, Body bytes, Query values, tokens,
// keys, and underlying error text cannot be logged accidentally.
func LogRequestCompleted(ctx context.Context, logger *slog.Logger, completion RequestCompletion) {
	if logger == nil {
		logger = slog.Default()
	}
	if ctx == nil {
		ctx = context.Background()
	} else {
		ctx = context.WithoutCancel(ctx)
	}

	durationMilliseconds := completion.Duration.Milliseconds()
	if durationMilliseconds < 0 {
		durationMilliseconds = 0
	}
	ttftMilliseconds := int64(-1)
	if completion.TTFT >= 0 {
		ttftMilliseconds = completion.TTFT.Milliseconds()
	}

	attributes := make([]any, 0, 30)
	if completion.AuditID != "" {
		attributes = append(attributes, "audit_id", completion.AuditID)
	}
	attributes = append(attributes,
		"route_id", completion.RouteID,
		"protocol", completion.Protocol,
		"method", completion.Method,
		"path", completion.EscapedPath,
		"status_code", completion.StatusCode,
		"duration_ms", durationMilliseconds,
		"ttft_ms", ttftMilliseconds,
		"forward_status", completion.ForwardStatus,
		"capture_status", completion.CaptureStatus,
		"parse_status", completion.ParseStatus,
	)
	if completion.BlockedBy != "" {
		attributes = append(attributes, "blocked_by", completion.BlockedBy)
	}
	if blockCode := normalizeStableCode(completion.BlockCode); blockCode != "" {
		attributes = append(attributes, "block_code", blockCode)
	}
	if errorCode := normalizeStableCode(completion.ErrorCode); errorCode != "" {
		attributes = append(attributes, "error_code", errorCode)
	}
	logger.InfoContext(ctx, RequestCompletedMessage, attributes...)
}

func normalizeStableCode(code string) string {
	if code == "" || stableCodePattern.MatchString(code) {
		return code
	}
	return "invalid_error_code"
}
