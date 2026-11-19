package web

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/uaguard"
)

// Shared plumbing of the read facade (contract section 4 conventions): query
// parameter checks, the unified time range, opaque cursors, the error
// mapping and the time converters. Every facade read handler goes through
// these, so the conventions cannot drift between endpoint groups.

// agentArgError is a parameter problem; field names the offending parameter.
type agentArgError struct {
	field string
}

func (err agentArgError) Error() string { return "invalid argument " + err.field }

func argError(field string) error { return agentArgError{field: field} }

// agentParams checks the query string of one facade call: every key must be
// in allowed and appear once. Unknown keys are refused rather than ignored,
// so a misspelt filter never silently widens a result.
func agentParams(request *http.Request, allowed ...string) (url.Values, error) {
	values := request.URL.Query()
	permitted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		permitted[key] = true
	}
	for key, entries := range values {
		if !permitted[key] || len(entries) != 1 {
			return nil, argError(key)
		}
	}
	return values, nil
}

// agentRange is a resolved time range in Unix nanoseconds. To is exclusive;
// either end is nil when the caller gave neither it nor something implying it.
type agentRange struct {
	FromNS *int64
	ToNS   *int64
}

// maxSinceDays bounds since; the services bound the range itself.
const maxSinceDays = 3660

// parseAgentRange reads from, to and since (contract section 4). from and to
// take RFC 3339 or YYYY-MM-DD; a date is the UTC day, so from=D starts at its
// midnight and to=D ends at the next midnight. since is a positive count of
// s, m, h, d or w back from to (or now). since and from are exclusive.
func parseAgentRange(values url.Values, now time.Time) (agentRange, error) {
	var result agentRange
	if values.Has("since") && values.Has("from") {
		return result, argError("since")
	}
	if values.Has("to") {
		to, err := parseAgentInstant(values.Get("to"), true)
		if err != nil {
			return result, argError("to")
		}
		ns := to.UnixNano()
		result.ToNS = &ns
	}
	if values.Has("from") {
		from, err := parseAgentInstant(values.Get("from"), false)
		if err != nil {
			return result, argError("from")
		}
		ns := from.UnixNano()
		result.FromNS = &ns
	}
	if values.Has("since") {
		duration, err := parseSince(values.Get("since"))
		if err != nil {
			return result, argError("since")
		}
		end := now
		if result.ToNS != nil {
			end = time.Unix(0, *result.ToNS)
		}
		ns := end.Add(-duration).UnixNano()
		result.FromNS = &ns
	}
	if result.FromNS != nil && result.ToNS != nil && *result.FromNS >= *result.ToNS {
		return result, argError("from")
	}
	return result, nil
}

func parseAgentInstant(value string, endOfDay bool) (time.Time, error) {
	if day, err := time.Parse(time.DateOnly, value); err == nil {
		if endOfDay {
			day = day.AddDate(0, 0, 1)
		}
		return day.UTC(), nil
	}
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || instant.UnixNano() <= 0 {
		return time.Time{}, errors.New("invalid time")
	}
	return instant.UTC(), nil
}

func parseSince(value string) (time.Duration, error) {
	if len(value) < 2 || len(value) > 8 {
		return 0, errors.New("invalid since")
	}
	count, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || count <= 0 || !asciiDigits(value[:len(value)-1]) {
		return 0, errors.New("invalid since")
	}
	var unit time.Duration
	switch value[len(value)-1] {
	case 's':
		unit = time.Second
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	case 'w':
		unit = 7 * 24 * time.Hour
	default:
		return 0, errors.New("invalid since")
	}
	duration := time.Duration(count) * unit
	if duration > maxSinceDays*24*time.Hour {
		return 0, errors.New("invalid since")
	}
	return duration, nil
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// parseAgentID parses a decimal identifier of ASCII digits only (contract
// section 4); negative values are allowed only when allowNegative is set.
func parseAgentID(value string, allowNegative bool) (int64, bool) {
	digits := value
	if allowNegative && strings.HasPrefix(value, "-") {
		digits = value[1:]
	}
	if !asciiDigits(digits) || len(digits) > 19 {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}

// parseAgentLimit reads limit with the endpoint's default and bounds.
func parseAgentLimit(values url.Values, fallback, maximum int) (int, error) {
	if !values.Has("limit") {
		return fallback, nil
	}
	limit, ok := parseAgentID(values.Get("limit"), false)
	if !ok || limit < 1 || limit > int64(maximum) {
		return 0, argError("limit")
	}
	return int(limit), nil
}

// parseAgentBool reads a boolean parameter: true, false, 1 or 0.
func parseAgentBool(values url.Values, name string, fallback bool) (bool, error) {
	if !values.Has(name) {
		return fallback, nil
	}
	switch values.Get(name) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, argError(name)
	}
}

// Opaque cursors. The facade wraps each service's own cursor with a version
// and the kind of list it belongs to, so a cursor of one list is refused by
// another instead of being misread.
const agentCursorVersion = "c1"

func wrapAgentCursor(kind, inner string) string {
	if inner == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(agentCursorVersion + "|" + kind + "|" + inner))
}

func unwrapAgentCursor(kind, cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", argError("cursor")
	}
	parts := strings.SplitN(string(decoded), "|", 3)
	if len(parts) != 3 || parts[0] != agentCursorVersion || parts[1] != kind || parts[2] == "" {
		return "", argError("cursor")
	}
	return parts[2], nil
}

// agentTime formats a Unix nanosecond time as RFC 3339 UTC with the full
// precision; zero means unset and becomes null.
func agentTime(ns int64) *string {
	if ns == 0 {
		return nil
	}
	formatted := time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
	return &formatted
}

func agentTimePointer(ns *int64) *string {
	if ns == nil {
		return nil
	}
	return agentTime(*ns)
}

// agentSeconds converts a nanosecond duration to seconds.
func agentSeconds(ns int64) float64 {
	return float64(ns) / float64(time.Second)
}

func agentMillis(ns *int64) *float64 {
	if ns == nil {
		return nil
	}
	value := float64(*ns) / float64(time.Millisecond)
	return &value
}

// Meta states of reads that are not a record with a lifecycle.
const (
	agentStateOK = "ok"
)

func agentMetaOK() agentapi.Meta {
	return agentapi.Meta{State: agentStateOK, Complete: true}
}

// writeAgentFailure writes a failure envelope with an explicit message or
// hint; empty strings take the code's defaults.
func writeAgentFailure(writer http.ResponseWriter, code agentapi.Code, message, hint string, details map[string]any) {
	writeJSON(writer, agentapi.HTTPStatus(code), agentapi.Failure(code, message, hint, details))
}

// writeAgentRead writes a read result, adding the fixed notice when the data
// carries _untrusted fields.
func writeAgentRead(writer http.ResponseWriter, data any, meta agentapi.Meta, untrusted bool, nextActions ...string) {
	envelope := agentapi.ReadSuccess(data, meta)
	if untrusted {
		envelope.Notice = agentapi.UntrustedNotice
	}
	envelope.NextActions = nextActions
	writeAgentOK(writer, envelope)
}

// agentErrorCodeOf classifies a service error (contract section 2.3). The
// catch-all of the web API ("unavailable", 503) is split: storage that cannot
// be reached is UPSTREAM_UNAVAILABLE, a deadline TIMEOUT and anything else
// INTERNAL. It never looks at the error text.
func agentErrorCodeOf(err error) agentapi.Code {
	var argument agentArgError
	switch {
	case errors.As(err, &argument):
		return agentapi.CodeInvalidArgument
	case errors.Is(err, errAdministratorOnly):
		return agentapi.CodeForbiddenRole
	case errors.Is(err, context.DeadlineExceeded):
		return agentapi.CodeTimeout
	case errors.Is(err, query.ErrInvalidQuery), errors.Is(err, orgreport.ErrInvalid),
		errors.Is(err, orgreport.ErrInvalidSettings), errors.Is(err, sessionanalysis.ErrInvalidSettings),
		errors.Is(err, uaguard.ErrInvalidRule), errors.Is(err, contentpolicy.ErrInvalidRule):
		return agentapi.CodeInvalidArgument
	case errors.Is(err, query.ErrNotFound), errors.Is(err, orgreport.ErrNotFound),
		errors.Is(err, uaguard.ErrNotFound), errors.Is(err, contentpolicy.ErrNotFound):
		return agentapi.CodeNotFound
	case errors.Is(err, query.ErrNotReady), errors.Is(err, query.ErrNoTurnGraph):
		return agentapi.CodeNotReady
	case errors.Is(err, query.ErrNotRetained):
		return agentapi.CodeNotRetained
	case errors.Is(err, query.ErrIntegrity):
		return agentapi.CodeEvidenceUnavailable
	case errors.Is(err, orgreport.ErrConflict):
		return agentapi.CodeConflict
	case errors.Is(err, errAgentUnavailable), errors.Is(err, orgreport.ErrUnavailable),
		errors.Is(err, contentpolicy.ErrUnavailable), storageUnavailable(err):
		return agentapi.CodeUpstreamUnavailable
	default:
		return agentapi.CodeInternal
	}
}

// errAgentUnavailable marks a dependency the handler found missing (a nil
// service), the facade form of the web API's 503 "unavailable".
var errAgentUnavailable = errors.New("web: dependency unavailable")

// storageUnavailable reports the storage error classes that mean "cannot be
// reached right now" rather than a fault in this request.
func storageUnavailable(err error) bool {
	switch storage.ErrorClass(err) {
	case "closed", "queue_full", "postgres_connection", "postgres_busy", "postgres_read_only",
		"postgres_full", "postgres_io_error", "sqlite_busy", "sqlite_read_only", "sqlite_full", "sqlite_io_error":
		return true
	default:
		return false
	}
}

// writeAgentServiceFailure maps a service error onto the envelope. A
// cancelled request (the client went away) writes nothing, as the web does.
// hint overrides the code's default hint when not empty.
func (handler *managementHandler) writeAgentServiceFailure(writer http.ResponseWriter, err error, hint string) {
	if errors.Is(err, context.Canceled) {
		return
	}
	code := agentErrorCodeOf(err)
	var details map[string]any
	var argument agentArgError
	if errors.As(err, &argument) {
		details = map[string]any{"field": argument.field}
	}
	if code == agentapi.CodeInternal || code == agentapi.CodeUpstreamUnavailable {
		handler.logger.Warn("agent facade read failed", "error_code", string(code), "error_class", storage.ErrorClass(err))
	}
	if code != agentapi.CodeNotFound {
		hint = ""
	}
	writeAgentFailure(writer, code, "", hint, details)
}

// agentModuleDisabled answers MODULE_DISABLED for an optional feature that
// is off on this deployment.
func agentModuleDisabled(writer http.ResponseWriter, module string) {
	writeAgentFailure(writer, agentapi.CodeModuleDisabled, "", "", map[string]any{"module": module})
}
