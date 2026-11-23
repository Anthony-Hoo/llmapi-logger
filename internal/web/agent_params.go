package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
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

// Reasons of an INVALID_ARGUMENT answer (contract section 0.1 item 115).
// Every refused argument of the read facade carries details.field, the
// parameter's wire name (query parameter, path segment or body field), and
// details.reason, one of these stable codes; the message says what is
// allowed. The command-line client rewrites field into the flag or argument
// the user typed.
const (
	reasonUnknownParameter  = "unknown_parameter"
	reasonRepeatedParameter = "repeated_parameter"
	reasonInvalidFormat     = "invalid_format"
	reasonOutOfRange        = "out_of_range"
	reasonNotAllowedValue   = "not_allowed_value"
	reasonConflict          = "conflicts_with_other_argument"
	reasonRequired          = "required"
	reasonRangeTooLong      = "range_too_long"
	reasonEmptyRange        = "empty_range"
	reasonAdministratorOnly = "administrator_only"
	reasonInvalidCursor     = "invalid_cursor"
	reasonCursorMismatch    = "cursor_query_mismatch"
	reasonCursorExpired     = "cursor_expired"
	reasonNotWeekStart      = "not_week_start"
	reasonRejectedByService = "rejected_by_service"
)

// agentArgError is a parameter problem: field names the offending parameter
// by its wire name, reason is one of the reason codes above and message
// tells the reader what is accepted. Parameter names inside message are
// written in backticks, so a client can rewrite them into its own names.
type agentArgError struct {
	field   string
	reason  string
	message string
	extra   map[string]any
}

func (err agentArgError) Error() string { return "invalid argument " + err.field }

// details is the details object of the failure envelope.
func (err agentArgError) details() map[string]any {
	details := map[string]any{"field": err.field, "reason": err.reason}
	for key, value := range err.extra {
		details[key] = value
	}
	return details
}

// with adds one more detail.
func (err agentArgError) with(key string, value any) agentArgError {
	extra := make(map[string]any, len(err.extra)+1)
	for name, existing := range err.extra {
		extra[name] = existing
	}
	extra[key] = value
	err.extra = extra
	return err
}

// argInvalid is a refused argument with an explicit reason and message.
func argInvalid(field, reason, message string) agentArgError {
	return agentArgError{field: field, reason: reason, message: message}
}

// argError is a value of field that does not have the expected form.
func argError(field string) error {
	return argInvalid(field, reasonInvalidFormat, "`"+field+"` does not have the expected form")
}

// argFormat is a value of field that does not have the form described.
func argFormat(field, expected string) error {
	return argInvalid(field, reasonInvalidFormat, "`"+field+"` must be "+expected)
}

// argNotAllowed is a value outside the closed set allowed.
func argNotAllowed(field string, allowed []string) error {
	return argInvalid(field, reasonNotAllowedValue, "`"+field+"` must be one of: "+strings.Join(allowed, ", ")).
		with("allowed", append([]string{}, allowed...))
}

// argRange is an integer outside [minimum, maximum].
func argRange(field string, minimum, maximum int64) error {
	return argInvalid(field, reasonOutOfRange, fmt.Sprintf("`%s` must be an integer from %d to %d", field, minimum, maximum)).
		with("minimum", minimum).with("maximum", maximum)
}

// argConflict names two arguments that cannot be given together.
func argConflict(field, other string) error {
	return argInvalid(field, reasonConflict, "`"+field+"` cannot be combined with `"+other+"`; give only one of them").
		with("conflicts_with", other)
}

// argAdministratorOnly is an administrator-only argument a developer token
// gave (contract D4, D5, D8 and section 0.1 item 116): the value is not the
// problem, the argument is, so it is INVALID_ARGUMENT and dropping it fixes
// the call.
func argAdministratorOnly(field string) error {
	return argInvalid(field, reasonAdministratorOnly,
		"`"+field+"` is available to administrators only; a developer token already reads only the data of its own API key")
}

const agentAdministratorOnlyHint = "Leave this argument out and run the command again; do not try another identity or another way to read other people's data."

// agentParams checks the query string of one facade call: every key must be
// in allowed and appear once. Unknown keys are refused rather than ignored,
// so a misspelt filter never silently widens a result.
func agentParams(request *http.Request, allowed ...string) (url.Values, error) {
	values := request.URL.Query()
	permitted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		permitted[key] = true
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch {
		case !permitted[key]:
			message := "`" + key + "` is not a parameter of this endpoint"
			if len(allowed) > 0 {
				message += "; it takes " + strings.Join(allowed, ", ")
			} else {
				message += "; it takes none"
			}
			return nil, argInvalid(key, reasonUnknownParameter, message).with("allowed", append([]string{}, allowed...))
		case len(values[key]) != 1:
			return nil, argInvalid(key, reasonRepeatedParameter, "`"+key+"` may be given only once")
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
		return result, argConflict("since", "from")
	}
	if values.Has("to") {
		to, err := parseAgentInstant(values.Get("to"), true)
		if err != nil {
			return result, argFormat("to", agentInstantForm)
		}
		ns := to.UnixNano()
		result.ToNS = &ns
	}
	if values.Has("from") {
		from, err := parseAgentInstant(values.Get("from"), false)
		if err != nil {
			return result, argFormat("from", agentInstantForm)
		}
		ns := from.UnixNano()
		result.FromNS = &ns
	}
	if values.Has("since") {
		duration, err := parseSince(values.Get("since"))
		if err != nil {
			return result, argFormat("since", fmt.Sprintf("a positive whole number followed by s, m, h, d or w (30m, 2h, 7d, 2w), at most %d days", maxSinceDays))
		}
		end := now
		if result.ToNS != nil {
			end = time.Unix(0, *result.ToNS)
		}
		ns := end.Add(-duration).UnixNano()
		result.FromNS = &ns
	}
	if result.FromNS != nil && result.ToNS != nil && *result.FromNS >= *result.ToNS {
		field := "from"
		if values.Has("since") {
			field = "since"
		}
		return result, argInvalid(field, reasonEmptyRange, "the range is empty: `"+field+"` must start before `to`").with("conflicts_with", "to")
	}
	return result, nil
}

const agentInstantForm = "an RFC 3339 time (2026-01-02T15:04:05Z) or a YYYY-MM-DD date"

// checkRangeLength refuses a range longer than maximum (the insights and
// session analysis services refuse more than 400 days). from and to are the
// resolved ends; the field named is the argument that set the start.
func checkRangeLength(values url.Values, fromNS, toNS int64, maximum time.Duration) error {
	if toNS-fromNS <= int64(maximum) {
		return nil
	}
	field := "from"
	if values.Has("since") {
		field = "since"
	}
	days := int64(maximum / (24 * time.Hour))
	return argInvalid(field, reasonRangeTooLong, fmt.Sprintf("the range may be at most %d days long; shorten `%s` or move `to`", days, field)).
		with("max_days", days)
}

// agentMaxServiceRange is the longest range the insights and session
// analysis services accept (query.MaxInsightsRange; sessionanalysis keeps
// the same 400 days unexported).
const agentMaxServiceRange = query.MaxInsightsRange

// agentInstantMinYear and agentInstantMaxYear bound the instants a query
// accepts: int64 nanoseconds end on 2262-04-11, and an instant beyond them
// would wrap to an unrelated time and the query would silently read the wrong
// interval (contract section 0.1 item 179).
const (
	agentInstantMinYear = 1970
	agentInstantMaxYear = 2261
)

func parseAgentInstant(value string, endOfDay bool) (time.Time, error) {
	if day, err := time.Parse(time.DateOnly, value); err == nil {
		if endOfDay {
			day = day.AddDate(0, 0, 1)
		}
		return checkAgentInstantYear(day.UTC())
	}
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || instant.UnixNano() <= 0 {
		return time.Time{}, errors.New("invalid time")
	}
	return checkAgentInstantYear(instant.UTC())
}

// checkAgentInstantYear refuses an instant, already in UTC and shifted to the
// end of its day when it is one, outside the years int64 nanoseconds hold.
func checkAgentInstantYear(instant time.Time) (time.Time, error) {
	if year := instant.Year(); year < agentInstantMinYear || year > agentInstantMaxYear {
		return time.Time{}, errors.New("invalid time")
	}
	return instant, nil
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
		return 0, argRange("limit", 1, int64(maximum))
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
		return false, argNotAllowed(name, []string{"true", "false", "1", "0"})
	}
}

// parseAgentPositiveID reads an optional ID parameter of ASCII digits that
// must be at least minimum (0 or 1).
func parseAgentPositiveID(values url.Values, name string, minimum int64) (*int64, error) {
	if !values.Has(name) {
		return nil, nil
	}
	id, ok := parseAgentID(values.Get(name), false)
	if !ok || id < minimum {
		return nil, argFormat(name, fmt.Sprintf("an integer of ASCII digits, at least %d", minimum))
	}
	return &id, nil
}

// asArgument turns a service's bare "invalid" refusal into refused, for
// calls where only that argument can be the cause (the facade checked
// everything else first). Other errors pass unchanged.
func asArgument(err error, refused error) error {
	if errors.Is(err, query.ErrInvalidQuery) || errors.Is(err, orgreport.ErrInvalid) {
		return refused
	}
	return err
}

// Opaque cursors (contract section 0.1 items 19, 117 and 149). The facade
// wraps each service's own cursor with a version, the kind of list it
// belongs to, the id of the key that signed it, a binding (a short keyed
// digest of the query the page answered and of the caller's scope) and a
// tag: a keyed digest over all of it, the service's cursor included, so
// no part can be changed. A cursor of one list is refused by another; a
// cursor signed with a key that has since been replaced (admin_token
// rotated) is refused with cursor_expired; one of another query or
// identity with cursor_query_mismatch, so pages of two queries are never
// mixed; and any other change with invalid_cursor.
const agentCursorVersion = "c3"

// agentCursorScope is what a cursor is bound to: the cursor key derived
// from the session key and the binding digest of one query and identity.
type agentCursorScope struct {
	key    []byte
	digest string
}

// keyID names the cursor key without revealing it, so a cursor of a
// replaced key can be told from a tampered one.
func (scope agentCursorScope) keyID() string {
	mac := hmac.New(sha256.New, scope.key)
	mac.Write([]byte("key-id"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:6])
}

// tag is the keyed digest of every other part of a cursor.
func (scope agentCursorScope) tag(parts ...string) string {
	mac := hmac.New(sha256.New, scope.key)
	mac.Write([]byte("tag"))
	for _, part := range parts {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// agentCursorBinding is the cursor key and the digest of the query
// parameters (every one but cursor and limit, as given: since=2h stays
// "2h", so the next page of a relative range still matches) and of the
// caller's role and scope.
func (handler *managementHandler) agentCursorBinding(kind string, values url.Values, caller principal) agentCursorScope {
	var key [32]byte
	if handler.authenticator != nil {
		key = handler.authenticator.sessionKey
	}
	derived := hmac.New(sha256.New, key[:])
	derived.Write([]byte("llmapi-logger/agent-cursor/v1"))
	cursorKey := derived.Sum(nil)
	mac := hmac.New(sha256.New, cursorKey)
	names := make([]string, 0, len(values))
	for name := range values {
		if name != "cursor" && name != "limit" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	write := func(part string) {
		mac.Write([]byte(strconv.Itoa(len(part))))
		mac.Write([]byte{':'})
		mac.Write([]byte(part))
	}
	write(kind)
	write(string(caller.Role))
	if scope := callerReadScope(caller); scope != nil {
		write(hex.EncodeToString(scope.Fingerprint))
		if scope.TokenID != nil {
			write(strconv.FormatInt(*scope.TokenID, 10))
		} else {
			write("-")
		}
	} else {
		write("all")
	}
	for _, name := range names {
		write(name)
		write(values.Get(name))
	}
	return agentCursorScope{key: cursorKey, digest: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:12])}
}

// wrapAgentCursor is BASE64URL(version "|" kind "|" key id "|" binding "|"
// tag "|" inner); the tag covers the other five.
func wrapAgentCursor(kind string, scope agentCursorScope, inner string) string {
	if inner == "" {
		return ""
	}
	keyID := scope.keyID()
	tag := scope.tag(agentCursorVersion, kind, keyID, scope.digest, inner)
	return base64.RawURLEncoding.EncodeToString([]byte(agentCursorVersion + "|" + kind + "|" + keyID + "|" + scope.digest + "|" + tag + "|" + inner))
}

// unwrapAgentCursor checks a cursor in this order: its form, version and
// list (invalid_cursor), its key (cursor_expired), its query and identity
// (cursor_query_mismatch), and the tag over the whole cursor
// (invalid_cursor).
func unwrapAgentCursor(kind string, scope agentCursorScope, cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", errInvalidCursor
	}
	parts := strings.SplitN(string(decoded), "|", 6)
	if len(parts) != 6 || parts[0] != agentCursorVersion || parts[1] != kind || parts[5] == "" {
		return "", errInvalidCursor
	}
	if !hmac.Equal([]byte(parts[2]), []byte(scope.keyID())) {
		return "", errCursorExpired
	}
	if !hmac.Equal([]byte(parts[3]), []byte(scope.digest)) {
		return "", errCursorMismatch
	}
	if !hmac.Equal([]byte(parts[4]), []byte(scope.tag(parts[0], parts[1], parts[2], parts[3], parts[5]))) {
		return "", errInvalidCursor
	}
	return parts[5], nil
}

// errCursorExpired refuses a cursor signed with a key that has since been
// replaced: the administrator changed admin_token, which every cursor key
// is derived from.
var errCursorExpired = argInvalid("cursor", reasonCursorExpired,
	"`cursor` is no longer valid: the server's keys changed since it was issued; start the list again without `cursor`")

// errCursorMismatch refuses a cursor of this list that belongs to another
// query or another identity.
var errCursorMismatch = argInvalid("cursor", reasonCursorMismatch,
	"`cursor` belongs to a different query: the next page must repeat every argument of the first page exactly (only `limit` may change) and come from the same identity; start again without `cursor` to read this query")

// errInvalidCursor refuses a cursor that is not a next_cursor of this list.
var errInvalidCursor = argInvalid("cursor", reasonInvalidCursor,
	"`cursor` is not a next_cursor of this list; pass next_cursor exactly as the previous page returned it, or leave it out for the first page")

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

// transientSQLStates are the PostgreSQL conditions that pass on their own
// (contract section 0.1 item 85): statement timeout or cancel (57014), too
// many connections (53300), administrator shutdown, crash shutdown and
// "cannot connect now" (57P01-57P03). Connection exceptions (class 08) and
// the lock, deadlock and serialization failures already have a storage error
// class. The shared storage.ErrorClass is left alone because the web routes
// report its classes.
var transientSQLStates = map[string]bool{"57014": true, "53300": true, "57P01": true, "57P02": true, "57P03": true}

func transientSQLState(err error) bool {
	var state interface{ SQLState() string }
	return errors.As(err, &state) && transientSQLStates[state.SQLState()]
}

// storageUnavailable reports the storage error classes that mean "cannot be
// reached right now" rather than a fault in this request.
func storageUnavailable(err error) bool {
	if transientSQLState(err) {
		return true
	}
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
	var failure *agentFailure
	if errors.As(err, &failure) {
		failure.write(writer)
		return
	}
	code := agentErrorCodeOf(err)
	var details map[string]any
	message := ""
	var argument agentArgError
	switch {
	case errors.As(err, &argument):
		details, message = argument.details(), argument.message
		if argument.reason == reasonAdministratorOnly {
			writeAgentFailure(writer, code, message, agentAdministratorOnlyHint, details)
			return
		}
	case code == agentapi.CodeInvalidArgument:
		// A service refused an argument the facade did not name. The read
		// facade checks every parameter first, so this is not expected; it
		// still says that the refusal came from the service.
		details = map[string]any{"reason": reasonRejectedByService}
		message = "the service refused one of the arguments"
	}
	if code == agentapi.CodeInternal || code == agentapi.CodeUpstreamUnavailable {
		handler.logger.Warn("agent facade read failed", "error_code", string(code), "error_class", storage.ErrorClass(err))
	}
	if code != agentapi.CodeNotFound {
		hint = ""
	}
	writeAgentFailure(writer, code, message, hint, details)
}

// agentModuleDisabled answers MODULE_DISABLED for an optional feature that
// is off on this deployment.
func agentModuleDisabled(writer http.ResponseWriter, module string) {
	writeAgentFailure(writer, agentapi.CodeModuleDisabled, "", "", map[string]any{"module": module})
}
