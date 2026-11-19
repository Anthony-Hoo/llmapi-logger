package agentapi

import (
	"net/http"
	"sort"
)

// Code is a stable error code (contract section 2.3).
type Code string

// Server error codes.
const (
	CodeFeatureDisabled     Code = "FEATURE_DISABLED"
	CodeUnauthenticated     Code = "UNAUTHENTICATED"
	CodeTokenExpired        Code = "TOKEN_EXPIRED"
	CodeTokenRevoked        Code = "TOKEN_REVOKED"
	CodeRoleUnavailable     Code = "ROLE_UNAVAILABLE"
	CodeClientTooOld        Code = "CLIENT_TOO_OLD"
	CodeForbiddenRole       Code = "FORBIDDEN_ROLE"
	CodeReadOnlyToken       Code = "READ_ONLY_TOKEN"
	CodeWriteDisabled       Code = "WRITE_DISABLED"
	CodeModuleDisabled      Code = "MODULE_DISABLED"
	CodeInvalidArgument     Code = "INVALID_ARGUMENT"
	CodeNotFound            Code = "NOT_FOUND"
	CodeAlreadyExists       Code = "ALREADY_EXISTS"
	CodeConflict            Code = "CONFLICT"
	CodeVersionConflict     Code = "VERSION_CONFLICT"
	CodePlanNotFound        Code = "PLAN_NOT_FOUND"
	CodePlanExpired         Code = "PLAN_EXPIRED"
	CodeLinkExpired         Code = "LINK_EXPIRED"
	CodeRunInProgress       Code = "RUN_IN_PROGRESS"
	CodeNotReady            Code = "NOT_READY"
	CodeNotRetained         Code = "NOT_RETAINED"
	CodeEvidenceUnavailable Code = "EVIDENCE_UNAVAILABLE"
	CodeRateLimited         Code = "RATE_LIMITED"
	CodeUpstreamUnavailable Code = "UPSTREAM_UNAVAILABLE"
	CodeTimeout             Code = "TIMEOUT"
	CodeInvalidGrant        Code = "INVALID_GRANT"
	CodeInternal            Code = "INTERNAL"
)

// Client-local error codes; the server never sends them.
const (
	CodeNotLoggedIn     Code = "NOT_LOGGED_IN"
	CodeNetworkError    Code = "NETWORK_ERROR"
	CodeInvalidResponse Code = "INVALID_RESPONSE"
	CodeRedirectRefused Code = "REDIRECT_REFUSED"
	CodeLoginTimeout    Code = "LOGIN_TIMEOUT"
	CodeLoginDenied     Code = "LOGIN_DENIED"
	CodeNoTTY           Code = "NO_TTY"
	CodeLocalFileError  Code = "LOCAL_FILE_ERROR"
)

// Exit codes of the command-line client (contract section 2.3). Exit code 3
// is deliberately unused.
const (
	ExitOK             = 0
	ExitError          = 1
	ExitInvalidUsage   = 2
	ExitUnauthorized   = 4
	ExitForbidden      = 5
	ExitOperationFails = 6
)

// CodeSpec is one row of the error table. HTTPStatus is zero for a
// client-local code.
type CodeSpec struct {
	Code       Code
	HTTPStatus int
	ExitCode   int
	Local      bool
	// Message and Hint are the defaults written when a handler gives none.
	// A hint names the next command to run, and only real commands.
	Message string
	Hint    string
}

// codeTable is the single source of truth for status and exit codes; both the
// server and the client read it.
var codeTable = map[Code]CodeSpec{
	CodeFeatureDisabled: {HTTPStatus: http.StatusNotFound, ExitCode: ExitError,
		Message: "agent access is not enabled on this deployment",
		Hint:    "Tell the user agent access is not enabled here. Do not retry, log in again or remove local credentials."},
	CodeUnauthenticated: {HTTPStatus: http.StatusUnauthorized, ExitCode: ExitUnauthorized,
		Message: "a valid agent token is required",
		Hint:    "Stop and ask the user to run `llmaudit login`."},
	CodeTokenExpired: {HTTPStatus: http.StatusUnauthorized, ExitCode: ExitUnauthorized,
		Message: "the agent token has expired",
		Hint:    "Stop and ask the user to run `llmaudit login`."},
	CodeTokenRevoked: {HTTPStatus: http.StatusUnauthorized, ExitCode: ExitUnauthorized,
		Message: "the agent token has been revoked",
		Hint:    "Stop, tell the user the token was revoked and ask them to run `llmaudit login`."},
	CodeRoleUnavailable: {HTTPStatus: http.StatusUnauthorized, ExitCode: ExitUnauthorized,
		Message: "developer sign-in is disabled, so developer agent tokens are no longer valid",
		Hint:    "Tell the user to contact the administrator."},
	CodeClientTooOld: {HTTPStatus: http.StatusUpgradeRequired, ExitCode: ExitError,
		Message: "this llmaudit version is older than the server supports",
		Hint:    "Ask the user to reinstall the llmapi-audit skill from the Agent access page."},
	CodeForbiddenRole: {HTTPStatus: http.StatusForbidden, ExitCode: ExitForbidden,
		Message: "this command is available to administrators only",
		Hint:    "Stop and tell the user; do not try another way."},
	CodeReadOnlyToken: {HTTPStatus: http.StatusForbidden, ExitCode: ExitForbidden,
		Message: "the agent token is read-only",
		Hint:    "Stop; if a write is needed, ask the user to run `llmaudit login --write`."},
	CodeWriteDisabled: {HTTPStatus: http.StatusForbidden, ExitCode: ExitForbidden,
		Message: "writes through agents are disabled on this deployment",
		Hint:    "Stop and tell the user to make the change in the web UI."},
	CodeModuleDisabled: {HTTPStatus: http.StatusNotFound, ExitCode: ExitError,
		Message: "the feature behind this command is not enabled",
		Hint:    "Tell the user the feature is not enabled."},
	CodeInvalidArgument: {HTTPStatus: http.StatusBadRequest, ExitCode: ExitInvalidUsage,
		Message: "invalid argument",
		Hint:    "Fix the argument named in details.field and retry."},
	CodeNotFound: {HTTPStatus: http.StatusNotFound, ExitCode: ExitError,
		Message: "not found",
		Hint:    "The object does not exist, is not visible to this identity, or is not ready yet. Do not switch identity or path to retry."},
	CodeAlreadyExists: {HTTPStatus: http.StatusConflict, ExitCode: ExitError,
		Message: "an object with this name already exists",
		Hint:    "Modify the existing object (details.id) or choose another name."},
	CodeConflict: {HTTPStatus: http.StatusConflict, ExitCode: ExitError,
		Message: "the change conflicts with existing data"},
	CodeVersionConflict: {HTTPStatus: http.StatusConflict, ExitCode: ExitError,
		Message: "the object changed after the plan was created",
		Hint:    "Read the object again and create a new plan."},
	CodePlanNotFound: {HTTPStatus: http.StatusNotFound, ExitCode: ExitError,
		Message: "the plan does not exist, was already applied or belongs to another token",
		Hint:    "Create a new plan."},
	CodePlanExpired: {HTTPStatus: http.StatusGone, ExitCode: ExitError,
		Message: "the plan has expired",
		Hint:    "Create a new plan."},
	CodeLinkExpired: {HTTPStatus: http.StatusGone, ExitCode: ExitError,
		Message: "the download link has expired",
		Hint:    "Ask the user to generate a new install prompt on the Agent access page of the web UI."},
	CodeRunInProgress: {HTTPStatus: http.StatusConflict, ExitCode: ExitError,
		Message: "a session analysis run is already in progress",
		Hint:    "Do not trigger another run; check progress with `llmaudit analysis overview --since 1d`."},
	CodeNotReady: {HTTPStatus: http.StatusConflict, ExitCode: ExitError,
		Message: "the evidence is not ready yet",
		Hint:    "Read it again later."},
	CodeNotRetained: {HTTPStatus: http.StatusGone, ExitCode: ExitError,
		Message: "the raw body was released after verification",
		Hint:    "Export the reconstructed request or response instead; this is not data loss."},
	CodeEvidenceUnavailable: {HTTPStatus: http.StatusInternalServerError, ExitCode: ExitError,
		Message: "the evidence failed its integrity check",
		Hint:    "Tell the user; do not retry."},
	CodeRateLimited: {HTTPStatus: http.StatusTooManyRequests, ExitCode: ExitError,
		Message: "rate limit exceeded",
		Hint:    "Wait until Retry-After has passed, then try once more."},
	CodeUpstreamUnavailable: {HTTPStatus: http.StatusBadGateway, ExitCode: ExitError,
		Message: "a dependency of the server is unavailable",
		Hint:    "Try once more later."},
	CodeTimeout: {HTTPStatus: http.StatusServiceUnavailable, ExitCode: ExitError,
		Message: "the request timed out",
		Hint:    "Narrow the request and retry; after a write, read first to check whether it took effect."},
	CodeInvalidGrant: {HTTPStatus: http.StatusBadRequest, ExitCode: ExitUnauthorized,
		Message: "the authorization code is invalid, expired, already used, or the verifier does not match",
		Hint:    "Run `llmaudit login` again."},
	CodeInternal: {HTTPStatus: http.StatusInternalServerError, ExitCode: ExitError,
		Message: "internal error",
		Hint:    "Tell the user; do not retry."},

	CodeNotLoggedIn: {ExitCode: ExitUnauthorized, Local: true,
		Message: "no local credentials", Hint: "Ask the user to run `llmaudit login`."},
	CodeNetworkError: {ExitCode: ExitError, Local: true,
		Message: "could not connect to the server"},
	CodeInvalidResponse: {ExitCode: ExitError, Local: true,
		Message: "the server response is not a valid envelope"},
	CodeRedirectRefused: {ExitCode: ExitError, Local: true,
		Message: "the server answered with a redirect, which llmaudit does not follow"},
	CodeLoginTimeout: {ExitCode: ExitUnauthorized, Local: true,
		Message: "timed out waiting for the browser authorization"},
	CodeLoginDenied: {ExitCode: ExitUnauthorized, Local: true,
		Message: "the authorization was denied"},
	CodeNoTTY: {ExitCode: ExitInvalidUsage, Local: true,
		Message: "this command must run in an interactive terminal",
		Hint:    "Ask the user to run this command themselves in a terminal."},
	CodeLocalFileError: {ExitCode: ExitError, Local: true,
		Message: "could not read or write a local file"},
}

// Lookup returns the table row of code. An unknown code reports false and
// the INTERNAL row, so a caller can never emit a status the table lacks.
func Lookup(code Code) (CodeSpec, bool) {
	spec, ok := codeTable[code]
	if !ok {
		spec = codeTable[CodeInternal]
		spec.Code = CodeInternal
		return spec, false
	}
	spec.Code = code
	return spec, true
}

// HTTPStatus is the response status of a server code; INTERNAL's for an
// unknown or client-local code.
func HTTPStatus(code Code) int {
	spec, ok := Lookup(code)
	if !ok || spec.Local {
		return http.StatusInternalServerError
	}
	return spec.HTTPStatus
}

// ExitCode is the client's exit code for code; ExitError for an unknown code.
func ExitCode(code Code) int {
	spec, ok := Lookup(code)
	if !ok {
		return ExitError
	}
	return spec.ExitCode
}

// Codes lists every code in the table, sorted.
func Codes() []CodeSpec {
	specs := make([]CodeSpec, 0, len(codeTable))
	for code := range codeTable {
		spec, _ := Lookup(code)
		specs = append(specs, spec)
	}
	sort.Slice(specs, func(left, right int) bool { return specs[left].Code < specs[right].Code })
	return specs
}
