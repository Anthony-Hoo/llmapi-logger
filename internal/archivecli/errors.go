package archivecli

import (
	"context"
	"errors"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/query"
)

// Exit codes of audit-archive.
const (
	// ExitOK: the command did what it was asked.
	ExitOK = 0
	// ExitFailed: a check failed, a bundle could not be read or verified,
	// the key does not match, or the output could not be written.
	ExitFailed = 1
	// ExitUsage: the command line is wrong.
	ExitUsage = 2
	// ExitNotFound: the audit or conversation is not in the index, the
	// export kind does not exist for the record, or fpr found no match.
	ExitNotFound = 3
)

// Error codes the tool prints. The bundle package's reason codes
// (bundle.Reason*) are printed as they are.
const (
	codeUsage         = "usage"
	codeKeyFile       = "key_file"
	codeKeyRequired   = bundle.ReasonKeyRequired
	codeKeyMismatch   = bundle.ReasonKeyMismatch
	codeNotFound      = "not_found"
	codeNotAvailable  = "not_available"
	codeNotRetained   = "not_retained"
	codeNotReady      = "not_ready"
	codeNoTurnGraph   = "no_turn_graph"
	codeIntegrity     = "integrity"
	codeWriteFailed   = "write_failed"
	codeCanceled      = bundle.ReasonCanceled
	codeInternal      = "internal"
	codeArchiveAbsent = "archive_not_found"
	// codeIncomplete: the index left out a manifest, so the output of a
	// command that claims a complete scope may lack records.
	codeIncomplete = "incomplete"
)

// cliError is a failure with a stable code and a message that carries no
// key material, credential value, file content or path the user did not
// pass.
type cliError struct {
	code    string
	message string
}

func (err *cliError) Error() string {
	if err.message == "" {
		return err.code
	}
	return err.code + ": " + err.message
}

// ErrorCode is the stable code of an error of this package, of the bundle
// package (its reason), or of the query layer's plaintext half (the error
// classes the read-equivalence test of design J.3 compares: not_found,
// not_retained, not_ready, no_turn_graph, integrity). Anything else is
// "internal".
func ErrorCode(err error) string {
	var coded *cliError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &coded):
		return coded.code
	case bundle.ReasonOf(err) != "":
		return bundle.ReasonOf(err)
	case errors.Is(err, query.ErrNotFound):
		return codeNotFound
	case errors.Is(err, query.ErrNotRetained):
		return codeNotRetained
	case errors.Is(err, query.ErrNotReady):
		return codeNotReady
	case errors.Is(err, query.ErrNoTurnGraph):
		return codeNoTurnGraph
	case errors.Is(err, query.ErrIntegrity), errors.Is(err, archive.ErrIntegrity), errors.Is(err, auditmodel.ErrIntegrity),
		errors.Is(err, archive.ErrNotMaterialized):
		return codeIntegrity
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return codeCanceled
	default:
		return codeInternal
	}
}

// exitCode maps a code to the exit code.
func exitCode(code string) int {
	switch code {
	case "":
		return ExitOK
	case codeUsage:
		return ExitUsage
	case codeNotFound, codeNotAvailable, codeNotRetained, codeNotReady, codeNoTurnGraph:
		return ExitNotFound
	default:
		return ExitFailed
	}
}

// messages explains the codes a user meets most; the others are bundle
// reason codes that name the failed check themselves.
var messages = map[string]string{
	codeKeyRequired:          "this needs the master key file (--key); bundles written without encryption can be read with --unauthenticated instead",
	codeKeyMismatch:          "the key does not match the key the bundle was written with",
	bundle.ReasonMACMismatch: "the manifest signature does not verify",
	codeNotFound:             "not in the archive",
	codeNotAvailable:         "this record has no such export",
	codeNotRetained:          "the raw body was not kept in full for this record",
	codeNotReady:             "the record was archived before this content was complete",
	codeNoTurnGraph:          "the record has no turn to rebuild a provider request or response from",
	codeIntegrity:            "archived content failed an integrity check",
	codeWriteFailed:          "could not write to standard output",
	codeCanceled:             "interrupted",
	codeInternal:             "unexpected error",
	codeArchiveAbsent:        "the archive directory does not exist or is not a directory",
}

// describe returns the code and the message of err for standard error.
func describe(err error) (string, string) {
	code := ErrorCode(err)
	var coded *cliError
	if errors.As(err, &coded) && coded.message != "" {
		return code, coded.message
	}
	if message, ok := messages[code]; ok {
		return code, message
	}
	return code, "check failed"
}
