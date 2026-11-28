// Package bundle writes, re-reads and indexes the segment and gap bundles of
// the cold archive (doc/design/issue-59-stage4-cold-archive.md, sections B.4,
// C, F, G, H.2 steps 2 to 6, H.6, H.7, J.2 and K.2).
//
// A segment is three files in one directory: the lines file, the objects
// file (absent when the segment has no object entries) and the plaintext
// manifest. Data files are JSONL, gzip-compressed and, when encryption is on,
// framed with internal/archive/stream. A segment exists once its manifest
// exists: the writer publishes the manifest last and never replaces a file.
//
// Errors are *Error values whose message is a stable reason code with no
// path, value or underlying error text, so they can be logged as they are;
// the cause stays reachable through errors.Unwrap for callers.
package bundle

import (
	"context"
	"errors"
)

// Reasons the writer reports.
const (
	ReasonInvalidOptions  = "invalid_options"
	ReasonInvalidRecord   = "invalid_record"
	ReasonOrder           = "order"
	ReasonContextMismatch = "context_mismatch"
	ReasonPayloadFailed   = "payload_failed"
	ReasonPayloadMismatch = "payload_mismatch"
	ReasonEntryTooLarge   = "entry_too_large"
	ReasonEmptySegment    = "empty_segment"
	ReasonClosed          = "writer_closed"
	ReasonUnsafeName      = "unsafe_name"
	ReasonNameExists      = "name_exists"
	ReasonManifestFailed  = "manifest_failed"
	ReasonRandomFailed    = "random_failed"
	ReasonMkdirFailed     = "mkdir_failed"
	ReasonCreateFailed    = "create_failed"
	ReasonWriteFailed     = "write_failed"
	ReasonDiskFull        = "disk_full"
	ReasonSyncFailed      = "sync_failed"
	ReasonCloseFailed     = "close_failed"
	ReasonLinkFailed      = "link_failed"
	ReasonDirSyncFailed   = "dir_sync_failed"
)

// Reasons the reader, the verifier and the index report. The verify codes
// of the reader tool (K.1) are among them: file_mismatch, mac_mismatch,
// key_mismatch, decrypt_failed, digest_mismatch, object_mismatch and
// reference_open.
const (
	ReasonManifestInvalid  = "manifest_invalid"
	ReasonKeyRequired      = "key_required"
	ReasonKeyMismatch      = "key_mismatch"
	ReasonMACMismatch      = "mac_mismatch"
	ReasonFileMissing      = "file_missing"
	ReasonFileMismatch     = "file_mismatch"
	ReasonReadFailed       = "read_failed"
	ReasonDecryptFailed    = "decrypt_failed"
	ReasonDecompressFailed = "decompress_failed"
	ReasonLineInvalid      = "line_invalid"
	ReasonCountMismatch    = "count_mismatch"
	ReasonMemberMismatch   = "member_mismatch"
	ReasonDigestMismatch   = "digest_mismatch"
	ReasonObjectMismatch   = "object_mismatch"
	ReasonRawMismatch      = "raw_mismatch"
	ReasonReferenceOpen    = "reference_open"
	ReasonEventMAC         = "event_mac_mismatch"
	ReasonNotVerified      = "not_verified"
	ReasonNotFound         = "not_found"
	ReasonRenameFailed     = "rename_failed"
	ReasonCanceled         = "canceled"
)

// Error is the error of every operation of the package. Error() is the
// reason code alone; Unwrap returns the cause, which may hold paths and
// values and must not be logged.
type Error struct {
	reason string
	err    error
}

func (e *Error) Error() string { return "archive bundle: " + e.reason }

// Reason is the stable reason code.
func (e *Error) Reason() string { return e.reason }

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.err }

// ReasonOf returns the reason code of a *Error in err's chain, or "" when
// there is none.
func ReasonOf(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}

func fail(reason string, err error) *Error {
	if err == nil {
		err = errors.New(reason)
	}
	return &Error{reason: reason, err: err}
}

// keep returns err when it already is a *Error, otherwise wraps it with
// reason. Context errors become ReasonCanceled.
func keep(reason string, err error) error {
	if err == nil {
		return nil
	}
	var target *Error
	if errors.As(err, &target) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fail(ReasonCanceled, err)
	}
	return fail(reason, err)
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fail(ReasonInvalidOptions, errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return fail(ReasonCanceled, err)
	}
	return nil
}
