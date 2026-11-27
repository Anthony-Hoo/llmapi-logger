package storage

// RawRetentionOutcome is what the raw retention decision of one parsed audit
// depends on. Both stores fill it inside the transaction that saves the parse,
// so the PostgreSQL and SQLite stores apply the same rule
// (doc/features/18-content-addressed-conversation-storage.md section 6).
type RawRetentionOutcome struct {
	// ParseStatus is the status the parse is saved with.
	ParseStatus string
	// TurnVerified is true when a prepared turn was persisted and its stored
	// request and response sequences re-read equal to what was prepared.
	TurnVerified bool
	// RequestNormalized is true when the turn rebuilt a request body, that
	// is, its request layout is not auditmodel.LayoutNone.
	RequestNormalized bool
	// ResponseOmitted is true when the turn carries no response (its
	// response layout is auditmodel.LayoutNone) although a response body was
	// captured: a request-only turn, prepared because the response was
	// incomplete, parsed partially or not normalized. Nothing stands in for
	// that response, so its raw is never released.
	ResponseOmitted bool
	ForwardStatus   string
	CaptureStatus   string
	// StatusCode is the HTTP status recorded on the audit; nil when no
	// response status was observed.
	StatusCode *int64
	// UpstreamErrorClass is the parser's policy classification of an upstream
	// error body; nil or empty means unclassified.
	UpstreamErrorClass *string
	// RequestStagesMerged is true when request_sent was found byte-identical
	// to request_received and merged into it (request_sent.source_stage ==
	// request_received), both request stages are complete and neither carries
	// body_stage_mismatch.
	RequestStagesMerged bool
}

// RawRetention says, per side, whether the raw body chunks are released
// (retention_state metadata) or kept (full). The request side is the stages
// request_for_newapi_received_from_nginx and request_sent_to_newapi; the
// response side is the other two.
type RawRetention struct {
	ReleaseRequest  bool
	ReleaseResponse bool
}

// requestRelease is what an abnormal outcome does to the request side.
type requestRelease int

const (
	// keepRequest keeps the request raw.
	keepRequest requestRelease = iota
	// releaseRequest releases the request raw.
	releaseRequest
	// releaseRequestIfClassified releases the request raw only when the
	// upstream error body was classified (upstream_error_class IS NOT NULL).
	// An unclassified 400 or 422 may mean the request itself was malformed,
	// so its bytes stay available for examination.
	releaseRequestIfClassified
)

// abnormalRequestRelease lists the non-2xx/3xx statuses the decision of issue
// #59 (design 5.9 item 1) names for releasing the request raw. 5xx is matched
// as a class in requestReleaseFor. A status missing here keeps the request
// raw: see the unlisted branch below.
var abnormalRequestRelease = map[int64]requestRelease{
	400: releaseRequestIfClassified,
	401: releaseRequest,
	403: releaseRequest,
	408: releaseRequest,
	409: releaseRequest,
	422: releaseRequestIfClassified,
	429: releaseRequest,
	499: releaseRequest,
}

// DecideRawRetention applies the per-side raw retention rule.
//
// Without a verified turn nothing is released: there is no verified
// reconstruction to stand in for the raw bytes. A turn that carries the
// response needs an ok parse; a request-only turn (ResponseOmitted) may also
// come with a partial one, since its parse is partial because of the response
// it does not carry. A normal outcome (forward completed, capture complete,
// 2xx/3xx) with the response in the turn releases both sides, as before. Any
// other outcome, and every request-only turn, keeps the response raw, and
// releases the request raw only when its two stages were merged and the
// outcome is normal or one the decision lists. A request-only turn of a
// normal outcome is the decision's "response parse incomplete" row (or a
// complete response the normalizer declined). A row that keeps the request
// wins over the cancellation: a client cancel after an unclassified 400 or an
// unlisted status keeps the request.
//
// What "verified" covers for the request: the parser rebuilt the request
// from its content objects and envelope and checked that the canonical JSON
// of the rebuild hashes equal to the canonical JSON of the decoded
// request_received body (auditmodel.PrepareWithLookup), and the store re-read
// the persisted request sequence and compared its hash (persistPreparedTurn).
// That is semantic JSON equality, not byte equality: key order, whitespace
// and the content encoding are not reproduced, which is the same guarantee a
// normal request already gets when its raw is released. Merged stages extend
// it to request_sent, whose bytes were found identical to request_received.
func DecideRawRetention(outcome RawRetentionOutcome) RawRetention {
	if !outcome.TurnVerified {
		return RawRetention{}
	}
	switch {
	case outcome.ParseStatus == ParseOK:
	case outcome.ParseStatus == ParsePartial && outcome.ResponseOmitted:
	default:
		return RawRetention{}
	}
	normal := outcome.ForwardStatus == ForwardCompleted && outcome.CaptureStatus == CaptureComplete &&
		outcome.StatusCode != nil && *outcome.StatusCode >= 200 && *outcome.StatusCode < 400
	if normal && !outcome.ResponseOmitted {
		return RawRetention{ReleaseRequest: true, ReleaseResponse: true}
	}
	if !outcome.RequestNormalized || !outcome.RequestStagesMerged {
		return RawRetention{}
	}
	if normal {
		return RawRetention{ReleaseRequest: true}
	}
	return RawRetention{ReleaseRequest: requestReleaseFor(outcome)}
}

func requestReleaseFor(outcome RawRetentionOutcome) bool {
	cancelled := outcome.ForwardStatus == ForwardClientCancelled
	if outcome.StatusCode == nil {
		// No response status: the client went away before one arrived, or
		// the upstream failed without answering.
		return cancelled
	}
	status := *outcome.StatusCode
	switch {
	case status >= 200 && status < 400:
		// The status was normal; the forward or the capture was not.
		if cancelled {
			return true
		}
		// Unlisted: a 2xx/3xx whose forward failed or whose capture was
		// incomplete for a reason other than a client cancel. Awaits the
		// maintainer (issue #59, design 5.9); until then the request raw is
		// kept, as before.
		return false
	case status >= 500 && status < 600:
		return true
	}
	switch abnormalRequestRelease[status] {
	case releaseRequest:
		return true
	case releaseRequestIfClassified:
		return outcome.UpstreamErrorClass != nil && *outcome.UpstreamErrorClass != ""
	default:
		// 402, 404, 405, 413, 415 and every other status the decision does
		// not name keep the request raw. The maintainer confirmed this when
		// asked (issue #59, design 5.9): a status releases the request only
		// by being listed in abnormalRequestRelease.
		return false
	}
}
