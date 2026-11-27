package storage

import "testing"

func TestDecideRawRetentionPerSide(t *testing.T) {
	t.Parallel()

	status := func(code int64) *int64 { return &code }
	class := func(value string) *string { return &value }
	// abnormal is a merged, normalized request whose response was answered by
	// the upstream; each case changes what it is about.
	abnormal := func(code *int64) RawRetentionOutcome {
		return RawRetentionOutcome{
			ParseStatus: ParseOK, TurnVerified: true, RequestNormalized: true,
			ForwardStatus: ForwardCompleted, CaptureStatus: CaptureComplete,
			StatusCode: code, RequestStagesMerged: true,
		}
	}
	with := func(outcome RawRetentionOutcome, change func(*RawRetentionOutcome)) RawRetentionOutcome {
		change(&outcome)
		return outcome
	}
	both := RawRetention{ReleaseRequest: true, ReleaseResponse: true}
	requestOnly := RawRetention{ReleaseRequest: true}
	keep := RawRetention{}

	cases := []struct {
		name    string
		outcome RawRetentionOutcome
		want    RawRetention
	}{
		// Normal outcomes release both sides, as before.
		{"200 normal", abnormal(status(200)), both},
		{"204 normal", abnormal(status(204)), both},
		{"304 normal", abnormal(status(304)), both},
		{"normal outcome, stages not merged", with(abnormal(status(200)), func(o *RawRetentionOutcome) { o.RequestStagesMerged = false }), both},

		// No verified turn or a parse that is not ok releases nothing.
		{"no turn", with(abnormal(status(200)), func(o *RawRetentionOutcome) { o.TurnVerified = false }), keep},
		{"no turn 503", with(abnormal(status(503)), func(o *RawRetentionOutcome) { o.TurnVerified = false }), keep},
		{"parse partial", with(abnormal(status(200)), func(o *RawRetentionOutcome) { o.ParseStatus = ParsePartial }), keep},
		{"parse error after turn prepared", with(abnormal(status(503)), func(o *RawRetentionOutcome) { o.ParseStatus = ParseError }), keep},

		// 5xx releases the request only.
		{"500", abnormal(status(500)), requestOnly},
		{"502 newapi error", with(abnormal(status(502)), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardNewAPIError; o.CaptureStatus = CapturePartial }), requestOnly},
		{"503", abnormal(status(503)), requestOnly},
		{"504", abnormal(status(504)), requestOnly},
		{"599", abnormal(status(599)), requestOnly},

		// Listed 4xx release the request only, classified or not.
		{"401", abnormal(status(401)), requestOnly},
		{"403", abnormal(status(403)), requestOnly},
		{"408", abnormal(status(408)), requestOnly},
		{"409", abnormal(status(409)), requestOnly},
		{"429", abnormal(status(429)), requestOnly},
		{"429 classified", with(abnormal(status(429)), func(o *RawRetentionOutcome) { o.UpstreamErrorClass = class("rate_limit") }), requestOnly},
		{"499", abnormal(status(499)), requestOnly},

		// 400 and 422 release the request only when the upstream error was
		// classified; an unclassified one may be a malformed request.
		{"400 classified", with(abnormal(status(400)), func(o *RawRetentionOutcome) { o.UpstreamErrorClass = class("content_policy") }), requestOnly},
		{"422 classified", with(abnormal(status(422)), func(o *RawRetentionOutcome) { o.UpstreamErrorClass = class("content_policy") }), requestOnly},
		{"400 unclassified", abnormal(status(400)), keep},
		{"422 unclassified", abnormal(status(422)), keep},
		{"400 empty class", with(abnormal(status(400)), func(o *RawRetentionOutcome) { o.UpstreamErrorClass = class("") }), keep},

		// Statuses the decision does not name keep the request (awaiting the
		// maintainer).
		{"402 unlisted", abnormal(status(402)), keep},
		{"404 unlisted", abnormal(status(404)), keep},
		{"405 unlisted", abnormal(status(405)), keep},
		{"413 unlisted", abnormal(status(413)), keep},
		{"415 unlisted", abnormal(status(415)), keep},
		{"404 classified unlisted", with(abnormal(status(404)), func(o *RawRetentionOutcome) { o.UpstreamErrorClass = class("content_policy") }), keep},
		{"101 unlisted", abnormal(status(101)), keep},
		{"200 forward newapi error unlisted", with(abnormal(status(200)), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardNewAPIError }), keep},
		{"200 capture partial unlisted", with(abnormal(status(200)), func(o *RawRetentionOutcome) { o.CaptureStatus = CapturePartial }), keep},
		{"no status, upstream failed", with(abnormal(nil), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardNewAPIError; o.CaptureStatus = CapturePartial }), keep},
		{"no status, completed", abnormal(nil), keep},

		// A client cancel releases the request, unless the status keeps it.
		{"cancelled before a status", with(abnormal(nil), func(o *RawRetentionOutcome) {
			o.ForwardStatus = ForwardClientCancelled
			o.CaptureStatus = CapturePartial
		}), requestOnly},
		{"cancelled after 200", with(abnormal(status(200)), func(o *RawRetentionOutcome) {
			o.ForwardStatus = ForwardClientCancelled
			o.CaptureStatus = CapturePartial
		}), requestOnly},
		{"cancelled after 503", with(abnormal(status(503)), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardClientCancelled }), requestOnly},
		{"cancelled after unclassified 400", with(abnormal(status(400)), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardClientCancelled }), keep},
		{"cancelled after unlisted 404", with(abnormal(status(404)), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardClientCancelled }), keep},

		// The request is released only when its two stages were merged and
		// the turn rebuilt a request.
		{"503 stages not merged", with(abnormal(status(503)), func(o *RawRetentionOutcome) { o.RequestStagesMerged = false }), keep},
		{"503 no request rebuilt", with(abnormal(status(503)), func(o *RawRetentionOutcome) { o.RequestNormalized = false }), keep},
		{"cancelled stages not merged", with(abnormal(nil), func(o *RawRetentionOutcome) { o.ForwardStatus = ForwardClientCancelled; o.RequestStagesMerged = false }), keep},
	}
	for _, test := range cases {
		if got := DecideRawRetention(test.outcome); got != test.want {
			t.Errorf("%s: DecideRawRetention = %+v, want %+v", test.name, got, test.want)
		}
	}
}
