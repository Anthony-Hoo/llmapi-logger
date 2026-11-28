package sqlite

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// eqScenario drives one request through the session model. Every scenario
// ends with finish unless it is an interruption scenario.
type eqScenario struct {
	name string
	run  func(*eqRun)
	// checkpoints is the number of checkpoints the unified sink must issue.
	checkpoints int
	// dedupInDB is the expected DedupInDB of the commit.
	dedupInDB [2]bool
	// shape is what the stored rows must contain, so a scenario cannot pass
	// without exercising the case its name claims.
	shape eqShape
	check func(*testing.T, *eqRun)
}

type eqShape struct {
	stages, bodies, chunks, timelines, trailerStages int
	forward                                          string
}

func (shape eqShape) check(t *testing.T, dump map[string][]eqRow) {
	t.Helper()
	trailerStages := map[string]bool{}
	for _, row := range dump["http_headers"] {
		if row["kind"] == `s:"trailer"` {
			trailerStages[row["stage"]] = true
		}
	}
	forward := ""
	if len(dump["audit_records"]) == 1 {
		forward = strings.Trim(strings.TrimPrefix(dump["audit_records"][0]["forward_status"], "s:"), `"`)
	}
	got := eqShape{
		stages: len(dump["http_stages"]), bodies: len(dump["body_streams"]), chunks: len(dump["body_chunks"]),
		timelines: len(dump["stream_timelines"]), trailerStages: len(trailerStages), forward: forward,
	}
	if got != shape {
		t.Fatalf("stored shape = %+v, want %+v", got, shape)
	}
}

func streamResponse(run *eqRun, events int, trailers http.Header) {
	run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
	run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
	for _, event := range eqSSE(events) {
		run.read(StageResponseReceived, event)
		run.write(event, nil)
	}
	run.eof(StageResponseReceived, trailers)
}

func jsonResponse(run *eqRun, body []byte, piece int) {
	headers := responseHeaders("application/json")
	run.startResponseReceived(http.StatusOK, headers, int64(len(body)), true)
	run.startResponseSent(http.StatusOK, headers)
	for _, part := range pieces(body, piece) {
		run.read(StageResponseReceived, part)
		run.write(part, nil)
	}
	run.eof(StageResponseReceived, nil)
}

func sendRequest(run *eqRun, body []byte, piece int, trailers http.Header) {
	headers := requestHeaders("application/json")
	run.begin(http.MethodPost, headers, int64(len(body)), true)
	run.startRequestSent(headers, int64(len(body)), true)
	for _, part := range pieces(body, piece) {
		run.readBoth(part)
	}
	run.requestEOF(trailers)
}

func bodyRow(t *testing.T, run *eqRun, stage string) BodyStream {
	t.Helper()
	snapshot, err := run.unified.store.Snapshot(run.ctx, run.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range snapshot.Bodies {
		if body.Stage == stage {
			return body
		}
	}
	t.Fatalf("no body row for %s", stage)
	return BodyStream{}
}

func expectMerged(stage, source string) func(*testing.T, *eqRun) {
	return func(t *testing.T, run *eqRun) {
		if body := bodyRow(t, run, stage); body.SourceStage != source {
			t.Fatalf("%s source = %s, want %s", stage, body.SourceStage, source)
		}
	}
}

func bothMerged(t *testing.T, run *eqRun) {
	expectMerged(StageRequestSent, StageRequestReceived)(t, run)
	expectMerged(StageResponseSent, StageResponseReceived)(t, run)
}

func eqScenarios() []eqScenario {
	trailer := http.Header{"X-Checksum": {"example-checksum"}}
	return []eqScenario{
		{
			name: "stream with both pairs merged",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(4096, 1), 1500, nil)
				streamResponse(run, 12, nil)
				run.finish()
			},
			checkpoints: 2, check: bothMerged,
			shape: eqShape{stages: 4, bodies: 4, chunks: 2, timelines: 1, forward: ForwardCompleted},
		},
		{
			name: "non-stream json",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(2048, 2), 4096, nil)
				jsonResponse(run, eqJSON(3000, 3), 1024)
				run.finish()
			},
			checkpoints: 2, check: bothMerged,
			shape: eqShape{stages: 4, bodies: 4, chunks: 2, forward: ForwardCompleted},
		},
		{
			name: "request without body",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				run.begin(http.MethodGet, headers, 0, false)
				run.startRequestSent(headers, 0, false)
				jsonResponse(run, eqJSON(500, 4), 4096)
				run.finish()
			},
			checkpoints: 1,
			shape:       eqShape{stages: 4, bodies: 2, chunks: 1, forward: ForwardCompleted},
		},
		{
			name: "bodies over one MiB on both sides",
			run: func(run *eqRun) {
				sendRequest(run, eqNoise(5<<19, 5), 300<<10, nil)
				jsonResponse(run, eqJSON(3<<19, 6), 256<<10)
				run.finish()
			},
			checkpoints: 2,
			shape:       eqShape{stages: 4, bodies: 4, chunks: 5, forward: ForwardCompleted},
			check: func(t *testing.T, run *eqRun) {
				bothMerged(t, run)
				if chunks := run.stages[StageRequestReceived].body.chunkCount; chunks != 3 {
					t.Fatalf("request chunks = %d, want 3", chunks)
				}
				if chunks := run.stages[StageResponseReceived].body.chunkCount; chunks != 2 {
					t.Fatalf("response chunks = %d, want 2", chunks)
				}
			},
		},
		{
			name: "request pair that does not merge",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				inbound, outbound := eqJSON(3000, 7), eqJSON(3000, 8)
				run.begin(http.MethodPost, headers, 3000, true)
				run.startRequestSent(headers, 3000, true)
				run.read(StageRequestReceived, inbound)
				run.read(StageRequestSent, outbound)
				run.requestEOF(nil)
				jsonResponse(run, eqJSON(800, 9), 4096)
				run.finish()
			},
			checkpoints: 2, dedupInDB: [2]bool{true, false},
			shape: eqShape{stages: 4, bodies: 4, chunks: 3, forward: ForwardCompleted},
			check: func(t *testing.T, run *eqRun) {
				expectMerged(StageRequestSent, StageRequestSent)(t, run)
				expectMerged(StageResponseSent, StageResponseReceived)(t, run)
			},
		},
		{
			name: "merged request pair unmerges at the end",
			run: func(run *eqRun) {
				sendRequest(run, eqNoise(3<<19, 10), 512<<10, nil)
				jsonResponse(run, eqJSON(900, 11), 4096)
				run.closeBody(StageRequestReceived, nil)
				run.closeBody(StageRequestSent, errEqClose)
				run.finish()
			},
			checkpoints: 2,
			shape:       eqShape{stages: 4, bodies: 4, chunks: 5, forward: ForwardCompleted},
			check: func(t *testing.T, run *eqRun) {
				if !run.unified.merged[StageRequestSent] {
					t.Fatal("checkpoint 1 did not merge the request pair")
				}
				expectMerged(StageRequestSent, StageRequestSent)(t, run)
			},
		},
		{
			name: "upstream answers before the request body ends",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				body := eqNoise(5<<19, 12)
				run.begin(http.MethodPost, headers, int64(len(body)), true)
				run.startRequestSent(headers, int64(len(body)), true)
				parts := pieces(body, 400<<10)
				for _, part := range parts[:4] {
					run.readBoth(part)
				}
				run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
				for _, part := range parts[4:] {
					run.readBoth(part)
				}
				run.requestEOF(nil)
				for _, event := range eqSSE(5) {
					run.read(StageResponseReceived, event)
					run.write(event, nil)
				}
				run.eof(StageResponseReceived, nil)
				run.finish()
			},
			checkpoints: 2, dedupInDB: [2]bool{true, false}, check: bothMerged,
			shape: eqShape{stages: 4, bodies: 4, chunks: 4, timelines: 1, forward: ForwardCompleted},
		},
		{
			name: "small request body still uploading when upstream answers",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				body := eqJSON(2000, 13)
				run.begin(http.MethodPost, headers, int64(len(body)), true)
				run.startRequestSent(headers, int64(len(body)), true)
				run.readBoth(body[:700])
				run.startResponseReceived(http.StatusOK, responseHeaders("application/json"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("application/json"))
				run.readBoth(body[700:])
				run.requestEOF(nil)
				response := eqJSON(600, 14)
				run.read(StageResponseReceived, response)
				run.write(response, nil)
				run.eof(StageResponseReceived, nil)
				run.finish()
			},
			checkpoints: 2, dedupInDB: [2]bool{true, false}, check: bothMerged,
			shape: eqShape{stages: 4, bodies: 4, chunks: 2, forward: ForwardCompleted},
		},
		{
			name: "rejected by an interceptor",
			run: func(run *eqRun) {
				run.begin(http.MethodPost, requestHeaders("application/json"), 100, true)
				run.reject(http.StatusForbidden, "user_agent", "blocked_user_agent")
				run.finish()
			},
			shape: eqShape{stages: 1, forward: ForwardRejected},
		},
		{
			name: "rejected after the body interceptor read over one MiB",
			run: func(run *eqRun) {
				body := eqNoise(3<<19, 15)
				run.begin(http.MethodPost, requestHeaders("application/json"), int64(len(body)), true)
				for _, part := range pieces(body, 256<<10) {
					run.read(StageRequestReceived, part)
				}
				run.eof(StageRequestReceived, nil)
				run.reject(http.StatusRequestEntityTooLarge, "body_limit", "body_too_large")
				run.finish()
			},
			shape: eqShape{stages: 1, bodies: 1, chunks: 2, forward: ForwardRejected},
		},
		{
			name: "upstream unreachable",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				run.begin(http.MethodPost, headers, 64, true)
				run.startRequestSent(headers, 64, true)
				run.markNewAPIError("newapi_unreachable")
				errorHeaders := http.Header{"Content-Type": {"application/json"}}
				run.startResponseSent(http.StatusBadGateway, errorHeaders)
				run.write([]byte(`{"error":"bad gateway"}`), nil)
				run.finish()
			},
			shape: eqShape{stages: 3, bodies: 1, chunks: 1, forward: ForwardNewAPIError},
		},
		{
			name: "client cancels during upload",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				body := eqNoise(5<<19, 16)
				run.begin(http.MethodPost, headers, int64(len(body)), true)
				run.startRequestSent(headers, int64(len(body)), true)
				for _, part := range pieces(body[:1300<<10], 650<<10) {
					run.readBoth(part)
				}
				run.cancelled = true
				run.readError(StageRequestReceived)
				run.readError(StageRequestSent)
				run.requestSentDone()
				run.markNewAPIError("newapi_transport_error")
				run.finish()
			},
			shape: eqShape{stages: 2, bodies: 2, chunks: 4, forward: ForwardClientCancelled},
		},
		{
			name: "trailers on every stage",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(3000, 17), 1000, trailer)
				streamResponse(run, 4, http.Header{"X-Upstream-Trailer": {"upstream"}})
				run.trailers(StageResponseSent, http.Header{"X-Downstream-Trailer": {"one", "two"}})
				run.finish()
			},
			checkpoints: 2, check: bothMerged,
			shape: eqShape{stages: 4, bodies: 4, chunks: 2, timelines: 1, trailerStages: 4, forward: ForwardCompleted},
		},
		{
			name: "client cancel mid-stream",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(1000, 18), 4096, nil)
				run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
				events := eqSSE(6)
				for _, event := range events[:3] {
					run.read(StageResponseReceived, event)
					run.write(event, nil)
				}
				run.read(StageResponseReceived, events[3])
				run.cancelled = true
				run.write(events[3], errEqClose)
				run.readError(StageResponseReceived)
				run.finish()
			},
			checkpoints: 2,
			shape:       eqShape{stages: 4, bodies: 4, chunks: 3, timelines: 1, forward: ForwardClientCancelled},
			check: func(t *testing.T, run *eqRun) {
				if run.commitResult.ForwardStatus != ForwardClientCancelled {
					t.Fatalf("forward = %s", run.commitResult.ForwardStatus)
				}
			},
		},
		{
			name: "upstream aborts mid-stream",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(1000, 19), 4096, nil)
				run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
				for _, event := range eqSSE(6)[:4] {
					run.read(StageResponseReceived, event)
					run.write(event, nil)
				}
				run.readError(StageResponseReceived)
				run.finish()
			},
			checkpoints: 2,
			shape:       eqShape{stages: 4, bodies: 4, chunks: 3, timelines: 1, forward: ForwardNewAPIError},
			check: func(t *testing.T, run *eqRun) {
				if run.commitResult.ForwardStatus != ForwardNewAPIError || run.commitResult.CaptureStatus != CapturePartial {
					t.Fatalf("outcome = %+v", run.commitResult)
				}
			},
		},
		{
			name: "response stages reached without bodies",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				run.begin(http.MethodGet, headers, 0, false)
				run.startRequestSent(headers, 0, false)
				run.startResponseReceived(http.StatusNoContent, http.Header{"X-Oneapi-Request-Id": {"request-example-2"}}, 0, false)
				run.startResponseSent(http.StatusNoContent, http.Header{})
				run.finish()
			},
			checkpoints: 1,
			shape:       eqShape{stages: 4, forward: ForwardCompleted},
		},
	}
}

func TestUnifiedWriteMatchesLegacyRows(t *testing.T) {
	t.Parallel()
	for index, scenario := range eqScenarios() {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			run := newEqRun(t, fmt.Sprintf("eq-%02d", index))
			scenario.run(run)
			if run.unified.checkpoints != scenario.checkpoints {
				t.Fatalf("checkpoints = %d, want %d", run.unified.checkpoints, scenario.checkpoints)
			}
			if run.unified.lastCommit.DedupInDB != scenario.dedupInDB {
				t.Fatalf("DedupInDB = %v, want %v", run.unified.lastCommit.DedupInDB, scenario.dedupInDB)
			}
			if !sameFinish(run.commitResult, run.legacyResult) {
				t.Fatalf("committed outcome %+v, legacy %+v", run.commitResult, run.legacyResult)
			}
			run.assertSameRows()
			_, unified := run.dumps()
			scenario.shape.check(t, unified)
			if scenario.check != nil {
				scenario.check(t, run)
			}
		})
	}
}

func sameFinish(left, right AuditFinish) bool {
	return renderValue(left.AuditID) == renderValue(right.AuditID) && left.EndedAtNS == right.EndedAtNS &&
		equalInt(left.StatusCode, right.StatusCode) && equalInt64(left.TTFTNS, right.TTFTNS) &&
		left.ForwardStatus == right.ForwardStatus && left.CaptureStatus == right.CaptureStatus && left.ParseStatus == right.ParseStatus &&
		equalString(left.BlockedBy, right.BlockedBy) && equalString(left.BlockCode, right.BlockCode) &&
		equalString(left.ErrorCode, right.ErrorCode) && equalString(left.NewAPIRequestID, right.NewAPIRequestID)
}

func equalInt(left, right *int) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// The comparator must be able to fail: a changed plain column, a ciphertext
// under the wrong AAD and a missing row are each reported.
func TestUnifiedHarnessDetectsDifferences(t *testing.T) {
	t.Parallel()
	for _, perturb := range []struct {
		name, statement, want string
	}{
		{"plain column", "UPDATE body_streams SET last_observed_at_ns = last_observed_at_ns + 1 WHERE stage = 'request_sent_to_newapi'", "body_streams: only unified"},
		{"ciphertext under another identity", "UPDATE http_headers SET value_enc = (SELECT value_enc FROM http_headers h WHERE h.name = 'Authorization' AND h.stage = 'request_sent_to_newapi') WHERE name = 'Authorization' AND stage = 'request_for_newapi_received_from_nginx'", "DECRYPT-FAILED"},
		{"missing chunk", "DELETE FROM body_chunks WHERE stage = 'response_received_from_newapi'", "body_chunks: only legacy"},
	} {
		t.Run(perturb.name, func(t *testing.T) {
			t.Parallel()
			run := newEqRun(t, "eq-perturb")
			sendRequest(run, eqJSON(2000, 30), 4096, nil)
			jsonResponse(run, eqJSON(2000, 31), 4096)
			run.finish()
			if _, err := run.unified.store.writerDB.Exec(perturb.statement); err != nil {
				t.Fatal(err)
			}
			legacy, unified := run.dumps()
			diffs := strings.Join(diffDumps(legacy, unified), "\n")
			if !strings.Contains(diffs, perturb.want) {
				t.Fatalf("perturbation not reported (want %q):\n%s", perturb.want, diffs)
			}
		})
	}
}

// An audit whose checkpoints ran and whose commit never came is finalized by
// RecoverInterruptedAudits after a restart. It is compared with the legacy
// audit interrupted at the same point. The only differences are the ones
// design B.7 lists for that moment, applied to the legacy dump explicitly.
func TestUnifiedInterruptedAuditMatchesLegacyAfterRecovery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		run   func(*eqRun)
		delta func(t *testing.T, legacy map[string][]eqRow)
	}{
		{
			// Checkpoint 1 merged the request pair: request_sent points at its
			// source and has no chunks of its own.
			name: "after checkpoint 2 with a merged request pair",
			run: func(run *eqRun) {
				sendRequest(run, eqNoise(5<<19, 40), 300<<10, http.Header{"X-Checksum": {"c"}})
				run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
			},
			delta: mergedRequestDelta,
		},
		{
			name: "after checkpoint 1 with an unmerged request pair",
			run: func(run *eqRun) {
				headers := requestHeaders("application/json")
				run.begin(http.MethodPost, headers, 3<<19, true)
				run.startRequestSent(headers, 3<<19, true)
				run.read(StageRequestReceived, eqNoise(3<<19, 41))
				run.read(StageRequestSent, eqNoise(3<<19, 42))
				run.requestEOF(nil)
			},
		},
		{
			// Legacy has also committed the response body rows by now; the
			// unified path writes them only at the commit (B.7, third row).
			name: "mid-stream",
			run: func(run *eqRun) {
				sendRequest(run, eqJSON(3000, 43), 4096, nil)
				run.startResponseReceived(http.StatusOK, responseHeaders("text/event-stream"), -1, true)
				run.startResponseSent(http.StatusOK, responseHeaders("text/event-stream"))
				for _, event := range eqSSE(3) {
					run.read(StageResponseReceived, event)
					run.write(event, nil)
				}
			},
			delta: func(t *testing.T, legacy map[string][]eqRow) {
				mergedRequestDelta(t, legacy)
				dropRows(t, legacy, "body_streams", 2, func(row eqRow) bool {
					return row["stage"] == "s:"+`"`+StageResponseReceived+`"` || row["stage"] == "s:"+`"`+StageResponseSent+`"`
				})
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			run := newEqRun(t, "eq-interrupted")
			testCase.run(run)
			const recoveredAt = eqClockOrigin + 1_000_000
			for _, sink := range []**Store{&run.legacy.store, &run.unified.store} {
				*sink = restartAndRecover(t, *sink, run.paths[*sink], recoveredAt)
			}
			legacy, unified := run.dumps()
			if testCase.delta != nil {
				testCase.delta(t, legacy)
			}
			if diffs := diffDumps(legacy, unified); len(diffs) != 0 {
				t.Fatalf("recovered rows differ beyond design B.7:\n%s", strings.Join(diffs, "\n"))
			}
			run.verifyIntegrity()
		})
	}
}

func restartAndRecover(t *testing.T, store *Store, path string, nowNS int64) *Store {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.EnableIntegrity(context.Background(), eqKey); err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.RecoverInterruptedAudits(context.Background(), nowNS); err != nil || count != 1 {
		t.Fatalf("recovered %d audits: %v", count, err)
	}
	return reopened
}

// mergedRequestDelta turns the legacy rows of a request pair that legacy had
// not yet merged into the unified shape: request_sent's body points at
// request_received and its own chunks do not exist.
func mergedRequestDelta(t *testing.T, legacy map[string][]eqRow) {
	t.Helper()
	sent := `s:"` + StageRequestSent + `"`
	changed := 0
	for _, row := range legacy["body_streams"] {
		if row["stage"] == sent {
			row["source_stage"] = `s:"` + StageRequestReceived + `"`
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("legacy request_sent body rows = %d", changed)
	}
	dropRows(t, legacy, "body_chunks", -1, func(row eqRow) bool { return row["stage"] == sent })
}

// dropRows removes the legacy rows that match; want is the expected count,
// or -1 for at least one.
func dropRows(t *testing.T, dump map[string][]eqRow, table string, want int, match func(eqRow) bool) {
	t.Helper()
	kept := dump[table][:0]
	dropped := 0
	for _, row := range dump[table] {
		if match(row) {
			dropped++
			continue
		}
		kept = append(kept, row)
	}
	if want >= 0 && dropped != want || want < 0 && dropped == 0 {
		t.Fatalf("dropped %d %s rows, want %d", dropped, table, want)
	}
	dump[table] = kept
}
