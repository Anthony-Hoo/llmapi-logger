package postgres

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
)

var (
	harnessCipherKey    = bytes.Repeat([]byte{0x5a}, security.KeySize)
	harnessIntegrityKey = bytes.Repeat([]byte{0x6b}, security.KeySize)
)

func harnessCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(harnessCipherKey)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func openHarnessStore(t *testing.T) *Store {
	t.Helper()
	store, _ := openTestStore(t)
	if err := store.EnableIntegrity(context.Background(), harnessIntegrityKey); err != nil {
		t.Fatal(err)
	}
	return store
}

func inboundHeaders(contentType string) http.Header {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	header.Set("User-Agent", "harness-client/1.0")
	header.Set("Accept", "text/event-stream")
	header["X-Trace"] = []string{"first", "second"}
	return header
}

func outboundHeaders(contentType string) http.Header {
	header := inboundHeaders(contentType)
	header.Set("Accept-Encoding", "identity")
	header.Set("X-Forwarded-For", "192.0.2.10")
	return header
}

func streamResponseHeaders() http.Header {
	header := http.Header{}
	header.Set("Content-Type", "text/event-stream")
	header.Set("X-Oneapi-Request-Id", "request-example-1")
	header.Set("Cache-Control", "no-cache")
	return header
}

func jsonResponseHeaders(length int) http.Header {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", fmt.Sprint(length))
	return header
}

// jsonRequest is a compressible request body of at least size bytes.
func jsonRequest(size int) []byte {
	var builder strings.Builder
	builder.WriteString(`{"model":"example-model","stream":true,"messages":[`)
	for index := 0; builder.Len() < size; index++ {
		fmt.Fprintf(&builder, `{"role":"user","content":"synthetic message %d with some filler text"},`, index)
	}
	builder.WriteString(`{"role":"user","content":"end"}]}`)
	return []byte(builder.String())
}

// sseResponse is an event stream of at least size bytes.
func sseResponse(size int) []byte {
	var builder strings.Builder
	for index := 0; builder.Len() < size; index++ {
		fmt.Fprintf(&builder, "data: {\"id\":\"chunk-%d\",\"delta\":\"synthetic token %d\"}\n\n", index, index*7919%104729)
	}
	builder.WriteString("data: [DONE]\n\n")
	return []byte(builder.String())
}

// pseudoRandom is incompressible deterministic data.
func pseudoRandom(size int, seed uint32) []byte {
	data := make([]byte, size)
	state := seed
	for index := range data {
		state = state*1664525 + 1013904223
		data[index] = byte(state >> 24)
	}
	return data
}

func pieces(data []byte, size int) [][]byte {
	var result [][]byte
	for len(data) > 0 {
		count := min(size, len(data))
		result = append(result, data[:count])
		data = data[count:]
	}
	return result
}

// --- proxy-shaped steps ------------------------------------------------------

func (h *harness) startRequest(method string, body []byte) {
	hasBody := body != nil
	length := int64(len(body))
	contentType := "application/json"
	if !hasBody {
		contentType = ""
	}
	h.startStage(StageRequestReceived, "HTTP/1.1", method, "proxy.example.com", nil, length, inboundHeaders(contentType), hasBody)
	h.startStage(StageRequestSent, "HTTP/1.1", method, "upstream.example.com", nil, length, outboundHeaders(contentType), hasBody)
}

// upload reads the request in step: Transport reads the outbound body, whose
// every Read first observes request_received, then request_sent.
func (h *harness) upload(data []byte, readSize int) {
	for _, piece := range pieces(data, readSize) {
		h.read(StageRequestReceived, piece)
		h.read(StageRequestSent, piece)
	}
}

func (h *harness) endUpload(trailers http.Header) {
	h.eof(StageRequestReceived, trailers)
	h.eof(StageRequestSent, trailers)
}

// respond is ModifyResponse followed by ReverseProxy's WriteHeader, which
// starts response_sent before any body byte is copied; checkpoint 2 fires
// there when the forward is still running.
func (h *harness) respond(status int, headers http.Header, contentLength int64, checkpoint bool) {
	if id := headers.Get("X-Oneapi-Request-Id"); id != "" {
		h.newAPIRequest = &id
	}
	h.startStage(StageResponseReceived, "HTTP/1.1", "POST", "upstream.example.com", &status, contentLength, headers, true)
	h.startResponseSent(headers.Clone(), status)
	if checkpoint {
		h.checkpoint()
	}
}

func (h *harness) relay(data []byte, readSize int) {
	for _, piece := range pieces(data, readSize) {
		h.read(StageResponseReceived, piece)
		h.write(piece, false, nil, 0)
	}
}

func (h *harness) typicalStream(requestSize, responseSize, readSize int) {
	request := jsonRequest(requestSize)
	h.startRequest("POST", request)
	h.upload(request, readSize)
	h.endUpload(nil)
	h.checkpoint()
	h.respond(200, streamResponseHeaders(), -1, true)
	h.relay(sseResponse(responseSize), readSize)
	h.eof(StageResponseReceived, nil)
}

// --- scenarios ----------------------------------------------------------------

type equivalenceScenario struct {
	name  string
	build func(h *harness)
	// adjust turns the legacy dump into what the unified path leaves by
	// design (B.7); only the crash scenarios use it.
	adjust func(t *testing.T, legacy harnessDump)
}

func equivalenceScenarios() []equivalenceScenario {
	return []equivalenceScenario{
		{name: "stream both pairs merged", build: func(h *harness) {
			h.typicalStream(600, 2000, 32<<10)
			h.finish()
		}},
		{name: "checkpoints deferred to the commit", build: func(h *harness) {
			// Both checkpoints met a full queue: the commit carries all.
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.respond(200, streamResponseHeaders(), -1, false)
			h.relay(sseResponse(3000), 1024)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "checkpoint 1 deferred to checkpoint 2", build: func(h *harness) {
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(3000), 1024)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "response pair merged in the database", build: func(h *harness) {
			h.responseInDB = true
			h.typicalStream(600, 5<<18, 32<<10)
			h.finish()
		}},
		{name: "non stream", build: func(h *harness) {
			request := jsonRequest(400)
			response := []byte(`{"id":"example","choices":[{"message":{"role":"assistant","content":"synthetic reply"}}]}`)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, jsonResponseHeaders(len(response)), int64(len(response)), true)
			h.relay(response, 32<<10)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "no request body", build: func(h *harness) {
			response := []byte(`{"object":"list","data":[]}`)
			h.startRequest("GET", nil)
			h.respond(200, jsonResponseHeaders(len(response)), int64(len(response)), true)
			h.relay(response, 32<<10)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "bodies over one MiB", build: func(h *harness) {
			h.typicalStream(5<<19, 5<<19, 32<<10)
			h.finish()
		}},
		{name: "incompressible bodies over one MiB", build: func(h *harness) {
			request := pseudoRandom(3<<20+17, 7)
			h.startRequest("POST", request)
			h.upload(request, 64<<10)
			h.endUpload(nil)
			h.checkpoint()
			response := pseudoRandom(2<<20+5, 11)
			headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
			h.respond(200, headers, int64(len(response)), true)
			h.relay(response, 48<<10)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "pair with different bytes", build: func(h *harness) {
			request := jsonRequest(900)
			rewritten := bytes.ToUpper(request)
			h.startRequest("POST", request)
			for index, piece := range pieces(request, 256) {
				h.read(StageRequestReceived, piece)
				h.read(StageRequestSent, pieces(rewritten, 256)[index])
			}
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(700), 128)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "pair with different lengths", build: func(h *harness) {
			request := jsonRequest(1500)
			h.startRequest("POST", request)
			for _, piece := range pieces(request, 512) {
				h.read(StageRequestReceived, piece)
			}
			h.read(StageRequestSent, request[:1000])
			h.endUpload(nil)
			h.checkpoint()
			response := sseResponse(900)
			h.respond(200, streamResponseHeaders(), -1, true)
			h.read(StageResponseReceived, response)
			h.write(response[:len(response)-40], false, nil, 0)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "duplicate ahead of its source", build: func(h *harness) {
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			// request_sent ends first: checkpoint 1 fires while
			// request_received has not seen EOF, so the pair is left to
			// the database merge.
			h.eof(StageRequestSent, nil)
			h.checkpoint()
			h.eof(StageRequestReceived, nil)
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(3000), 1024)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "merged request pair unmerges at finish", build: func(h *harness) {
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.closeBody(StageRequestReceived, false)
			h.closeBody(StageRequestSent, true)
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(1500), 512)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "upstream answers before the request ends", build: func(h *harness) {
			request := jsonRequest(3 << 19)
			h.startRequest("POST", request)
			h.upload(request[:5<<18], 32<<10)
			h.respond(200, streamResponseHeaders(), -1, true)
			response := sseResponse(4000)
			h.relay(response[:2000], 500)
			h.upload(request[5<<18:], 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.relay(response[2000:], 500)
			h.eof(StageResponseReceived, nil)
			h.finish()
		}},
		{name: "rejected by an interceptor", build: func(h *harness) {
			request := jsonRequest(300)
			h.startStage(StageRequestReceived, "HTTP/1.1", "POST", "proxy.example.com", nil, int64(len(request)), inboundHeaders("application/json"), true)
			h.markRejected(403, "content_policy", "blocked_content")
			h.closeBody(StageRequestReceived, false)
			h.finish()
		}},
		{name: "upstream unreachable", build: func(h *harness) {
			request := jsonRequest(300)
			h.startRequest("POST", request)
			h.markNewAPIError("newapi_unavailable")
			reply := []byte(`{"error":{"code":"newapi_unavailable"}}`)
			h.write(reply, false, jsonResponseHeaders(len(reply)), 502)
			h.finish()
		}},
		{name: "cancelled early", build: func(h *harness) {
			request := jsonRequest(300)
			h.startRequest("POST", request)
			h.upload(request[:100], 100)
			h.cancelled = true
			h.markNewAPIError("newapi_unavailable")
			h.finish()
		}},
		{name: "response sent never reached", build: func(h *harness) {
			request := jsonRequest(300)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			status := 200
			h.startStage(StageResponseReceived, "HTTP/1.1", "POST", "upstream.example.com", &status, -1, streamResponseHeaders(), true)
			h.read(StageResponseReceived, []byte("data: {\"id\":\"partial\"}\n\n"))
			h.readError(StageResponseReceived)
			h.finish()
		}},
		{name: "request and response trailers", build: func(h *harness) {
			request := jsonRequest(700)
			h.startRequest("POST", request)
			h.upload(request, 256)
			h.endUpload(http.Header{"X-Request-Checksum": []string{"sum-1"}, "X-Request-Note": []string{"a", "b"}})
			h.checkpoint()
			headers := streamResponseHeaders()
			headers.Set("Trailer", "X-Response-Usage")
			h.respond(200, headers, -1, true)
			h.relay(sseResponse(1200), 400)
			h.eof(StageResponseReceived, http.Header{"X-Response-Usage": []string{"tokens=42"}})
			h.trailers(StageResponseSent, http.Header{"X-Response-Usage": []string{"tokens=42"}})
			h.finish()
		}},
		{name: "client cancel mid stream", build: func(h *harness) {
			request := jsonRequest(600)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, streamResponseHeaders(), -1, true)
			response := sseResponse(3000)
			h.relay(response[:1200], 300)
			h.cancelled = true
			h.read(StageResponseReceived, response[1200:1500])
			h.write(response[1200:1500], true, nil, 0)
			h.readError(StageResponseReceived)
			h.finish()
		}},
		{name: "upstream abort mid stream", build: func(h *harness) {
			request := jsonRequest(600)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(3000)[:1700], 300)
			h.readError(StageResponseReceived)
			h.finish()
		}},
		{name: "interrupted after checkpoint 2", build: func(h *harness) {
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, streamResponseHeaders(), -1, true)
			h.crash()
		}, adjust: func(t *testing.T, legacy harnessDump) {
			// B.7: the merged request_sent has no chunks of its own and
			// points at its source; its lengths come from the source's
			// chunks, which recovery aggregates by source_stage.
			if legacy.dropRows("body_chunks", stageIs(StageRequestSent)) == 0 {
				t.Fatal("legacy interrupted audit lacks request_sent chunks")
			}
			setSourceStage(t, legacy, StageRequestSent, StageRequestReceived)
		}},
		{name: "interrupted mid stream", build: func(h *harness) {
			request := jsonRequest(5 << 18)
			h.startRequest("POST", request)
			h.upload(request, 32<<10)
			h.endUpload(nil)
			h.checkpoint()
			h.respond(200, streamResponseHeaders(), -1, true)
			h.relay(sseResponse(5 << 19)[:5<<19], 32<<10)
			h.crash()
		}, adjust: func(t *testing.T, legacy harnessDump) {
			if legacy.dropRows("body_chunks", stageIs(StageRequestSent)) == 0 {
				t.Fatal("legacy interrupted audit lacks request_sent chunks")
			}
			setSourceStage(t, legacy, StageRequestSent, StageRequestReceived)
			// B.7: response bodies below the memory budget are not
			// checkpointed, so the unified audit has neither their rows
			// nor their committed 1 MiB chunks.
			if legacy.dropRows("body_chunks", stageIs(StageResponseReceived, StageResponseSent)) != 4 {
				t.Fatal("legacy interrupted audit lacks the committed response chunks")
			}
			if legacy.dropRows("body_streams", stageIs(StageResponseReceived, StageResponseSent)) != 2 {
				t.Fatal("legacy interrupted audit lacks the response body rows")
			}
		}},
	}
}

// expectScenarioShape pins that each scenario exercises the path its name
// claims, so an equal comparison cannot come from both sides skipping it.
func expectScenarioShape(t *testing.T, name string, h *harness, legacyOps, unifiedOps []hOp, legacy harnessDump) {
	t.Helper()
	source := func(stage string) any {
		for _, row := range legacy["body_streams"] {
			if row["stage"] == stage {
				return row["source_stage"]
			}
		}
		return nil
	}
	chunks := func(stage string) int {
		count := 0
		for _, row := range legacy["body_chunks"] {
			if row["stage"] == stage {
				count++
			}
		}
		return count
	}
	kinds := func(ops []hOp) map[writeKind]int {
		counts := make(map[writeKind]int)
		for _, op := range ops {
			counts[op.kind]++
		}
		return counts
	}
	var commit *AuditCommit
	if last := unifiedOps[len(unifiedOps)-1]; last.kind == writeCommitAudit {
		value := last.data.(AuditCommit)
		commit = &value
	}
	fail := func(format string, arguments ...any) {
		t.Helper()
		t.Fatalf("scenario shape: "+format, arguments...)
	}
	switch name {
	case "stream both pairs merged":
		// A.2 and B.9: 22 capture operations against 4.
		if len(legacyOps) != 22 || len(unifiedOps) != 4 {
			fail("operations legacy=%d unified=%d", len(legacyOps), len(unifiedOps))
		}
		if source(StageRequestSent) != StageRequestReceived || source(StageResponseSent) != StageResponseReceived || !h.mergedAtCheckpoint {
			fail("pairs not merged")
		}
		if commit.DedupInDB != [2]bool{} {
			fail("dedup in database %v", commit.DedupInDB)
		}
	case "checkpoints deferred to the commit":
		if len(unifiedOps) != 2 || commit.Stages[1].StageWritten || commit.Stages[0].BodyWritten || commit.DedupInDB != [2]bool{} ||
			source(StageRequestSent) != StageRequestReceived || chunks(StageRequestSent) != 0 {
			fail("commit did not insert and merge the request pair")
		}
	case "checkpoint 1 deferred to checkpoint 2":
		if len(h.checkpoints) != 1 || !h.mergedAtCheckpoint || len(unifiedOps[1].data.(AuditCheckpoint).Stages) != 3 {
			fail("checkpoint 2 did not carry the request side")
		}
	case "response pair merged in the database":
		if commit.DedupInDB != [2]bool{false, true} || commit.Stages[3].Body.SourceStage != StageResponseSent ||
			source(StageResponseSent) != StageResponseReceived || chunks(StageResponseSent) != 0 {
			fail("response pair not left to the database")
		}
	case "bodies over one MiB", "incompressible bodies over one MiB":
		if chunks(StageRequestReceived) < 3 || chunks(StageResponseReceived) < 3 || chunks(StageRequestSent) != 0 || chunks(StageResponseSent) != 0 {
			fail("chunks %d %d %d %d", chunks(StageRequestReceived), chunks(StageRequestSent), chunks(StageResponseReceived), chunks(StageResponseSent))
		}
		if kinds(legacyOps)[writeAddChunk] < 12 {
			fail("legacy chunk writes %d", kinds(legacyOps)[writeAddChunk])
		}
	case "pair with different bytes", "pair with different lengths":
		if source(StageRequestSent) != StageRequestSent || chunks(StageRequestSent) == 0 || !h.requestSentWrittenAsSelf || !commit.DedupInDB[0] {
			fail("request pair merged or not left to the database")
		}
	case "duplicate ahead of its source":
		if !h.requestSentWrittenAsSelf || !commit.DedupInDB[0] || source(StageRequestSent) != StageRequestReceived {
			fail("pair was not merged by the database")
		}
	case "merged request pair unmerges at finish":
		if !h.mergedAtCheckpoint || source(StageRequestSent) != StageRequestSent || chunks(StageRequestSent) == 0 {
			fail("pair did not unmerge")
		}
	case "upstream answers before the request ends":
		if len(h.checkpoints) != 2 || !h.requestSentWrittenAsSelf || !commit.DedupInDB[0] {
			fail("checkpoint order")
		}
		first := unifiedOps[1].data.(AuditCheckpoint)
		if len(first.Stages) != 3 || first.Chunks == nil {
			fail("checkpoint 2 did not carry the response stages and the sealed request chunks")
		}
	case "rejected by an interceptor", "upstream unreachable", "cancelled early":
		if len(unifiedOps) != 2 || len(h.checkpoints) != 0 {
			fail("single commit expected, got %d operations", len(unifiedOps))
		}
	case "response sent never reached":
		if len(legacy["http_stages"]) != 3 || commit.Stages[2].StageWritten || commit.Stages[2].Timeline == nil {
			fail("response_received was not inserted by the commit with its timeline")
		}
	case "request and response trailers":
		trailers := 0
		for _, row := range legacy["http_headers"] {
			if row["kind"] == HeaderKindTrailer {
				trailers++
			}
		}
		if trailers != 8 || len(commit.Headers) != 2 {
			fail("trailers %d, commit headers %d", trailers, len(commit.Headers))
		}
	case "client cancel mid stream":
		if legacy["audit_records"][0]["forward_status"] != ForwardClientCancelled {
			fail("forward %v", legacy["audit_records"][0]["forward_status"])
		}
	case "upstream abort mid stream":
		if legacy["audit_records"][0]["forward_status"] != ForwardNewAPIError {
			fail("forward %v", legacy["audit_records"][0]["forward_status"])
		}
	}
}

func scenarioByName(t *testing.T, name string) equivalenceScenario {
	t.Helper()
	for _, scenario := range equivalenceScenarios() {
		if scenario.name == name {
			return scenario
		}
	}
	t.Fatalf("no scenario %q", name)
	return equivalenceScenario{}
}

func setSourceStage(t *testing.T, dump harnessDump, stage, source string) {
	t.Helper()
	for _, row := range dump["body_streams"] {
		if row["stage"] == stage {
			if row["source_stage"] != stage {
				t.Fatalf("legacy %s already points at %v", stage, row["source_stage"])
			}
			row["source_stage"] = source
			return
		}
	}
	t.Fatalf("legacy dump lacks the %s body", stage)
}

// TestStagedWriteMatchesLegacyRows writes each described request once with
// the legacy operations and once with BeginAudit, checkpoints and
// CommitAudit, into two schemas, and compares every row (B.10).
func TestStagedWriteMatchesLegacyRows(t *testing.T) {
	t.Parallel()
	legacyStore := openHarnessStore(t)
	unifiedStore := openHarnessStore(t)
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	clock := &harnessClock{now: 1_000_000}
	for index, scenario := range equivalenceScenarios() {
		t.Run(scenario.name, func(t *testing.T) {
			h := newHarness(t, clock, fmt.Sprintf("staged-%02d", index))
			scenario.build(h)
			legacyOps, unifiedOps := h.legacyOps(sealer), h.unifiedOps(sealer)
			legacyOutcome := runHarnessOps(t, legacyStore, legacyOps)
			unifiedOutcome := runHarnessOps(t, unifiedStore, unifiedOps)
			if fmt.Sprintf("%+v", derefFinish(legacyOutcome)) != fmt.Sprintf("%+v", derefFinish(unifiedOutcome)) {
				t.Fatalf("outcomes differ:\nlegacy  %+v\nunified %+v", derefFinish(legacyOutcome), derefFinish(unifiedOutcome))
			}
			legacy := dumpAudit(t, legacyStore.readerDB, cipher, h.id)
			unified := dumpAudit(t, unifiedStore.readerDB, cipher, h.id)
			if countRows(legacy, "integrity_events") != 1 {
				t.Fatalf("legacy audit has %d integrity events", countRows(legacy, "integrity_events"))
			}
			expectScenarioShape(t, scenario.name, h, legacyOps, unifiedOps, legacy)
			if scenario.adjust != nil {
				scenario.adjust(t, legacy)
			}
			if differences := diffDumps(legacy, unified); len(differences) != 0 {
				t.Fatalf("unified rows differ from legacy:\n%s", strings.Join(differences, "\n"))
			}
		})
	}
	ctx := context.Background()
	for _, store := range []*Store{legacyStore, unifiedStore} {
		if err := store.VerifyIntegrityPayloads(ctx); err != nil {
			t.Fatal(err)
		}
	}
	legacyGaps := dumpTable(t, legacyStore, "audit_gaps")
	unifiedGaps := dumpTable(t, unifiedStore, "audit_gaps")
	if legacyGaps != unifiedGaps || !strings.Contains(legacyGaps, GapReasonProcessExit) {
		t.Fatalf("gaps differ or lack the recovery gap:\nlegacy  %s\nunified %s", legacyGaps, unifiedGaps)
	}
}

type printableFinish struct {
	AuditID, ForwardStatus, CaptureStatus, ParseStatus string
	EndedAtNS                                          int64
	StatusCode                                         string
	TTFTNS                                             string
	BlockedBy, BlockCode, ErrorCode, NewAPIRequestID   string
}

func derefFinish(finish AuditFinish) printableFinish {
	text := func(value any) string {
		switch typed := value.(type) {
		case *int:
			if typed != nil {
				return fmt.Sprint(*typed)
			}
		case *int64:
			if typed != nil {
				return fmt.Sprint(*typed)
			}
		case *string:
			if typed != nil {
				return *typed
			}
		}
		return "<nil>"
	}
	return printableFinish{AuditID: finish.AuditID, ForwardStatus: finish.ForwardStatus, CaptureStatus: finish.CaptureStatus,
		ParseStatus: finish.ParseStatus, EndedAtNS: finish.EndedAtNS, StatusCode: text(finish.StatusCode), TTFTNS: text(finish.TTFTNS),
		BlockedBy: text(finish.BlockedBy), BlockCode: text(finish.BlockCode), ErrorCode: text(finish.ErrorCode), NewAPIRequestID: text(finish.NewAPIRequestID)}
}

func dumpTable(t *testing.T, store *Store, table string) string {
	t.Helper()
	rows, err := store.readerDB.Query(`SELECT * FROM ` + table + ` ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, _ := rows.Columns()
	var builder strings.Builder
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for index := range values {
			pointers[index] = &values[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(&builder, values...)
	}
	return builder.String()
}
