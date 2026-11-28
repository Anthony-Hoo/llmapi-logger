package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/postgres"
)

// J.3 on PostgreSQL (plan section 7 "归档完整性", bullet 2): every exchange of
// the protofixture catalogue on the four protocols, streamed and not, the
// abnormal scenarios included (error answers, missing terminal event,
// upstream abort, client cancel), plus a request the credential interceptor
// blocks (an audit without a turn) and a request with hostile headers and
// query, is captured through the proxy, parsed, and archived by one
// export_only run with everything due. For every audit the reader tool's
// output from the bundles alone equals the query service's output from the
// hot store after the credential projection: summary, detail, the rebuilt
// turn with its provider request and response, the session conversation,
// timeline, raw metadata and raw bytes of each side, and every export kind,
// or the same error class where the hot side has none. Once with encryption
// on, once off.
func TestArchiveReadEquivalenceCatalogue(t *testing.T) {
	if testing.Short() {
		t.Skip("the fixture catalogue")
	}
	for _, encrypt := range []bool{true, false} {
		t.Run(fmt.Sprintf("encrypt=%v", encrypt), func(t *testing.T) {
			rig := newArchiveRig(t, archiveRigOptions{encrypt: encrypt})
			exchanges := map[string]protofixture.Exchange{}
			for index, value := range protofixture.Catalog() {
				built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(index + 1)})
				if err != nil {
					t.Fatal(err)
				}
				for _, exchange := range built {
					exchanges[rig.send(exchange)] = exchange
				}
			}
			if stats := rig.upstream.Stats(); stats.Mismatched != 0 || stats.Unknown != 0 {
				t.Fatalf("upstream stats %+v", stats)
			}
			blocked := rig.sendBlocked()
			hostile := rig.sendHostile()
			ids := rig.auditIDs()
			rig.due()
			result := rig.mustRun()
			rig.requireCleanRun(result, len(ids))
			reader := rig.reader(rig.dir)
			comparison := rig.compare(reader, ids)
			t.Logf("%d audits, %d segments\n%s", len(ids), result.Counts.Segments, comparison.report())
			for _, difference := range comparison.differences {
				t.Error(difference)
			}
			if t.Failed() {
				t.FailNow()
			}
			// Enough was compared by value, not only by error class.
			if comparison.values["detail"] != len(ids) || comparison.values["summary"] != len(ids) || comparison.values["session"] < len(ids)/2 ||
				comparison.values["turn"] < len(ids)/2 || comparison.values["timeline.response"] == 0 ||
				comparison.values["raw.request"] == 0 || comparison.values["raw.response"] == 0 ||
				comparison.classes["raw.request"]["not_retained"] == 0 || comparison.classes["turn"]["no_turn_graph"] == 0 {
				t.Fatalf("too little compared:\n%s", comparison.report())
			}
			rig.anchorToFixtures(reader, exchanges)
			for _, id := range []string{blocked, hostile} {
				if _, err := reader.Audit(rig.ctx, id); err != nil {
					t.Fatalf("%s: %v", id, err)
				}
			}
			rig.requireHostileProjection(reader, hostile)
		})
	}
}

// anchorToFixtures checks the archive against the fixture itself, not only
// against the hot store (both sides share the query layer's assembly): a
// kept raw request is the request the client sent, a kept raw response of a
// complete exchange is what the provider sent, and a rebuilt request is
// JSON-equivalent to the request body.
func (rig *archiveRig) anchorToFixtures(reader *archivecli.Reader, exchanges map[string]protofixture.Exchange) {
	t := rig.t
	t.Helper()
	rawRequests, rawResponses, rebuilt := 0, 0, 0
	for id, exchange := range exchanges {
		audit, err := reader.Audit(rig.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		if err := audit.StreamRaw(rig.ctx, query.SideRequest, &raw); err == nil {
			if !bytes.Equal(raw.Bytes(), exchange.RequestBody) {
				t.Errorf("%s %s: archived raw request differs from the request sent", id, exchange.Scenario)
			}
			rawRequests++
		}
		raw.Reset()
		complete := exchange.Response.CutAt == 0
		if err := audit.StreamRaw(rig.ctx, query.SideResponse, &raw); err == nil && complete {
			if !bytes.Equal(raw.Bytes(), exchange.Response.Body()) {
				t.Errorf("%s %s: archived raw response differs from the answer", id, exchange.Scenario)
			}
			rawResponses++
		}
		if turn, err := audit.Turn(rig.ctx); err == nil {
			got, _ := json.Marshal(turn.Request)
			var left, right any
			if json.Unmarshal(got, &left) != nil || json.Unmarshal(exchange.RequestBody, &right) != nil || !reflect.DeepEqual(left, right) {
				t.Errorf("%s %s/%s: rebuilt request differs from the request sent", id, exchange.Protocol, exchange.Scenario)
			}
			rebuilt++
		}
	}
	t.Logf("anchored to the fixtures: %d raw requests, %d raw responses, %d rebuilt requests", rawRequests, rawResponses, rebuilt)
	if rawRequests == 0 || rawResponses == 0 || rebuilt < len(exchanges)/2 {
		t.Fatal("too little anchored")
	}
}

// sendBlocked sends a chat request without a credential: the interceptor
// rejects it before NewAPI, which leaves an audit without a turn.
func (rig *archiveRig) sendBlocked() string {
	rig.t.Helper()
	header := http.Header{"Content-Type": {"application/json"}}
	return rig.sendRequest(http.MethodPost, "/v1/chat/completions", header, []byte(`{"model":"model-example","messages":[{"role":"user","content":"blocked"}]}`), false, 0)
}

// hostileQuery has an empty segment, a credential without a value
// separator, a value that does not decode, a plus, a credential that is
// percent-encoded, and a trailing separator.
const hostileQuery = "?a=1&&key&%zz=%zz&b=+x&api%5Fkey=sk-hostile%2Dvalue&"

// sendHostile sends a chat request whose headers hold a value that is not
// valid UTF-8, an empty value, a repeated header and names whose byte order
// differs from their lower-case order, and whose Request-URI has
// hostileQuery.
func (rig *archiveRig) sendHostile() string {
	rig.t.Helper()
	built, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic}, protofixture.Options{Seed: 4242})
	if err != nil {
		rig.t.Fatal(err)
	}
	exchange := built[0]
	exchange.Path += hostileQuery
	header := exchange.RequestHeader
	header["X-Odd-Bytes"] = []string{"\xff\xfe-odd"}
	header["X-Empty"] = []string{""}
	header["X-Repeated"] = []string{"first", "second", "third"}
	header["X-B"] = []string{"b"}
	header["X-_a"] = []string{"a"}
	header["x-lower"] = []string{"lower"}
	return rig.send(exchange)
}

// requireHostileProjection checks the hostile audit's projected Request-URI:
// non-credential segments keep their bytes and rebuild the query, the
// credential segments keep only name, separator, length and fingerprint.
func (rig *archiveRig) requireHostileProjection(reader *archivecli.Reader, id string) {
	t := rig.t
	t.Helper()
	audit, err := reader.Audit(rig.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	uri := audit.Record.Audit.RequestURI
	var rebuilt []string
	credentials := 0
	for _, segment := range uri.Segments {
		if segment.Credential {
			credentials++
			rebuilt = append(rebuilt, "<"+segment.RawName+">")
			continue
		}
		rebuilt = append(rebuilt, segment.Raw)
	}
	want := "a=1||<key>|%zz=%zz|b=+x|<api%5Fkey>|"
	if got := strings.Join(rebuilt, "|"); !uri.HasQuery || got != want || credentials != 2 {
		t.Fatalf("hostile query projected as %q (%d credentials), want %q", got, credentials, want)
	}
	if fpr := rig.keys.CredentialFingerprint([]byte("sk-hostile-value")); uri.Segments[5].Fingerprint != fpr || uri.Segments[5].Length != int64(len("sk-hostile-value")) {
		t.Fatal("the percent-encoded credential is not fingerprinted decoded")
	}
	names := map[string]bool{}
	for _, header := range audit.Record.Headers.Values {
		names[header.Name] = true
	}
	for _, name := range []string{"X-Odd-Bytes", "X-Empty", "X-Repeated", "X-B", "X-_a"} {
		if !names[name] && !names[http.CanonicalHeaderKey(name)] {
			t.Fatalf("header %s is not in the archive (%v)", name, names)
		}
	}
}

// J.3 for rows the current write path no longer produces, on PostgreSQL:
//
//   - capture version 1 (one http_headers row per value, no block, no
//     user_agent_enc), written with the store's per-operation writes from
//     real fixture exchanges of the four protocols, some chunks sealed with
//     the legacy body_chunk AAD, then parsed by the parser worker;
//   - the pre-stage-2 shape: real exchanges captured through the proxy whose
//     parse is saved without a turn, the conversation in parsed_json_enc
//     (both plain and gzip-compressed forms), so all four stages keep their
//     raw (DecideRawRetention releases nothing without a turn), for normal
//     and error answers.
//
// The same comparison as the catalogue, then the shapes are checked to be
// present.
func TestArchiveReadEquivalenceOldRows(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, deferWorker: true})
	var oldShape []string
	for index, value := range []protofixture.Case{
		{Protocol: protofixture.AnthropicMessages, Scenario: protofixture.ScenarioBasic, Stream: true},
		{Protocol: protofixture.AnthropicMessages, Scenario: protofixture.ScenarioError500},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioBasic, Stream: true},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioMultimodal},
		{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioError429, Stream: true},
		{Protocol: protofixture.OpenAIResponses, Scenario: protofixture.ScenarioNoTerminal, Stream: true},
	} {
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(700 + index)})
		if err != nil {
			t.Fatal(err)
		}
		id := rig.send(built[0])
		rig.saveTurnlessParse(id, built[0], index%2 == 0)
		oldShape = append(oldShape, id)
	}
	var versionOne []string
	for index, value := range []protofixture.Case{
		{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioToolCalls},
		{Protocol: protofixture.OpenAIResponses, Scenario: protofixture.ScenarioBasic, Stream: true},
		{Protocol: protofixture.AnthropicMessages, Scenario: protofixture.ScenarioReasoning},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioBasic},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioError400, Stream: true},
	} {
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(800 + index)})
		if err != nil {
			t.Fatal(err)
		}
		versionOne = append(versionOne, rig.writeVersion1(fmt.Sprintf("v1-audit-%02d", index), built[0], int64(1000+index)))
	}
	rig.startWorker()
	rig.waitParsed()

	// The shapes are what this test is about.
	for _, id := range oldShape {
		var turns, full, parsed int
		if err := rig.db.QueryRow(`SELECT (SELECT COUNT(*) FROM turns WHERE audit_id = $1),
  (SELECT COUNT(*) FROM body_streams WHERE audit_id = $1 AND retention_state = 'full'),
  (SELECT COUNT(*) FROM parsed_results WHERE audit_id = $1 AND parsed_json_enc IS NOT NULL)`, id).Scan(&turns, &full, &parsed); err != nil {
			t.Fatal(err)
		}
		if turns != 0 || full != 4 || parsed != 1 {
			t.Fatalf("%s: %d turns, %d full stages, %d parsed json", id, turns, full, parsed)
		}
	}
	var v1Headers, v1Turns int
	if err := rig.db.QueryRow(`SELECT (SELECT COUNT(*) FROM http_headers WHERE audit_id LIKE 'v1-audit-%'),
  (SELECT COUNT(*) FROM turns WHERE audit_id LIKE 'v1-audit-%')`).Scan(&v1Headers, &v1Turns); err != nil {
		t.Fatal(err)
	}
	if v1Headers < 6*4 || v1Turns < 4 {
		t.Fatalf("version 1 fixtures: %d header rows, %d turns", v1Headers, v1Turns)
	}

	ids := rig.auditIDs()
	for _, id := range ids {
		if _, err := rig.hot.Get(rig.ctx, id, nil); err != nil {
			t.Errorf("hot detail of %s: %v", id, err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	rig.due()
	result := rig.mustRun()
	rig.requireCleanRun(result, len(ids))
	reader := rig.reader(rig.dir)
	comparison := rig.compare(reader, ids)
	t.Logf("%d audits\n%s", len(ids), comparison.report())
	for _, difference := range comparison.differences {
		t.Error(difference)
	}
	if t.Failed() {
		t.FailNow()
	}
	if comparison.values["detail"] != len(ids) || comparison.values["raw.request"] < len(oldShape) || comparison.values["session"] < len(oldShape) {
		t.Fatalf("too little compared:\n%s", comparison.report())
	}
	for _, id := range versionOne {
		audit, err := reader.Audit(rig.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if audit.Record.Headers.CaptureVersion != 1 || audit.Record.Headers.BlockPresent || audit.Record.Audit.UserAgent != nil {
			t.Fatalf("%s is not archived as capture version 1: %+v", id, audit.Record.Headers)
		}
		credentials := 0
		for _, header := range audit.Record.Headers.Values {
			if header.Value.Omitted {
				credentials++
			}
		}
		if credentials < 2 {
			t.Fatalf("%s: %d projected credentials in the version 1 headers", id, credentials)
		}
	}
}

// saveTurnlessParse claims the audit's pending parse and saves it as audits
// were saved before stage 2: no turn, the conversation in parsed_json_enc.
func (rig *archiveRig) saveTurnlessParse(id string, exchange protofixture.Exchange, large bool) {
	t := rig.t
	t.Helper()
	claimed, err := rig.store.ClaimPendingParse(rig.ctx, id)
	if err != nil || !claimed {
		t.Fatalf("claim %s = %v, %v", id, claimed, err)
	}
	fallback := conversation.New()
	message := func(role, phase, direction, text string) {
		fallback.Messages = append(fallback.Messages, conversation.Message{Index: len(fallback.Messages), Role: role, Phase: phase, Direction: direction,
			Content: []conversation.Part{{Index: 0, Type: conversation.PartText, Text: text}}})
	}
	message(conversation.RoleUser, conversation.PhaseRequest, conversation.DirectionClientToUpstream, "fallback for "+string(exchange.Scenario))
	if large {
		for index := 0; index < 300; index++ {
			message(conversation.RoleAssistant, conversation.PhaseResponse, conversation.DirectionUpstreamToClient, strings.Repeat("fallback text ", 6))
		}
	}
	plaintext, err := json.Marshal(map[string]any{"status": "ok", "conversation": fallback})
	if err != nil {
		t.Fatal(err)
	}
	parsed := postgres.ParsedAudit{Result: postgres.ParsedResult{AuditID: id, ParserName: exchange.ParserName, ParserVersion: "1",
		Status: storage.ParseOK, ParsedAtNS: 1}}
	if parsed.Result.ParsedJSONEnc, err = auditmodel.SealParsedResult(rig.cipher, id, exchange.ParserName, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := rig.store.SaveParsedAudit(rig.ctx, parsed); err != nil {
		t.Fatal(err)
	}
}

// routeFor is the archive route of an exchange.
func routeFor(exchange protofixture.Exchange) string {
	for _, route := range archiveRoutes {
		if route.Parser == exchange.ParserName {
			return route.ID
		}
	}
	return ""
}

// writeVersion1 stores one exchange as capture version 1 through the
// store's per-operation writes, as the removed legacy path stored it: one
// http_headers row per value, an Authorization or key header and a ?key=
// segment that are credentials, the bodies in chunks of at most 4 KiB (the
// first chunk of each body under the legacy body_chunk AAD), and a pending
// parse for the worker.
func (rig *archiveRig) writeVersion1(id string, exchange protofixture.Exchange, started int64) string {
	t := rig.t
	t.Helper()
	ctx := rig.ctx
	requestURI := exchange.Path + "?key=v1-query-credential&alt=sse"
	aad, _ := security.AAD(id, "request_uri")
	uriEnc, err := rig.cipher.Encrypt(aad, []byte(requestURI))
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := security.NewCredentialFingerprinter(rig.key)
	if err != nil {
		t.Fatal(err)
	}
	record := postgres.AuditRecord{
		AuditID: id, StartedAtNS: started, RouteID: routeFor(exchange), Protocol: exchange.Protocol.Family(), ParserName: exchange.ParserName,
		Method: exchange.Method, Path: exchange.Path, RequestURIEnc: uriEnc, Mode: "available",
		APIKeyFPR: fingerprints.Fingerprint(security.ExtractCredential(exchange.RequestHeader, nil)),
	}
	if err := rig.store.BeginAudit(ctx, record); err != nil {
		t.Fatal(err)
	}
	requestHeader := exchange.RequestHeader.Clone()
	requestHeader.Add("X-Repeated", "one")
	requestHeader.Add("X-Repeated", "two")
	responseHeader := exchange.Response.Header.Clone()
	if responseHeader == nil {
		responseHeader = http.Header{}
	}
	responseHeader.Set("Set-Cookie", "session=v1-cookie-credential")
	status := exchange.Response.Status
	if status == 0 {
		status = http.StatusOK
	}
	headerRows := func(stage string, header http.Header) []postgres.HTTPHeader {
		var out []postgres.HTTPHeader
		for _, field := range headerblock.Snapshot(header) {
			for index, value := range field.Values {
				aad, _ := security.AAD(id, "header", stage, storage.HeaderKindHeader, field.Name, strconv.Itoa(index))
				enc, err := rig.cipher.Encrypt(aad, value)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, postgres.HTTPHeader{AuditID: id, Stage: stage, Kind: storage.HeaderKindHeader, Name: field.Name,
					ValueIndex: index, ValueLength: len(value), ValueEnc: enc})
			}
		}
		return out
	}
	stages := []struct {
		name   string
		header http.Header
		body   []byte
	}{
		{storage.StageRequestReceived, requestHeader, exchange.RequestBody},
		{storage.StageRequestSent, requestHeader, exchange.RequestBody},
		{storage.StageResponseReceived, responseHeader, exchange.Response.Body()},
		{storage.StageResponseSent, responseHeader, exchange.Response.Body()},
	}
	at := started
	for _, stage := range stages {
		at += 10
		httpStage := postgres.HTTPStage{AuditID: id, Stage: stage.name, Proto: "HTTP/1.1", Method: exchange.Method, Host: "newapi.example.com", StartedAtNS: at}
		var statusCode *int
		if stage.name == storage.StageResponseReceived || stage.name == storage.StageResponseSent {
			statusCode = &status
			httpStage.StatusCode = statusCode
		}
		if err := rig.store.StartStage(ctx, httpStage); err != nil {
			t.Fatal(err)
		}
		if err := rig.store.AddHeaders(ctx, headerRows(stage.name, stage.header)); err != nil {
			t.Fatal(err)
		}
		if err := rig.store.StartBody(ctx, postgres.BodyStream{AuditID: id, Stage: stage.name}); err != nil {
			t.Fatal(err)
		}
		var chunks int64
		for offset := 0; offset < len(stage.body); offset += 4096 {
			piece := stage.body[offset:min(offset+4096, len(stage.body))]
			label := "body_chunk_v2"
			aad, _ := security.AAD(id, label, stage.name, strconv.FormatInt(chunks, 10), storage.ChunkCompressionNone)
			if chunks == 0 {
				aad, _ = security.AAD(id, "body_chunk", stage.name, strconv.FormatInt(chunks, 10))
			}
			enc, err := rig.cipher.Encrypt(aad, piece)
			if err != nil {
				t.Fatal(err)
			}
			at++
			if err := rig.store.AddChunk(ctx, postgres.BodyChunk{AuditID: id, Stage: stage.name, Seq: chunks, Offset: int64(offset),
				PlaintextLength: len(piece), EncodedLength: len(piece), ObservedAtNS: at, Compression: storage.ChunkCompressionNone, DataEnc: enc}); err != nil {
				t.Fatal(err)
			}
			chunks++
		}
		digest := sha256.Sum256(stage.body)
		at += 10
		first, last := started+11, at
		if err := rig.store.FinishStage(ctx, postgres.StageFinish{AuditID: id, Stage: stage.name, State: storage.StageStateComplete, StatusCode: statusCode, EndedAtNS: at,
			Body: &postgres.BodyFinish{ObservedLength: int64(len(stage.body)), StoredLength: int64(len(stage.body)), SHA256: digest[:],
				HashComplete: true, EOFSeen: true, State: storage.StageStateComplete, ChunkCount: chunks, FirstObservedAtNS: &first, LastObservedAtNS: &last}}); err != nil {
			t.Fatal(err)
		}
	}
	forward := storage.ForwardCompleted
	if status >= 400 {
		forward = storage.ForwardNewAPIError
	}
	if err := rig.store.FinishAudit(ctx, postgres.AuditFinish{AuditID: id, EndedAtNS: at + 10, StatusCode: &status,
		ForwardStatus: forward, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParsePending}); err != nil {
		t.Fatal(err)
	}
	return id
}
