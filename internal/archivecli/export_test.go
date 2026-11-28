package archivecli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
)

// hotDetail is what query.Service.Get gives for the record on the hot side:
// query.BuildDetail on the plaintext rows, with the plaintext request URI and
// header values the hot database holds, in headerblock.Expand order.
func (s *scenario) hotDetail(t *testing.T, record *archive.Record) query.Detail {
	t.Helper()
	plain, err := record.PlainDetail(s.payloads, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := s.originals[record.Audit.AuditID]
	plain.RequestURI = source.uri
	plain.Headers = nil
	for _, projected := range record.Headers.Values {
		for _, value := range source.headers {
			if value.Stage == projected.Stage && value.Kind == projected.Kind && value.Name == projected.Name && int64(value.ValueIndex) == projected.ValueIndex {
				plain.Headers = append(plain.Headers, headerblock.Value{Stage: value.Stage, Kind: value.Kind, Name: value.Name, ValueIndex: value.ValueIndex, Value: value.Value})
			}
		}
	}
	if len(plain.Headers) != len(record.Headers.Values) {
		t.Fatal("headers do not map back to the originals")
	}
	detail, err := query.BuildDetail(plain)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

func encodeExpected(t *testing.T, write func(*bytes.Buffer) error) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := write(&buffer); err != nil {
		t.Fatal(err)
	}
	return buffer.String()
}

func jsonLine(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

// Every export form of every audit equals what the query layer's plaintext
// half gives for the same record, called directly on the records the bundles
// were written from (with the hot side's plaintext request URI and headers
// projected afterwards, design J.3), and the error class where there is no
// such export.
func TestExportFormsEqualTheQueryLayer(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			for _, id := range []string{"c1", "c2", "c3", "c4", "loose"} {
				record := s.records[id]
				hot := s.hotDetail(t, record)
				projected := archive.ProjectDetail(s.keys.Archive, hot)
				plain, err := record.PlainDetail(s.payloads, nil)
				if err != nil {
					t.Fatal(err)
				}
				export := func(kind string, exit int) string {
					t.Helper()
					out := run(t, s.read("export", "--audit", id, "--what", kind)...).want(t, exit)
					return out.stdout
				}

				if got, want := export(KindDetail, ExitOK), encodeExpected(t, func(buffer *bytes.Buffer) error { return WriteDetail(buffer, projected) }); got != want {
					t.Fatalf("%s detail:\n got %.400s\nwant %.400s", id, got, want)
				}
				if got, want := export(KindHeaders, ExitOK), encodeExpected(t, func(buffer *bytes.Buffer) error { return WriteHeaders(buffer, id, projected.Headers) }); got != want {
					t.Fatalf("%s headers:\n got %s\nwant %s", id, got, want)
				}
				checkHeaders(t, s, id, export(KindHeaders, ExitOK))
				if hot.Conversation == nil {
					t.Fatalf("%s has no conversation; the fixture should give every audit one", id)
				}
				if got, want := export(KindConversation, ExitOK), jsonLine(t, hot.Conversation); got != want {
					t.Fatalf("%s conversation:\n got %.300s\nwant %.300s", id, got, want)
				}
				if !strings.Contains(export(KindConversation, ExitOK), contentMarker) {
					t.Fatalf("%s conversation without content", id)
				}

				if id == "loose" {
					// No turn: the provider bodies cannot be rebuilt; the
					// partial request body was kept, the response body not.
					export(KindRequest, ExitNotFound)
					export(KindResponse, ExitNotFound)
					export(KindTimelineResponse, ExitNotFound)
					if got := export(KindRawRequest, ExitOK); got != string(s.raw["loose/request"]) {
						t.Fatalf("loose raw request %q", got)
					}
					out := run(t, s.read("export", "--audit", id, "--what", KindRawResponse)...).want(t, ExitNotFound)
					if !strings.Contains(out.stderr, "not_retained") || out.stdout != "" {
						t.Fatalf("loose raw response: %+v", out)
					}
					continue
				}
				rebuilt, err := query.ReconstructPlainTurn(plain)
				if err != nil {
					t.Fatal(err)
				}
				exchange := s.exchanges[id]
				for kind, body := range map[string]any{KindRequest: rebuilt.Request, KindResponse: rebuilt.Response} {
					got := export(kind, ExitOK)
					if want := jsonLine(t, body); got != want {
						t.Fatalf("%s %s:\n got %.300s\nwant %.300s", id, kind, got, want)
					}
					var decoded any
					if err := json.Unmarshal([]byte(got), &decoded); err != nil {
						t.Fatal(err)
					}
					canonical, err := auditmodel.CanonicalJSON(decoded)
					if err != nil {
						t.Fatal(err)
					}
					original := map[string][]byte{KindRequest: exchange.request, KindResponse: exchange.response}[kind]
					if !bytes.Equal(canonical, original) {
						t.Fatalf("%s %s is not the provider body", id, kind)
					}
				}
				// The paired stage request_sent is served from request_received.
				if got := export(KindRawRequest, ExitOK); got != string(exchange.request) {
					t.Fatalf("%s raw request differs", id)
				}
				if got := export(KindRawResponse, ExitOK); got != string(exchange.response) {
					t.Fatalf("%s raw response differs", id)
				}
				selected, _, _ := record.SelectBody(query.SideResponse)
				stored, plaintext, _ := record.StoredTimeline(selected)
				timeline, err := query.TimelineFromPlain(stored, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				got := export(KindTimelineResponse, ExitOK)
				if want := encodeExpected(t, func(buffer *bytes.Buffer) error { return WriteTimeline(buffer, timeline) }); got != want {
					t.Fatalf("%s timeline:\n got %s\nwant %s", id, got, want)
				}
				var decoded TimelineExport
				if err := json.Unmarshal([]byte(got), &decoded); err != nil {
					t.Fatal(err)
				}
				if len(decoded.Points) != len(exchange.points) || decoded.Points[1].Offset != exchange.points[1].Offset ||
					*decoded.Points[1].ObservedAt != time.Unix(0, exchange.points[1].AtNS).UTC().Format(time.RFC3339Nano) || !decoded.Complete {
					t.Fatalf("%s timeline points %+v", id, decoded)
				}
				export(KindTimelineRequest, ExitNotFound)
			}
			run(t, s.read("export", "--audit", "absent")...).want(t, ExitNotFound)
		})
	}
}

// checkHeaders: every credential header is projected with the length and
// the keyed fingerprint of its original value; other values are shown.
func checkHeaders(t *testing.T, s *scenario, id, output string) {
	t.Helper()
	var decoded struct {
		AuditID string            `json:"audit_id"`
		Headers []ProjectedHeader `json:"headers"`
	}
	if err := json.Unmarshal([]byte(output), &decoded); err != nil || decoded.AuditID != id {
		t.Fatalf("headers %v", err)
	}
	omitted := 0
	for _, header := range decoded.Headers {
		var value []byte
		for _, original := range s.originals[id].headers {
			if original.Name == header.Name && original.Stage == header.Stage {
				value = original.Value
			}
		}
		if header.ValueOmitted != "" {
			fingerprint := s.keys.Archive.CredentialFingerprint(value)
			if header.ValueUntrusted != nil || header.Length != int64(len(value)) || header.ValueFPR != hex.EncodeToString(fingerprint[:]) {
				t.Fatalf("%s credential header %+v", id, header)
			}
			omitted++
		} else if header.ValueUntrusted == nil || *header.ValueUntrusted != string(value) {
			t.Fatalf("%s header %+v", id, header)
		}
	}
	if omitted != 4 {
		t.Fatalf("%s: %d credential headers, want Authorization, x-api-key, Cookie and Set-Cookie", id, omitted)
	}
}

// export --conversation follows the conversation over the conversation
// bundle and the buckets, in turn order, at each audit's highest revision.
func TestExportConversationAcrossBundles(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			lines := run(t, s.read("export", "--conversation", s.conversation)...).want(t, ExitOK).lines()
			if len(lines) != 3 {
				t.Fatalf("%d lines", len(lines))
			}
			for index, id := range []string{"c1", "c2", "c3"} {
				var line struct {
					AuditID      string          `json:"audit_id"`
					TurnID       string          `json:"turn_id"`
					CreatedAtNS  string          `json:"created_at_ns"`
					Conversation json.RawMessage `json:"conversation"`
				}
				if err := json.Unmarshal([]byte(lines[index]), &line); err != nil {
					t.Fatal(err)
				}
				hot := s.hotDetail(t, s.records[id])
				if line.AuditID != id || line.TurnID != "turn-"+id || jsonLine(t, hot.Conversation) != string(line.Conversation)+"\n" {
					t.Fatalf("line %d: %.200s", index, lines[index])
				}
			}
			keys, err := LoadKeys(s.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := OpenReader(context.Background(), s.root, ReaderOptions{Keys: keys})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var revisions []int64
			err = reader.ConversationTurns(context.Background(), s.conversation, func(audit *AuditRecord) error {
				revisions = append(revisions, audit.Record.Revision)
				return nil
			})
			if err != nil || len(revisions) != 3 || revisions[1] != 2 {
				t.Fatalf("revisions %v, %v", revisions, err)
			}
			run(t, s.read("export", "--conversation", "conv_absent")...).want(t, ExitNotFound)
		})
	}
}

// The Go entry points the read-equivalence tests call: an opened reader,
// one export per form, and the typed values the query layer gives.
func TestGoAPI(t *testing.T) {
	s := newScenario(t, true)
	keys, err := LoadKeys(s.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reader, err := OpenReader(ctx, s.root, ReaderOptions{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if !reader.Authenticated() {
		t.Fatal("reader with keys is not authenticated")
	}
	audit, err := reader.Audit(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	// A raw body streams without loading the objects of the bundle.
	var raw bytes.Buffer
	if err := ExportRaw(ctx, audit, query.SideRequest, &raw); err != nil || raw.String() != string(s.exchanges["c1"].request) {
		t.Fatalf("raw %v", err)
	}
	if audit.loaded {
		t.Fatal("a raw export loaded the objects")
	}
	metadata, err := audit.RawMeta(query.SideRequest)
	if err != nil || !metadata.Complete || metadata.StoredLength != int64(raw.Len()) {
		t.Fatalf("raw metadata %+v %v", metadata, err)
	}
	projected, err := audit.Detail(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := archive.ProjectDetail(s.keys.Archive, s.hotDetail(t, s.records["c1"]))
	if jsonLine(t, DetailOf(projected)) != jsonLine(t, DetailOf(want)) {
		t.Fatal("Detail differs from the projected hot detail")
	}
	summary := audit.Summary()
	if summary.UserAgent == nil || summary.UserAgent.Value != "client/1.0" || summary.Summary.ConversationID == nil {
		t.Fatalf("summary %+v", summary)
	}
	session, err := audit.SessionConversation(ctx)
	if err != nil || session == nil {
		t.Fatalf("session conversation %v", err)
	}
	for _, kind := range ExportKinds {
		var out bytes.Buffer
		if err := Export(ctx, reader, "c3", kind, &out); err != nil && kind != KindTimelineRequest {
			t.Fatalf("%s: %v", kind, err)
		} else if kind == KindTimelineRequest && ErrorCode(err) != codeNotFound {
			t.Fatalf("timeline-request error %q", ErrorCode(err))
		}
	}
	if err := Export(ctx, reader, "loose", KindRequest, &bytes.Buffer{}); ErrorCode(err) != codeNoTurnGraph {
		t.Fatalf("loose request error %q", ErrorCode(err))
	}
	if err := Export(ctx, reader, "loose", KindRawResponse, &bytes.Buffer{}); ErrorCode(err) != codeNotRetained {
		t.Fatalf("loose raw response error %q", ErrorCode(err))
	}
}
