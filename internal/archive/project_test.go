package archive

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// rebuildQuery joins the raw segments of a projection, which equals the raw
// query when no segment is a credential.
func rebuildURI(uri RequestURI) string {
	if !uri.HasQuery {
		return uri.Path
	}
	parts := make([]string, 0, len(uri.Segments))
	for _, segment := range uri.Segments {
		if segment.Credential {
			parts = append(parts, "<credential>")
			continue
		}
		parts = append(parts, segment.Raw)
	}
	return uri.Path + "?" + strings.Join(parts, "&")
}

// Every inbound and outbound credential transport is projected; ordinary
// values are kept byte for byte.
func TestProjectionOmitsEveryCredentialTransport(t *testing.T) {
	keys := newTestKeys()
	credentials := map[string]string{
		"Authorization":       "Bearer sk-transport-one",
		"Proxy-Authorization": "Basic dXNlcjpwYXNz",
		"X-Api-Key":           "sk-transport-two",
		"X-Goog-Api-Key":      "AIza-transport-three",
		"Api-Key":             "plain-but-named",
		"Cookie":              "session=abc",
		"Set-Cookie":          "session=abc; HttpOnly",
		"X-Client-Secret":     "plain",
		"X-Auth-Token":        "plain",
		"X-Anything":          "sk-prefixed-value",
		"X-Other":             "  bearer lower-case",
		"X-Agent":             "lla_agent-token",
	}
	for name, value := range credentials {
		projected := ProjectValue(keys, name, []byte(value))
		if !projected.Omitted || projected.Value != "" || projected.Length != int64(len(value)) || projected.Fingerprint != keys.CredentialFingerprint([]byte(value)) {
			t.Errorf("%s: %+v", name, projected)
		}
	}
	for name, value := range map[string]string{
		"Content-Type": "application/json", "User-Agent": "client/1 (\xff\xfe)", "X-Session-Id": "abc",
		"X-Ratelimit-Remaining-Tokens": "100", "Accept": "",
	} {
		projected := ProjectValue(keys, name, []byte(value))
		if projected.Omitted || projected.Value != value {
			t.Errorf("%s: plain value changed: %+v", name, projected)
		}
	}
	uri := ProjectRequestURI(keys, []byte("/v1beta/models/m:streamGenerateContent?alt=sse&key=AIza-query&api_key=x&token=y&debug"))
	if uri.Path != "/v1beta/models/m:streamGenerateContent" || !uri.HasQuery || len(uri.Segments) != 5 {
		t.Fatalf("uri = %+v", uri)
	}
	for index, credential := range []bool{false, true, true, true, false} {
		if uri.Segments[index].Credential != credential {
			t.Errorf("segment %d credential=%v", index, uri.Segments[index].Credential)
		}
	}
	if uri.Segments[1].RawName != "key" || !uri.Segments[1].HasEquals || uri.Segments[1].Length != int64(len("AIza-query")) {
		t.Fatalf("key segment = %+v", uri.Segments[1])
	}
}

// The same credential gets the same fingerprint at every stage and in every
// transport that carries the same bytes, so the inbound and outbound copies
// can be compared (5.5).
func TestFingerprintMatchesAcrossStages(t *testing.T) {
	keys := newTestKeys()
	values := []headerblock.Value{
		{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer sk-stage")},
		{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "authorization", Value: []byte("Bearer sk-stage")},
		{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "X-Api-Key", Value: []byte("Bearer sk-stage")},
		{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer sk-other")},
	}
	projected := ProjectHeaders(keys, values)
	if projected[0].Value.Fingerprint != projected[1].Value.Fingerprint || projected[0].Value.Fingerprint != projected[2].Value.Fingerprint {
		t.Fatal("same value, different fingerprints")
	}
	if projected[0].Value.Fingerprint == projected[3].Value.Fingerprint {
		t.Fatal("different values, same fingerprint")
	}
	// The query value is fingerprinted decoded, so it matches the header.
	header := ProjectValue(keys, "X-Goog-Api-Key", []byte("AIza a+b/c"))
	uri := ProjectRequestURI(keys, []byte("/x?key=AIza%20a%2Bb%2Fc"))
	if uri.Segments[0].Fingerprint != header.Fingerprint || uri.Segments[0].Length != header.Length {
		t.Fatal("decoded query credential does not match the header value")
	}
}

// D.4: a known key is checked against value_fpr through the raw and Bearer
// candidates.
func TestKnownKeyCheck(t *testing.T) {
	keys := newTestKeys()
	key := []byte("sk-known-key-0123456789")
	raw, bearer := KnownKeyFingerprints(keys, key)
	authorization := ProjectValue(keys, "Authorization", append([]byte("Bearer "), key...))
	apiKey := ProjectValue(keys, "X-Api-Key", key)
	query := ProjectRequestURI(keys, []byte("/v1beta/models/m:generateContent?key="+string(key)))
	if authorization.Fingerprint != bearer || apiKey.Fingerprint != raw || query.Segments[0].Fingerprint != raw {
		t.Fatal("known key candidates do not match the projected values")
	}
	otherRaw, otherBearer := KnownKeyFingerprints(keys, []byte("sk-another-key"))
	if otherRaw == raw || otherBearer == bearer {
		t.Fatal("another key matches")
	}
}

// Request-URI edge cases (Q3 甲): structure preserved byte for byte, empty
// segments kept, undecodable pairs judged on their raw bytes, an empty
// credential value still fingerprinted.
func TestRequestURIProjection(t *testing.T) {
	keys := newTestKeys()
	for _, raw := range []string{
		"/v1/chat/completions",
		"/v1/chat/completions?",
		"/v1/x?a=1&&b=2&",
		"/v1/x?&",
		"/v1/x?a=%zz&%zz=1&c=%E4%BD%A0&d=+&e==&f",
		"/v1/x?trace=a#frag",
		"/v1/x?bad=\xff\xfe",
		"/p%2Fq?x=1?y=2",
	} {
		uri := ProjectRequestURI(keys, []byte(raw))
		if rebuilt := rebuildURI(uri); rebuilt != raw {
			t.Errorf("%q rebuilt as %q", raw, rebuilt)
		}
	}
	empty := ProjectRequestURI(keys, []byte("/x"))
	if empty.HasQuery || empty.Segments == nil || len(empty.Segments) != 0 {
		t.Fatalf("no query = %+v", empty)
	}
	question := ProjectRequestURI(keys, []byte("/x?"))
	if !question.HasQuery || len(question.Segments) != 1 || question.Segments[0].Raw != "" {
		t.Fatalf("bare question mark = %+v", question)
	}
	undecodable := ProjectRequestURI(keys, []byte("/x?key=%zz&k%zzey=1&sk-name=1"))
	if s := undecodable.Segments[0]; !s.Credential || s.Length != 3 || s.Fingerprint != keys.CredentialFingerprint([]byte("%zz")) {
		t.Fatalf("undecodable credential value = %+v", s)
	}
	if undecodable.Segments[1].Credential || undecodable.Segments[1].Raw != "k%zzey=1" {
		t.Fatalf("undecodable name = %+v", undecodable.Segments[1])
	}
	if undecodable.Segments[2].Credential {
		t.Fatal("a name with an sk- prefix is not a credential by itself")
	}
	blank := ProjectRequestURI(keys, []byte("/x?key=&key"))
	for index, hasEquals := range []bool{true, false} {
		s := blank.Segments[index]
		if !s.Credential || s.Length != 0 || s.HasEquals != hasEquals || s.Fingerprint != keys.CredentialFingerprint(nil) {
			t.Fatalf("empty credential %d = %+v", index, s)
		}
	}
	valueRule := ProjectRequestURI(keys, []byte("/x?auth=Bearer%20sk-x&q=sk-y"))
	if !valueRule.Segments[0].Credential || !valueRule.Segments[1].Credential || valueRule.Segments[0].RawName != "auth" {
		t.Fatalf("value rule = %+v", valueRule.Segments)
	}
}

// ProjectDetail and ProjectSummary replace exactly the raw values and leave
// everything else of the hot side's output alone.
func TestProjectDetailAndSummary(t *testing.T) {
	keys := newTestKeys()
	agent := "sk-agent-as-ua"
	detail := query.Detail{
		Audit:      query.AuditSummary{AuditID: "a", UserAgent: &agent, Protocol: "openai"},
		RequestURI: "/v1/x?key=sk-q&y=1",
		Headers: []query.Header{
			{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", ValueLength: 9, Value: "Bearer sk"},
			{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Accept", ValueIndex: 1, ValueLength: 3, Value: "*/*"},
		},
		Stages: []query.Stage{{Stage: storage.StageRequestReceived}},
	}
	projected := ProjectDetail(keys, detail)
	if projected.Detail.RequestURI != "" || projected.Detail.Headers != nil || projected.Detail.Audit.UserAgent != nil ||
		projected.Detail.Audit.AuditID != "a" || len(projected.Detail.Stages) != 1 {
		t.Fatalf("detail = %+v", projected.Detail)
	}
	if !projected.Headers[0].Value.Omitted || projected.Headers[0].Value.Length != 9 || projected.Headers[1].Value.Value != "*/*" || projected.Headers[1].ValueIndex != 1 {
		t.Fatalf("headers = %+v", projected.Headers)
	}
	if projected.UserAgent == nil || !projected.UserAgent.Omitted || !projected.RequestURI.Segments[0].Credential {
		t.Fatalf("projected = %+v", projected)
	}
	if detail.RequestURI != "/v1/x?key=sk-q&y=1" || detail.Headers[0].Value != "Bearer sk" || *detail.Audit.UserAgent != agent {
		t.Fatal("projection changed its input")
	}
	summary := ProjectSummary(keys, query.AuditSummary{AuditID: "b"})
	if summary.UserAgent != nil || summary.Summary.AuditID != "b" {
		t.Fatalf("summary without a User-Agent = %+v", summary)
	}
}

// Property: whatever credential values a record carries, in headers,
// User-Agent or the query, their bytes appear nowhere in its encoded line,
// neither raw nor percent-encoded, while plain values do.
func TestProjectionNeverLeaksCredentialBytes(t *testing.T) {
	keys := newTestKeys()
	random := rand.New(rand.NewSource(59))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/= %&"
	secret := func(index int) string {
		var builder strings.Builder
		fmt.Fprintf(&builder, "sk-%03d-", index)
		for range 24 + random.Intn(40) {
			builder.WriteByte(alphabet[random.Intn(len(alphabet))])
		}
		return builder.String()
	}
	for round := 0; round < 200; round++ {
		header, ua, param, named := secret(round*4), secret(round*4+1), secret(round*4+2), secret(round*4+3)
		plain := fmt.Sprintf("plain-value-%d-%d", round, random.Int63())
		record := minimalRecord()
		record.Audit.CaptureVersion, record.Headers.CaptureVersion = storage.CaptureVersion2, storage.CaptureVersion2
		record.Audit.RequestURI = ProjectRequestURI(keys, []byte("/v1/x?key="+url.QueryEscape(param)+"&trace="+plain+"&q="+url.QueryEscape(header)))
		record.Audit.UserAgent = ProjectUserAgent(keys, []string{ua, plain})
		record.Headers.Values = ProjectHeaders(keys, []headerblock.Value{
			{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "Authorization", Value: []byte("Bearer " + header)},
			{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: "X-Note", Value: []byte(plain)},
			{Stage: storage.StageRequestSent, Kind: storage.HeaderKindHeader, Name: "X-Api-Key", Value: []byte(named)},
			{Stage: storage.StageResponseReceived, Kind: storage.HeaderKindTrailer, Name: "Set-Cookie", Value: []byte("id=" + named)},
		})
		line, _, _, err := EncodeLine(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{header, ua, param, named} {
			for _, form := range []string{value, url.QueryEscape(value), value[:16]} {
				if bytes.Contains(line, []byte(form)) {
					t.Fatalf("round %d: credential bytes %q in line %s", round, form, line)
				}
			}
		}
		if !bytes.Contains(line, []byte(plain)) {
			t.Fatalf("round %d: plain value missing", round)
		}
	}
}
