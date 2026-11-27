package parser

import (
	"cmp"
	"math/rand/v2"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// TestContentHeaderRuleMatchesHeaderBlock pins headerblock.ContentHeaders,
// which selects the version 2 http_stages content columns, to the rule
// decryptContentHeaders applies to version 1 rows, on the same Headers. The
// rows are fed both in name byte order and in the order LoadParserStage reads
// them (lower(name), value_index).
func TestContentHeaderRuleMatchesHeaderBlock(t *testing.T) {
	key := make([]byte, security.KeySize)
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{cipher: cipher}
	const auditID = "aud_content_pin"
	stage := storage.StageResponseReceived

	cases := []struct {
		name     string
		headers  http.Header
		trailers http.Header
	}{
		{name: "none", headers: http.Header{"Accept": {"x"}}},
		{name: "both", headers: http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}},
		{name: "first non-empty", headers: http.Header{"Content-Type": {"", "text/plain", "text/html"}, "Content-Encoding": {"", ""}}},
		{name: "case variants", headers: http.Header{"Content-Type": {"", "b"}, "content-type": {"c"}, "CONTENT-ENCODING": {"br"}}},
		{name: "lower case only", headers: http.Header{"content-type": {"lost"}}},
		{name: "trailer ignored", headers: http.Header{"X": {"1"}}, trailers: http.Header{"Content-Type": {"text/plain"}}},
		{name: "non-UTF-8", headers: http.Header{"Content-Type": {"\xff\xfe"}}},
	}
	random := rand.New(rand.NewPCG(6, 59))
	pool := []string{"Content-Type", "content-type", "CONTENT-TYPE", "Content-Encoding", "content-encoding", "Accept"}
	for round := 0; round < 200; round++ {
		headers := http.Header{}
		for range random.IntN(5) {
			var values []string
			for range random.IntN(3) {
				values = append(values, []string{"", "a", "b", "text/event-stream"}[random.IntN(4)])
			}
			headers[pool[random.IntN(len(pool))]] = values
		}
		cases = append(cases, struct {
			name     string
			headers  http.Header
			trailers http.Header
		}{name: "random " + strconv.Itoa(round), headers: headers})
	}

	for _, testCase := range cases {
		rows := append(legacyHeaderRows(t, cipher, auditID, stage, storage.HeaderKindHeader, testCase.headers),
			legacyHeaderRows(t, cipher, auditID, stage, storage.HeaderKindTrailer, testCase.trailers)...)
		readerOrder := slices.Clone(rows)
		slices.SortStableFunc(readerOrder, func(left, right storage.HTTPHeader) int {
			return cmp.Or(strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name)), cmp.Compare(left.ValueIndex, right.ValueIndex))
		})
		wantType, wantEncoding := headerblock.ContentHeaders(headerblock.Snapshot(testCase.headers))
		for order, input := range map[string][]storage.HTTPHeader{"byte order": rows, "reader order": readerOrder} {
			var source BodySource
			if err := worker.decryptContentHeaders(auditID, stage, input, &source); err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}
			if source.ContentType != deref(wantType) || source.ContentEncoding != deref(wantEncoding) ||
				wantType != nil && *wantType == "" || wantEncoding != nil && *wantEncoding == "" {
				t.Fatalf("%s (%s): parser %q %q, header block %v %v", testCase.name, order, source.ContentType, source.ContentEncoding, wantType, wantEncoding)
			}
		}
	}
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// legacyHeaderRows writes rows the way Session.addHeadersLocked does.
func legacyHeaderRows(t *testing.T, cipher security.Cipher, auditID, stage, kind string, headers http.Header) []storage.HTTPHeader {
	t.Helper()
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var rows []storage.HTTPHeader
	for _, name := range names {
		for index, value := range headers.Values(name) {
			aad, err := security.AAD(auditID, "header", stage, kind, name, strconv.Itoa(index))
			if err != nil {
				t.Fatal(err)
			}
			enc, err := cipher.Encrypt(aad, []byte(value))
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, storage.HTTPHeader{AuditID: auditID, Stage: stage, Kind: kind, Name: name, ValueIndex: index, ValueLength: len(value), ValueEnc: enc})
		}
	}
	return rows
}
