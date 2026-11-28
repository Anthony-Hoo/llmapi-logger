package query

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
)

// countingHeaderStore counts the per-row User-Agent queries of version 1
// rows.
type countingHeaderStore struct {
	*fakeStore
	headerQueries atomic.Int64
}

func (store *countingHeaderStore) QueryRequestHeaderEvidence(ctx context.Context, auditID string) ([]sqlite.HeaderEvidence, error) {
	store.headerQueries.Add(1)
	return store.fakeStore.QueryRequestHeaderEvidence(ctx, auditID)
}

// userAgentRows stores one inbound Header map both ways: as the version 1 rows
// QueryRequestHeaderEvidence returns (lower-case name, then value_index, as
// the stores order them) and as the version 2 user_agent_enc.
func userAgentRows(t *testing.T, cipher security.Cipher, auditID string, headers http.Header) ([]sqlite.HeaderEvidence, []byte) {
	t.Helper()
	fields := headerblock.Snapshot(headers)
	var rows []sqlite.HeaderEvidence
	for _, field := range fields {
		if !strings.EqualFold(field.Name, "user-agent") {
			continue
		}
		for index, value := range field.Values {
			aad, err := security.AAD(auditID, "header", sqlite.StageRequestReceived, sqlite.HeaderKindHeader, field.Name, strconv.Itoa(index))
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := cipher.Encrypt(aad, value)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, sqlite.HeaderEvidence{Stage: sqlite.StageRequestReceived, Kind: sqlite.HeaderKindHeader, Name: field.Name,
				ValueIndex: index, ValueLength: len(value), ValueEnc: encrypted})
		}
	}
	sort.SliceStable(rows, func(left, right int) bool {
		if strings.ToLower(rows[left].Name) != strings.ToLower(rows[right].Name) {
			return strings.ToLower(rows[left].Name) < strings.ToLower(rows[right].Name)
		}
		return rows[left].ValueIndex < rows[right].ValueIndex
	})
	sealed, err := headerblock.SealUserAgent(cipher, auditID, headerblock.UserAgentValues(fields))
	if err != nil {
		t.Fatal(err)
	}
	return rows, sealed
}

var userAgentCases = []struct {
	name    string
	headers http.Header
}{
	{"absent", http.Header{"Accept": {"*/*"}}},
	{"empty value", http.Header{"User-Agent": {""}}},
	{"one value", http.Header{"User-Agent": {"Codex-CLI/1.2 Windows"}, "Authorization": {"Bearer secret"}}},
	{"two values", http.Header{"User-Agent": {"curl/8", "Codex Desktop/3"}}},
	{"two keys", http.Header{"User-Agent": {"first/1"}, "user-agent": {"second/2"}}},
	{"lower-case key only", http.Header{"user-agent": {"hidden/1"}}},
}

// The list shows and filters a version 2 row's User-Agent exactly as it does
// the same Headers stored as version 1, in every case of today's rule:
// absent, empty, several values and several keys. A page of version 2 rows
// makes no per-row query.
func TestListUserAgentIsTheSameForBothCaptureVersions(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	headers := map[string][]sqlite.HeaderEvidence{}
	var v1Rows, v2Rows, mixed []sqlite.AuditListRow
	for index, test := range userAgentCases {
		v1ID, v2ID := "v1-"+strconv.Itoa(index), "v2-"+strconv.Itoa(index)
		rows, _ := userAgentRows(t, cipher, v1ID, test.headers)
		headers[v1ID] = rows
		_, sealed := userAgentRows(t, cipher, v2ID, test.headers)
		started := int64(1000 - index*2)
		v1 := sqlite.AuditListRow{AuditID: v1ID, StartedAtNS: started, ForwardStatus: sqlite.ForwardCompleted, CaptureVersion: storage.CaptureVersion1}
		v2 := sqlite.AuditListRow{AuditID: v2ID, StartedAtNS: started - 1, ForwardStatus: sqlite.ForwardCompleted, CaptureVersion: storage.CaptureVersion2, UserAgentEnc: sealed}
		v1Rows, v2Rows, mixed = append(v1Rows, v1), append(v2Rows, v2), append(mixed, v1, v2)
	}
	list := func(rows []sqlite.AuditListRow, filter Filter) ([]string, int64) {
		t.Helper()
		store := &countingHeaderStore{fakeStore: &fakeStore{healthy: true, listPage: sqlite.AuditListPage{Rows: rows}, requestHeaders: headers}}
		service, err := New(store, cipher)
		if err != nil {
			t.Fatal(err)
		}
		page, err := service.List(context.Background(), filter, Cursor{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		var shown []string
		for _, item := range page.Items {
			encoded, _ := json.Marshal(item.UserAgent)
			shown = append(shown, strings.TrimPrefix(strings.TrimPrefix(item.AuditID, "v1-"), "v2-")+"="+string(encoded))
		}
		return shown, store.headerQueries.Load()
	}
	for _, needle := range []string{"", "codex", "CURL", "second", "hidden", "zzz"} {
		filter := Filter{UserAgent: needle}
		v1Shown, v1Queries := list(v1Rows, filter)
		v2Shown, v2Queries := list(v2Rows, filter)
		if !reflect.DeepEqual(v1Shown, v2Shown) {
			t.Fatalf("needle %q: version 1 shows %v, version 2 %v", needle, v1Shown, v2Shown)
		}
		if v1Queries != int64(len(v1Rows)) || v2Queries != 0 {
			t.Fatalf("needle %q: %d queries for %d version 1 rows, %d for version 2 rows", needle, v1Queries, len(v1Rows), v2Queries)
		}
		mixedShown, mixedQueries := list(mixed, filter)
		var want []string
		for index := range v1Shown {
			want = append(want, v1Shown[index], v2Shown[index])
		}
		if !reflect.DeepEqual(mixedShown, want) || mixedQueries != int64(len(v1Rows)) {
			t.Fatalf("needle %q: mixed page %v with %d queries, want %v", needle, mixedShown, mixedQueries, want)
		}
		if needle == "" && !reflect.DeepEqual(v1Shown, []string{`0=null`, `1=""`, `2="Codex-CLI/1.2 Windows"`, `3="curl/8"`, `4="first/1"`, `5=null`}) {
			t.Fatalf("shown = %v", v1Shown)
		}
	}
	// A version 2 row whose user_agent_enc does not open fails the page, as a
	// tampered version 1 value does; an unknown version is refused too.
	tampered := append([]sqlite.AuditListRow(nil), v2Rows[2])
	tampered[0].UserAgentEnc = append([]byte(nil), tampered[0].UserAgentEnc...)
	tampered[0].UserAgentEnc[len(tampered[0].UserAgentEnc)-1] ^= 1
	unknown := append([]sqlite.AuditListRow(nil), v2Rows[2])
	unknown[0].CaptureVersion = 3
	for _, rows := range [][]sqlite.AuditListRow{tampered, unknown} {
		service, err := New(&fakeStore{healthy: true, listPage: sqlite.AuditListPage{Rows: rows}}, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.List(context.Background(), Filter{}, Cursor{}, 10); err != ErrIntegrity {
			t.Fatalf("list = %v", err)
		}
	}
}

// The detail of a version 2 audit carries the same Headers as the same request
// stored as version 1, so every view built on Detail.Headers (the web detail,
// the Agent API and its credential masking, the header export) is the same.
func TestGetExpandsBothCaptureVersions(t *testing.T) {
	t.Parallel()
	cipher := testCipher(t)
	stages := []struct {
		name              string
		headers, trailers http.Header
	}{
		{sqlite.StageRequestReceived, http.Header{"Authorization": {"Bearer secret"}, "User-Agent": {"client/1"}, "X-Multi": {"a", "b"}}, http.Header{"X-Sum": {"1"}}},
		{sqlite.StageResponseReceived, http.Header{"Content-Type": {"text/event-stream"}}, nil},
	}
	uri := func(auditID string) []byte {
		aad, _ := security.AAD(auditID, "request_uri")
		encrypted, err := cipher.Encrypt(aad, []byte("/v1/chat/completions"))
		if err != nil {
			t.Fatal(err)
		}
		return encrypted
	}
	v1 := sqlite.AuditQueryDetail{Audit: sqlite.AuditListRow{AuditID: "audit-v1", CaptureVersion: storage.CaptureVersion1}, RequestURIEnc: uri("audit-v1")}
	v2 := sqlite.AuditQueryDetail{Audit: sqlite.AuditListRow{AuditID: "audit-v2", CaptureVersion: storage.CaptureVersion2}, RequestURIEnc: uri("audit-v2")}
	var sections []headerblock.Stage
	for _, stage := range stages {
		v1.Stages = append(v1.Stages, sqlite.HTTPStage{AuditID: "audit-v1", Stage: stage.name})
		v2.Stages = append(v2.Stages, sqlite.HTTPStage{AuditID: "audit-v2", Stage: stage.name})
		for kind, headers := range map[string]http.Header{sqlite.HeaderKindHeader: stage.headers, sqlite.HeaderKindTrailer: stage.trailers} {
			for _, field := range headerblock.Snapshot(headers) {
				for index, value := range field.Values {
					aad, _ := security.AAD("audit-v1", "header", stage.name, kind, field.Name, strconv.Itoa(index))
					encrypted, err := cipher.Encrypt(aad, value)
					if err != nil {
						t.Fatal(err)
					}
					v1.Headers = append(v1.Headers, sqlite.HeaderEvidence{Stage: stage.name, Kind: kind, Name: field.Name, ValueIndex: index, ValueLength: len(value), ValueEnc: encrypted})
				}
			}
		}
		sections = append(sections, headerblock.Stage{Name: stage.name, Headers: headerblock.Snapshot(stage.headers), Trailers: headerblock.Snapshot(stage.trailers)})
	}
	block, err := headerblock.SealBlock(cipher, "audit-v2", sections)
	if err != nil {
		t.Fatal(err)
	}
	v2.HeaderBlock = &sqlite.HeaderBlockEvidence{Compression: block.Compression, PlaintextLength: block.PlaintextLength, DataEnc: block.DataEnc}
	get := func(detail sqlite.AuditQueryDetail) ([]Header, error) {
		service, err := New(&fakeStore{healthy: true, detail: detail}, cipher)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.Get(context.Background(), detail.Audit.AuditID, nil)
		return result.Headers, err
	}
	v1Headers, err := get(v1)
	if err != nil {
		t.Fatal(err)
	}
	v2Headers, err := get(v2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v1Headers, v2Headers) || len(v2Headers) != 6 {
		t.Fatalf("headers differ:\n v1 %+v\n v2 %+v", v1Headers, v2Headers)
	}
	// A version 2 detail whose block names another stage set, or with header
	// rows beside its block, is an integrity failure.
	short := v2
	short.Stages = append(append([]sqlite.HTTPStage(nil), v2.Stages...), sqlite.HTTPStage{AuditID: "audit-v2", Stage: sqlite.StageResponseSent})
	rows := v2
	rows.Headers = v1.Headers[:1]
	for _, detail := range []sqlite.AuditQueryDetail{short, rows} {
		if _, err := get(detail); err != ErrIntegrity {
			t.Fatalf("Get = %v", err)
		}
	}
}
