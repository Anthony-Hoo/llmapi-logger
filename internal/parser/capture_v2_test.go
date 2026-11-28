package parser

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// headerSourceStore answers LoadParserHeaderSource with a fixed source and
// LoadParserStage with fixed stages; nothing else is used.
type headerSourceStore struct {
	Store
	source storage.HeaderSource
	stages map[string]storage.ParserStage
}

func (store *headerSourceStore) LoadParserHeaderSource(context.Context, string, []string) (storage.HeaderSource, error) {
	return store.source, nil
}

func (store *headerSourceStore) LoadParserStage(_ context.Context, _ string, stage string) (storage.ParserStage, error) {
	loaded, ok := store.stages[stage]
	if !ok {
		return storage.ParserStage{}, sql.ErrNoRows
	}
	return loaded, nil
}

func (store *headerSourceStore) ReadParserChunks(context.Context, string, string, int64, int) ([]storage.BodyChunk, error) {
	return nil, nil
}

// The allowlisted inbound headers read from a version 2 block (the whole
// block opened in the process, then filtered) are the headers the version 1
// query selects from the same Headers.
func TestLoadRequestHeadersFromABlockMatchesTheRows(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x61}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	inbound := http.Header{
		"X-Agent-Id":        {"agent-1", "agent-2"},
		"x-agent-id":        {"shadowed"},
		"X-Agent-Parent-Id": {"parent-9"},
		"Authorization":     {"Bearer secret"},
		"User-Agent":        {"client/1"},
	}
	trailers := http.Header{"X-Agent-Id": {"from-trailer"}}
	outbound := http.Header{"X-Agent-Id": {"other-stage"}}
	names := []string{"x-agent-id", " X-AGENT-PARENT-ID ", "x-missing"}
	allowed := map[string]bool{"x-agent-id": true, "x-agent-parent-id": true}

	// Version 1: the rows the stores return, filtered and ordered in SQL by
	// lower-case name and value_index.
	var rows []storage.HeaderEvidence
	for _, field := range headerblock.Snapshot(inbound) {
		if !allowed[strings.ToLower(field.Name)] {
			continue
		}
		for index, value := range field.Values {
			aad, _ := security.AAD("audit-v1", "header", storage.StageRequestReceived, storage.HeaderKindHeader, field.Name, strconv.Itoa(index))
			encrypted, err := cipher.Encrypt(aad, value)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, storage.HeaderEvidence{Stage: storage.StageRequestReceived, Kind: storage.HeaderKindHeader, Name: field.Name,
				ValueIndex: index, ValueLength: len(value), ValueEnc: encrypted})
		}
	}
	sort.SliceStable(rows, func(left, right int) bool {
		if strings.ToLower(rows[left].Name) != strings.ToLower(rows[right].Name) {
			return strings.ToLower(rows[left].Name) < strings.ToLower(rows[right].Name)
		}
		return rows[left].ValueIndex < rows[right].ValueIndex
	})
	block, err := headerblock.SealBlock(cipher, "audit-v2", []headerblock.Stage{
		{Name: storage.StageRequestReceived, Headers: headerblock.Snapshot(inbound), Trailers: headerblock.Snapshot(trailers)},
		{Name: storage.StageRequestSent, Headers: headerblock.Snapshot(outbound)},
	})
	if err != nil {
		t.Fatal(err)
	}
	v1Worker := &Worker{cipher: cipher, store: &headerSourceStore{source: storage.HeaderSource{CaptureVersion: storage.CaptureVersion1, Rows: rows}}}
	v2Worker := &Worker{cipher: cipher, store: &headerSourceStore{source: storage.HeaderSource{CaptureVersion: storage.CaptureVersion2,
		Block:    &storage.HeaderBlockEvidence{Compression: block.Compression, PlaintextLength: block.PlaintextLength, DataEnc: block.DataEnc},
		StageSet: []string{storage.StageRequestReceived, storage.StageRequestSent}}}}
	v1Headers, err := v1Worker.loadRequestHeaders(context.Background(), "audit-v1", names)
	if err != nil {
		t.Fatal(err)
	}
	v2Headers, err := v2Worker.loadRequestHeaders(context.Background(), "audit-v2", names)
	if err != nil {
		t.Fatal(err)
	}
	want := http.Header{"X-Agent-Id": {"agent-1", "agent-1", "agent-2", "agent-2"}, "X-Agent-Parent-Id": {"parent-9"}}
	if !reflect.DeepEqual(v1Headers, v2Headers) || !reflect.DeepEqual(v2Headers, want) {
		t.Fatalf("version 1 %v, version 2 %v, want %v", v1Headers, v2Headers, want)
	}
	// A block that does not match its stage rows yields no headers and an
	// error, which loadInput logs without downgrading the body evidence.
	mismatched := v2Worker.store.(*headerSourceStore)
	mismatched.source.StageSet = []string{storage.StageRequestReceived}
	if headers, err := v2Worker.loadRequestHeaders(context.Background(), "audit-v2", names); err == nil || headers != nil {
		t.Fatalf("mismatched block = %v, %v", headers, err)
	}
}

// A version 2 stage takes its content headers from the stage row and never
// decrypts Header values for them.
func TestLoadBodyUsesTheVersion2ContentColumns(t *testing.T) {
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x62}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	contentType, contentEncoding := "text/event-stream", "identity"
	body := &storage.BodyStream{AuditID: "audit-v2", Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived,
		State: storage.StageStateComplete, HashComplete: true, EOFSeen: true}
	worker := &Worker{cipher: cipher, store: &headerSourceStore{stages: map[string]storage.ParserStage{
		storage.StageResponseReceived: {Body: body, CaptureVersion: storage.CaptureVersion2, ContentType: &contentType, ContentEncoding: &contentEncoding,
			// Rows a version 2 stage never has: if they were read they would
			// fail to decrypt.
			Headers: []storage.HTTPHeader{{Stage: storage.StageResponseReceived, Kind: storage.HeaderKindHeader, Name: "Content-Type", ValueEnc: []byte("x")}}},
	}}}
	source, _, err := worker.loadBody(context.Background(), "audit-v2", storage.StageResponseReceived)
	if err != nil || source.ContentType != contentType || source.ContentEncoding != contentEncoding || !source.Present || !source.Complete {
		t.Fatalf("source = %+v, %v", source, err)
	}
}
