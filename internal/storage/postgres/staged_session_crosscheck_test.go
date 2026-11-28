package postgres

// The legacy half of the staged write harness models internal/audit. This
// test pins that model to the real Session: it drives a Session over a
// recording store with the same request and compares the operation stream,
// with times and audit identifiers blanked and ciphertext opened.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/legacyoracle"
	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

type recordingStore struct {
	mu  sync.Mutex
	ops []hOp
}

func (store *recordingStore) add(kind writeKind, data any) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ops = append(store.ops, hOp{kind: kind, data: data, event: -1})
}

func (store *recordingStore) Healthy() bool { return true }
func (store *recordingStore) BeginAudit(_ context.Context, record storage.AuditRecord) error {
	store.add(writeBeginAudit, record)
	return nil
}
func (store *recordingStore) StartStage(_ context.Context, stage storage.HTTPStage) error {
	store.add(writeStartStage, stage)
	return nil
}
func (store *recordingStore) StartBody(_ context.Context, body storage.BodyStream) error {
	store.add(writeStartBody, body)
	return nil
}
func (store *recordingStore) AddHeaders(_ context.Context, headers []storage.HTTPHeader) error {
	if len(headers) != 0 {
		store.add(writeAddHeaders, append([]storage.HTTPHeader(nil), headers...))
	}
	return nil
}
func (store *recordingStore) AddChunk(_ context.Context, chunk storage.BodyChunk) error {
	store.add(writeAddChunk, chunk)
	return nil
}
func (store *recordingStore) FinishStage(_ context.Context, finish storage.StageFinish) error {
	store.add(writeFinishStage, finish)
	return nil
}
func (store *recordingStore) FinishAuditWithResult(_ context.Context, finish storage.AuditFinish) (storage.AuditFinish, error) {
	store.add(writeFinishAudit, finish)
	return finish, nil
}
func (store *recordingStore) InsertAuditGaps(context.Context, []storage.AuditGap) error { return nil }

// The cross-check drives the legacy path only.
func (store *recordingStore) Checkpoint(context.Context, storage.AuditCheckpoint) error {
	return errors.ErrUnsupported
}
func (store *recordingStore) CommitAudit(context.Context, storage.AuditCommit) (storage.AuditFinish, error) {
	return storage.AuditFinish{}, errors.ErrUnsupported
}
func (store *recordingStore) SupportsUnifiedWrite() bool { return false }

type sessionDrive struct {
	request          []byte
	requestRead      int
	requestTrailers  http.Header
	response         []byte
	responseRead     int
	responseHeaders  http.Header
	responseTrailers http.Header
}

// fixedReads returns at most size bytes per Read, then io.EOF on its own.
type fixedReads struct {
	data []byte
	size int
}

func (reader *fixedReads) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := copy(buffer[:min(len(buffer), reader.size)], reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

// driveSession runs one request through a real Session as the proxy does:
// Begin, Rewrite, Transport reading the outbound body, ModifyResponse,
// WriteHeader, the copy loop, CaptureTrailers and Finish.
func driveSession(t *testing.T, cipher security.Cipher, drive sessionDrive) []hOp {
	t.Helper()
	store := &recordingStore{}
	manager, err := audit.NewManager(store, cipher, nil, "available", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inbound := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/v1/chat/completions?trace=x", &fixedReads{data: drive.request, size: drive.requestRead})
	inbound.RequestURI = "/v1/chat/completions?trace=x"
	inbound.ContentLength = int64(len(drive.request))
	inbound.Header = inboundHeaders("application/json")
	inbound.Trailer = drive.requestTrailers
	session, err := manager.Begin(ctx, inbound, routing.Match{RouteID: "openai-chat", Parser: "openai.chat_completions"})
	if err != nil {
		t.Fatal(err)
	}
	outbound := inbound.Clone(ctx)
	outbound.Host = "upstream.example.com"
	outbound.Header = outboundHeaders("application/json")
	outbound.Body = inbound.Body
	outbound.Trailer = drive.requestTrailers
	session.WrapRequestSent(outbound)
	buffer := make([]byte, 64<<10)
	for {
		if _, err := outbound.Body.Read(buffer); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	response := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: drive.responseHeaders.Clone(), ContentLength: -1,
		Body: io.NopCloser(&fixedReads{data: drive.response, size: drive.responseRead}), Trailer: drive.responseTrailers, Request: outbound}
	session.WrapResponseReceived(response)
	writer := session.WrapResponseWriter(httptest.NewRecorder(), inbound)
	for name, values := range response.Header {
		writer.Header()[name] = append([]string(nil), values...)
	}
	writer.WriteHeader(200)
	for {
		count, err := response.Body.Read(buffer)
		if count > 0 {
			if _, err := writer.Write(buffer[:count]); err != nil {
				t.Fatal(err)
			}
		}
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	for name, values := range drive.responseTrailers {
		writer.Header()[name] = values
	}
	writer.CaptureTrailers()
	if err := session.Finish(); err != nil {
		t.Fatal(err)
	}
	return store.ops
}

// normalizeOps blanks times and identifiers and opens ciphertext, leaving
// what the two streams must agree on.
func normalizeOps(t *testing.T, cipher security.Cipher, ops []hOp) []string {
	t.Helper()
	var auditID string
	open := func(blob []byte, parts ...string) string {
		aad, err := security.AAD(parts...)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := cipher.Decrypt(aad, blob)
		if err != nil {
			t.Fatalf("ciphertext under %v does not open", parts[1:])
		}
		return fmt.Sprintf("%q", plaintext)
	}
	result := make([]string, 0, len(ops))
	for _, op := range ops {
		var text string
		switch value := op.data.(type) {
		case storage.AuditRecord:
			auditID = value.AuditID
			text = fmt.Sprintf("begin %s %s %s %s %s uri=%s", value.RouteID, value.Protocol, value.ParserName, value.Method, value.Path,
				open(value.RequestURIEnc, auditID, "request_uri"))
		case storage.HTTPStage:
			value.AuditID, value.StartedAtNS = "", 0
			text = fmt.Sprintf("stage %s %s %s %s %s status=%v length=%v", value.Stage, value.State, value.Proto, value.Method, value.Host,
				derefInt(value.StatusCode), derefInt64(value.ContentLength))
		case []storage.HTTPHeader:
			text = "headers"
			for _, header := range value {
				text += fmt.Sprintf(" %s/%s/%s/%d=%s(%d)", header.Stage, header.Kind, header.Name, header.ValueIndex,
					open(header.ValueEnc, auditID, "header", header.Stage, header.Kind, header.Name, strconv.Itoa(header.ValueIndex)), header.ValueLength)
			}
		case storage.BodyStream:
			value.AuditID = ""
			text = fmt.Sprintf("body %+v", value)
		case storage.BodyChunk:
			encoded := open(value.DataEnc, auditID, "body_chunk_v2", value.Stage, strconv.FormatInt(value.Seq, 10), value.Compression)
			text = fmt.Sprintf("chunk %s seq=%d offset=%d length=%d encoded=%d %s sha=%x", value.Stage, value.Seq, value.Offset,
				value.PlaintextLength, value.EncodedLength, value.Compression, sha256Hex(encoded))
		case storage.StageFinish:
			text = fmt.Sprintf("finish %s %s status=%v length=%v error=%v", value.Stage, value.State, derefInt(value.StatusCode),
				derefInt64(value.ContentLength), derefString(value.ErrorCode))
			if body := value.Body; body != nil {
				text += fmt.Sprintf(" body observed=%d stored=%d sha=%x hash=%v eof=%v %s %s chunks=%d events=%d complete=%v error=%v first=%v",
					body.ObservedLength, body.StoredLength, body.SHA256, body.HashComplete, body.EOFSeen, body.State, body.RetentionState,
					body.ChunkCount, body.StreamEventCount, body.StreamTimelineComplete, derefString(body.ErrorCode), body.FirstObservedAtNS != nil)
				if timeline := body.Timeline; timeline != nil {
					aad, _ := security.AAD(auditID, "stream_timeline_v1", value.Stage, timeline.Compression)
					encoded, err := cipher.Decrypt(aad, timeline.DataEnc)
					if err != nil {
						t.Fatal(err)
					}
					plaintext, err := bodycodec.Decode(encoded, timeline.Compression, int(timeline.PlaintextLength))
					if err != nil {
						t.Fatal(err)
					}
					points, err := streamtimeline.Decode(plaintext, 1<<20)
					if err != nil {
						t.Fatal(err)
					}
					offsets := make([]int64, len(points))
					for index, point := range points {
						offsets[index] = point.Offset
					}
					text += fmt.Sprintf(" timeline events=%d complete=%v offsets=%v", timeline.EventCount, timeline.Complete, offsets)
				}
			}
		case storage.AuditFinish:
			text = fmt.Sprintf("audit %s %s %s status=%v error=%v request=%v ttft=%v", value.ForwardStatus, value.CaptureStatus, value.ParseStatus,
				derefInt(value.StatusCode), derefString(value.ErrorCode), derefString(value.NewAPIRequestID), value.TTFTNS != nil)
		default:
			t.Fatalf("unexpected operation %T", op.data)
		}
		result = append(result, text)
	}
	return result
}

func derefInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func derefInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func derefString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func sha256Hex(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// digestOps keeps long operations (chunk contents) as their digest.
func digestOps(ops []string) []string {
	for index := range ops {
		ops[index] = legacyoracle.Digest(ops[index])
	}
	return ops
}

func frozenLegacySession(t *testing.T, legacy func() []string) []string {
	t.Helper()
	if legacy == nil {
		return legacyoracle.Value[[]string](t, "session", nil)
	}
	ops := legacy()
	return legacyoracle.Value(t, "session", &ops)
}

func TestHarnessLegacyModelMatchesSession(t *testing.T) {
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	trailersHeaders := streamResponseHeaders()
	trailersHeaders.Set("Trailer", "X-Response-Usage")
	cases := []struct {
		scenario string
		drive    sessionDrive
	}{
		{"stream both pairs merged", sessionDrive{request: jsonRequest(600), requestRead: 32 << 10, response: sseResponse(2000), responseRead: 32 << 10,
			responseHeaders: streamResponseHeaders()}},
		{"bodies over one MiB", sessionDrive{request: jsonRequest(5 << 19), requestRead: 32 << 10, response: sseResponse(5 << 19), responseRead: 32 << 10,
			responseHeaders: streamResponseHeaders()}},
		{"request and response trailers", sessionDrive{request: jsonRequest(700), requestRead: 256,
			requestTrailers: http.Header{"X-Request-Checksum": []string{"sum-1"}, "X-Request-Note": []string{"a", "b"}},
			response:        sseResponse(1200), responseRead: 400, responseHeaders: trailersHeaders,
			responseTrailers: http.Header{"X-Response-Usage": []string{"tokens=42"}}}},
	}
	for _, test := range cases {
		t.Run(test.scenario, func(t *testing.T) {
			h := newHarness(t, &harnessClock{now: 1_000_000}, "model")
			h.uri = "/v1/chat/completions?trace=x"
			scenarioByName(t, test.scenario).build(h)
			model := digestOps(normalizeOps(t, cipher, h.legacyOps(sealer)))
			// The real legacy Session's operations, frozen by the legacy
			// oracle: times and audit ids blanked, ciphertext opened.
			session := frozenLegacySession(t, func() []string { return digestOps(normalizeOps(t, cipher, driveSession(t, cipher, test.drive))) })
			if !reflect.DeepEqual(model, session) {
				for index := 0; index < max(len(model), len(session)); index++ {
					var left, right string
					if index < len(model) {
						left = model[index]
					}
					if index < len(session) {
						right = session[index]
					}
					if left != right {
						t.Errorf("operation %d:\n  model   %s\n  session %s", index, left, right)
					}
				}
				t.FailNow()
			}
			if !bytes.Contains([]byte(model[len(model)-1]), []byte("audit completed")) {
				t.Fatalf("unexpected outcome %s", model[len(model)-1])
			}
		})
	}
}
