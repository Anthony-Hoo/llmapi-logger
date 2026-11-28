package postgres

// The legacy half of the staged write harness models the legacy session of
// internal/audit, which no longer exists. This test pins that model to the
// operation stream the real legacy Session produced, frozen by the legacy
// oracle, with times and audit identifiers blanked and ciphertext opened.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"testing"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/legacyoracle"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

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

// TestHarnessLegacyModelMatchesSession pins the harness's model of the
// legacy session to what the real legacy Session wrote for the same request
// (Begin, Rewrite, Transport reading the outbound body, ModifyResponse,
// WriteHeader, the copy loop, CaptureTrailers and Finish over a recording
// store). That session is gone; its operation stream was frozen by the
// legacy oracle (internal/legacyoracle) with times and audit ids blanked,
// ciphertext opened and long operations kept as their digest.
func TestHarnessLegacyModelMatchesSession(t *testing.T) {
	cipher := harnessCipher(t)
	sealer := harnessSealer{t: t, cipher: cipher}
	for _, scenario := range []string{"stream both pairs merged", "bodies over one MiB", "request and response trailers"} {
		t.Run(scenario, func(t *testing.T) {
			h := newHarness(t, &harnessClock{now: 1_000_000}, "model")
			h.uri = "/v1/chat/completions?trace=x"
			scenarioByName(t, scenario).build(h)
			model := digestOps(normalizeOps(t, cipher, h.legacyOps(sealer)))
			session := legacyoracle.Value[[]string](t, "session", nil)
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
