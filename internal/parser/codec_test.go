package parser

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeJSONUsesNumberAndRejectsTrailingValue(t *testing.T) {
	t.Parallel()

	var value map[string]any
	if err := DecodeJSON([]byte(`{"count":9007199254740993}`), &value); err != nil {
		t.Fatal(err)
	}
	if number, ok := value["count"].(json.Number); !ok || number.String() != "9007199254740993" {
		t.Fatalf("count = %#v", value["count"])
	}
	if err := DecodeJSON([]byte(`{} {}`), &value); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("trailing JSON error = %v", err)
	}
}

func TestDecodeSSESupportsLineEndingsMultilineDataAndEOF(t *testing.T) {
	t.Parallel()

	events, tailClosed := DecodeSSEWithStatus([]byte(": comment\r\nevent: update\r\ndata: first\r\ndata: second\r\n\r\ndata: tail"))
	if len(events) != 2 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Event != "update" || string(events[0].Data) != "first\nsecond" {
		t.Fatalf("first event = %+v", events[0])
	}
	if string(events[1].Data) != "tail" {
		t.Fatalf("EOF event = %+v", events[1])
	}
	if tailClosed {
		t.Fatal("unterminated EOF event reported as closed")
	}

	closedEvents, tailClosed := DecodeSSEWithStatus([]byte("data: closed\ndata: event\n\n"))
	if !tailClosed || len(closedEvents) != 1 || string(closedEvents[0].Data) != "closed\nevent" {
		t.Fatalf("closed events = %+v, tailClosed = %v", closedEvents, tailClosed)
	}
	if compatibility := DecodeSSE([]byte("data: tail")); len(compatibility) != 1 || string(compatibility[0].Data) != "tail" {
		t.Fatalf("DecodeSSE compatibility result = %+v", compatibility)
	}
	if !LooksLikeSSE("text/event-stream; charset=utf-8", nil) || !LooksLikeSSE("application/json", []byte("data: {}\n\n")) {
		t.Fatal("SSE detection failed")
	}
}

func TestDecodeContentIdentityGzipAndLimits(t *testing.T) {
	t.Parallel()

	plain := []byte(`{"ok":true}`)
	decoded, code, err := decodeContent(plain, "identity")
	if err != nil || code != "" || !bytes.Equal(decoded, plain) {
		t.Fatalf("identity = %q, %q, %v", decoded, code, err)
	}

	compressed := gzipBytes(t, plain)
	decoded, code, err = decodeContent(compressed, "gzip")
	if err != nil || code != "" || !bytes.Equal(decoded, plain) {
		t.Fatalf("gzip = %q, %q, %v", decoded, code, err)
	}

	highRatio := gzipBytes(t, bytes.Repeat([]byte("x"), 1<<20))
	_, code, err = decodeContent(highRatio, "gzip")
	if err == nil || code != "gzip_ratio_exceeded" {
		t.Fatalf("high-ratio gzip = code %q, err %v", code, err)
	}

	tooLarge := []byte(strings.Repeat("x", MaxDecodedBodyBytes+1))
	decoded, code, err = decodeContent(tooLarge, "")
	if err == nil || code != "body_too_large" || len(decoded) != MaxDecodedBodyBytes {
		t.Fatalf("large identity = len %d, code %q, err %v", len(decoded), code, err)
	}
	if _, code, err = decodeContent(plain, "br"); err == nil || code != "unsupported_content_encoding" {
		t.Fatalf("unsupported encoding = code %q, err %v", code, err)
	}
}

func gzipBytes(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
