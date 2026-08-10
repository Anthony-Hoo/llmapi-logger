package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
)

var ErrTrailingJSON = errors.New("parser: trailing JSON value")

// DecodeJSON decodes one JSON value with UseNumber and rejects trailing values.
func DecodeJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("parser: inspect trailing JSON: %w", err)
	}
	return ErrTrailingJSON
}

// SSEEvent is one event assembled from event/data fields. Multiple data lines
// are joined with a single LF as required by the SSE format.
type SSEEvent struct {
	Event string
	Data  []byte
}

// DecodeSSE handles LF, CRLF, CR, comments, cross-chunk lines represented in
// the reconstructed body, and multi-line data. It preserves an unterminated
// tail event for callers that only need best-effort extraction. Call
// DecodeSSEWithStatus when the distinction matters.
func DecodeSSE(data []byte) []SSEEvent {
	events, _ := DecodeSSEWithStatus(data)
	return events
}

// DecodeSSEWithStatus returns assembled events and whether every data-bearing
// event was terminated by an empty line. An unterminated tail event is still
// returned so protocol parsers can keep trusted fields while marking the
// result partial.
func DecodeSSEWithStatus(data []byte) ([]SSEEvent, bool) {
	lines := splitSSELines(data)
	events := make([]SSEEvent, 0)
	eventName := ""
	dataLines := make([]string, 0, 1)
	dispatch := func() {
		if len(dataLines) == 0 {
			eventName = ""
			return
		}
		events = append(events, SSEEvent{Event: eventName, Data: []byte(strings.Join(dataLines, "\n"))})
		eventName = ""
		dataLines = dataLines[:0]
	}

	for _, line := range lines {
		if line == "" {
			dispatch()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			value = ""
		}
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		switch field {
		case "event":
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	tailClosed := len(dataLines) == 0
	dispatch()
	return events, tailClosed
}

// LooksLikeSSE uses Content-Type first and a conservative body prefix fallback.
func LooksLikeSSE(contentType string, data []byte) bool {
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil && strings.EqualFold(mediaType, "text/event-stream") {
		return true
	}
	prefix := strings.TrimSpace(string(data[:min(len(data), 128)]))
	return strings.HasPrefix(prefix, "data:") || strings.HasPrefix(prefix, "event:") || strings.HasPrefix(prefix, ":")
}

func splitSSELines(data []byte) []string {
	lines := make([]string, 0, bytes.Count(data, []byte{'\n'})+1)
	start := 0
	for index := 0; index < len(data); index++ {
		if data[index] != '\n' && data[index] != '\r' {
			continue
		}
		lines = append(lines, string(data[start:index]))
		if data[index] == '\r' && index+1 < len(data) && data[index+1] == '\n' {
			index++
		}
		start = index + 1
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}
