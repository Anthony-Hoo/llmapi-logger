package streamevidence

import (
	"crypto/sha256"
	"encoding/hex"

	base "llmapi-logger/internal/parser"
)

// eventsHashDomain separates the stream event hash from every other hash.
const eventsHashDomain = "llmapi-logger/sse-events/v1\x00"

// EventsHash binds the order, names and data bytes of decoded SSE events:
//
//	SHA-256("llmapi-logger/sse-events/v1\x00" ||
//	        for each event in order:
//	            uint64be(len(name)) || name || uint64be(len(data)) || data)
//
// name is the event field (empty when the event had none) and data the data
// lines joined by LF, both as bytes, as parser.DecodeSSEWithStatus yields
// them. Lengths are byte counts in eight-byte big-endian form.
func EventsHash(events []base.SSEEvent) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(eventsHashDomain))
	var length [8]byte
	for _, event := range events {
		putUint64(length[:], uint64(len(event.Event)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(event.Event))
		putUint64(length[:], uint64(len(event.Data)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(event.Data)
	}
	return digest.Sum(nil)
}

// Describe returns the compact description of a stream's events:
//
//	{"names": [[name, count], ...], "data_lengths": [n, ...], "sha256": hex}
//
// names is the run-length encoding of the event names in order, each run a
// name and how many consecutive events carry it; data_lengths is the byte
// length of every event's data in order; sha256 is EventsHash in lowercase
// hex.
func Describe(events []base.SSEEvent) map[string]any {
	names := make([]any, 0)
	lengths := make([]any, 0, len(events))
	for index, event := range events {
		if index > 0 && events[index-1].Event == event.Event {
			run := names[len(names)-1].([]any)
			run[1] = run[1].(int) + 1
		} else {
			names = append(names, []any{event.Event, 1})
		}
		lengths = append(lengths, len(event.Data))
	}
	return map[string]any{
		"names":        names,
		"data_lengths": lengths,
		"sha256":       hex.EncodeToString(EventsHash(events)),
	}
}

func putUint64(destination []byte, value uint64) {
	for index := 7; index >= 0; index-- {
		destination[index] = byte(value)
		value >>= 8
	}
}
