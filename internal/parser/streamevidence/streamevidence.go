// Package streamevidence holds what the stream normalizers share for keeping
// a released SSE response lossless: the decoded events, the comparison that
// decides whether the aggregate already holds an event's value, and the
// residue that keeps whatever it does not.
//
// A stream normalizer folds the events into one aggregate, the provider's
// non-stream response body. Everything an event carries that the aggregate
// cannot give back is kept in the residue, which the envelope stores next to
// the event description. The residue is bounded: a stream whose residue
// exceeds MaxResidueBytes is declined, and its raw body stays.
package streamevidence

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
)

// MaxResidueBytes bounds the canonical JSON of one stream's residue. Past it,
// releasing the raw body would save little and the envelope would grow
// without limit, so the normalizer declines the stream instead.
const MaxResidueBytes = 1 << 20

// ErrResidueTooLarge declines a stream whose residue exceeds MaxResidueBytes.
// It is parser.ErrStreamResidueTooLarge, which the worker can recognise.
var ErrResidueTooLarge = base.ErrStreamResidueTooLarge

// Event is one decoded SSE event. Object is set when Data is a JSON object.
type Event struct {
	Index  int
	Name   string
	Data   []byte
	Object map[string]any
}

// DecodeEvents decodes the data of every event. The error reports a JSON
// object carrying a reserved marker: the aggregate and the residue keep
// provider values verbatim next to the stored markers, so a normalizer must
// refuse such a stream. The events are returned either way, for parsing.
func DecodeEvents(events []base.SSEEvent) ([]Event, error) {
	decoded := make([]Event, len(events))
	var markerErr error
	for index, event := range events {
		decoded[index] = Event{Index: index, Name: event.Event, Data: event.Data}
		var object map[string]any
		if err := auditmodel.DecodeJSON(event.Data, &object); err == nil && object != nil {
			if err := auditmodel.CheckReservedMarkers(object); err != nil && markerErr == nil {
				markerErr = err
			}
			decoded[index].Object = object
		}
	}
	return decoded, markerErr
}

// Equal compares two decoded JSON values.
func Equal(left, right any) bool { return reflect.DeepEqual(left, right) }

// Clone deep-copies a decoded JSON value.
func Clone(value any) any {
	cloned, err := auditmodel.CloneJSON(value)
	if err != nil {
		// Decoded JSON always re-encodes; keep the value rather than lose it.
		return value
	}
	return cloned
}

// Leftover returns the part of an event's value that the aggregate does not
// hold at the same place. held is the aggregate's value there and present
// tells whether the aggregate has that place at all. The rules, applied
// recursively through objects:
//
//   - a value equal to the held one is held;
//   - null is held when the aggregate has the place: null means "not
//     reported yet", and the aggregate keeps the value reported later;
//   - an empty string, array or object is held when the aggregate holds a
//     value of the same JSON type: it is the start value of a field the
//     stream fills later;
//   - two objects are compared key by key, and only differing keys are kept;
//   - anything else is kept whole.
func Leftover(value, held any, present bool) (any, bool) {
	if !present {
		return value, true
	}
	if value == nil || Equal(value, held) {
		return nil, false
	}
	if emptyOfSameType(value, held) {
		return nil, false
	}
	object, objectOK := value.(map[string]any)
	heldObject, heldOK := held.(map[string]any)
	if objectOK && heldOK {
		kept := make(map[string]any)
		for key, child := range object {
			heldChild, exists := heldObject[key]
			if leftover, keep := Leftover(child, heldChild, exists); keep {
				kept[key] = leftover
			}
		}
		if len(kept) == 0 {
			return nil, false
		}
		return kept, true
	}
	return value, true
}

func emptyOfSameType(value, held any) bool {
	switch typed := value.(type) {
	case string:
		_, ok := held.(string)
		return typed == "" && ok
	case []any:
		_, ok := held.([]any)
		return len(typed) == 0 && ok
	case map[string]any:
		_, ok := held.(map[string]any)
		return len(typed) == 0 && ok
	}
	return false
}

// MergeSet folds a later snapshot into dst: every key of src replaces the
// one in dst, except that null does not replace a reported value, and nested
// objects merge key by key.
func MergeSet(dst, src map[string]any) {
	for key, value := range src {
		current, exists := dst[key]
		if value == nil {
			if !exists {
				dst[key] = nil
			}
			continue
		}
		currentObject, currentOK := current.(map[string]any)
		valueObject, valueOK := value.(map[string]any)
		if currentOK && valueOK {
			MergeSet(currentObject, valueObject)
			continue
		}
		dst[key] = Clone(value)
	}
}

// Residue collects what the aggregate does not hold, per event.
type Residue struct {
	objects map[int]map[string]any
	whole   map[int]any
	text    map[int]string
}

// NewResidue returns an empty residue.
func NewResidue() *Residue {
	return &Residue{objects: make(map[int]map[string]any), whole: make(map[int]any), text: make(map[int]string)}
}

// Position names an array element inside a residue path. The residue writes
// arrays as objects keyed by element position, holding only the elements
// with something left over.
func Position(index int) string { return strconv.Itoa(index) }

// Keep records value under path in the residue of event index.
func (residue *Residue) Keep(index int, path []string, value any) {
	if len(path) == 0 {
		return
	}
	if _, whole := residue.whole[index]; whole {
		return
	}
	object := residue.objects[index]
	if object == nil {
		object = make(map[string]any)
		residue.objects[index] = object
	}
	for _, key := range path[:len(path)-1] {
		existing, exists := object[key]
		child, ok := existing.(map[string]any)
		if exists && !ok {
			// A prefix of path is already kept whole, value included.
			return
		}
		if !ok {
			child = make(map[string]any)
			object[key] = child
		}
		object = child
	}
	object[path[len(path)-1]] = Clone(value)
}

// KeepLeftover keeps what Leftover finds of value at path.
func (residue *Residue) KeepLeftover(index int, path []string, value, held any, present bool) {
	if leftover, keep := Leftover(value, held, present); keep {
		residue.Keep(index, path, leftover)
	}
}

// KeepUnknownKeys keeps every key of object that known does not list.
func (residue *Residue) KeepUnknownKeys(index int, path []string, object map[string]any, known ...string) {
	for key, value := range object {
		consumed := false
		for _, name := range known {
			if key == name {
				consumed = true
				break
			}
		}
		if !consumed {
			residue.Keep(index, append(append([]string(nil), path...), key), value)
		}
	}
}

// KeepEvent keeps the whole data of an event the aggregate does not consume:
// its JSON value, or its text when the data is not JSON.
func (residue *Residue) KeepEvent(event Event) {
	delete(residue.objects, event.Index)
	if event.Object != nil {
		residue.whole[event.Index] = Clone(event.Object)
		return
	}
	var value any
	if err := auditmodel.DecodeJSON(event.Data, &value); err == nil {
		residue.whole[event.Index] = value
		return
	}
	residue.text[event.Index] = string(event.Data)
}

// Empty reports whether nothing was kept.
func (residue *Residue) Empty() bool {
	return len(residue.objects) == 0 && len(residue.whole) == 0 && len(residue.text) == 0
}

// Entries returns the residue in its stored form, ordered by event index:
// {"index": i, "data": value} for kept JSON, {"index": i, "text": string}
// for kept non-JSON data. Consecutive events with equal data are folded into
// one entry with "count": n covering events i to i+n-1. The canonical JSON of
// the entries must fit in MaxResidueBytes, and kept text must be UTF-8.
func (residue *Residue) Entries() ([]any, error) {
	indexes := make([]int, 0, len(residue.objects)+len(residue.whole)+len(residue.text))
	for index := range residue.objects {
		indexes = append(indexes, index)
	}
	for index := range residue.whole {
		indexes = append(indexes, index)
	}
	for index := range residue.text {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	entries := make([]any, 0, len(indexes))
	var last map[string]any
	lastIndex := -2
	for _, index := range indexes {
		var entry map[string]any
		if text, ok := residue.text[index]; ok {
			if !utf8.ValidString(text) {
				return nil, fmt.Errorf("streamevidence: event %d data is not UTF-8", index)
			}
			entry = map[string]any{"index": index, "text": text}
		} else if value, ok := residue.whole[index]; ok {
			entry = map[string]any{"index": index, "data": value}
		} else {
			entry = map[string]any{"index": index, "data": residue.objects[index]}
		}
		if last != nil && index == lastIndex+1 && sameKept(last, entry) {
			count := 1
			if value, ok := last["count"].(int); ok {
				count = value
			}
			last["count"] = count + 1
			lastIndex = index
			continue
		}
		entries = append(entries, entry)
		last, lastIndex = entry, index
	}
	value, err := auditmodel.CloneJSON(entries)
	if err != nil {
		return nil, err
	}
	encoded, err := auditmodel.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxResidueBytes {
		return nil, ErrResidueTooLarge
	}
	cloned, _ := value.([]any)
	return cloned, nil
}

func sameKept(left, right map[string]any) bool {
	if _, ok := left["text"]; ok {
		return Equal(left["text"], right["text"]) && right["text"] != nil
	}
	_, rightText := right["text"]
	return !rightText && Equal(left["data"], right["data"])
}

// Int reads a non-negative JSON integer.
func Int(value any) (int, bool) {
	switch typed := value.(type) {
	case interface{ Int64() (int64, error) }:
		parsed, err := typed.Int64()
		if err != nil || parsed < 0 || int64(int(parsed)) != parsed {
			return 0, false
		}
		return int(parsed), true
	case int:
		return typed, typed >= 0
	case float64:
		converted := int(typed)
		return converted, converted >= 0 && float64(converted) == typed
	}
	return 0, false
}
