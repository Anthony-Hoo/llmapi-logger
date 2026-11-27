// Package headerblock is the version 2 storage format of captured Headers: the
// Header and Trailer values of all stages of one audit in one length-prefixed
// plaintext, compressed and sealed with AES-GCM as a single value, plus the
// separately sealed inbound User-Agent the audit list reads. Expand is the one
// read entry point: it turns either version 1 per-value rows or a version 2
// block into the same flat list. The format is specified in
// doc/design/issue-59-stage3-write-path.md (C.3 to C.8) and documented in
// doc/features/09-security-encryption-and-redaction.md.
package headerblock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"llmapi-logger/internal/storage"
)

// ContentType is the media type the block plaintext is compressed under. It
// is not a known compressed format, so bodycodec gzips blocks of 128 bytes or
// more when that saves at least 32 bytes.
const ContentType = "application/x-llmapi-header-block"

// MaxPlaintextLength bounds the plaintext of one block.
const MaxPlaintextLength = storage.HeaderBlockMaxPlaintextLength

const formatVersion = 0x01

var magic = []byte("LLHB")

// ErrIntegrity reports stored header evidence that does not authenticate or
// does not decode under the strict rules. Messages never contain values.
var ErrIntegrity = errors.New("headerblock: integrity failure")

// Field is one Header name with its values in value_index order.
type Field struct {
	Name   string
	Values [][]byte
}

// Stage is the section of one reached stage. Name is a storage stage
// constant; Headers and Trailers are sorted by name in byte order.
type Stage struct {
	Name     string
	Headers  []Field
	Trailers []Field
}

// Value is one entry of the flat list Expand returns. Kind is
// storage.HeaderKindHeader or storage.HeaderKindTrailer.
type Value struct {
	Stage      string
	Kind       string
	Name       string
	ValueIndex int
	Value      []byte
}

var stageNames = [...]string{
	storage.StageRequestReceived,
	storage.StageRequestSent,
	storage.StageResponseReceived,
	storage.StageResponseSent,
}

// StageCode returns the one-byte code of a stage (1 to 4 in stage order).
func StageCode(stage string) (byte, bool) {
	for index, name := range stageNames {
		if name == stage {
			return byte(index + 1), true
		}
	}
	return 0, false
}

func stageForCode(code byte) (string, bool) {
	if code < 1 || int(code) > len(stageNames) {
		return "", false
	}
	return stageNames[code-1], true
}

// Snapshot deep-copies one Header map into the fields the block stores, with
// the loop legacy uses for per-value rows (addHeadersLocked): names are the
// map keys in sort.Strings order and the values of each are
// headers.Values(name). Values canonicalizes its argument, so a key that is
// not in canonical form reads the canonical key's values; a name that reads no
// values is left out, as legacy writes no row for it.
func Snapshot(headers http.Header) []Field {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]Field, 0, len(names))
	for _, name := range names {
		values := headers.Values(name)
		if len(values) == 0 {
			continue
		}
		copied := make([][]byte, len(values))
		for index, value := range values {
			copied[index] = []byte(value)
		}
		fields = append(fields, Field{Name: name, Values: copied})
	}
	return fields
}

// Encode returns the block plaintext of the given stages. It does not sort:
// stages must be in stage order without repeats, names within one kind
// strictly increasing in byte order, and every name must have a value.
func Encode(stages []Stage) ([]byte, error) {
	size := len(magic) + 1
	previous := byte(0)
	for _, stage := range stages {
		code, ok := StageCode(stage.Name)
		if !ok {
			return nil, fmt.Errorf("headerblock: unknown stage %q", stage.Name)
		}
		if code <= previous {
			return nil, errors.New("headerblock: stages must be in stage order without repeats")
		}
		previous = code
		size++
		for _, fields := range [2][]Field{stage.Headers, stage.Trailers} {
			kindSize, err := kindLength(fields)
			if err != nil {
				return nil, err
			}
			size += kindSize
			if size > MaxPlaintextLength {
				return nil, errors.New("headerblock: block exceeds the plaintext limit")
			}
		}
	}
	plaintext := make([]byte, 0, size)
	plaintext = append(plaintext, magic...)
	plaintext = append(plaintext, formatVersion)
	for _, stage := range stages {
		code, _ := StageCode(stage.Name)
		plaintext = append(plaintext, code)
		plaintext = appendKind(plaintext, stage.Headers)
		plaintext = appendKind(plaintext, stage.Trailers)
	}
	return plaintext, nil
}

// kindLength checks one kind's fields and returns its encoded size. The
// plaintext limit also bounds every count and length to fit a u32.
func kindLength(fields []Field) (int, error) {
	size := 4
	for index, field := range fields {
		if index > 0 && field.Name <= fields[index-1].Name {
			return 0, errors.New("headerblock: names must be strictly increasing in byte order")
		}
		if len(field.Values) == 0 {
			return 0, errors.New("headerblock: a name requires at least one value")
		}
		if len(field.Name) > MaxPlaintextLength || len(field.Values) > MaxPlaintextLength {
			return 0, errors.New("headerblock: block exceeds the plaintext limit")
		}
		size += 4 + len(field.Name) + 4
		for _, value := range field.Values {
			if len(value) > MaxPlaintextLength {
				return 0, errors.New("headerblock: block exceeds the plaintext limit")
			}
			size += 4 + len(value)
		}
		if size > MaxPlaintextLength {
			return 0, errors.New("headerblock: block exceeds the plaintext limit")
		}
	}
	return size, nil
}

func appendKind(plaintext []byte, fields []Field) []byte {
	plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(fields)))
	for _, field := range fields {
		plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(field.Name)))
		plaintext = append(plaintext, field.Name...)
		plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(field.Values)))
		for _, value := range field.Values {
			plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(value)))
			plaintext = append(plaintext, value...)
		}
	}
	return plaintext
}

// Decode parses a block plaintext under every rule Encode enforces, so one
// plaintext has exactly one decoding and Encode(Decode(p)) == p. The returned
// names and values are copies; the caller may clear plaintext afterwards.
func Decode(plaintext []byte) ([]Stage, error) {
	if len(plaintext) > MaxPlaintextLength {
		return nil, fmt.Errorf("%w: block exceeds the plaintext limit", ErrIntegrity)
	}
	if len(plaintext) < len(magic)+1 || !bytes.Equal(plaintext[:len(magic)], magic) {
		return nil, fmt.Errorf("%w: missing block magic", ErrIntegrity)
	}
	if plaintext[len(magic)] != formatVersion {
		return nil, fmt.Errorf("%w: unsupported block version", ErrIntegrity)
	}
	reader := decoder{data: plaintext[len(magic)+1:]}
	stages := make([]Stage, 0, 4)
	previous := byte(0)
	for len(reader.data) > 0 {
		code := reader.data[0]
		reader.data = reader.data[1:]
		name, known := stageForCode(code)
		if !known {
			return nil, decodeError("unknown stage code")
		}
		if code <= previous {
			return nil, decodeError("stage codes not strictly increasing")
		}
		previous = code
		headers, err := reader.kind()
		if err != nil {
			return nil, err
		}
		trailers, err := reader.kind()
		if err != nil {
			return nil, err
		}
		stages = append(stages, Stage{Name: name, Headers: headers, Trailers: trailers})
	}
	return stages, nil
}

type decoder struct{ data []byte }

// Each rejection has its own message so the tests can tell which rule fired.
// The messages never contain block content.
func decodeError(rule string) error {
	return fmt.Errorf("%w: %s", ErrIntegrity, rule)
}

func (reader *decoder) uint32() (int, error) {
	if len(reader.data) < 4 {
		return 0, decodeError("truncated integer")
	}
	value := binary.BigEndian.Uint32(reader.data)
	reader.data = reader.data[4:]
	if value > MaxPlaintextLength {
		return 0, decodeError("integer over the plaintext limit")
	}
	return int(value), nil
}

// bytes reads one length-prefixed string. The length is checked against what
// remains before anything is allocated.
func (reader *decoder) bytes() ([]byte, error) {
	length, err := reader.uint32()
	if err != nil {
		return nil, err
	}
	if length > len(reader.data) {
		return nil, decodeError("length beyond the block")
	}
	value := bytes.Clone(reader.data[:length])
	if value == nil {
		value = []byte{}
	}
	reader.data = reader.data[length:]
	return value, nil
}

func (reader *decoder) kind() ([]Field, error) {
	count, err := reader.uint32()
	if err != nil {
		return nil, err
	}
	// Every name entry takes at least 12 bytes (name length, value count and
	// one value length), so a count beyond that is rejected before the loop.
	if count > len(reader.data)/12 {
		return nil, decodeError("name count beyond the block")
	}
	var fields []Field
	for index := 0; index < count; index++ {
		name, err := reader.bytes()
		if err != nil {
			return nil, err
		}
		if index > 0 && string(name) <= fields[index-1].Name {
			return nil, decodeError("names not strictly increasing")
		}
		valueCount, err := reader.uint32()
		if err != nil {
			return nil, err
		}
		if valueCount == 0 {
			return nil, decodeError("name without values")
		}
		if valueCount > len(reader.data)/4 {
			return nil, decodeError("value count beyond the block")
		}
		values := make([][]byte, 0, valueCount)
		for range valueCount {
			value, err := reader.bytes()
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		fields = append(fields, Field{Name: string(name), Values: values})
	}
	return fields, nil
}

// Flatten lists the values of decoded stages in the fixed order of the flat
// list: stage order, Headers before Trailers, names in byte order, then
// value_index. It is the order of readHeaderEvidence under the "C" collation.
// The values alias the stages' slices.
func Flatten(stages []Stage) []Value {
	var values []Value
	for _, stage := range stages {
		for _, kind := range [2]struct {
			name   string
			fields []Field
		}{{storage.HeaderKindHeader, stage.Headers}, {storage.HeaderKindTrailer, stage.Trailers}} {
			for _, field := range kind.fields {
				for index, value := range field.Values {
					values = append(values, Value{Stage: stage.Name, Kind: kind.name, Name: field.Name, ValueIndex: index, Value: value})
				}
			}
		}
	}
	return values
}

// StageNames returns the stages that have a section, in stage order.
func StageNames(stages []Stage) []string {
	names := make([]string, 0, len(stages))
	for _, stage := range stages {
		names = append(names, stage.Name)
	}
	return names
}

// CheckStageSet enforces the invariant of a stored block, complete or not: the
// stages that have a section are exactly the stages that have an http_stages
// row. stageSet may be in any order but must not repeat a stage.
func CheckStageSet(stages []Stage, stageSet []string) error {
	want := make(map[string]bool, len(stageSet))
	for _, name := range stageSet {
		if _, ok := StageCode(name); !ok || want[name] {
			return fmt.Errorf("%w: invalid stage set", ErrIntegrity)
		}
		want[name] = true
	}
	if len(stages) != len(want) {
		return fmt.Errorf("%w: block stages differ from stage rows", ErrIntegrity)
	}
	for _, stage := range stages {
		if !want[stage.Name] {
			return fmt.Errorf("%w: block stages differ from stage rows", ErrIntegrity)
		}
	}
	return nil
}
