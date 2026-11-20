package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"llmapi-logger/internal/agentapi"
)

// Strict decoding of write input (contract section 0.1 item 132).
// encoding/json matches object keys to struct fields without regard to case
// and lets the last of two equal keys win, so {"pattern_untrusted": "a",
// "Pattern": "b"} reached a project rule as two spellings of one field, and
// {"name": "x", "name": "y"} silently became "y". Write input is therefore
// read twice over: once for duplicate keys in any object at any depth, and
// once, against the Go type a value is decoded into, for keys that do not
// name a field exactly.

// Reasons of the refusals of this file.
const (
	reasonDuplicateKey = "duplicate_key"
	reasonUnknownField = "unknown_field"
)

// checkDuplicateKeys refuses a JSON document in which some object names a
// key twice, naming the key's path ("set.name", "args.labels[3].task_type").
// A document that is not valid JSON is left to the decoder.
func checkDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var path keyPath
	found, err := duplicateKeyIn(decoder, &path)
	if err != nil || !found {
		return nil
	}
	field := path.String()
	return validationFailure(agentapi.CodeInvalidArgument, field, reasonDuplicateKey,
		"the key "+strconv.Quote(lastSegment(field))+" appears more than once in one JSON object; give each field once")
}

// keyPath is the path to a value as a stack of segments: a key, or an array
// index when key is unset. Its text is built only for a refusal, so checking
// a document costs memory linear in its size whatever its depth (contract
// section 0.1 item 163).
type keyPath []pathSegment

type pathSegment struct {
	key   string
	index int
	isKey bool
}

func (path *keyPath) pushKey(key string)  { *path = append(*path, pathSegment{key: key, isKey: true}) }
func (path *keyPath) pushIndex(index int) { *path = append(*path, pathSegment{index: index}) }
func (path *keyPath) pop()                { *path = (*path)[:len(*path)-1] }

// String is the path as errors name it ("set.name", "args.labels[3].task_type").
func (path keyPath) String() string {
	var builder strings.Builder
	for _, segment := range path {
		if !segment.isKey {
			builder.WriteString("[" + strconv.Itoa(segment.index) + "]")
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('.')
		}
		builder.WriteString(segment.key)
	}
	return builder.String()
}

// duplicateKeyIn reads one JSON value and reports whether a key is repeated
// inside one of its objects; path then ends with that key.
func duplicateKeyIn(decoder *json.Decoder, path *keyPath) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, _ := keyToken.(string)
			path.pushKey(key)
			if seen[key] {
				return true, nil
			}
			seen[key] = true
			if found, err := duplicateKeyIn(decoder, path); err != nil || found {
				return found, err
			}
			path.pop()
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			path.pushIndex(index)
			if found, err := duplicateKeyIn(decoder, path); err != nil || found {
				return found, err
			}
			path.pop()
		}
	default:
		return false, errors.New("unexpected delimiter")
	}
	_, err = decoder.Token()
	return false, err
}

func lastSegment(path string) string {
	if index := strings.LastIndexAny(path, ".]"); index >= 0 && index+1 < len(path) {
		return path[index+1:]
	}
	return path
}

// checkExactKeys refuses a key of a JSON object that does not name a field
// of the Go type the object is decoded into exactly, with its case, at any
// depth (struct fields, slice and array elements, map values). prefix is the
// path the error names the key under ("rules" gives "rules[0].Pattern").
func checkExactKeys(data []byte, target reflect.Type, prefix string) error {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil // the decoder reports it
	}
	var path keyPath
	if prefix != "" {
		path.pushKey(prefix)
	}
	if inexactKey(value, target, &path) {
		field := path.String()
		return validationFailure(agentapi.CodeInvalidArgument, field, reasonUnknownField,
			"unknown field "+strconv.Quote(lastSegment(field))+": field names are matched exactly, with their case")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// inexactKey reports whether some key of value names no field of target
// exactly; path then ends with that key.
func inexactKey(value any, target reflect.Type, path *keyPath) bool {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == rawMessageType {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		switch target.Kind() {
		case reflect.Struct:
			fields := exactJSONFields(target)
			for _, key := range sortedKeys(typed) {
				field, ok := fields[key]
				path.pushKey(key)
				if !ok || inexactKey(typed[key], field, path) {
					return true
				}
				path.pop()
			}
		case reflect.Map:
			for _, key := range sortedKeys(typed) {
				path.pushKey(key)
				if inexactKey(typed[key], target.Elem(), path) {
					return true
				}
				path.pop()
			}
		}
	case []any:
		if target.Kind() == reflect.Slice || target.Kind() == reflect.Array {
			for index, element := range typed {
				path.pushIndex(index)
				if inexactKey(element, target.Elem(), path) {
					return true
				}
				path.pop()
			}
		}
	}
	return false
}

// exactJSONFields maps the exact JSON names of a struct's fields, the fields of
// embedded structs included as encoding/json promotes them, to their types.
func exactJSONFields(target reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				for promoted, fieldType := range exactJSONFields(embedded) {
					if _, shadowed := fields[promoted]; !shadowed {
						fields[promoted] = fieldType
					}
				}
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// readStrictJSON decodes data into target refusing unknown fields, fields
// spelled with another case and trailing data. prefix names the keys in an
// error.
func readStrictJSON(data []byte, target any, prefix string) error {
	if err := checkExactKeys(data, reflect.TypeOf(target), prefix); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}
