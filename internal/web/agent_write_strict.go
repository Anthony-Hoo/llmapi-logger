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
	path, err := duplicateKeyIn(decoder, "")
	if err != nil || path == "" {
		return nil
	}
	return validationFailure(agentapi.CodeInvalidArgument, path, reasonDuplicateKey,
		"the key "+strconv.Quote(lastSegment(path))+" appears more than once in one JSON object; give each field once")
}

// duplicateKeyIn reads one JSON value and returns the path of the first key
// repeated inside one of its objects, "" when there is none.
func duplicateKeyIn(decoder *json.Decoder, path string) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return "", nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return "", err
			}
			key, _ := keyToken.(string)
			child := joinPath(path, key)
			if seen[key] {
				return child, nil
			}
			seen[key] = true
			if found, err := duplicateKeyIn(decoder, child); err != nil || found != "" {
				return found, err
			}
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if found, err := duplicateKeyIn(decoder, path+"["+strconv.Itoa(index)+"]"); err != nil || found != "" {
				return found, err
			}
		}
	default:
		return "", errors.New("unexpected delimiter")
	}
	_, err = decoder.Token()
	return "", err
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
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
	if path := inexactKey(value, target, prefix); path != "" {
		return validationFailure(agentapi.CodeInvalidArgument, path, reasonUnknownField,
			"unknown field "+strconv.Quote(lastSegment(path))+": field names are matched exactly, with their case")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// inexactKey returns the path of the first key of value that names no field
// of target exactly, "" when every key does.
func inexactKey(value any, target reflect.Type, path string) string {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == rawMessageType {
		return ""
	}
	switch typed := value.(type) {
	case map[string]any:
		switch target.Kind() {
		case reflect.Struct:
			fields := exactJSONFields(target)
			for _, key := range sortedKeys(typed) {
				field, ok := fields[key]
				child := joinPath(path, key)
				if !ok {
					return child
				}
				if found := inexactKey(typed[key], field, child); found != "" {
					return found
				}
			}
		case reflect.Map:
			for _, key := range sortedKeys(typed) {
				if found := inexactKey(typed[key], target.Elem(), joinPath(path, key)); found != "" {
					return found
				}
			}
		}
	case []any:
		if target.Kind() == reflect.Slice || target.Kind() == reflect.Array {
			for index, element := range typed {
				if found := inexactKey(element, target.Elem(), path+"["+strconv.Itoa(index)+"]"); found != "" {
					return found
				}
			}
		}
	}
	return ""
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
