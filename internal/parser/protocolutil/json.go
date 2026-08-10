package protocolutil

import (
	"encoding/json"
	"strconv"

	base "llmapi-logger/internal/parser"
)

func Object(data []byte) (map[string]any, error) {
	var value map[string]any
	if err := base.DecodeJSON(data, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func Map(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func Slice(value any) []any {
	result, _ := value.([]any)
	return result
}

func String(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func Bool(value any) (*bool, bool) {
	typed, ok := value.(bool)
	if !ok {
		return nil, false
	}
	copy := typed
	return &copy, true
}

func Int64(value any) *int64 {
	var parsed int64
	var err error
	switch typed := value.(type) {
	case json.Number:
		parsed, err = typed.Int64()
	case float64:
		parsed = int64(typed)
		if float64(parsed) != typed {
			return nil
		}
	case int:
		parsed = int64(typed)
	case int64:
		parsed = typed
	default:
		return nil
	}
	if err != nil || parsed < 0 {
		return nil
	}
	return &parsed
}

func Int(value any) *int {
	number := Int64(value)
	if number == nil {
		return nil
	}
	converted := int(*number)
	if int64(converted) != *number {
		return nil
	}
	return &converted
}

func Count(value any) int {
	if values := Slice(value); values != nil {
		return len(values)
	}
	if value != nil {
		return 1
	}
	return 0
}

func ErrorFields(root map[string]any) (string, string) {
	errorObject := Map(root["error"])
	if errorObject == nil {
		return "", ""
	}
	return String(errorObject["type"]), String(errorObject["code"])
}

func MarshalSafe(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func BoolPointer(value bool) *bool {
	copy := value
	return &copy
}

func IntPointer(value int) *int {
	copy := value
	return &copy
}
