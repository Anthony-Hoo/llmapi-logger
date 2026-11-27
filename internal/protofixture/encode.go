package protofixture

import (
	"bytes"
	"encoding/json"
)

// object is a JSON object that keeps its keys in insertion order, so the
// generated bodies list fields in the order providers and clients send them.
type object []field

type field struct {
	key   string
	value any
}

func obj(pairs ...any) object {
	result := make(object, 0, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		result = append(result, field{key: pairs[index].(string), value: pairs[index+1]})
	}
	return result
}

func (value object) with(key string, item any) object {
	return append(value, field{key: key, value: item})
}

func (value object) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, entry := range value {
		if index > 0 {
			buffer.WriteByte(',')
		}
		key, err := json.Marshal(entry.key)
		if err != nil {
			return nil, err
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		encoded, err := marshal(entry.value)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// marshal encodes without HTML escaping, as provider SDKs do.
func marshal(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

// mustJSON encodes generated values, which are always encodable.
func mustJSON(value any) []byte {
	encoded, err := marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

// jsonString encodes value as a JSON document string, the form tool
// arguments take inside OpenAI bodies.
func jsonString(value any) string { return string(mustJSON(value)) }
