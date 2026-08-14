package auditmodel

import (
	"encoding/base64"
	"fmt"
	"strings"
)

type binaryCandidate struct {
	Hash      []byte
	MediaType string
	Data      []byte
}

type transformResult struct {
	Value        any
	BinaryRefs   []BinaryReference
	ExternalRefs []plainExternalReference
}

type plainExternalReference struct {
	JSONPointer string
	Kind        string
	Value       string
}

type binaryAccumulator struct {
	objects map[string]binaryCandidate
}

func newBinaryAccumulator() *binaryAccumulator {
	return &binaryAccumulator{objects: make(map[string]binaryCandidate)}
}

func (accumulator *binaryAccumulator) transform(value any) (transformResult, error) {
	return accumulator.transformAt(value, "")
}

func (accumulator *binaryAccumulator) transformAt(value any, pointer string) (transformResult, error) {
	switch typed := value.(type) {
	case string:
		candidate, marker, ok, err := parseDataURL(typed)
		if err != nil {
			return transformResult{}, err
		}
		if !ok {
			return transformResult{Value: typed}, nil
		}
		accumulator.add(candidate)
		return transformResult{
			Value: marker,
			BinaryRefs: []BinaryReference{{
				JSONPointer: pointer,
				BinaryHash:  append([]byte(nil), candidate.Hash...),
				MediaType:   candidate.MediaType,
				Encoding:    "data_url",
				Header:      marker[BinaryMarkerKey].(map[string]any)["header"].(string),
			}},
		}, nil
	case []any:
		result := transformResult{Value: make([]any, len(typed))}
		output := result.Value.([]any)
		for index, child := range typed {
			transformed, err := accumulator.transformAt(child, pointer+"/"+fmt.Sprintf("%d", index))
			if err != nil {
				return transformResult{}, err
			}
			output[index] = transformed.Value
			result.BinaryRefs = append(result.BinaryRefs, transformed.BinaryRefs...)
			result.ExternalRefs = append(result.ExternalRefs, transformed.ExternalRefs...)
		}
		return result, nil
	case map[string]any:
		result := transformResult{Value: make(map[string]any, len(typed))}
		output := result.Value.(map[string]any)
		for key, child := range typed {
			childPointer := pointer + "/" + escapePointer(key)
			if text, ok := child.(string); ok && isExternalReferenceKey(key) && text != "" {
				result.ExternalRefs = append(result.ExternalRefs, plainExternalReference{
					JSONPointer: childPointer,
					Kind:        key,
					Value:       text,
				})
			}
			if text, ok := child.(string); ok && isInlineFileData(typed, key) {
				candidate, marker, decoded, err := parseInlineFileData(typed, text)
				if err != nil {
					return transformResult{}, err
				}
				if decoded {
					accumulator.add(candidate)
					output[key] = marker
					result.BinaryRefs = append(result.BinaryRefs, BinaryReference{
						JSONPointer: childPointer,
						BinaryHash:  append([]byte(nil), candidate.Hash...),
						MediaType:   candidate.MediaType,
						Encoding:    "base64",
					})
					continue
				}
			}
			transformed, err := accumulator.transformAt(child, childPointer)
			if err != nil {
				return transformResult{}, err
			}
			output[key] = transformed.Value
			result.BinaryRefs = append(result.BinaryRefs, transformed.BinaryRefs...)
			result.ExternalRefs = append(result.ExternalRefs, transformed.ExternalRefs...)
		}
		return result, nil
	default:
		return transformResult{Value: typed}, nil
	}
}

func (accumulator *binaryAccumulator) add(candidate binaryCandidate) {
	key := hashHex(candidate.Hash)
	if _, exists := accumulator.objects[key]; exists {
		return
	}
	accumulator.objects[key] = binaryCandidate{
		Hash:      append([]byte(nil), candidate.Hash...),
		MediaType: candidate.MediaType,
		Data:      append([]byte(nil), candidate.Data...),
	}
}

func parseDataURL(value string) (binaryCandidate, map[string]any, bool, error) {
	if len(value) < 5 || !strings.EqualFold(value[:5], "data:") {
		return binaryCandidate{}, nil, false, nil
	}
	comma := strings.IndexByte(value, ',')
	if comma < 5 {
		return binaryCandidate{}, nil, false, fmt.Errorf("%w: malformed data URL", ErrInvalidModel)
	}
	header := value[5:comma]
	parts := strings.Split(header, ";")
	base64Encoded := false
	for _, part := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(part), "base64") {
			base64Encoded = true
			break
		}
	}
	if !base64Encoded {
		return binaryCandidate{}, nil, false, nil
	}
	mediaType := strings.TrimSpace(parts[0])
	if mediaType == "" {
		mediaType = "text/plain"
	}
	decoded, err := decodeBase64(value[comma+1:])
	if err != nil {
		return binaryCandidate{}, nil, false, fmt.Errorf("%w: invalid data URL base64", ErrInvalidModel)
	}
	hash := BinaryHash(decoded)
	metadata := map[string]any{
		"hash":       hashHex(hash),
		"media_type": mediaType,
		"encoding":   "data_url",
		"header":     header,
	}
	return binaryCandidate{Hash: hash, MediaType: mediaType, Data: decoded}, map[string]any{BinaryMarkerKey: metadata}, true, nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func isExternalReferenceKey(key string) bool {
	switch strings.ToLower(key) {
	case "file_id", "image_file_id", "attachment_id", "asset_id":
		return true
	default:
		return false
	}
}

func isInlineFileData(parent map[string]any, key string) bool {
	lower := strings.ToLower(key)
	if lower != "file_data" && lower != "file_content" && lower != "attachment_data" {
		return false
	}
	typeName, _ := parent["type"].(string)
	typeName = strings.ToLower(typeName)
	return strings.Contains(typeName, "file") || strings.Contains(typeName, "attachment") || typeName == ""
}

func parseInlineFileData(parent map[string]any, value string) (binaryCandidate, map[string]any, bool, error) {
	if len(value) >= 5 && strings.EqualFold(value[:5], "data:") {
		candidate, marker, decoded, err := parseDataURL(value)
		return candidate, marker, decoded, err
	}
	decoded, err := decodeBase64(value)
	if err != nil {
		return binaryCandidate{}, nil, false, fmt.Errorf("%w: invalid inline file base64", ErrInvalidModel)
	}
	mediaType := "application/octet-stream"
	for _, key := range []string{"media_type", "mime_type", "content_type"} {
		if candidate, ok := parent[key].(string); ok && strings.TrimSpace(candidate) != "" {
			mediaType = strings.TrimSpace(candidate)
			break
		}
	}
	hash := BinaryHash(decoded)
	metadata := map[string]any{
		"hash":       hashHex(hash),
		"media_type": mediaType,
		"encoding":   "base64",
	}
	return binaryCandidate{Hash: hash, MediaType: mediaType, Data: decoded}, map[string]any{BinaryMarkerKey: metadata}, true, nil
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func restoreBinaryMarker(marker map[string]any, data []byte) (string, error) {
	encoding, _ := marker["encoding"].(string)
	switch encoding {
	case "data_url":
		header, _ := marker["header"].(string)
		return "data:" + header + "," + base64.StdEncoding.EncodeToString(data), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(data), nil
	default:
		return "", ErrReconstruction
	}
}

// RestoreBinaries replaces binary markers using a caller-provided resolver.
func RestoreBinaries(value any, resolve func(hash []byte) ([]byte, error)) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 1 {
			if rawMarker, exists := typed[BinaryMarkerKey]; exists {
				marker, ok := rawMarker.(map[string]any)
				if !ok {
					return nil, ErrReconstruction
				}
				hashText, _ := marker["hash"].(string)
				hash, err := decodeHexHash(hashText)
				if err != nil {
					return nil, err
				}
				data, err := resolve(hash)
				if err != nil {
					return nil, err
				}
				return restoreBinaryMarker(marker, data)
			}
		}
		for key, child := range typed {
			restored, err := RestoreBinaries(child, resolve)
			if err != nil {
				return nil, err
			}
			typed[key] = restored
		}
		return typed, nil
	case []any:
		for index, child := range typed {
			restored, err := RestoreBinaries(child, resolve)
			if err != nil {
				return nil, err
			}
			typed[index] = restored
		}
		return typed, nil
	default:
		return typed, nil
	}
}

func decodeHexHash(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrReconstruction
	}
	decoded := make([]byte, 32)
	for index := 0; index < len(decoded); index++ {
		high := strings.IndexByte("0123456789abcdef", byte(strings.ToLower(value[index*2 : index*2+1])[0]))
		low := strings.IndexByte("0123456789abcdef", byte(strings.ToLower(value[index*2+1 : index*2+2])[0]))
		if high < 0 || low < 0 {
			return nil, ErrReconstruction
		}
		decoded[index] = byte(high<<4 | low)
	}
	return decoded, nil
}
