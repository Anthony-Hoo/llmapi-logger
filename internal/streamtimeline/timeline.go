// Package streamtimeline encodes logical streaming-event observation points
// without storing event payloads or one SQLite row per token/chunk.
package streamtimeline

import (
	"encoding/binary"
	"errors"
)

const Version = 1

type Point struct {
	Offset int64
	AtNS   int64
}

func Encode(points []Point) ([]byte, error) {
	result := make([]byte, 0, 2+len(points)*8)
	result = append(result, Version)
	result = binary.AppendUvarint(result, uint64(len(points)))
	var previousOffset, previousAt int64
	for index, point := range points {
		if point.Offset <= previousOffset || point.AtNS <= 0 || index > 0 && point.AtNS < previousAt {
			return nil, errors.New("streamtimeline: invalid point order")
		}
		result = binary.AppendUvarint(result, uint64(point.Offset-previousOffset))
		if index == 0 {
			result = binary.AppendUvarint(result, uint64(point.AtNS))
		} else {
			result = binary.AppendUvarint(result, uint64(point.AtNS-previousAt))
		}
		previousOffset = point.Offset
		previousAt = point.AtNS
	}
	return result, nil
}

func Decode(encoded []byte, maximumPoints int) ([]Point, error) {
	if len(encoded) == 0 || encoded[0] != Version || maximumPoints < 0 {
		return nil, errors.New("streamtimeline: invalid encoding")
	}
	encoded = encoded[1:]
	count, read := binary.Uvarint(encoded)
	if read <= 0 || count > uint64(maximumPoints) {
		return nil, errors.New("streamtimeline: invalid point count")
	}
	encoded = encoded[read:]
	result := make([]Point, 0, int(count))
	var previousOffset, previousAt int64
	for index := 0; index < int(count); index++ {
		offsetDelta, consumed := binary.Uvarint(encoded)
		if consumed <= 0 || offsetDelta == 0 {
			return nil, errors.New("streamtimeline: invalid offset delta")
		}
		encoded = encoded[consumed:]
		timeValue, consumed := binary.Uvarint(encoded)
		if consumed <= 0 {
			return nil, errors.New("streamtimeline: invalid time delta")
		}
		encoded = encoded[consumed:]
		offset := previousOffset + int64(offsetDelta)
		at := int64(timeValue)
		if index > 0 {
			at = previousAt + int64(timeValue)
		}
		if at <= 0 || index > 0 && at < previousAt {
			return nil, errors.New("streamtimeline: invalid time order")
		}
		result = append(result, Point{Offset: offset, AtNS: at})
		previousOffset = offset
		previousAt = at
	}
	if len(encoded) != 0 {
		return nil, errors.New("streamtimeline: trailing bytes")
	}
	return result, nil
}
