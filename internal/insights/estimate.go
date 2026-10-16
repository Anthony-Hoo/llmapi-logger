package insights

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/gif"  // register decoders for dimension probing
	_ "image/jpeg" // register decoders for dimension probing
	_ "image/png"  // register decoders for dimension probing
	"math/bits"
	"strings"
)

const (
	messageOverheadTokens = 4
	blockOverheadTokens   = 4
	// unknownImageTokens is the conservative OpenAI estimate when the image
	// size is unknown: 85 base plus four 512px tiles.
	unknownOpenAIImageTokens = 85 + 170*4
	lowDetailImageTokens     = 85
	maxAnthropicImageTokens  = 1600
	geminiImageTokens        = 258
	unknownFileTokens        = 1500
	maxFileTokens            = 100000
	probeBytes               = 64 * 1024
)

// textTokens is the dsh-context density heuristic: ceil(bytes/4) plus a fixed
// per-block overhead.
func textTokens(text string) int64 {
	return bytesTokens(len(text)) + blockOverheadTokens
}

func bytesTokens(length int) int64 {
	if length <= 0 {
		return 0
	}
	return int64((length + 3) / 4)
}

// splitDataURL separates "data:<mime>;base64,<payload>" into mime and payload.
// ok is false for any other URL.
func splitDataURL(value string) (mime, payload string, ok bool) {
	if !strings.HasPrefix(value, "data:") {
		return "", "", false
	}
	header, payload, found := strings.Cut(value[len("data:"):], ",")
	if !found {
		return "", "", false
	}
	mime, _, _ = strings.Cut(header, ";")
	return mime, payload, true
}

// base64DecodedLen estimates decoded bytes without decoding.
func base64DecodedLen(payload string) int {
	length := len(payload)
	if length == 0 {
		return 0
	}
	padding := 0
	for index := length - 1; index >= 0 && index >= length-2 && payload[index] == '='; index-- {
		padding++
	}
	decoded := length*3/4 - padding
	if decoded < 0 {
		return 0
	}
	return decoded
}

// imageDimensions probes a base64 payload prefix for width and height.
func imageDimensions(payload string) (width, height int, ok bool) {
	if payload == "" {
		return 0, 0, false
	}
	prefix := payload
	if len(prefix) > probeBytes {
		prefix = prefix[:probeBytes]
	}
	prefix = prefix[:len(prefix)/4*4]
	decoded, err := base64.StdEncoding.DecodeString(prefix)
	if err != nil && len(decoded) == 0 {
		return 0, 0, false
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(decoded))
	if err != nil || config.Width <= 0 || config.Height <= 0 {
		return 0, 0, false
	}
	return config.Width, config.Height, true
}

// openAIImageTokens applies the OpenAI tile formula. Unknown dimensions use a
// conservative four-tile estimate; detail "low" is always 85.
func openAIImageTokens(width, height int, known bool, detail string) int64 {
	if strings.EqualFold(detail, "low") {
		return lowDetailImageTokens
	}
	if !known {
		return unknownOpenAIImageTokens
	}
	w, h := float64(width), float64(height)
	if longest := max(w, h); longest > 2048 {
		scale := 2048 / longest
		w, h = w*scale, h*scale
	}
	if shortest := min(w, h); shortest > 768 {
		scale := 768 / shortest
		w, h = w*scale, h*scale
	}
	tiles := ceilDiv(int(w+0.5), 512) * ceilDiv(int(h+0.5), 512)
	if tiles < 1 {
		tiles = 1
	}
	return int64(lowDetailImageTokens + 170*tiles)
}

func ceilDiv(value, divisor int) int {
	return (value + divisor - 1) / divisor
}

// anthropicImageTokens is width*height/750 capped at 1600; unknown size uses
// the cap.
func anthropicImageTokens(width, height int, known bool) int64 {
	if !known {
		return maxAnthropicImageTokens
	}
	tokens := int64(width) * int64(height) / 750
	if tokens < 1 {
		tokens = 1
	}
	return min(tokens, maxAnthropicImageTokens)
}

// fileTokens estimates a document from its decoded size, capped.
func fileTokens(decodedBytes int, known bool) int64 {
	if !known {
		return unknownFileTokens
	}
	return min(bytesTokens(decodedBytes), maxFileTokens)
}

// Anchor scales an estimate so its categories sum exactly to promptTotal,
// using largest-remainder rounding (ties go to the earlier category). A zero
// estimate or a non-positive promptTotal yields zeros.
func Anchor(estimate CategoryValues, promptTotal int64) CategoryValues {
	values := [8]int64{
		estimate.System, estimate.Tools, estimate.User, estimate.Injected,
		estimate.Assistant, estimate.Reasoning, estimate.ToolResult, estimate.Media,
	}
	var sum uint64
	for index, value := range values {
		if value < 0 {
			values[index] = 0
			continue
		}
		sum += uint64(value)
	}
	if sum == 0 || promptTotal <= 0 {
		return CategoryValues{}
	}
	var result [8]int64
	var remainders [8]uint64
	var assigned int64
	for index, value := range values {
		high, low := bits.Mul64(uint64(value), uint64(promptTotal))
		quotient, remainder := bits.Div64(high, low, sum)
		result[index] = int64(quotient)
		remainders[index] = remainder
		assigned += int64(quotient)
	}
	for left := promptTotal - assigned; left > 0; left-- {
		best := -1
		for index := range remainders {
			if values[index] > 0 && (best < 0 || remainders[index] > remainders[best]) {
				best = index
			}
		}
		result[best]++
		remainders[best] = 0
	}
	return CategoryValues{
		System: result[0], Tools: result[1], User: result[2], Injected: result[3],
		Assistant: result[4], Reasoning: result[5], ToolResult: result[6], Media: result[7],
	}
}

func (values *CategoryValues) add(category string, tokens int64) {
	switch category {
	case CategorySystem:
		values.System += tokens
	case CategoryTools:
		values.Tools += tokens
	case CategoryUser:
		values.User += tokens
	case CategoryInjected:
		values.Injected += tokens
	case CategoryAssistant:
		values.Assistant += tokens
	case CategoryReasoning:
		values.Reasoning += tokens
	case CategoryToolResult:
		values.ToolResult += tokens
	case CategoryMedia:
		values.Media += tokens
	}
}
