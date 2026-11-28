package gemini

import (
	"errors"
	"sort"
	"strings"

	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
	"llmapi-logger/internal/parser/streamevidence"
)

// A Gemini stream has one event type: every event's data is a
// GenerateContentResponse chunk (the same object a non-stream call returns,
// carrying a piece of the answer). These lists name the fields the stream
// fold reads at each level of a chunk; any other field is kept in the
// residue. Every listed field except candidates and content is a snapshot:
// the folded body keeps the last reported value, and an earlier value it
// replaced is kept in the residue with the chunk that sent it. A part is
// read whole: see foldParts.
var (
	ConsumedChunkFields     = []string{"candidates", "usageMetadata", "modelVersion", "responseId", "createTime", "promptFeedback", "modelStatus", "error"}
	ConsumedCandidateFields = []string{"index", "content", "finishReason", "finishMessage", "safetyRatings", "citationMetadata", "tokenCount",
		"groundingAttributions", "groundingMetadata", "avgLogprobs", "logprobsResult", "urlContextMetadata", "continuationToken"}
	ConsumedContentFields = []string{"role", "parts"}
)

// chunkSnapshotFields and candidateSnapshotFields are the snapshot fields:
// everything consumed except the nested objects the fold builds itself.
var (
	chunkSnapshotFields     = without(ConsumedChunkFields, "candidates")
	candidateSnapshotFields = without(ConsumedCandidateFields, "content")
)

// textPartFields are the keys a text part may carry and still be joined with
// its neighbour: a part with any other key is kept as it came.
var textPartFields = []string{"text", "thought", "thoughtSignature"}

// streamFold is a Gemini stream folded into the non-stream response body.
type streamFold struct {
	body    map[string]any
	residue *streamevidence.Residue
	// stopReason is the last finish reason reported, read the way the
	// insights stop mapping reads the raw stream: per chunk the first
	// candidate with a reason, the last such chunk winning.
	stopReason string
	// candidates counts the candidates the stream started and finished how
	// many of them reported a finish reason.
	candidates, finished int
	// blocked is set by a prompt block reason, errored by an error object.
	blocked, errored bool
	// problem is why the stream cannot be stored without its raw body; the
	// body is still usable for display.
	problem error
}

type candidateFold struct {
	value   map[string]any
	content map[string]any
	parts   []any
	// hasContent and hasParts tell whether any chunk sent a content object
	// and a parts array for this candidate.
	hasContent, hasParts bool
	finished             bool
}

// complete reports whether the stream ended the way a Gemini stream ends:
// every candidate it started reported a finish reason (STOP, MAX_TOKENS,
// SAFETY, MALFORMED_FUNCTION_CALL, ...; a function call ends with STOP), or
// the prompt was blocked, which answers with promptFeedback.blockReason and
// no candidates. A stream that stops cleanly between two chunks has neither.
// An error object also ends the stream, but not with an answer; the parser
// reports it as partial.
func (fold streamFold) complete() bool {
	return fold.errored || fold.blocked || (fold.candidates > 0 && fold.finished == fold.candidates)
}

// foldStream folds decoded Gemini chunks into the non-stream body:
// snapshot fields keep their last reported value, candidates are keyed by
// index (their position when a chunk sends none), and each candidate's parts
// are appended in order, adjacent text pieces joined (see foldParts).
func foldStream(events []base.SSEEvent) streamFold {
	decoded, markerErr := streamevidence.DecodeEvents(events)
	fold := foldDecoded(decoded)
	if fold.problem == nil {
		fold.problem = markerErr
	}
	return fold
}

func foldDecoded(decoded []streamevidence.Event) streamFold {
	fold := streamFold{body: map[string]any{}, residue: streamevidence.NewResidue()}
	candidates := make(map[int]*candidateFold)
	candidate := func(index int) *candidateFold {
		if candidates[index] == nil {
			candidates[index] = &candidateFold{value: map[string]any{}, content: map[string]any{}}
		}
		return candidates[index]
	}
	sawCandidates := false

	for _, event := range decoded {
		root := event.Object
		if root == nil {
			fold.residue.KeepEvent(event)
			continue
		}
		fold.residue.KeepUnknownKeys(event.Index, nil, root, ConsumedChunkFields...)
		for _, key := range chunkSnapshotFields {
			if value, exists := root[key]; exists {
				setReported(fold.body, key, value)
			}
		}
		if reason := protocolutil.String(protocolutil.Map(root["promptFeedback"])["blockReason"]); reason != "" && reason != "BLOCK_REASON_UNSPECIFIED" {
			fold.blocked = true
		}
		if protocolutil.Map(root["error"]) != nil {
			fold.errored = true
		}
		values, isArray := root["candidates"].([]any)
		if root["candidates"] != nil && !isArray {
			fold.residue.Keep(event.Index, []string{"candidates"}, root["candidates"])
			continue
		}
		sawCandidates = sawCandidates || isArray
		stop := ""
		for position, value := range values {
			path := []string{"candidates", streamevidence.Position(position)}
			object := protocolutil.Map(value)
			if object == nil {
				fold.residue.Keep(event.Index, path, value)
				continue
			}
			target := candidate(candidateIndex(object, position))
			fold.residue.KeepUnknownKeys(event.Index, path, object, ConsumedCandidateFields...)
			for _, key := range candidateSnapshotFields {
				if value, exists := object[key]; exists {
					setReported(target.value, key, value)
				}
			}
			if reason := finishReason(object); reason != "" {
				target.finished = true
				if stop == "" {
					stop = reason
				}
			}
			value, exists := object["content"]
			if !exists {
				continue
			}
			contentPath := append(append([]string(nil), path...), "content")
			content := protocolutil.Map(value)
			if content == nil {
				fold.residue.Keep(event.Index, contentPath, value)
				continue
			}
			target.hasContent = true
			fold.residue.KeepUnknownKeys(event.Index, contentPath, content, ConsumedContentFields...)
			if role, exists := content["role"]; exists {
				setReported(target.content, "role", role)
			}
			if parts, exists := content["parts"]; exists {
				pieces, ok := parts.([]any)
				if !ok {
					fold.residue.Keep(event.Index, append(contentPath, "parts"), parts)
					continue
				}
				target.hasParts = true
				target.parts = foldParts(target.parts, pieces)
			}
		}
		if stop != "" {
			fold.stopReason = stop
		}
	}

	indexes := make([]int, 0, len(candidates))
	for index := range candidates {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	built := make([]any, 0, len(indexes))
	for _, index := range indexes {
		target := candidates[index]
		fold.candidates++
		if target.finished {
			fold.finished++
		}
		if target.hasContent {
			if target.hasParts {
				target.content["parts"] = target.parts
			}
			target.value["content"] = target.content
		}
		built = append(built, target.value)
	}
	if sawCandidates {
		fold.body["candidates"] = built
	}

	// Values a later chunk replaced are kept with the chunk that sent them.
	for _, event := range decoded {
		root := event.Object
		if root == nil {
			continue
		}
		for _, key := range chunkSnapshotFields {
			if value, exists := root[key]; exists {
				held, present := fold.body[key]
				fold.residue.KeepLeftover(event.Index, []string{key}, value, held, present)
			}
		}
		for position, value := range protocolutil.Slice(root["candidates"]) {
			object := protocolutil.Map(value)
			if object == nil {
				continue
			}
			path := []string{"candidates", streamevidence.Position(position)}
			target := candidates[candidateIndex(object, position)]
			for _, key := range candidateSnapshotFields {
				if value, exists := object[key]; exists {
					held, present := target.value[key]
					fold.residue.KeepLeftover(event.Index, append(append([]string(nil), path...), key), value, held, present)
				}
			}
			if role, exists := protocolutil.Map(object["content"])["role"]; exists {
				held, present := target.content["role"]
				fold.residue.KeepLeftover(event.Index, append(append([]string(nil), path...), "content", "role"), role, held, present)
			}
		}
	}
	return fold
}

// foldParts appends the parts of one chunk. A text part joins the part
// before it when both carry only text, thought and thoughtSignature, their
// thought fields are the same (both absent or equal), and the new piece has
// no thoughtSignature: the text is concatenated, as the non-stream body
// holds the answer's text in one part. A piece with a thoughtSignature starts
// a new part, so the signature stays on the piece that carried it; the text
// that follows joins that part. Every other part (function calls included,
// so the tool call count is the one the chunks give) is kept as it came.
func foldParts(parts []any, pieces []any) []any {
	for _, value := range pieces {
		piece := protocolutil.Map(value)
		if len(parts) > 0 && piece != nil && textPart(piece) {
			if _, signed := piece["thoughtSignature"]; !signed {
				if last := protocolutil.Map(parts[len(parts)-1]); last != nil && textPart(last) && sameThought(last, piece) {
					last["text"] = last["text"].(string) + piece["text"].(string)
					continue
				}
			}
		}
		parts = append(parts, streamevidence.Clone(value))
	}
	return parts
}

func textPart(part map[string]any) bool {
	if _, ok := part["text"].(string); !ok {
		return false
	}
	for key := range part {
		known := false
		for _, name := range textPartFields {
			known = known || key == name
		}
		if !known {
			return false
		}
	}
	return true
}

func sameThought(left, right map[string]any) bool {
	leftValue, leftExists := left["thought"]
	rightValue, rightExists := right["thought"]
	return leftExists == rightExists && streamevidence.Equal(leftValue, rightValue)
}

// candidateIndex is the candidate's index, or its position in the chunk when
// it sends none.
func candidateIndex(candidate map[string]any, position int) int {
	if index, ok := streamevidence.Int(candidate["index"]); ok && candidate["index"] != nil {
		return index
	}
	return position
}

// finishReason is a candidate's reported finish reason, ignoring the unused
// FINISH_REASON_UNSPECIFIED default.
func finishReason(candidate map[string]any) string {
	reason := protocolutil.String(candidate["finishReason"])
	if strings.EqualFold(strings.TrimSpace(reason), "FINISH_REASON_UNSPECIFIED") {
		return ""
	}
	return reason
}

// setReported sets a later reported value; null does not replace one.
func setReported(target map[string]any, key string, value any) {
	if value == nil {
		if _, exists := target[key]; exists {
			return
		}
	}
	target[key] = streamevidence.Clone(value)
}

func without(values []string, drop string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != drop {
			result = append(result, value)
		}
	}
	return result
}

// arrayEvents turns the elements of a JSON array stream into the events an
// equivalent SSE stream carries.
func arrayEvents(data []byte) ([]base.SSEEvent, error) {
	var elements []rawElement
	if err := base.DecodeJSON(data, &elements); err != nil {
		return nil, err
	}
	if len(elements) == 0 {
		return nil, errEmptyArray
	}
	events := make([]base.SSEEvent, len(elements))
	for index, element := range elements {
		events[index] = base.SSEEvent{Data: element}
	}
	return events, nil
}

var (
	errEmptySSE   = errors.New("gemini parser: empty SSE")
	errEmptyArray = errors.New("gemini parser: empty JSON array stream")
)
