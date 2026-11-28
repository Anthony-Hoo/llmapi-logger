package gemini

import (
	"context"
	"errors"
	"fmt"

	"llmapi-logger/internal/auditmodel"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/protocolutil"
	"llmapi-logger/internal/parser/streamevidence"
)

// NormalizeAudit splits a GenerateContent request and response into
// envelopes and content-addressed items. A client resends the whole history
// in contents on every call, so each Content is one item, and a candidate's
// content is stored as the same object: when the client resends the answer
// verbatim, the next request refers to the object this response stored.
//
// Gemini requests carry no conversation identifier (the API has none, and
// cachedContent names a context cache any request may share), so the turn
// has no conversation key and its parent is inferred from repeated content.
func (implementation *Parser) NormalizeAudit(_ context.Context, input base.Input, result base.Result) (auditmodel.Turn, error) {
	if implementation == nil {
		return auditmodel.Turn{}, errors.New("gemini normalizer: nil parser")
	}
	turn := auditmodel.Turn{
		AuditID:        input.AuditID,
		Protocol:       input.Protocol,
		ParserName:     implementation.name,
		ResponseID:     result.ResponseID,
		RequestLayout:  auditmodel.LayoutNone,
		ResponseLayout: auditmodel.LayoutNone,
		// GenerateContent has no file_data convention; a function argument
		// with such a name is ordinary text. Its inline parts are
		// inlineData objects instead.
		SkipInlineFileData: true,
		InlineDataParts:    true,
	}
	if input.Request.Present {
		root, err := decodeRoot(input.Request.Data, "request")
		if err != nil {
			return auditmodel.Turn{}, err
		}
		request, err := normalizeRequest(root)
		if err != nil {
			return auditmodel.Turn{}, err
		}
		turn.RequestLayout = request.layout
		turn.RequestEnvelope = request.envelope
		turn.RequestItems = request.items
		turn.RequestOriginal = request.original
	}
	if input.Response.Present {
		var response normalizedSide
		var err error
		// The same order Parse uses to tell the three response forms apart.
		switch {
		case base.LooksLikeSSE(input.Response.ContentType, input.Response.Data):
			response, err = normalizeStreamResponse(input.Response.Data, result)
		case looksLikeJSONArray(input.Response.Data):
			response, err = normalizeArrayResponse(input.Response.Data)
		default:
			var root map[string]any
			if root, err = decodeRoot(input.Response.Data, "response"); err == nil {
				response, err = normalizeJSONResponse(root)
			}
		}
		if err != nil {
			return auditmodel.Turn{}, err
		}
		turn.ResponseLayout = response.layout
		turn.ResponseEnvelope = response.envelope
		turn.ResponseItems = response.items
		turn.ResponseOriginal = response.original
	}
	return turn, nil
}

type normalizedSide struct {
	layout   string
	envelope any
	items    []auditmodel.Item
	original any
}

func decodeRoot(data []byte, side string) (map[string]any, error) {
	var root map[string]any
	if err := auditmodel.DecodeJSON(data, &root); err != nil {
		return nil, fmt.Errorf("gemini normalizer: %s JSON: %w", side, err)
	}
	if root == nil {
		return nil, fmt.Errorf("gemini normalizer: %s JSON is not an object", side)
	}
	if err := auditmodel.CheckReservedMarkers(root); err != nil {
		return nil, err
	}
	return root, nil
}

// normalizeRequest takes contents and systemInstruction out of the envelope.
// The systemInstruction item follows the contents in the sequence: parent
// inference compares sequence prefixes, and a system instruction shared by
// unrelated sessions of one client must not count as common history.
// systemInstruction is one Content, so it is one item; a null one stays in
// the envelope like any other scalar field.
func normalizeRequest(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	values, exists := envelope[auditmodel.SlotContents]
	if !exists {
		return normalizedSide{}, errors.New("gemini normalizer: request has no contents")
	}
	contents, ok := values.([]any)
	if !ok {
		return normalizedSide{}, errors.New("gemini normalizer: contents is not an array")
	}
	items := make([]auditmodel.Item, 0, len(contents)+1)
	for _, value := range contents {
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotContents, Kind: contentKind(value), Value: value})
	}
	delete(envelope, auditmodel.SlotContents)

	layout := auditmodel.LayoutGeminiRequestSystemNone
	if instruction, exists := envelope[auditmodel.SlotSystemInstruction]; exists && instruction != nil {
		delete(envelope, auditmodel.SlotSystemInstruction)
		layout = auditmodel.LayoutGeminiRequestSystemSingle
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotSystemInstruction, Kind: "system_instruction", Value: instruction})
	}
	return normalizedSide{layout: layout, envelope: envelope, items: items, original: original}, nil
}

// normalizeJSONResponse stores each candidate's content as an item and
// leaves a marker in its place. The content is the Content object a client
// appends to its history, with the kind a request's contents entry gets, so
// both are one object. An error body or a prompt block has no candidate
// content and stays whole in the envelope.
func normalizeJSONResponse(root map[string]any) (normalizedSide, error) {
	original, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	envelope, err := cloneMap(root)
	if err != nil {
		return normalizedSide{}, err
	}
	items := make([]auditmodel.Item, 0)
	for _, value := range protocolutil.Slice(envelope["candidates"]) {
		candidate := protocolutil.Map(value)
		content, exists := candidate["content"]
		if !exists || protocolutil.Map(content) == nil {
			continue
		}
		candidate["content"] = auditmodel.ItemMarker(len(items))
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotContent, Kind: contentKind(content), Value: content})
	}
	return normalizedSide{layout: auditmodel.LayoutMarkerEnvelope, envelope: envelope, items: items, original: original}, nil
}

// normalizeArrayResponse stores a streamGenerateContent answer sent as one
// JSON array (no alt=sse) whole as the envelope of a marker_envelope layout,
// with no items: it is a JSON body, kept as canonical JSON like every other
// one. Its chunks are not folded, because the event description and the
// residue are defined for SSE events only.
func normalizeArrayResponse(data []byte) (normalizedSide, error) {
	var root []any
	if err := auditmodel.DecodeJSON(data, &root); err != nil {
		return normalizedSide{}, fmt.Errorf("gemini normalizer: response JSON array: %w", err)
	}
	if err := auditmodel.CheckReservedMarkers(root); err != nil {
		return normalizedSide{}, err
	}
	// The same completeness rule as for an SSE stream.
	events, err := arrayEvents(data)
	if err != nil {
		return normalizedSide{}, err
	}
	if fold := foldStream(events); fold.errored || !fold.complete() {
		return normalizedSide{}, errIncompleteStream
	}
	original, err := auditmodel.CloneJSON(root)
	if err != nil {
		return normalizedSide{}, err
	}
	return normalizedSide{layout: auditmodel.LayoutMarkerEnvelope, envelope: root, items: []auditmodel.Item{}, original: original}, nil
}

// normalizeStreamResponse stores an SSE stream as the compact description of
// its events, its summary, the folded body (slot aggregate: the
// GenerateContentResponse the same answer has without streaming) and the
// residue: whatever the chunks carry that the folded body does not. The
// folded body is split as a non-stream response is.
func normalizeStreamResponse(data []byte, result base.Result) (normalizedSide, error) {
	events, _ := base.DecodeSSEWithStatus(data)
	if len(events) == 0 {
		return normalizedSide{}, errEmptySSE
	}
	fold := foldStream(events)
	if fold.problem != nil {
		return normalizedSide{}, fold.problem
	}
	if fold.errored || !fold.complete() {
		// Parse reports such a stream as partial; refuse it here as well so
		// a truncated stream can never verify.
		return normalizedSide{}, errIncompleteStream
	}
	residue, err := fold.residue.Entries()
	if err != nil {
		return normalizedSide{}, err
	}
	fields := map[string]any{
		"format": "sse",
		"events": streamevidence.Describe(events),
		"summary": map[string]any{
			"response_id":      result.ResponseID,
			"usage":            result.Usage,
			"normalized_usage": result.Normalized,
			"stop_reason":      fold.stopReason,
			"error_type":       result.ErrorType,
			"error_code":       result.ErrorCode,
		},
	}
	if len(residue) > 0 {
		fields["residue"] = residue
	}
	split, err := normalizeJSONResponse(fold.body)
	if err != nil {
		return normalizedSide{}, err
	}
	original, err := cloneMap(fields)
	if err != nil {
		return normalizedSide{}, err
	}
	original[auditmodel.SlotAggregate] = split.original
	fields[auditmodel.SlotAggregate] = split.envelope
	envelope, err := cloneMap(fields)
	if err != nil {
		return normalizedSide{}, err
	}
	return normalizedSide{layout: auditmodel.LayoutGeminiStreamResponse, envelope: envelope, items: split.items, original: original}, nil
}

// contentKind names a Content by its role, the same way on both sides, so a
// candidate's content and the contents entry that resends it hash alike.
func contentKind(value any) string {
	if role := protocolutil.String(protocolutil.Map(value)["role"]); role != "" {
		return role + "_content"
	}
	return "content"
}

func cloneMap(value map[string]any) (map[string]any, error) {
	cloned, err := auditmodel.CloneJSON(value)
	if err != nil {
		return nil, err
	}
	result, ok := cloned.(map[string]any)
	if !ok {
		return nil, errors.New("gemini normalizer: cloned value is not an object")
	}
	return result, nil
}

var errIncompleteStream = errors.New("gemini normalizer: stream has no finish reason")

var _ base.AuditNormalizer = (*Parser)(nil)
