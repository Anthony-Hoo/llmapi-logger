// Package auditmodel defines the protocol-neutral content-addressed audit
// objects used between protocol normalizers, SQLite, and the query service.
package auditmodel

import (
	"errors"

	"llmapi-logger/internal/conversation"
)

const (
	SchemaVersion = 1

	CompressionNone = "none"
	CompressionGZIP = "gzip"

	ItemMarkerKey   = "$llmapi_logger_item_v1"
	BinaryMarkerKey = "$llmapi_logger_binary_v1"

	LayoutNone                          = "none"
	LayoutOpenAIChatRequest             = "openai.chat.request.messages"
	LayoutOpenAIResponsesRequestArray   = "openai.responses.request.input_array"
	LayoutOpenAIResponsesRequestSingle  = "openai.responses.request.input_single"
	LayoutOpenAIResponsesRequestNone    = "openai.responses.request.input_none"
	LayoutOpenAICompletionsPromptArray  = "openai.completions.request.prompt_array"
	LayoutOpenAICompletionsPromptSingle = "openai.completions.request.prompt_single"
	LayoutMarkerEnvelope                = "marker_envelope"
	LayoutOpenAIStreamResponse          = "openai.stream.response"

	SlotInstructions = "instructions"
	SlotMessages     = "messages"
	SlotInput        = "input"
	SlotPrompt       = "prompt"
	SlotOutput       = "output"
	SlotChoice       = "choice"
	SlotAggregate    = "aggregate"

	OperationRetain = "retain"
	OperationDelete = "delete"
	OperationInsert = "insert"
)

var (
	ErrInvalidModel      = errors.New("auditmodel: invalid normalized model")
	ErrReservedMarker    = errors.New("auditmodel: provider value contains a reserved marker")
	ErrReconstruction    = errors.New("auditmodel: reconstruction failed")
	ErrIntegrity         = errors.New("auditmodel: object integrity check failed")
	ErrUnsupportedLayout = errors.New("auditmodel: unsupported reconstruction layout")
)

// DisplayMessage is occurrence-independent. Request/response phase, direction,
// indexes, and turn identifiers are applied only while serving a query.
type DisplayMessage struct {
	Role       string        `json:"role"`
	Name       string        `json:"name,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Content    []DisplayPart `json:"content"`
}

type DisplayPart struct {
	Type       string `json:"type"`
	Text       string `json:"text,omitempty"`
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Arguments  string `json:"arguments,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Result     string `json:"result,omitempty"`
	Data       string `json:"data,omitempty"`
}

// ConversationMessage applies occurrence-specific phase and direction to a
// reusable display projection.
func (display DisplayMessage) ConversationMessage(phase, direction string) conversation.Message {
	message := conversation.Message{
		Role:       display.Role,
		Phase:      phase,
		Direction:  direction,
		Name:       display.Name,
		ToolCallID: display.ToolCallID,
		Content:    make([]conversation.Part, 0, len(display.Content)),
	}
	for _, part := range display.Content {
		message.Content = append(message.Content, conversation.Part{
			Type:       part.Type,
			Text:       part.Text,
			ID:         part.ID,
			Name:       part.Name,
			Arguments:  part.Arguments,
			ToolCallID: part.ToolCallID,
			Result:     part.Result,
			Data:       part.Data,
		})
	}
	return message
}

// DisplayFromConversation strips occurrence-specific fields from one parsed
// conversation message so the same provider item can be reused across turns.
func DisplayFromConversation(message conversation.Message) DisplayMessage {
	display := DisplayMessage{
		Role:       message.Role,
		Name:       message.Name,
		ToolCallID: message.ToolCallID,
		Content:    make([]DisplayPart, 0, len(message.Content)),
	}
	for _, part := range message.Content {
		display.Content = append(display.Content, DisplayPart{
			Type:       part.Type,
			Text:       part.Text,
			ID:         part.ID,
			Name:       part.Name,
			Arguments:  part.Arguments,
			ToolCallID: part.ToolCallID,
			Result:     part.Result,
			Data:       part.Data,
		})
	}
	return display
}

// Item is one provider context or output item before hashing. Value must be a
// JSON-compatible value decoded with json.Decoder.UseNumber.
type Item struct {
	Slot    string
	Kind    string
	Value   any
	Display []DisplayMessage
}

// Turn is produced by a protocol normalizer. Original values are used only for
// local reconstruction verification and are never stored as additional copies.
type Turn struct {
	AuditID            string
	Protocol           string
	ParserName         string
	RequestLayout      string
	ResponseLayout     string
	RequestEnvelope    any
	ResponseEnvelope   any
	RequestItems       []Item
	ResponseItems      []Item
	RequestOriginal    any
	ResponseOriginal   any
	PreviousResponseID string
	ResponseID         string
	ConversationKey    string
	CreatedAtNS        int64
}

type ObjectRef struct {
	Slot         string
	ObjectHash   []byte
	SemanticHash []byte
}

type BinaryReference struct {
	JSONPointer string
	BinaryHash  []byte
	MediaType   string
	Encoding    string
	Header      string
}

type ExternalReference struct {
	JSONPointer string
	Kind        string
	ValueHash   []byte
	ValueEnc    []byte
}

type ContentObject struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	Compression     string
	PlaintextLength int64
	EncodedLength   int64
	DataEnc         []byte
	BinaryRefs      []BinaryReference
	ExternalRefs    []ExternalReference
}

type BinaryObject struct {
	Hash            []byte
	MediaType       string
	Compression     string
	PlaintextLength int64
	EncodedLength   int64
	DataEnc         []byte
}

// PreparedTurn contains no plaintext provider content.
type PreparedTurn struct {
	AuditID                    string
	Protocol                   string
	ParserName                 string
	RequestLayout              string
	ResponseLayout             string
	RequestEnvelopeHash        []byte
	ResponseEnvelopeHash       []byte
	RequestRefs                []ObjectRef
	ResponseRefs               []ObjectRef
	RequestSequenceHash        []byte
	ResponseSequenceHash       []byte
	RequestReconstructionHash  []byte
	ResponseReconstructionHash []byte
	PreviousResponseID         string
	ResponseID                 string
	ConversationKeyHash        []byte
	CreatedAtNS                int64
	Objects                    []ContentObject
	Binaries                   []BinaryObject
}

type StoredContent struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	Compression     string
	PlaintextLength int64
	EncodedLength   int64
	DataEnc         []byte
}

type StoredBinary struct {
	Hash            []byte
	MediaType       string
	Compression     string
	PlaintextLength int64
	EncodedLength   int64
	DataEnc         []byte
}

type DecodedObject struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Value         any    `json:"value"`
}

// ContextOp transforms one parent sequence into a child request sequence.
// Insert carries exactly one reference; Retain/Delete carry Count references.
type ContextOp struct {
	Operation string
	Count     int
	Ref       *ObjectRef
}
