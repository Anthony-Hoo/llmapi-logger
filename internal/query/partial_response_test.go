package query

import (
	"encoding/json"
	"reflect"
	"testing"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/parser"
)

func requestOnlyView(texts ...string) *conversation.Conversation {
	view := conversation.New()
	for _, text := range texts {
		view.Append(conversation.Message{
			Role: conversation.RoleUser, Phase: conversation.PhaseRequest, Direction: conversation.DirectionClientToUpstream,
			Content: []conversation.Part{conversation.Text(text)},
		})
	}
	return view
}

func TestMergePartialResponseRenumbersAfterTheRebuiltRequest(t *testing.T) {
	t.Parallel()
	rebuilt := requestOnlyView("first", "second")
	before, _ := json.Marshal(rebuilt)
	// Stored with the index the message had in the parsed conversation.
	partial := []conversation.Message{{
		Index: 7, Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient,
		Content: []conversation.Part{conversation.Text("half an answer")},
	}}
	merged, ok := MergePartialResponse(rebuilt, partial)
	if !ok || len(merged.Messages) != 3 || merged.Messages[2].Index != 2 || merged.Messages[2].Content[0].Text != "half an answer" {
		t.Fatalf("merged = %+v, %v", merged, ok)
	}
	if after, _ := json.Marshal(rebuilt); string(after) != string(before) || partial[0].Index != 7 {
		t.Fatal("the merge changed its arguments")
	}
	if same, ok := MergePartialResponse(rebuilt, nil); !ok || same != rebuilt {
		t.Fatalf("no partial messages: %+v, %v", same, ok)
	}
	if !reflect.DeepEqual(merged.Messages[:2], rebuilt.Messages) {
		t.Fatalf("request messages changed: %+v", merged.Messages)
	}
}

func TestMergePartialResponseRejectsWhatIsNotAResponseMessage(t *testing.T) {
	t.Parallel()
	for name, message := range map[string]conversation.Message{
		"request phase": {Role: conversation.RoleUser, Phase: conversation.PhaseRequest, Direction: conversation.DirectionClientToUpstream,
			Content: []conversation.Part{conversation.Text("x")}},
		"wrong direction": {Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionClientToUpstream,
			Content: []conversation.Part{conversation.Text("x")}},
		"parts not contiguous": {Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient,
			Content: []conversation.Part{{Index: 3, Type: conversation.PartText, Text: "x"}}},
		"no content": {Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient},
	} {
		if _, ok := MergePartialResponse(requestOnlyView("first"), []conversation.Message{message}); ok {
			t.Errorf("%s: merged", name)
		}
	}
}

// The reader's key is the writer's.
func TestParsedEnvelopeReadsTheWritersKey(t *testing.T) {
	t.Parallel()
	field, _ := reflect.TypeOf(parsedEnvelope{}).FieldByName("PartialResponse")
	if field.Tag.Get("json") != parser.PartialResponseMessagesKey {
		t.Fatalf("json tag %q, writer key %q", field.Tag.Get("json"), parser.PartialResponseMessagesKey)
	}
}
