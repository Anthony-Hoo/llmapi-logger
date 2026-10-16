package openai

import "testing"

func TestServerManagedConversationOnlyForProviderConversations(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		root map[string]any
		want bool
	}{
		"conversation id":      {map[string]any{"conversation_id": "conv-example"}, true},
		"conversation string":  {map[string]any{"conversation": "conv-example"}, true},
		"conversation object":  {map[string]any{"conversation": map[string]any{"id": "conv-example"}}, true},
		"conversation and key": {map[string]any{"conversation": "conv-example", "prompt_cache_key": "session-example"}, true},
		"prompt cache key":     {map[string]any{"prompt_cache_key": "session-example"}, false},
		"thread id":            {map[string]any{"thread_id": "thread-example"}, false},
		"metadata id":          {map[string]any{"metadata": map[string]any{"conversation_id": "conv-example"}}, false},
		"empty conversation":   {map[string]any{"conversation": map[string]any{}}, false},
		"none":                 {map[string]any{}, false},
	} {
		if got := serverManagedConversation(test.root); got != test.want {
			t.Errorf("%s: serverManagedConversation = %v, want %v", name, got, test.want)
		}
	}
}
