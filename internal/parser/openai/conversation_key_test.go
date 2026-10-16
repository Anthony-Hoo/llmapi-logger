package openai

import "testing"

func TestProviderConversationsOutrankGroupingKeys(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		root          map[string]any
		key           string
		serverManaged bool
	}{
		"conversation id":     {map[string]any{"conversation_id": "conv-example"}, "conversation_id\x00conv-example", true},
		"conversation string": {map[string]any{"conversation": "conv-example"}, "conversation\x00conv-example", true},
		"conversation object": {map[string]any{"conversation": map[string]any{"id": "conv-example"}}, "conversation.id\x00conv-example", true},
		// Several provider conversations may share one cache key, so the
		// conversation decides the key whenever both are present.
		"conversation and cache key": {map[string]any{"conversation": "conv-example", "prompt_cache_key": "session-example"}, "conversation\x00conv-example", true},
		"conversation and thread":    {map[string]any{"conversation": map[string]any{"id": "conv-example"}, "thread_id": "thread-example"}, "conversation.id\x00conv-example", true},
		"prompt cache key":           {map[string]any{"prompt_cache_key": "session-example"}, "prompt_cache_key\x00session-example", false},
		"thread id":                  {map[string]any{"thread_id": "thread-example"}, "thread_id\x00thread-example", false},
		"metadata id":                {map[string]any{"metadata": map[string]any{"conversation_id": "conv-example"}}, "metadata.conversation_id\x00conv-example", false},
		"empty conversation":         {map[string]any{"conversation": map[string]any{}, "prompt_cache_key": "session-example"}, "prompt_cache_key\x00session-example", false},
		"none":                       {map[string]any{}, "", false},
	} {
		if got := conversationKey(test.root); got != test.key {
			t.Errorf("%s: conversationKey = %q, want %q", name, got, test.key)
		}
		if got := serverManagedConversation(test.root); got != test.serverManaged {
			t.Errorf("%s: serverManagedConversation = %v, want %v", name, got, test.serverManaged)
		}
	}
}
