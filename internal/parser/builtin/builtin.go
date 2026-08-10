// Package builtin assembles the small fixed parser set used by the personal
// single-process deployment.
package builtin

import (
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/parser/gemini"
	"llmapi-logger/internal/parser/openai"
)

// All returns one parser for every configured first-version parser name.
func All() []base.Parser {
	chat, _ := openai.New(openai.ChatCompletions)
	completions, _ := openai.New(openai.Completions)
	responses, _ := openai.New(openai.Responses)
	compact, _ := openai.New(openai.ResponsesCompact)
	generate, _ := gemini.New(gemini.GenerateContent)
	streamGenerate, _ := gemini.New(gemini.StreamGenerateContent)
	return []base.Parser{
		chat,
		completions,
		responses,
		compact,
		anthropic.New(),
		generate,
		streamGenerate,
	}
}
