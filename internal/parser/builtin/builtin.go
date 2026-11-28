// Package builtin assembles the small fixed parser set used by the personal
// single-process deployment. It is the one place that lists the protocol
// adapters: the proxy, the query service and every tool that rebuilds turns
// reach them through Registry, so none can run without them.
package builtin

import (
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/anthropic"
	"llmapi-logger/internal/parser/gemini"
	"llmapi-logger/internal/parser/openai"
)

// registry is built when the package is initialized. An invalid adapter list
// is a programming error and stops every binary at start-up, before any turn
// is rebuilt.
var registry = mustRegistry()

func mustRegistry() *base.Registry {
	registry, err := base.NewRegistry(adapters()...)
	if err != nil {
		panic(err)
	}
	return registry
}

// adapters is the built-in protocol list. Adding a protocol means writing its
// adapter and adding it here.
func adapters() []base.Adapter {
	return []base.Adapter{
		must(openai.Adapter(openai.ChatCompletions)),
		must(openai.Adapter(openai.Completions)),
		must(openai.Adapter(openai.Responses)),
		must(openai.Adapter(openai.ResponsesCompact)),
		anthropic.Adapter(),
		must(gemini.Adapter(gemini.GenerateContent)),
		must(gemini.Adapter(gemini.StreamGenerateContent)),
	}
}

func must(adapter base.Adapter, err error) base.Adapter {
	if err != nil {
		panic(err)
	}
	return adapter
}

// Registry returns the built-in adapters keyed by parser name.
func Registry() *base.Registry { return registry }

// All returns one parser for every configured first-version parser name.
func All() []base.Parser { return registry.Parsers() }
