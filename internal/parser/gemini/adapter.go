package gemini

import base "llmapi-logger/internal/parser"

// Adapter returns the protocol adapter for one Gemini parser name. Gemini has
// no normalizer yet: it keeps a summary and full raw evidence, so the adapter
// has no conversation rebuild and emits no layout.
func Adapter(name string) (base.Adapter, error) {
	implementation, err := New(name)
	if err != nil {
		return base.Adapter{}, err
	}
	return base.Adapter{Parser: implementation}, nil
}
