package parser

import (
	"errors"
	"fmt"
	"strings"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
)

// ConversationRebuilder projects provider values rebuilt from a verified turn
// graph onto the protocol-neutral conversation DTO. responseLayout is the
// stored response layout, which tells a stream aggregate from a JSON body.
type ConversationRebuilder func(request, response any, responseLayout string) (*conversation.Conversation, error)

// Adapter gathers what is specific to one parser name: the parser itself,
// whether it normalizes into a turn graph, how a rebuilt turn becomes a
// conversation again, and which stored layouts its normalizer emits. How each
// layout is assembled lives in auditmodel, because a stored layout must be
// assemblable by every reader without any registration.
type Adapter struct {
	Parser Parser
	// Conversation is set exactly when Parser is an AuditNormalizer.
	Conversation ConversationRebuilder
	// Layouts lists every request and response layout the normalizer writes
	// today; empty without a normalizer. A layout replaced by a new version
	// leaves this list (rows that carry it still assemble from the auditmodel
	// table and are projected by Conversation).
	Layouts []string
}

// Name is the parser name the adapter is registered under.
func (adapter Adapter) Name() string { return adapter.Parser.Name() }

// Normalizer returns the parser's AuditNormalizer, or nil when the protocol
// keeps only a summary and full raw evidence.
func (adapter Adapter) Normalizer() AuditNormalizer {
	normalizer, _ := adapter.Parser.(AuditNormalizer)
	return normalizer
}

// Registry is the fixed set of protocol adapters, keyed by parser name. It is
// built once from an explicit list (internal/parser/builtin) and never
// changes afterwards.
type Registry struct {
	adapters map[string]Adapter
	names    []string
}

// ErrUnknownParser reports a parser name no adapter is registered under.
var ErrUnknownParser = errors.New("parser: no adapter registered")

// NewRegistry validates the adapters and indexes them by parser name.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{adapters: make(map[string]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter.Parser == nil {
			return nil, errors.New("parser: adapter without parser")
		}
		name := adapter.Name()
		if strings.TrimSpace(name) == "" || strings.TrimSpace(adapter.Parser.Version()) == "" {
			return nil, errors.New("parser: adapter without parser name or version")
		}
		if _, exists := registry.adapters[name]; exists {
			return nil, fmt.Errorf("parser: duplicate adapter %q", name)
		}
		normalizes := adapter.Normalizer() != nil
		if normalizes != (adapter.Conversation != nil) {
			return nil, fmt.Errorf("parser: adapter %q must have a conversation rebuild exactly when it normalizes", name)
		}
		if normalizes != (len(adapter.Layouts) > 0) {
			return nil, fmt.Errorf("parser: adapter %q must list layouts exactly when it normalizes", name)
		}
		for _, layout := range adapter.Layouts {
			if !auditmodel.KnownLayout(layout) {
				return nil, fmt.Errorf("parser: adapter %q emits unknown layout %q", name, layout)
			}
		}
		adapter.Layouts = append([]string(nil), adapter.Layouts...)
		registry.adapters[name] = adapter
		registry.names = append(registry.names, name)
	}
	return registry, nil
}

// Lookup returns the adapter registered under parserName.
func (registry *Registry) Lookup(parserName string) (Adapter, bool) {
	if registry == nil {
		return Adapter{}, false
	}
	adapter, ok := registry.adapters[parserName]
	return adapter, ok
}

// Names lists the registered parser names in registration order.
func (registry *Registry) Names() []string {
	if registry == nil {
		return nil
	}
	return append([]string(nil), registry.names...)
}

// Adapters lists the registered adapters in registration order.
func (registry *Registry) Adapters() []Adapter {
	if registry == nil {
		return nil
	}
	result := make([]Adapter, 0, len(registry.names))
	for _, name := range registry.names {
		adapter := registry.adapters[name]
		adapter.Layouts = append([]string(nil), adapter.Layouts...)
		result = append(result, adapter)
	}
	return result
}

// Parsers lists the registered parsers in registration order.
func (registry *Registry) Parsers() []Parser {
	if registry == nil {
		return nil
	}
	result := make([]Parser, 0, len(registry.names))
	for _, name := range registry.names {
		result = append(result, registry.adapters[name].Parser)
	}
	return result
}

// RebuildConversation projects a rebuilt turn with the adapter of the parser
// that normalized it.
func (registry *Registry) RebuildConversation(parserName string, request, response any, responseLayout string) (*conversation.Conversation, error) {
	adapter, ok := registry.Lookup(parserName)
	if !ok || adapter.Conversation == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownParser, parserName)
	}
	return adapter.Conversation(request, response, responseLayout)
}
