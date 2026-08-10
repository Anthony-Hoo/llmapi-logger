package interceptor

import (
	"fmt"
	"strings"
	"sync"
)

// Registry maps explicit type names to interceptor factories. Registration is
// intentionally explicit; this package does not use init-time registration.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// NewDefaultRegistry returns a registry containing the built-in interceptors.
func NewDefaultRegistry() *Registry {
	registry := NewRegistry()
	if err := RegisterBuiltins(registry); err != nil {
		panic(err)
	}
	return registry
}

// Register adds a factory under a stable type name.
func (r *Registry) Register(typeName string, factory Factory) error {
	if r == nil {
		return fmt.Errorf("interceptor: nil registry")
	}
	if strings.TrimSpace(typeName) == "" {
		return fmt.Errorf("interceptor: empty type name")
	}
	if factory == nil {
		return fmt.Errorf("interceptor: nil factory for type %q", typeName)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[typeName]; exists {
		return fmt.Errorf("interceptor: type %q already registered", typeName)
	}
	r.factories[typeName] = factory
	return nil
}

func (r *Registry) snapshot() map[string]Factory {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	factories := make(map[string]Factory, len(r.factories))
	for typeName, factory := range r.factories {
		factories[typeName] = factory
	}
	return factories
}

// RegisterBuiltins registers all first-party interceptor types.
func RegisterBuiltins(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("interceptor: nil registry")
	}
	if err := registry.Register("require_credential", newRequireCredential); err != nil {
		return err
	}
	return registry.Register("max_body_bytes", newMaxBodyBytes)
}
