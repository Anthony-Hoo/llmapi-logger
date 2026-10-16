// Package models resolves model metadata that the context insights need and
// that is not billing configuration: the context window used for occupancy.
// Cost comes from NewAPI's actual billing (doc/features/21-newapi-billing.md),
// so this table carries no prices.
package models

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

//go:embed context_windows.json
var embeddedContextWindows []byte

// Table resolves model names to context windows. It is immutable and safe for
// concurrent use.
type Table struct {
	windows map[string]int64
	byBare  map[string][]string // bare model name -> full ids
	bares   []string            // distinct bare names, longest first
}

// Load returns the embedded context-window table with overrides applied.
// Override keys are matched like any model id (case-insensitive) and replace
// an embedded entry with the same id or add a new one.
func Load(overrides map[string]int64) (*Table, error) {
	base, err := decode(embeddedContextWindows)
	if err != nil {
		return nil, fmt.Errorf("models: embedded table: %w", err)
	}
	table := &Table{windows: base}
	seen := make(map[string]string, len(overrides))
	for id, window := range overrides {
		key, err := normalizeID(id)
		if err != nil {
			return nil, fmt.Errorf("models: override: %w", err)
		}
		if previous, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("models: override ids %q and %q are the same model", previous, id)
		}
		if window <= 0 {
			return nil, fmt.Errorf("models: override %q: context window must be positive", id)
		}
		seen[key] = id
		table.windows[key] = window
	}
	table.index()
	return table, nil
}

// ValidateOverrideID reports whether id is acceptable as an override key.
func ValidateOverrideID(id string) error {
	_, err := normalizeID(id)
	return err
}

func normalizeID(id string) (string, error) {
	key := strings.ToLower(id)
	if key == "" || strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t\r\n\x00") {
		return "", fmt.Errorf("invalid model id %q", id)
	}
	return key, nil
}

func decode(data []byte) (map[string]int64, error) {
	var parsed map[string]int64
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&parsed); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected trailing data")
	}
	normalized := make(map[string]int64, len(parsed))
	for id, window := range parsed {
		key, err := normalizeID(id)
		if err != nil {
			return nil, err
		}
		if _, duplicate := normalized[key]; duplicate {
			return nil, fmt.Errorf("duplicate model id %q", id)
		}
		if window <= 0 {
			return nil, fmt.Errorf("model %q: context window must be positive", id)
		}
		normalized[key] = window
	}
	return normalized, nil
}

func (table *Table) index() {
	table.byBare = make(map[string][]string, len(table.windows))
	for id := range table.windows {
		bare := bareName(id)
		table.byBare[bare] = append(table.byBare[bare], id)
	}
	for _, ids := range table.byBare {
		sort.Strings(ids)
	}
	table.bares = table.bares[:0]
	for bare := range table.byBare {
		table.bares = append(table.bares, bare)
	}
	sort.Slice(table.bares, func(i, j int) bool {
		if len(table.bares[i]) != len(table.bares[j]) {
			return len(table.bares[i]) > len(table.bares[j])
		}
		return table.bares[i] < table.bares[j]
	})
}

func bareName(id string) string {
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}

// lookup resolves a model name: exact id (case-insensitive), then the id with
// its provider prefix stripped, then the longest known family that the name
// extends with a "-", "@" or ":" suffix (a dated release). Anything ambiguous
// is unknown.
func (table *Table) lookup(model string) (string, bool) {
	if table == nil {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(model))
	if name == "" {
		return "", false
	}
	if _, ok := table.windows[name]; ok {
		return name, true
	}
	bare := bareName(name)
	if bare == "" {
		return "", false
	}
	if ids, ok := table.byBare[bare]; ok {
		if len(ids) == 1 {
			return ids[0], true
		}
		return "", false
	}
	for _, candidate := range table.bares {
		if len(candidate) >= len(bare) || !strings.HasPrefix(bare, candidate) {
			continue
		}
		if separator := bare[len(candidate)]; separator != '-' && separator != '@' && separator != ':' {
			continue
		}
		// bares is longest first, so the first hit is the longest family and
		// the only question is whether it is shared between providers.
		if ids := table.byBare[candidate]; len(ids) == 1 {
			return ids[0], true
		}
		return "", false
	}
	return "", false
}

// ContextWindow returns the model's context window in tokens, or nil when the
// model is unknown.
func (table *Table) ContextWindow(model string) *int64 {
	id, ok := table.lookup(model)
	if !ok {
		return nil
	}
	window := table.windows[id]
	return &window
}
