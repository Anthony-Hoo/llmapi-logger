package insights

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// maxProjectPatternBytes bounds one project text pattern.
const maxProjectPatternBytes = 1024

func normalizeProjectLists(headers []ProjectHeader, paths []ProjectBodyPath, patterns []ProjectTextPattern) ([]ProjectHeader, []ProjectBodyPath, []ProjectTextPattern) {
	if headers != nil {
		normalized := make([]ProjectHeader, 0, len(headers))
		for _, header := range headers {
			normalized = append(normalized, ProjectHeader{
				Header: strings.ToLower(strings.TrimSpace(header.Header)),
				Kind:   strings.ToLower(strings.TrimSpace(header.Kind)),
			})
		}
		headers = normalized
	}
	if paths != nil {
		normalized := make([]ProjectBodyPath, 0, len(paths))
		for _, path := range paths {
			normalized = append(normalized, ProjectBodyPath{
				Path: strings.TrimSpace(path.Path),
				Kind: strings.ToLower(strings.TrimSpace(path.Kind)),
			})
		}
		paths = normalized
	}
	if patterns != nil {
		normalized := make([]ProjectTextPattern, 0, len(patterns))
		for _, pattern := range patterns {
			normalized = append(normalized, ProjectTextPattern{
				Kind:    strings.ToLower(strings.TrimSpace(pattern.Kind)),
				Pattern: pattern.Pattern,
			})
		}
		patterns = normalized
	}
	return headers, paths, patterns
}

func validateProjectLists(owner string, headers []ProjectHeader, paths []ProjectBodyPath, patterns []ProjectTextPattern) error {
	for _, header := range headers {
		if !validHeaderName(header.Header) {
			return fmt.Errorf("%s: project header has invalid name %q", owner, header.Header)
		}
		if !knownProjectKinds[header.Kind] || header.Kind == ProjectKindRootFile {
			return fmt.Errorf("%s: project header %s has unknown kind %q", owner, header.Header, header.Kind)
		}
	}
	for _, path := range paths {
		if path.Path == "" || strings.Contains(path.Path, "..") || strings.HasPrefix(path.Path, ".") || strings.HasSuffix(path.Path, ".") {
			return fmt.Errorf("%s: project body path %q is invalid", owner, path.Path)
		}
		if !knownProjectKinds[path.Kind] {
			return fmt.Errorf("%s: project body path %s has unknown kind %q", owner, path.Path, path.Kind)
		}
	}
	for _, pattern := range patterns {
		if !knownProjectKinds[pattern.Kind] || pattern.Kind == ProjectKindCodexTurnMetadata || pattern.Kind == ProjectKindOpenCodeProject {
			return fmt.Errorf("%s: project text pattern has unsupported kind %q", owner, pattern.Kind)
		}
		if _, err := compileProjectPattern(pattern.Pattern); err != nil {
			return fmt.Errorf("%s: project text pattern for %s: %w", owner, pattern.Kind, err)
		}
	}
	return nil
}

func compileProjectPattern(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" || len(pattern) > maxProjectPatternBytes {
		return nil, fmt.Errorf("pattern must be non-empty and at most %d bytes", maxProjectPatternBytes)
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regular expression")
	}
	if compiled.NumSubexp() < 1 {
		return nil, fmt.Errorf("pattern needs a capture group")
	}
	return compiled, nil
}

// ProjectHeaderAllowlist returns the sorted, lower-cased project headers of
// every client and of the shared list. The parser decrypts them only when the
// organisation reports are enabled.
func (vocab *Vocabulary) ProjectHeaderAllowlist() []string {
	if vocab == nil {
		return nil
	}
	set := map[string]struct{}{}
	for _, header := range vocab.Project.Headers {
		set[header.Header] = struct{}{}
	}
	for _, rule := range vocab.Clients {
		for _, header := range rule.ProjectHeaders {
			set[header.Header] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
