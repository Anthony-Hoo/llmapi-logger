package insights

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// customAgentHeaders is the contract documented in doc/features/20 section 11
// and doc/deployment/insights-and-agent-headers.md.
var customAgentHeaders = []string{"X-Agent-Session-Id", "X-Agent-Id", "X-Agent-Parent-Id", "X-Agent-Role", "X-Agent-Name"}

func TestCustomAgentHeadersMatchDocumentation(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("vocabulary_default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Clients map[string]struct {
			RootHeaders   []string `yaml:"root_headers"`
			NodeHeaders   []string `yaml:"node_headers"`
			ParentHeaders []string `yaml:"parent_headers"`
			NameHeaders   []string `yaml:"name_headers"`
			RoleHeaders   []struct {
				Header string `yaml:"header"`
			} `yaml:"role_headers"`
		} `yaml:"clients"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	custom, found := document.Clients["custom"]
	if !found {
		t.Fatal("default vocabulary has no custom client")
	}
	var declared []string
	declared = append(declared, custom.RootHeaders...)
	declared = append(declared, custom.NodeHeaders...)
	declared = append(declared, custom.ParentHeaders...)
	declared = append(declared, custom.NameHeaders...)
	for _, role := range custom.RoleHeaders {
		declared = append(declared, role.Header)
	}
	for _, header := range customAgentHeaders {
		if !slices.Contains(declared, strings.ToLower(header)) {
			t.Errorf("custom client does not read %s; declared %v", header, declared)
		}
		if !slices.Contains(DefaultVocabulary().HeaderAllowlist(), strings.ToLower(header)) {
			t.Errorf("%s is not in the header allowlist", header)
		}
	}

	for _, doc := range []string{
		filepath.Join("..", "..", "doc", "features", "20-context-insights.md"),
		filepath.Join("..", "..", "doc", "deployment", "insights-and-agent-headers.md"),
	} {
		text, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		for _, header := range customAgentHeaders {
			if !strings.Contains(string(text), header) {
				t.Errorf("%s does not document %s", filepath.Base(doc), header)
			}
		}
	}
}
