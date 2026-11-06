package insights

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type userInputFixture struct {
	Prefixes []string `json:"prefixes"`
	Cases    []struct {
		Text     string `json:"text"`
		Injected bool   `json:"injected"`
	} `json:"cases"`
}

func loadUserInputFixture(t *testing.T) userInputFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/user_input_prefixes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture userInputFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// The default list is the single source of the user-input exclusion rule
// (doc/features/24-session-analysis.md section 6.3). The conversation view's
// user-input outline keeps a copy until it reads the vocabulary; the shared
// fixture pins both to the same list and cases.
func TestUserInputExcludePrefixesMatchSharedFixture(t *testing.T) {
	fixture := loadUserInputFixture(t)
	vocab := DefaultVocabulary()
	if !reflect.DeepEqual(vocab.UserInputExcludePrefixes, fixture.Prefixes) {
		t.Fatalf("default prefixes = %q, fixture = %q", vocab.UserInputExcludePrefixes, fixture.Prefixes)
	}
	for _, testCase := range fixture.Cases {
		if got := vocab.IsInjectedUserText(testCase.Text); got != testCase.Injected {
			t.Errorf("IsInjectedUserText(%q) = %v, want %v", testCase.Text, got, testCase.Injected)
		}
	}
}

func TestUserInputExcludePrefixesOverride(t *testing.T) {
	path := t.TempDir() + "/vocab.yaml"
	if err := os.WriteFile(path, []byte("user_input_exclude_prefixes: [\"  <Company-Context\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vocab, err := LoadVocabulary(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vocab.UserInputExcludePrefixes, []string{"<company-context"}) ||
		!vocab.IsInjectedUserText("<Company-Context>x") || vocab.IsInjectedUserText("<turn_aborted>") {
		t.Fatalf("override = %q", vocab.UserInputExcludePrefixes)
	}
	if err := os.WriteFile(path, []byte("user_input_exclude_prefixes: [\"   \"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVocabulary(path); err == nil {
		t.Fatal("blank prefix accepted")
	}
}
