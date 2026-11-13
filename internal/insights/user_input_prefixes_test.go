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

// The vocabulary is the single source of the user-input exclusion rule
// (doc/features/24-session-analysis.md section 6.3). The management session
// hands InjectedUserTextPrefixes to the UI, whose classifier is tested against
// the same fixture, so both sides classify the fixture cases alike.
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

func TestInjectedUserTextPrefixesMergeMarkers(t *testing.T) {
	vocab := &Vocabulary{
		UserInputExcludePrefixes: []string{"<environment_context", "# agents.md"},
		InjectionMarkers:         []string{"<System-Reminder>", "# AGENTS.md", "<environment_context"},
	}
	want := []string{"<environment_context", "# agents.md", "<system-reminder>"}
	if got := vocab.InjectedUserTextPrefixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("InjectedUserTextPrefixes() = %q, want %q", got, want)
	}
	if !vocab.IsInjectedUserText("  <SYSTEM-REMINDER>x") || vocab.IsInjectedUserText("<system-reminder") {
		t.Fatal("IsInjectedUserText does not follow InjectedUserTextPrefixes")
	}
	var missing *Vocabulary
	if missing.InjectedUserTextPrefixes() != nil || missing.IsInjectedUserText("<system-reminder>") {
		t.Fatal("nil vocabulary must classify nothing as injected")
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
	if got := vocab.InjectedUserTextPrefixes(); len(got) == 0 || got[0] != "<company-context" {
		t.Fatalf("InjectedUserTextPrefixes() = %q, want the override first", got)
	}
	if err := os.WriteFile(path, []byte("user_input_exclude_prefixes: [\"   \"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVocabulary(path); err == nil {
		t.Fatal("blank prefix accepted")
	}
}
