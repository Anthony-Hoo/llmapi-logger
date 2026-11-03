package contentpolicy

import "testing"

func TestMatcherCaseInsensitiveSubstring(t *testing.T) {
	m := newMatcher([]string{"apple", "机密", "A.*B"})

	tests := []struct {
		text  string
		wants bool
	}{
		{"APPLE", true},
		{"pineapple", true},
		{"app le", false},
		{"这不是机密信息", true},
		{"axxxb", false},
		{"a.*b", true},
		{"nothing", false},
		{"", false},
	}
	for _, test := range tests {
		if got := m.Match(test.text); got != test.wants {
			t.Fatalf("Match(%q) = %v, want %v", test.text, got, test.wants)
		}
	}
}

func TestMatcherMultipleKeywordsAndUnicode(t *testing.T) {
	m := newMatcher([]string{"reverse shell", "Ключ", "秘密"})
	if !m.Match("open a REVERSE SHELL") {
		t.Fatal("reverse shell did not match")
	}
	if !m.Match("найден КЛЮЧ здесь") {
		t.Fatal("Cyrillic keyword did not match case-insensitively")
	}
	if !m.Match("这是一个秘密") {
		t.Fatal("Chinese keyword did not match")
	}
	if m.Match("unrelated") {
		t.Fatal("unexpected match")
	}
}

func TestEmptyMatcherNeverMatches(t *testing.T) {
	m := newMatcher(nil)
	if m.Match("anything") {
		t.Fatal("empty matcher matched")
	}
}
