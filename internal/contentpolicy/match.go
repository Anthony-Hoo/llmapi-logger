package contentpolicy

import "strings"

// matcher is an immutable Aho–Corasick automaton over lower-cased literal
// keywords. It is built once per rule snapshot and is safe for concurrent
// reads.
type matcher struct {
	root *matcherNode
}

type matcherNode struct {
	next map[byte]*matcherNode
	fail *matcherNode
	out  bool
}

func newMatcher(keywords []string) *matcher {
	root := &matcherNode{}
	for _, keyword := range keywords {
		lower := strings.ToLower(keyword)
		if lower == "" {
			continue
		}
		node := root
		for index := 0; index < len(lower); index++ {
			if node.next == nil {
				node.next = make(map[byte]*matcherNode, 1)
			}
			child := node.next[lower[index]]
			if child == nil {
				child = &matcherNode{}
				node.next[lower[index]] = child
			}
			node = child
		}
		node.out = true
	}

	queue := make([]*matcherNode, 0, len(root.next))
	for _, child := range root.next {
		child.fail = root
		queue = append(queue, child)
	}
	for len(queue) != 0 {
		node := queue[0]
		queue = queue[1:]
		for symbol, child := range node.next {
			fail := node.fail
			for fail != nil && fail.next[symbol] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = root
			} else {
				child.fail = fail.next[symbol]
			}
			child.out = child.out || child.fail.out
			queue = append(queue, child)
		}
	}
	return &matcher{root: root}
}

// Match reports whether the text contains any configured keyword. Matching is
// case-insensitive and uses contiguous substrings; there is intentionally no
// word-boundary, regular-expression, Unicode-normalization or fuzzy matching.
func (m *matcher) Match(text string) bool {
	if m == nil || m.root == nil || text == "" {
		return false
	}
	lower := strings.ToLower(text)
	node := m.root
	for index := 0; index < len(lower); index++ {
		symbol := lower[index]
		for node != nil && node.next[symbol] == nil {
			node = node.fail
		}
		if node == nil {
			node = m.root
			continue
		}
		node = node.next[symbol]
		if node.out {
			return true
		}
	}
	return false
}
