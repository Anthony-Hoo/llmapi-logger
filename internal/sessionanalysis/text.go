package sessionanalysis

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fingerprinter tags values with a keyed, domain-separated HMAC
// (security.AnalysisFingerprinter).
type Fingerprinter interface {
	Fingerprint(domain string, value []byte) []byte
}

// Fingerprint domains owned by this package.
const (
	domainSentence = "session-analysis/sentence"
	domainToolCall = "session-analysis/tool-call"
	domainPath     = "session-analysis/path"
	domainDigest   = "session-analysis/chat-digest"
)

const (
	minSentenceRunes = 6
	maxSentenceRunes = 200
	maxUserFPRs      = 500
	maxRuleFPRs      = 2000
)

// splitSentences cuts text at line breaks, CJK and ASCII sentence punctuation
// and ". " boundaries.
func splitSentences(text string) []string {
	out := make([]string, 0, 8)
	var current strings.Builder
	flush := func() {
		if sentence := strings.TrimSpace(current.String()); sentence != "" {
			out = append(out, sentence)
		}
		current.Reset()
	}
	runes := []rune(text)
	for index, r := range runes {
		switch r {
		case '\n', '\r', '。', '！', '？', '；', '!', '?', ';':
			flush()
			continue
		case '.':
			if index+1 == len(runes) || unicode.IsSpace(runes[index+1]) {
				flush()
				continue
			}
		}
		current.WriteRune(r)
	}
	flush()
	return out
}

// normalizeSentence lower-cases, drops list markers, punctuation and symbols,
// and collapses whitespace, so "- 日期一律按 UTC+8 解析。" and "日期一律按utc+8解析"
// fingerprint alike only when their words agree.
func normalizeSentence(sentence string) string {
	sentence = strings.ToLower(strings.TrimSpace(sentence))
	sentence = strings.TrimLeft(sentence, "-*•·>#0123456789.)( \t")
	var builder strings.Builder
	space := false
	for _, r := range sentence {
		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			if space && builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			space = false
			builder.WriteRune(r)
		default:
			space = true
		}
	}
	return builder.String()
}

// sentenceFingerprints tags every normalized sentence of texts once, keeping
// at most limit tags.
func sentenceFingerprints(fp Fingerprinter, texts []string, limit int) [][]byte {
	if fp == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([][]byte, 0)
	for _, text := range texts {
		for _, sentence := range splitSentences(text) {
			normalized := normalizeSentence(sentence)
			length := utf8.RuneCountInString(normalized)
			if length < minSentenceRunes || length > maxSentenceRunes || seen[normalized] {
				continue
			}
			seen[normalized] = true
			out = append(out, fp.Fingerprint(domainSentence, []byte(normalized)))
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// truncateRunes keeps at most limit runes.
func truncateRunes(text string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	runes := []rune(text)
	return string(runes[:limit])
}

// headRunes returns the first limit runes of text, lower-cased.
func headLower(text string, limit int) string {
	return strings.ToLower(truncateRunes(text, limit))
}

// collapseBlankLines turns runs of three or more line breaks into two.
func collapseBlankLines(text string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	blank := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blank++
			if blank > 1 {
				continue
			}
			out = append(out, "")
			continue
		}
		blank = 0
		out = append(out, strings.TrimRight(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
