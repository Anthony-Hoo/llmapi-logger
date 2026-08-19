// Package streamterminal owns the protocol-specific knowledge of which SSE
// lines announce the logical end of a provider stream. It lives with the
// parser layer so that audit capture consumes only an opaque line matcher and
// never interprets provider conventions itself.
package streamterminal

import "strings"

// Matcher reports whether one complete, untruncated SSE line is a terminal
// marker for the protocol it was built for. Implementations must be cheap:
// they run inline on the capture path.
type Matcher func(line []byte) bool

// MatcherFor returns the terminal-line matcher for a parser name such as
// "openai.chat_completions" or "anthropic.messages", or nil when the protocol
// has no reliable in-stream terminal marker (for example Gemini).
func MatcherFor(parserName string) Matcher {
	protocol, _, _ := strings.Cut(parserName, ".")
	switch protocol {
	case "openai":
		return matchOpenAI
	case "anthropic":
		return matchAnthropic
	default:
		return nil
	}
}

func matchOpenAI(line []byte) bool {
	text := string(line)
	if rest, ok := strings.CutPrefix(text, "data:"); ok {
		return strings.TrimSpace(rest) == "[DONE]"
	}
	if rest, ok := strings.CutPrefix(text, "event:"); ok {
		switch strings.TrimSpace(rest) {
		case "response.completed", "response.failed", "response.incomplete":
			return true
		}
	}
	return false
}

func matchAnthropic(line []byte) bool {
	rest, ok := strings.CutPrefix(string(line), "event:")
	return ok && strings.TrimSpace(rest) == "message_stop"
}
