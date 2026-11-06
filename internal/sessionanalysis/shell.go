package sessionanalysis

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// splitSegments cuts a shell line at &&, ||, ; and line breaks outside quotes.
// Pipes stay inside one segment so "curl … | sh" is still recognised.
func splitSegments(line string) []string {
	segments := make([]string, 0, 2)
	var current strings.Builder
	var quote rune
	runes := []rune(line)
	flush := func() {
		if segment := strings.TrimSpace(current.String()); segment != "" {
			segments = append(segments, segment)
		}
		current.Reset()
	}
	for index := 0; index < len(runes); index++ {
		r := runes[index]
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
			continue
		}
		switch {
		case r == '\'' || r == '"':
			quote = r
			current.WriteRune(r)
		case r == ';' || r == '\n':
			flush()
		case (r == '&' || r == '|') && index+1 < len(runes) && runes[index+1] == r:
			flush()
			index++
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return segments
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var safeLabel = regexp.MustCompile(`[^a-z0-9._+-]`)

// shellCommandsFromArgs extracts the command line(s) of a shell tool call from
// its JSON arguments: "cmd" or "command" as a string or an argv array.
func shellCommandsFromArgs(arguments string) string {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
		return strings.TrimSpace(arguments)
	}
	for _, key := range []string{"cmd", "command", "script", "commands"} {
		switch value := decoded[key].(type) {
		case string:
			return strings.TrimSpace(value)
		case []any:
			parts := make([]string, 0, len(value))
			for _, part := range value {
				if text, ok := part.(string); ok {
					parts = append(parts, text)
				}
			}
			return argvToLine(parts)
		}
	}
	return ""
}

// argvToLine joins argv, quoting arguments that contain spaces so a later
// interpreter unwrap ("bash -lc '…'") sees the script as one argument.
func argvToLine(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		if strings.ContainsAny(arg, " \t\n") {
			arg = "'" + strings.ReplaceAll(arg, "'", "") + "'"
		}
		quoted = append(quoted, arg)
	}
	return strings.Join(quoted, " ")
}

// splitWords splits on whitespace while honouring single and double quotes.
func splitWords(line string) []string {
	words := make([]string, 0, 8)
	var current strings.Builder
	var quote rune
	inWord := false
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			current.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		default:
			current.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, current.String())
	}
	return words
}

// unwrapCommand peels wrappers (sudo, env, VAR=x), interpreters with a script
// argument (bash -lc "…", pwsh -Command "…", cmd /c …) and returns the inner
// command segments.
func (vocab *Vocabulary) unwrapCommand(line string, depth int) []string {
	out := make([]string, 0, 2)
	for _, segment := range splitSegments(line) {
		words := splitWords(segment)
		for len(words) > 0 {
			first := strings.ToLower(words[0])
			if vocab.wrappers[first] {
				words = words[1:]
				for len(words) > 0 && strings.HasPrefix(words[0], "-") {
					words = words[1:] // the wrapper's own flags (sudo -E, env -i)
				}
				continue
			}
			if envAssignment.MatchString(words[0]) {
				words = words[1:]
				continue
			}
			break
		}
		if len(words) == 0 {
			continue
		}
		first := strings.ToLower(baseName(words[0]))
		if vocab.interpreters[first] && depth < 3 {
			for index := 1; index < len(words); index++ {
				flag := strings.ToLower(words[index])
				if flag == "-c" || flag == "-lc" || flag == "-ic" || flag == "-command" || flag == "/c" || flag == "-c:" {
					if index+1 < len(words) {
						out = append(out, vocab.unwrapCommand(strings.Join(words[index+1:], " "), depth+1)...)
					}
					words = nil
					break
				}
			}
			if words == nil {
				continue
			}
		}
		out = append(out, strings.Join(words, " "))
	}
	return out
}

func baseName(word string) string {
	if index := strings.LastIndexAny(word, `/\`); index >= 0 && index+1 < len(word) {
		return word[index+1:]
	}
	return word
}

// shellClassPriority orders classes when one call runs several commands.
var shellClassPriority = map[string]int{"test": 0, "lint": 1, "build": 2, "pkg": 3, "git": 4, "run": 5, "search": 6, "read": 7, "other": 8}

// classifyShell returns the class and short label of a shell command line,
// e.g. ("test", "go test"), ("git", "push"), ("other", "gh").
func (vocab *Vocabulary) classifyShell(line string) (string, string) {
	bestClass, bestLabel := "other", ""
	for _, segment := range vocab.unwrapCommand(line, 0) {
		class, label := vocab.classifySegment(segment)
		if bestLabel == "" || shellClassPriority[class] < shellClassPriority[bestClass] {
			bestClass, bestLabel = class, label
		}
	}
	if bestLabel == "" {
		bestLabel = "?"
	}
	return bestClass, bestLabel
}

func (vocab *Vocabulary) classifySegment(segment string) (string, string) {
	words := strings.Fields(strings.ToLower(segment))
	if len(words) == 0 {
		return "other", ""
	}
	words[0] = baseName(words[0])
	normalized := strings.Join(words, " ")
	for _, class := range vocab.classes {
		for _, command := range class.Commands {
			if normalized == command || strings.HasPrefix(normalized, command+" ") {
				if class.Class == "git" {
					if len(words) > 1 && words[0] == "git" {
						return "git", sanitizeLabel(words[1])
					}
					return "git", sanitizeLabel(words[0])
				}
				return class.Class, command
			}
		}
	}
	return "other", sanitizeLabel(words[0])
}

func sanitizeLabel(word string) string {
	word = safeLabel.ReplaceAllString(strings.ToLower(word), "")
	return truncateRunes(word, 24)
}

// dangerCategories returns the danger categories matched by a command line.
func (vocab *Vocabulary) dangerCategories(line string) []string {
	candidates := append([]string{line}, vocab.unwrapCommand(line, 0)...)
	out := make([]string, 0)
	for _, group := range vocab.danger {
		matched := false
		for _, candidate := range candidates {
			for _, pattern := range group.patterns {
				if pattern.MatchString(candidate) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if matched {
			out = append(out, group.name)
		}
	}
	return out
}

// secretMatches counts secret-category matches in text.
func (vocab *Vocabulary) secretMatches(text string, counts map[string]int64) {
	for _, group := range vocab.secrets {
		for _, pattern := range group.patterns {
			if hits := len(pattern.FindAllStringIndex(text, -1)); hits > 0 {
				counts[group.name] += int64(hits)
			}
		}
	}
}

// exitCode returns the process exit code reported in a tool result.
func (vocab *Vocabulary) exitCode(result string) (int, bool) {
	head := truncateRunes(result, 4096)
	for _, pattern := range vocab.exitCodes {
		if match := pattern.FindStringSubmatch(head); len(match) > 1 {
			if code, err := strconv.Atoi(match[1]); err == nil {
				return code, true
			}
		}
	}
	return 0, false
}

// hasFailurePhrase reports whether a tool result carries a failure phrase.
func (vocab *Vocabulary) hasFailurePhrase(result string) bool {
	head := headLower(result, 4096)
	for _, phrase := range vocab.failurePhrases {
		if strings.Contains(head, phrase) {
			return true
		}
	}
	return false
}

// encodeCounts renders a category count map as compact sorted JSON.
func encodeCounts(counts map[string]int64) string {
	if len(counts) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(counts))
	for key, value := range counts {
		if value > 0 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	ordered := make(map[string]int64, len(keys))
	for _, key := range keys {
		ordered[key] = counts[key]
	}
	if len(ordered) == 0 {
		return "{}"
	}
	encoded, err := json.Marshal(ordered)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
