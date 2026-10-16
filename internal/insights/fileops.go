package insights

import (
	"strings"
)

func parseArgs(args string) map[string]any {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	value, err := decodeJSON([]byte(args))
	if err != nil {
		return nil
	}
	return asMap(value)
}

// callToolKind classifies one tool call. The vocabulary decides by name;
// str_replace_editor-style tools are refined by their command.
func (vocab *Vocabulary) callToolKind(name, args string) string {
	kind := vocab.ToolKind(name)
	if rule, ok := vocab.FileOps.Tools[strings.ToLower(name)]; ok && rule.Style == "editor" {
		if asString(parseArgs(args)["command"]) == "view" {
			return ToolKindFileRead
		}
	}
	return kind
}

// fileOpsForCall decodes the file operations of one response tool call.
func (vocab *Vocabulary) fileOpsForCall(name, args string) []FileOp {
	rule, ok := vocab.FileOps.Tools[strings.ToLower(name)]
	if !ok {
		return nil
	}
	rules := vocab.FileOps
	object := parseArgs(args)
	path := firstString(object, rules.PathKeys)
	op := FileOp{Tool: name, Op: rule.Op, Path: path}
	switch rule.Op {
	case "shell":
		if text := embeddedPatch(object, args); text != "" {
			return patchOps(name, text)
		}
		return []FileOp{{Tool: name, Op: "shell"}}
	case "read", "search":
		return []FileOp{op}
	}
	switch rule.Style {
	case "patch":
		ops := patchOps(name, patchText(rules, object, args))
		if len(ops) == 0 {
			return []FileOp{op}
		}
		return ops
	case "write":
		op.AddedLines = lineCount(firstString(object, rules.ContentKeys))
	case "edit":
		op.RemovedLines = lineCount(firstString(object, rules.OldKeys))
		op.AddedLines = lineCount(firstString(object, rules.NewKeys))
	case "multi_edit":
		for _, key := range rules.EditsKeys {
			for _, value := range asSlice(object[key]) {
				edit := asMap(value)
				op.RemovedLines += lineCount(firstString(edit, rules.OldKeys))
				op.AddedLines += lineCount(firstString(edit, rules.NewKeys))
			}
		}
	case "editor":
		switch asString(object["command"]) {
		case "view":
			op.Op = "read"
		case "create":
			op.AddedLines = lineCount(firstString(object, rules.ContentKeys))
		case "str_replace":
			op.RemovedLines = lineCount(firstString(object, rules.OldKeys))
			op.AddedLines = lineCount(firstString(object, rules.NewKeys))
		case "insert":
			op.AddedLines = lineCount(firstString(object, rules.NewKeys))
		}
	}
	return []FileOp{op}
}

func looksLikePatch(text string) bool {
	return strings.Contains(text, "*** Begin Patch") || strings.Contains(text, "*** Update File:") ||
		strings.Contains(text, "*** Add File:") || strings.Contains(text, "\n+++ ") ||
		strings.HasPrefix(text, "--- ") || strings.HasPrefix(text, "diff --git ")
}

// patchText finds the patch inside apply_patch arguments: a JSON object with
// one of the patch keys (string, or an argv array), or the raw argument text.
func patchText(rules FileOpRules, object map[string]any, raw string) string {
	var candidates []string
	for _, key := range rules.PatchKeys {
		switch typed := object[key].(type) {
		case string:
			candidates = append(candidates, typed)
		case []any:
			for _, element := range typed {
				if text, ok := element.(string); ok {
					candidates = append(candidates, text)
				}
			}
		}
	}
	if object == nil {
		candidates = append(candidates, raw)
	}
	for _, candidate := range candidates {
		if looksLikePatch(candidate) {
			return candidate
		}
	}
	for index := len(candidates) - 1; index >= 0; index-- {
		if strings.TrimSpace(candidates[index]) != "" {
			return candidates[index]
		}
	}
	return ""
}

// embeddedPatch finds an apply_patch document inside a shell command.
func embeddedPatch(object map[string]any, raw string) string {
	var values []string
	for _, value := range object {
		switch typed := value.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, element := range typed {
				if text, ok := element.(string); ok {
					values = append(values, text)
				}
			}
		}
	}
	if object == nil {
		values = append(values, raw)
	}
	for _, value := range values {
		if index := strings.Index(value, "*** Begin Patch"); index >= 0 {
			return value[index:]
		}
	}
	return ""
}

// patchOps parses an apply_patch ("*** Update File:") or unified diff document
// into one FileOp per file with exact +/- line counts.
func patchOps(tool, text string) []FileOp {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	codex := strings.Contains(text, "*** Begin Patch") || strings.Contains(text, "*** Update File:") ||
		strings.Contains(text, "*** Add File:")
	var ops []FileOp
	current := -1
	start := func(path string) {
		ops = append(ops, FileOp{Tool: tool, Op: "write", Path: path})
		current = len(ops) - 1
	}
	pendingOld, afterOld := "", false
	for index, line := range lines {
		line = strings.TrimRight(line, "\r")
		wasAfterOld := afterOld
		afterOld = false
		switch {
		case codex && strings.HasPrefix(line, "*** Add File: "):
			start(strings.TrimSpace(line[len("*** Add File: "):]))
		case codex && strings.HasPrefix(line, "*** Update File: "):
			start(strings.TrimSpace(line[len("*** Update File: "):]))
		case codex && strings.HasPrefix(line, "*** Delete File: "):
			start(strings.TrimSpace(line[len("*** Delete File: "):]))
		case codex && strings.HasPrefix(line, "*** "):
			// Begin/End Patch and Move to markers carry no line changes.
		case !codex && strings.HasPrefix(line, "diff --git "):
			current = -1
		case !codex && strings.HasPrefix(line, "--- ") && index+1 < len(lines) && strings.HasPrefix(lines[index+1], "+++ "):
			pendingOld, afterOld = cleanDiffPath(line[4:]), true
		case !codex && wasAfterOld && strings.HasPrefix(line, "+++ "):
			path := cleanDiffPath(line[4:])
			if path == "/dev/null" {
				path = pendingOld
			}
			start(path)
		case strings.HasPrefix(line, "+"):
			if current < 0 {
				start("")
			}
			ops[current].AddedLines++
		case strings.HasPrefix(line, "-"):
			if current < 0 {
				start("")
			}
			ops[current].RemovedLines++
		}
	}
	return ops
}

func cleanDiffPath(raw string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(raw), "\t")
	path = strings.Trim(path, "\"")
	if path == "/dev/null" {
		return path
	}
	for _, prefix := range []string{"a/", "b/"} {
		if strings.HasPrefix(path, prefix) {
			return path[len(prefix):]
		}
	}
	return path
}
