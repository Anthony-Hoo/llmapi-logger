package agentcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"llmapi-logger/internal/agentapi"
)

// tokenPattern matches token-shaped text: the prefix and at least the
// encoded length of base64url characters.
var tokenPattern = regexp.MustCompile(regexp.QuoteMeta(agentapi.TokenPrefix) + fmt.Sprintf("[A-Za-z0-9_-]{%d,}", agentapi.TokenEncodedChars))

// maskTokens replaces token-shaped strings in explanatory text (message,
// hint, next_actions). Business data is never touched.
func maskTokens(text string) string {
	return tokenPattern.ReplaceAllString(text, agentapi.TokenPrefix+"***")
}

func renderPrettySuccess(envelope outEnvelope) string {
	var builder strings.Builder
	builder.WriteString("ok\n")
	var data any
	if err := decodeNumbers(envelope.Data, &data); err == nil {
		renderValue(&builder, "", data, 0)
	}
	if len(envelope.Meta) > 0 {
		var meta map[string]any
		if decodeNumbers(envelope.Meta, &meta) == nil {
			fmt.Fprintf(&builder, "meta: state=%v complete=%v", meta["state"], meta["complete"])
			if reason, _ := meta["incomplete_reason"].(string); reason != "" {
				fmt.Fprintf(&builder, " incomplete_reason=%s", reason)
			}
			builder.WriteString("\n")
		}
	}
	if envelope.WebURL != "" {
		builder.WriteString("web: " + envelope.WebURL + "\n")
	} else if envelope.WebPath != "" {
		builder.WriteString("web: " + envelope.WebPath + "\n")
	}
	for _, action := range envelope.NextActions {
		builder.WriteString("next: " + action + "\n")
	}
	if envelope.Notice != "" {
		builder.WriteString("notice: " + envelope.Notice + "\n")
	}
	return builder.String()
}

func renderPrettyFailure(body agentapi.ErrorBody) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "error %s: %s\n", body.Code, body.Message)
	if body.Hint != "" {
		builder.WriteString("hint: " + body.Hint + "\n")
	}
	keys := make([]string, 0, len(body.Details))
	for key := range body.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&builder, "%s: %s\n", key, scalarText(body.Details[key]))
	}
	return builder.String()
}

func decodeNumbers(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}

func renderValue(builder *strings.Builder, label string, value any, depth int) {
	indent := strings.Repeat("  ", depth)
	switch typed := value.(type) {
	case map[string]any:
		if label != "" {
			builder.WriteString(indent + label + ":\n")
			depth++
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			renderValue(builder, key, typed[key], depth)
		}
	case []any:
		if rows, columns := tableOf(typed); rows != nil {
			if label != "" {
				builder.WriteString(indent + label + ":\n")
			}
			writer := tabwriter.NewWriter(builder, 0, 2, 2, ' ', 0)
			fmt.Fprintln(writer, indent+"  "+strings.Join(columns, "\t"))
			for _, row := range rows {
				cells := make([]string, len(columns))
				for index, column := range columns {
					cells[index] = shorten(scalarText(row[column]), 60)
				}
				fmt.Fprintln(writer, indent+"  "+strings.Join(cells, "\t"))
			}
			_ = writer.Flush()
			return
		}
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, scalarText(item))
		}
		builder.WriteString(indent + label + ": " + strings.Join(parts, ", ") + "\n")
	default:
		builder.WriteString(indent + label + ": " + scalarText(value) + "\n")
	}
}

// tableOf turns a list of objects into rows with the scalar columns (at most
// eight, in first-seen order).
func tableOf(items []any) ([]map[string]any, []string) {
	if len(items) == 0 {
		return nil, nil
	}
	rows := make([]map[string]any, 0, len(items))
	var columns []string
	seen := map[string]bool{}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, nil
		}
		rows = append(rows, row)
		keys := make([]string, 0, len(row))
		for key := range row {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			switch row[key].(type) {
			case map[string]any, []any:
				continue
			}
			if !seen[key] && len(columns) < 8 {
				seen[key] = true
				columns = append(columns, key)
			}
		}
	}
	if len(columns) == 0 {
		return nil, nil
	}
	return rows, columns
}

func scalarText(value any) string {
	switch typed := value.(type) {
	case nil:
		return "-"
	case string:
		return strings.Map(func(char rune) rune {
			if char < 0x20 || char == 0x7f {
				return ' '
			}
			return char
		}, typed)
	case map[string]any, []any:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	default:
		return fmt.Sprint(typed)
	}
}

func shorten(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-1]) + "…"
}
