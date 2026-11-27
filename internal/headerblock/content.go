package headerblock

import "strings"

// ContentHeaders selects the content-type and content-encoding a stage row
// stores in version 2, with the rule parser.decryptContentHeaders applies to
// version 1 rows: among the stage's Headers (never Trailers) whose name in
// lower case is the target, the first non-empty value in order. headers is
// the stage's Header fields in byte order of name (Snapshot order). nil means
// none, stored as NULL.
func ContentHeaders(headers []Field) (contentType, contentEncoding *string) {
	for _, field := range headers {
		lowerName := strings.ToLower(field.Name)
		if lowerName != "content-type" && lowerName != "content-encoding" {
			continue
		}
		for _, value := range field.Values {
			if len(value) == 0 {
				continue
			}
			switch lowerName {
			case "content-type":
				if contentType == nil {
					selected := string(value)
					contentType = &selected
				}
			case "content-encoding":
				if contentEncoding == nil {
					selected := string(value)
					contentEncoding = &selected
				}
			}
		}
	}
	return contentType, contentEncoding
}
