package archive

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The host-side coverage test reads the embedded PostgreSQL migrations
// rather than keeping a second hand-written column list: a list copied from
// the migrations would have to be updated by the same person who forgets the
// specification. The parser below understands exactly the statement forms
// the migrations use (CREATE TABLE, ALTER TABLE ... ADD/DROP COLUMN, column
// and table REFERENCES clauses); TestMigrationParserFindsTrickyColumns pins
// the cases a line-based reader would miss. The PostgreSQL-backed test reads
// information_schema instead and calls the same CheckSchema.

const migrationsDir = "../storage/postgres/migrations"

func migrationSchema(t *testing.T) Schema {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("migrations: %v (%d files)", err, len(paths))
	}
	sort.Strings(paths)
	schema := Schema{Columns: map[string][]string{}}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := parseMigration(string(data), &schema); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	return schema
}

var (
	lineComment   = regexp.MustCompile(`--[^\n]*`)
	createTable   = regexp.MustCompile(`(?is)^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s*\((.*)\)\s*$`)
	alterTable    = regexp.MustCompile(`(?is)^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)\s+(.*)$`)
	referencesTo  = regexp.MustCompile(`(?i)\bREFERENCES\s+("?[A-Za-z_][A-Za-z0-9_]*"?)`)
	dropTable     = regexp.MustCompile(`(?is)^DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?("?[A-Za-z_][A-Za-z0-9_]*"?)`)
	firstToken    = regexp.MustCompile(`^\s*("[^"]+"|[A-Za-z_][A-Za-z0-9_]*)`)
	constraintKey = map[string]bool{"PRIMARY": true, "FOREIGN": true, "CHECK": true, "UNIQUE": true, "CONSTRAINT": true, "EXCLUDE": true}
)

func unquote(name string) string { return strings.Trim(name, `"`) }

// splitTopLevel splits at sep outside parentheses and single-quoted strings.
func splitTopLevel(text string, sep byte) []string {
	var parts []string
	depth, start, quoted := 0, 0, false
	for index := 0; index < len(text); index++ {
		switch c := text[index]; {
		case c == '\'':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == sep && depth == 0:
			parts = append(parts, text[start:index])
			start = index + 1
		}
	}
	return append(parts, text[start:])
}

func parseMigration(sql string, schema *Schema) error {
	sql = lineComment.ReplaceAllString(sql, "")
	for _, statement := range splitTopLevel(sql, ';') {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if match := createTable.FindStringSubmatch(statement); match != nil {
			table := unquote(match[1])
			if _, exists := schema.Columns[table]; exists {
				return errors.New("table created twice: " + table)
			}
			schema.Columns[table] = []string{}
			for _, element := range splitTopLevel(match[2], ',') {
				token := firstToken.FindStringSubmatch(element)
				if token == nil {
					return errors.New("unparsed element in " + table + ": " + element)
				}
				for _, reference := range referencesTo.FindAllStringSubmatch(element, -1) {
					schema.ForeignKeys = append(schema.ForeignKeys, ForeignKey{Table: table, References: unquote(reference[1])})
				}
				if constraintKey[strings.ToUpper(token[1])] {
					continue
				}
				schema.Columns[table] = append(schema.Columns[table], unquote(token[1]))
			}
			continue
		}
		if match := alterTable.FindStringSubmatch(statement); match != nil {
			table := unquote(match[1])
			for _, action := range splitTopLevel(match[2], ',') {
				words := strings.Fields(action)
				if len(words) < 2 {
					return errors.New("unparsed ALTER TABLE action: " + action)
				}
				verb, object := strings.ToUpper(words[0]), strings.ToUpper(words[1])
				switch {
				case verb == "ADD" && object == "COLUMN":
					if _, exists := schema.Columns[table]; !exists {
						return errors.New("column added to unknown table " + table)
					}
					name := words[2]
					if strings.EqualFold(name, "IF") {
						name = words[5]
					}
					schema.Columns[table] = append(schema.Columns[table], unquote(name))
					for _, reference := range referencesTo.FindAllStringSubmatch(action, -1) {
						schema.ForeignKeys = append(schema.ForeignKeys, ForeignKey{Table: table, References: unquote(reference[1])})
					}
				case verb == "DROP" && object == "COLUMN":
					name := unquote(words[len(words)-1])
					schema.Columns[table] = slices.DeleteFunc(schema.Columns[table], func(column string) bool { return column == name })
				case verb == "ADD" && (object == "CONSTRAINT" || object == "CHECK" || object == "FOREIGN"):
					for _, reference := range referencesTo.FindAllStringSubmatch(action, -1) {
						schema.ForeignKeys = append(schema.ForeignKeys, ForeignKey{Table: table, References: unquote(reference[1])})
					}
				case verb == "DROP" && object == "CONSTRAINT", verb == "VALIDATE", verb == "ALTER" && object == "COLUMN":
				default:
					return errors.New("unhandled ALTER TABLE action: " + action)
				}
			}
			continue
		}
		if match := dropTable.FindStringSubmatch(statement); match != nil {
			delete(schema.Columns, unquote(match[1]))
			continue
		}
		upper := strings.ToUpper(statement)
		if strings.HasPrefix(upper, "CREATE INDEX") || strings.HasPrefix(upper, "CREATE UNIQUE INDEX") || strings.HasPrefix(upper, "DROP INDEX") ||
			strings.HasPrefix(upper, "INSERT") || strings.HasPrefix(upper, "UPDATE") || strings.HasPrefix(upper, "DELETE") {
			continue
		}
		return errors.New("unhandled statement: " + strings.SplitN(statement, "\n", 2)[0])
	}
	return nil
}

func TestSpecificationIsConsistent(t *testing.T) {
	if err := CheckSpecification(); err != nil {
		t.Fatal(err)
	}
	if len(ArchivedTables) != 20 {
		t.Fatalf("%d archived tables, E.3 lists 20", len(ArchivedTables))
	}
	broken := append(slices.Clone(Columns), Column{Table: "http_stages", Name: "stage", Class: ClassDigest, Field: "x"},
		Column{Table: "audit_records", Name: "probe", Class: ClassExcluded},
		Column{Table: "not_archived", Name: "x", Class: ClassArchived, Field: "x"})
	err := checkSpecification(broken)
	for _, want := range []string{"http_stages.stage: listed twice", "audit_records.probe: excluded needs a reason", "not_archived.x: table is not an archived table"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("broken specification: %v, want %q", err, want)
		}
	}
}

func TestMigrationParserFindsTrickyColumns(t *testing.T) {
	schema := migrationSchema(t)
	for table, columns := range map[string][]string{
		"audit_records":  {"api_key_fpr", "parse_save_failures", "parse_next_at_ns", "capture_version", "user_agent_enc", "caller_updated_at_ns"},
		"parsed_results": {"upstream_error_class", "parsed_at_ns"},
		"body_chunks":    {"offset"},
		"token_links":    {"billing_attempts", "quota_per_unit"},
		"http_stages":    {"content_type", "content_encoding"},
		"audit_analysis": {"detail_root"},
	} {
		for _, column := range columns {
			if !slices.Contains(schema.Columns[table], column) {
				t.Errorf("parser missed %s.%s; got %v", table, column, schema.Columns[table])
			}
		}
	}
	for _, column := range schema.Columns["audit_records"] {
		if constraintKey[strings.ToUpper(column)] {
			t.Errorf("constraint taken for a column: %s", column)
		}
	}
	if got := len(schema.Columns["audit_records"]); got != 29 {
		t.Errorf("audit_records has %d columns, want 29", got)
	}
}

// The specification covers exactly the columns the migrations define for
// the archived tables, and every table that references an archived root is
// archived or derived.
func TestSpecificationCoversTheMigrations(t *testing.T) {
	schema := migrationSchema(t)
	if err := CheckSchema(schema); err != nil {
		t.Fatal(err)
	}
	referring := ReferringTables(schema.ForeignKeys)
	for _, table := range []string{"http_stages", "parsed_results", "turns", "token_links", "audit_analysis", "agent_spawn_hints",
		"audit_project_identity", "http_header_blocks", "http_headers", "body_streams", "body_chunks", "stream_timelines",
		"turn_context_ops", "turn_response_items", "content_binary_refs", "content_external_refs"} {
		if !slices.Contains(referring, table) {
			t.Errorf("%s does not reference an archived root; referring = %v", table, referring)
		}
	}
	for _, table := range []string{"session_signals", "projects", "agent_tokens", "analysis_detail_objects"} {
		if slices.Contains(referring, table) {
			t.Errorf("%s reported as referring", table)
		}
	}
}

// The check fails, naming the column or table, when the schema gains a
// column or a referring table the specification does not know, or loses a
// column it specifies (J.1 step 4, on the host).
func TestSpecificationCheckFails(t *testing.T) {
	clone := func() Schema {
		schema := migrationSchema(t)
		columns := make(map[string][]string, len(schema.Columns))
		for table, names := range schema.Columns {
			columns[table] = slices.Clone(names)
		}
		return Schema{Columns: columns, ForeignKeys: slices.Clone(schema.ForeignKeys)}
	}
	added := clone()
	if err := parseMigration(`ALTER TABLE http_stages ADD COLUMN archive_probe TEXT;`, &added); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(added); !errors.Is(err, ErrCoverage) || !strings.Contains(err.Error(), "http_stages.archive_probe") {
		t.Fatalf("added column: %v", err)
	}
	child := clone()
	if err := parseMigration(`CREATE TABLE archive_probe_child (audit_id TEXT REFERENCES audit_records(audit_id));`, &child); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(child); err == nil || !strings.Contains(err.Error(), "archive_probe_child") {
		t.Fatalf("referring table: %v", err)
	}
	grandchild := clone()
	if err := parseMigration(`CREATE TABLE probe_a (turn_id TEXT REFERENCES turns(turn_id)); CREATE TABLE probe_b (id TEXT, FOREIGN KEY (id) REFERENCES probe_a(turn_id));`, &grandchild); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(grandchild); err == nil || !strings.Contains(err.Error(), "probe_b") {
		t.Fatalf("indirectly referring table: %v", err)
	}
	dropped := clone()
	dropped.Columns["turns"] = slices.DeleteFunc(dropped.Columns["turns"], func(name string) bool { return name == "link_reason" })
	if err := CheckSchema(dropped); err == nil || !strings.Contains(err.Error(), "turns.link_reason") {
		t.Fatalf("missing column: %v", err)
	}
}

func TestManifestTablesFollowTheSpecification(t *testing.T) {
	tables := ManifestTables()
	if len(tables) != len(ArchivedTables) {
		t.Fatalf("%d tables", len(tables))
	}
	if slices.Contains(tables["conversations"], "updated_at_ns") || slices.Contains(tables["body_chunks"], "compression") {
		t.Fatal("excluded column in manifest tables")
	}
	if !slices.Contains(tables["content_objects"], "created_at_ns") || !slices.Contains(tables["turn_context_ops"], "op_index") ||
		tables["audit_records"][0] != "audit_id" {
		t.Fatalf("archived columns missing: %v", tables)
	}
}
