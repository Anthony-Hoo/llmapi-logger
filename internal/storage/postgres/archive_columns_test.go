package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

// These tests need a real PostgreSQL (TEST_DATABASE_URL) and skip otherwise.

// readArchiveSchema reads the live schema the column coverage check needs
// (design J.1): every column of every table of the current schema from
// information_schema, and every foreign key from pg_constraint.
func readArchiveSchema(t *testing.T, db rowQueryer) archive.Schema {
	t.Helper()
	ctx := context.Background()
	schema := archive.Schema{Columns: map[string][]string{}}
	rows, err := db.QueryContext(ctx, `
SELECT table_name, column_name FROM information_schema.columns
WHERE table_schema = current_schema()
ORDER BY table_name, ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		schema.Columns[table] = append(schema.Columns[table], column)
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}
	rows, err = db.QueryContext(ctx, `
SELECT source.relname, target.relname
FROM pg_constraint AS c
JOIN pg_class AS source ON source.oid = c.conrelid
JOIN pg_class AS target ON target.oid = c.confrelid
WHERE c.contype = 'f' AND c.connamespace = to_regnamespace(current_schema())
ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key archive.ForeignKey
		if err := rows.Scan(&key.Table, &key.References); err != nil {
			t.Fatal(err)
		}
		schema.ForeignKeys = append(schema.ForeignKeys, key)
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}
	return schema
}

// The column specification covers the live schema of a freshly migrated
// database, and the same check fails, naming the column or the table, once
// an archived table gains a column or a new table refers to an archived one.
func TestArchiveColumnCoverageMatchesLiveSchema(t *testing.T) {
	ctx := context.Background()
	store, dsn := openTestStore(t)
	if err := archive.CheckSchema(readArchiveSchema(t, store.readerDB)); err != nil {
		t.Fatalf("live schema: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, probe := range []struct {
		create, drop, names string
	}{
		{`ALTER TABLE http_stages ADD COLUMN archive_probe TEXT`, `ALTER TABLE http_stages DROP COLUMN archive_probe`, "http_stages.archive_probe"},
		{`CREATE TABLE archive_probe_child (audit_id TEXT COLLATE "C" REFERENCES audit_records(audit_id))`, `DROP TABLE archive_probe_child`, "archive_probe_child"},
		// Referring to an archived table through another table counts too.
		{`CREATE TABLE archive_probe_grandchild (audit_id TEXT COLLATE "C" PRIMARY KEY REFERENCES audit_analysis(audit_id))`, `DROP TABLE archive_probe_grandchild`, "archive_probe_grandchild"},
	} {
		if _, err := admin.ExecContext(ctx, probe.create); err != nil {
			t.Fatal(err)
		}
		err := archive.CheckSchema(readArchiveSchema(t, admin))
		if !errors.Is(err, archive.ErrCoverage) || !strings.Contains(err.Error(), probe.names+":") {
			t.Fatalf("after %q the check = %v, want a problem naming %s", probe.create, err, probe.names)
		}
		if _, err := admin.ExecContext(ctx, probe.drop); err != nil {
			t.Fatal(err)
		}
		if err := archive.CheckSchema(readArchiveSchema(t, admin)); err != nil {
			t.Fatalf("after %q: %v", probe.drop, err)
		}
	}
}

// --- Digest sensitivity (J.1, the database side) ---

// digestFixture is one audit of each shape the representative rows come
// from: a version 2 audit with a turn (objects, a binary, an external ref,
// a token link, a project identity), a version 1 audit with header rows,
// and a version 2 audit without a turn whose raw is kept.
type digestFixture struct {
	store  *Store
	cipher security.Cipher
	turn   string
	v1     string
	raw    string
}

func buildDigestSensitivityFixture(t *testing.T) *digestFixture {
	t.Helper()
	ctx := context.Background()
	store, _ := openSignedStore(t)
	cipher := v2TestCipher(t)
	fixture := &digestFixture{store: store, cipher: cipher}

	fixture.turn = runSession(t, store, cipher, typicalV2Drive(), crashNone)
	request, response := objectFixtureWithFile()
	parseArchiveAudit(t, store, cipher, fixture.turn, archiveTurnSpec{request: request, response: response,
		responseID: "digest-response", createdAtNS: 100, conversationKey: "digest-conversation", parsedJSON: []byte(`{"status":"ok"}`)})
	identity := identityTestRow(fixture.turn)
	aad, err := orgreport.IdentityAAD(fixture.turn, identity.Version)
	if err != nil {
		t.Fatal(err)
	}
	if identity.IdentityEnc, err = cipher.Encrypt(aad, []byte(`{"remotes":["example.com/repo"]}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveProjectIdentity(ctx, identity); err != nil {
		t.Fatal(err)
	}

	fixture.v1 = "digest-v1"
	writeV1Audit(t, store, cipher, fixture.v1)
	uriAAD, _ := security.AAD(fixture.v1, "request_uri")
	uri, err := cipher.Encrypt(uriAAD, []byte("/v1/chat/completions?alt=sse"))
	if err != nil {
		t.Fatal(err)
	}
	mustExecWriter(t, store, `UPDATE audit_records SET request_uri_enc = $1 WHERE audit_id = $2`, uri, fixture.v1)

	fixture.raw = runSession(t, store, cipher, typicalV2Drive(), crashNone)
	parseArchiveAudit(t, store, cipher, fixture.raw, archiveTurnSpec{noTurn: true, createdAtNS: 200})

	// Every constraint is dropped so that any column can take any value: the
	// test is about what the export does with it.
	mustExecWriter(t, store, `
DO $$
DECLARE item record;
BEGIN
    FOR item IN SELECT conrelid::regclass AS relation, conname FROM pg_constraint
                WHERE connamespace = to_regnamespace(current_schema()) AND contype IN ('c', 'f')
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', item.relation, item.conname);
    END LOOP;
END
$$`)
	// A caller and a billed token link, written behind the writer; then the
	// fixture is signed as it stands.
	mustExecWriter(t, store, `UPDATE audit_records SET newapi_request_id = 'digest-request', caller_status = 'resolved', caller_attempts = 1,
	    caller_updated_at_ns = 50 WHERE audit_id = $1`, fixture.turn)
	mustExecWriter(t, store, `INSERT INTO token_links (audit_id, newapi_user_id, username, newapi_token_id, token_name, linked_at_ns,
	    billing_state, quota, quota_per_unit, billed_prompt_tokens, billed_completion_tokens, billing_attempts)
	    VALUES ($1, 7, 'owner', 8, 'personal', 60, 'billed', 10, 500000, 3, 4, 1)`, fixture.turn)
	for _, id := range []string{fixture.turn, fixture.v1, fixture.raw} {
		resignArchiveEvents(t, store, id)
	}
	return fixture
}

func mustExecWriter(t *testing.T, store *Store, statement string, arguments ...any) {
	t.Helper()
	if _, err := store.writerConn.ExecContext(context.Background(), statement, arguments...); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

// resignArchiveEvents re-derives the payload digest of each of the audit's
// events from its current rows and signs it again with its stored previous
// MAC, so the export's event re-verification accepts a row the test changed
// behind the writer. The chain linkage to later events is not repaired; the
// export does not check it.
func resignArchiveEvents(t *testing.T, store *Store, auditID string) {
	t.Helper()
	ctx := context.Background()
	signer := store.integrity.Load()
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `SELECT sequence, event_type, previous_mac, created_at_ns FROM integrity_events WHERE audit_id = $1 ORDER BY sequence`, auditID)
	if err != nil {
		t.Fatal(err)
	}
	type event struct {
		sequence    int64
		eventType   string
		previousMAC []byte
		createdAtNS int64
	}
	var events []event
	for rows.Next() {
		var row event
		if err := rows.Scan(&row.sequence, &row.eventType, &row.previousMAC, &row.createdAtNS); err != nil {
			t.Fatal(err)
		}
		events = append(events, row)
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range events {
		digest, err := integrityPayloadDigestFor(ctx, transaction, newIntegrityGraphCache(), auditID, row.eventType, schemaLive)
		if err != nil {
			// A row the export will reject anyway: leave the event as it is.
			continue
		}
		mac, err := signer.MAC(row.previousMAC, auditID, row.eventType, digest, row.createdAtNS)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.ExecContext(ctx, `UPDATE integrity_events SET payload_digest = $1, event_mac = $2 WHERE sequence = $3`, digest, mac, row.sequence); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

// digestScope says which audit of the fixture a table's representative row
// belongs to and how to find it ($1 is the audit id).
var digestScope = map[string]struct {
	audit func(*digestFixture) string
	where string
}{
	"audit_records":          {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"http_stages":            {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"http_headers":           {func(f *digestFixture) string { return f.v1 }, `audit_id = $1`},
	"http_header_blocks":     {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"body_streams":           {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"body_chunks":            {func(f *digestFixture) string { return f.raw }, `audit_id = $1`},
	"stream_timelines":       {func(f *digestFixture) string { return f.turn }, `audit_id = $1 AND timeline_enc IS NOT NULL`},
	"parsed_results":         {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"token_links":            {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"turns":                  {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"turn_response_items":    {func(f *digestFixture) string { return f.turn }, `turn_id = (SELECT turn_id FROM turns WHERE audit_id = $1)`},
	"conversations":          {func(f *digestFixture) string { return f.turn }, `conversation_id = (SELECT conversation_id FROM turns WHERE audit_id = $1)`},
	"content_objects":        {func(f *digestFixture) string { return f.turn }, `object_hash IN (SELECT object_hash FROM turn_response_items WHERE turn_id = (SELECT turn_id FROM turns WHERE audit_id = $1))`},
	"binary_objects":         {func(f *digestFixture) string { return f.turn }, `binary_hash IN (SELECT binary_hash FROM content_binary_refs) AND $1 <> ''`},
	"content_binary_refs":    {func(f *digestFixture) string { return f.turn }, `$1 <> ''`},
	"content_external_refs":  {func(f *digestFixture) string { return f.turn }, `$1 <> ''`},
	"audit_project_identity": {func(f *digestFixture) string { return f.turn }, `audit_id = $1`},
	"integrity_events":       {func(f *digestFixture) string { return f.turn }, `audit_id = $1 AND event_type = 'capture_finalized'`},
}

// digestExpectation is what changing one column must do. The default is a
// different record digest. A column the export checks against something
// else (an AAD, a content address, a sequence hash, a length) makes the
// change exclude the audit instead: that reason is listed, so the change is
// still never invisible. skip names a column that cannot be changed on its
// own, with the reason.
type digestExpectation struct {
	excluded string
	skip     string
	// keepEvents leaves the events as the change left them: the change is to
	// an event itself, which re-signing would undo.
	keepEvents bool
	// mutate replaces the generic change of the column's type.
	mutate func(t *testing.T, f *digestFixture, ctid string) mutation
}

// mutation is one change: the statement and its arguments ($1 is the row's
// ctid) and, when it also sets other columns or rows, what puts those back.
type mutation struct {
	statement string
	arguments []any
	restore   func(moved string)
}

const keySkip = "key column: it names the row, and the record carries it through the line head or the enclosing record"

var digestExpectations = map[string]digestExpectation{
	"audit_records.audit_id":                  {skip: keySkip},
	"audit_records.capture_version":           {excluded: ArchiveReasonEventPayload},
	"audit_records.request_uri_enc":           {mutate: mutateRequestURI},
	"audit_records.user_agent_enc":            {mutate: mutateUserAgent},
	"audit_records.ended_at_ns":               {},
	"http_stages.audit_id":                    {skip: keySkip},
	"http_stages.stage":                       {excluded: ArchiveReasonDecrypt},
	"http_headers.audit_id":                   {skip: keySkip},
	"http_headers.stage":                      {excluded: ArchiveReasonDecrypt},
	"http_headers.kind":                       {excluded: ArchiveReasonDecrypt},
	"http_headers.name":                       {excluded: ArchiveReasonDecrypt},
	"http_headers.value_index":                {excluded: ArchiveReasonDecrypt},
	"http_headers.value_length":               {excluded: ArchiveReasonDecrypt},
	"http_headers.value_enc":                  {mutate: mutateHeaderValue},
	"http_header_blocks.audit_id":             {excluded: ArchiveReasonDecrypt},
	"http_header_blocks.block_enc":            {mutate: mutateHeaderBlock},
	"body_streams.audit_id":                   {skip: keySkip},
	"body_streams.stage":                      {excluded: ArchiveReasonRecordFormat},
	"body_streams.source_stage":               {excluded: ArchiveReasonRecordFormat},
	"body_chunks.audit_id":                    {skip: keySkip},
	"body_chunks.stage":                       {excluded: ArchiveReasonDecrypt},
	"body_chunks.seq":                         {excluded: ArchiveReasonDecrypt},
	"body_chunks.offset":                      {excluded: ArchiveReasonRawUnservable},
	"body_chunks.plaintext_length":            {excluded: ArchiveReasonDecrypt},
	"body_chunks.data_enc":                    {mutate: mutateChunk},
	"stream_timelines.audit_id":               {skip: keySkip},
	"stream_timelines.stage":                  {excluded: ArchiveReasonDecrypt},
	"stream_timelines.plaintext_length":       {excluded: ArchiveReasonDecrypt},
	"stream_timelines.timeline_enc":           {mutate: mutateTimeline},
	"parsed_results.audit_id":                 {skip: keySkip},
	"parsed_results.parser_name":              {excluded: ArchiveReasonDecrypt},
	"parsed_results.parsed_json_enc":          {mutate: mutateParsedJSON},
	"token_links.audit_id":                    {skip: keySkip},
	"turns.turn_id":                           {excluded: ArchiveReasonEventPayload},
	"turns.audit_id":                          {skip: keySkip},
	"turns.conversation_id":                   {excluded: ArchiveReasonTurnGraph},
	"turns.request_envelope_hash":             {excluded: ArchiveReasonEventPayload},
	"turns.response_envelope_hash":            {excluded: ArchiveReasonEventPayload},
	"turns.request_item_count":                {excluded: ArchiveReasonEventPayload},
	"turns.response_item_count":               {excluded: ArchiveReasonTurnGraph},
	"turns.request_sequence_hash":             {excluded: ArchiveReasonEventPayload},
	"turns.response_sequence_hash":            {excluded: ArchiveReasonTurnGraph},
	"turn_response_items.turn_id":             {excluded: ArchiveReasonTurnGraph},
	"turn_response_items.slot":                {excluded: ArchiveReasonTurnGraph},
	"turn_response_items.object_hash":         {excluded: ArchiveReasonEventPayload},
	"turn_response_items.semantic_hash":       {excluded: ArchiveReasonTurnGraph},
	"conversations.conversation_id":           {excluded: ArchiveReasonTurnGraph},
	"content_objects.object_hash":             {excluded: ArchiveReasonEventPayload},
	"content_objects.semantic_hash":           {excluded: ArchiveReasonTurnGraph},
	"content_objects.kind":                    {excluded: ArchiveReasonDecrypt},
	"content_objects.plaintext_length":        {excluded: ArchiveReasonDecrypt},
	"binary_objects.binary_hash":              {excluded: ArchiveReasonTurnGraph},
	"binary_objects.plaintext_length":         {excluded: ArchiveReasonDecrypt},
	"content_binary_refs.object_hash":         {skip: "moving the ref to an object the turn does not reach drops it from the record; the host digest test covers the column"},
	"content_binary_refs.binary_hash":         {excluded: ArchiveReasonTurnGraph},
	"content_external_refs.object_hash":       {skip: "moving the ref to an object the turn does not reach drops it from the record; the host digest test covers the column"},
	"content_external_refs.json_pointer":      {excluded: ArchiveReasonDecrypt},
	"content_external_refs.ref_kind":          {excluded: ArchiveReasonDecrypt},
	"content_external_refs.value_hash":        {excluded: ArchiveReasonDecrypt},
	"content_external_refs.value_enc":         {mutate: mutateExternalValue},
	"audit_project_identity.audit_id":         {skip: keySkip},
	"audit_project_identity.identity_version": {excluded: ArchiveReasonDecrypt},
	"audit_project_identity.identity_enc":     {mutate: mutateIdentity},
	"integrity_events.audit_id":               {skip: keySkip},
	"integrity_events.event_type":             {excluded: ArchiveReasonEventMissing},
	"integrity_events.payload_digest":         {excluded: ArchiveReasonEventPayload, keepEvents: true},
	"integrity_events.event_mac":              {excluded: ArchiveReasonEventMAC, keepEvents: true},
	"integrity_events.sequence":               {mutate: mutateEventSequence},
	// The timeline metadata is checked against the decoded points (query.Timeline).
	"stream_timelines.event_count":       {excluded: ArchiveReasonTimeline},
	"stream_timelines.first_event_at_ns": {excluded: ArchiveReasonTimeline},
	"stream_timelines.last_event_at_ns":  {excluded: ArchiveReasonTimeline},
	// Garbage lineage breaks the graph walk behind the semantic event; the
	// host digest test shows the lineage columns change the digest.
	"turns.parent_turn_id": {excluded: ArchiveReasonEventPayload},
	"turns.parent_base":    {excluded: ArchiveReasonEventPayload},
}

func TestArchiveDigestCoversEveryDigestColumn(t *testing.T) {
	ctx := context.Background()
	fixture := buildDigestSensitivityFixture(t)
	store := fixture.store
	baseline := map[string][32]byte{}
	export := func(auditID string) (*ArchiveExport, error) {
		snapshot := openArchiveSnapshot(t, store, fixture.cipher)
		defer snapshot.Close()
		return snapshot.Export(auditID, 1)
	}
	for _, id := range []string{fixture.turn, fixture.v1, fixture.raw} {
		exported, err := export(id)
		if err != nil {
			t.Fatalf("baseline export of %s: %v", id, err)
		}
		baseline[id] = exported.Digest
	}
	types := map[string]string{}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT table_name || '.' || column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema()`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			t.Fatal(err)
		}
		types[name] = kind
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}

	changed, excluded, skipped := 0, 0, 0
	for _, column := range archive.Columns {
		if column.Class != archive.ClassDigest {
			continue
		}
		name := column.Table + "." + column.Name
		expectation := digestExpectations[name]
		if expectation.skip != "" {
			skipped++
			continue
		}
		scope, ok := digestScope[column.Table]
		if !ok {
			t.Errorf("%s: no representative row for table %s", name, column.Table)
			continue
		}
		auditID := scope.audit(fixture)
		t.Run(name, func(t *testing.T) {
			var ctid, original sql.NullString
			if err := store.readerDB.QueryRowContext(ctx, `SELECT ctid::text, `+textOf(column.Name, types[name])+` FROM `+column.Table+` WHERE `+scope.where+` ORDER BY ctid LIMIT 1`, auditID).Scan(&ctid, &original); err != nil {
				t.Fatalf("representative row: %v", err)
			}
			var change mutation
			if expectation.mutate != nil {
				change = expectation.mutate(t, fixture, ctid.String)
			} else {
				change.statement, change.arguments = genericMutation(t, column.Table, column.Name, types[name], ctid.String)
			}
			var moved string
			var sequence sql.NullInt64
			returning := ` RETURNING ctid::text, NULL::bigint`
			if column.Table == "integrity_events" {
				// Re-signing rewrites the event rows; find the row again by
				// its key afterwards.
				returning = ` RETURNING ctid::text, sequence`
			}
			if err := store.writerConn.QueryRowContext(ctx, change.statement+returning, change.arguments...).Scan(&moved, &sequence); err != nil {
				t.Fatalf("mutate: %v", err)
			}
			if !expectation.keepEvents {
				resignArchiveEvents(t, store, auditID)
			}
			exported, exportErr := export(auditID)
			// Restore the row and the events, and require the baseline back.
			if sequence.Valid {
				if err := store.readerDB.QueryRowContext(ctx, `SELECT ctid::text FROM integrity_events WHERE sequence = $1`, sequence.Int64).Scan(&moved); err != nil {
					t.Fatal(err)
				}
			}
			moved = restoreRow(t, store, column.Table, moved, original, types, name)
			if change.restore != nil {
				change.restore(moved)
			}
			resignArchiveEvents(t, store, auditID)
			store.payloadState.Store(integrityPayloadsPending)
			if expectation.excluded != "" {
				var member *ArchiveMemberError
				if !errors.As(exportErr, &member) || member.Reason != expectation.excluded {
					t.Errorf("export = %v, want exclusion %s", exportErr, expectation.excluded)
				}
			} else if exportErr != nil {
				t.Errorf("export after the change: %v", exportErr)
			} else if exported.Digest == baseline[auditID] {
				t.Errorf("the record digest did not change")
			}
			restored, err := export(auditID)
			if err != nil || restored.Digest != baseline[auditID] {
				t.Fatalf("restoring did not return the baseline: %v", err)
			}
		})
		if expectation.excluded != "" {
			excluded++
		} else {
			changed++
		}
	}
	for name, expectation := range digestExpectations {
		found := false
		for _, column := range archive.Columns {
			found = found || column.Table+"."+column.Name == name && column.Class == archive.ClassDigest
		}
		if !found {
			t.Errorf("expectation for %s, which is not a digest column", name)
		}
		if expectation.skip != "" && expectation.excluded != "" {
			t.Errorf("%s: both skipped and expected", name)
		}
	}
	t.Logf("digest columns: %d change the record digest, %d exclude the audit, %d skipped", changed, excluded, skipped)
}

// zeroOneColumns are the 0/1 flags of the archived tables.
var zeroOneColumns = map[string]bool{
	"hash_complete": true, "eof_seen": true, "stream_timeline_complete": true, "timeline_complete": true,
	"requested_stream": true, "observed_stream": true, "has_tool_call": true, "body_scanned": true,
}

func quoteColumn(name string) string { return `"` + name + `"` }

// textOf and fromText carry a column's value through text: bytea as hex.
func textOf(column, dataType string) string {
	if dataType == "bytea" {
		return `encode(` + quoteColumn(column) + `, 'hex')`
	}
	return quoteColumn(column) + `::text`
}

func fromText(dataType string) string {
	if dataType == "bytea" {
		return `decode($1::text, 'hex')`
	}
	return `$1::text::` + dataType
}

// genericMutation changes one column by its type: an integer gains one, a
// text gains a byte, a byte string has its first bit flipped (or becomes one
// byte when NULL or empty), a float doubles.
func genericMutation(t *testing.T, table, column, dataType, ctid string) (string, []any) {
	t.Helper()
	name := quoteColumn(column)
	var expression string
	switch dataType {
	case "bigint":
		expression = `COALESCE(` + name + `, 0) + 1`
		if zeroOneColumns[column] {
			// A 0/1 flag: any other value would still read as the same flag.
			expression = `CASE WHEN ` + name + ` = 1 THEN 0 ELSE 1 END`
		}
	case "text":
		expression = `COALESCE(` + name + `, '') || 'x'`
	case "bytea":
		expression = `CASE WHEN ` + name + ` IS NULL OR length(` + name + `) = 0 THEN decode(repeat('01', 32), 'hex') ELSE set_byte(` + name + `, 0, get_byte(` + name + `, 0) # 1) END`
	case "double precision":
		expression = `COALESCE(` + name + `, 1) * 2`
	default:
		t.Fatalf("no generic change for %s.%s of type %s", table, column, dataType)
	}
	return `UPDATE ` + table + ` SET ` + name + ` = ` + expression + ` WHERE ctid = $1::tid`, []any{ctid}
}

func restoreRow(t *testing.T, store *Store, table, ctid string, original sql.NullString, types map[string]string, name string) string {
	t.Helper()
	column := name[strings.Index(name, ".")+1:]
	var value any
	if original.Valid {
		value = original.String
	}
	var moved string
	if err := store.writerConn.QueryRowContext(context.Background(), `UPDATE `+table+` SET `+quoteColumn(column)+` = `+fromText(types[name])+` WHERE ctid = $2::tid RETURNING ctid::text`, value, ctid).Scan(&moved); err != nil {
		t.Fatalf("restore: %v", err)
	}
	return moved
}

// captureCompanions reads the companion columns a re-encrypting change also
// sets, and returns what puts them back on the moved row.
func captureCompanions(t *testing.T, store *Store, table, ctid string, columns ...string) func(moved string) {
	t.Helper()
	type saved struct {
		value sql.NullString
		kind  string
	}
	values := map[string]saved{}
	for _, column := range columns {
		var entry saved
		if err := store.readerDB.QueryRow(`SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`, table, column).Scan(&entry.kind); err != nil {
			t.Fatal(err)
		}
		if err := store.readerDB.QueryRow(`SELECT `+textOf(column, entry.kind)+` FROM `+table+` WHERE ctid = $1::tid`, ctid).Scan(&entry.value); err != nil {
			t.Fatal(err)
		}
		values[column] = entry
	}
	return func(moved string) {
		// One statement: every UPDATE moves the row to a new ctid.
		assignments := make([]string, 0, len(values))
		arguments := []any{moved}
		for column, entry := range values {
			var argument any
			if entry.value.Valid {
				argument = entry.value.String
			}
			arguments = append(arguments, argument)
			placeholder := fmt.Sprintf("$%d::text", len(arguments))
			value := placeholder + "::" + entry.kind
			if entry.kind == "bytea" {
				value = "decode(" + placeholder + ", 'hex')"
			}
			assignments = append(assignments, quoteColumn(column)+" = "+value)
		}
		mustExecWriter(t, store, `UPDATE `+table+` SET `+strings.Join(assignments, ", ")+` WHERE ctid = $1::tid`, arguments...)
	}
}

func readBytes(t *testing.T, store *Store, query string, arguments ...any) []byte {
	t.Helper()
	var value []byte
	if err := store.readerDB.QueryRow(query, arguments...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func mutateRequestURI(t *testing.T, f *digestFixture, ctid string) mutation {
	aad, _ := security.AAD(f.turn, "request_uri")
	plaintext, err := f.cipher.Decrypt(aad, readBytes(t, f.store, `SELECT request_uri_enc FROM audit_records WHERE ctid = $1::tid`, ctid))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := f.cipher.Encrypt(aad, append(plaintext, []byte("&extra=1")...))
	if err != nil {
		t.Fatal(err)
	}
	return mutation{statement: `UPDATE audit_records SET request_uri_enc = $2 WHERE ctid = $1::tid`, arguments: []any{ctid, enc}}
}

func mutateUserAgent(t *testing.T, f *digestFixture, ctid string) mutation {
	values, err := headerblock.OpenUserAgent(f.cipher, f.turn, readBytes(t, f.store, `SELECT user_agent_enc FROM audit_records WHERE ctid = $1::tid`, ctid))
	if err != nil {
		t.Fatal(err)
	}
	values[0] += " changed"
	enc, err := headerblock.SealUserAgent(f.cipher, f.turn, values)
	if err != nil {
		t.Fatal(err)
	}
	return mutation{statement: `UPDATE audit_records SET user_agent_enc = $2 WHERE ctid = $1::tid`, arguments: []any{ctid, enc}}
}

func mutateHeaderValue(t *testing.T, f *digestFixture, ctid string) mutation {
	var stage, kind, name string
	var index int
	var enc []byte
	if err := f.store.readerDB.QueryRow(`SELECT stage, kind, name, value_index, value_enc FROM http_headers WHERE ctid = $1::tid`, ctid).Scan(&stage, &kind, &name, &index, &enc); err != nil {
		t.Fatal(err)
	}
	aad, _ := security.AAD(f.v1, "header", stage, kind, name, strconv.Itoa(index))
	plaintext, err := f.cipher.Decrypt(aad, enc)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := f.cipher.Encrypt(aad, append(plaintext, 'x'))
	if err != nil {
		t.Fatal(err)
	}
	restore := captureCompanions(t, f.store, "http_headers", ctid, "value_length")
	return mutation{statement: `UPDATE http_headers SET value_enc = $2, value_length = value_length + 1 WHERE ctid = $1::tid`,
		arguments: []any{ctid, changed}, restore: restore}
}

func mutateHeaderBlock(t *testing.T, f *digestFixture, ctid string) mutation {
	var block storage.HeaderBlockEvidence
	if err := f.store.readerDB.QueryRow(`SELECT compression, plaintext_length, block_enc FROM http_header_blocks WHERE ctid = $1::tid`, ctid).Scan(&block.Compression, &block.PlaintextLength, &block.DataEnc); err != nil {
		t.Fatal(err)
	}
	stages, err := headerblock.OpenBlock(f.cipher, f.turn, block)
	if err != nil {
		t.Fatal(err)
	}
	stages[0].Headers[0].Values[0] = append(stages[0].Headers[0].Values[0], 'x')
	sealed, err := headerblock.SealBlock(f.cipher, f.turn, stages)
	if err != nil {
		t.Fatal(err)
	}
	restore := captureCompanions(t, f.store, "http_header_blocks", ctid, "compression", "plaintext_length")
	return mutation{statement: `UPDATE http_header_blocks SET block_enc = $2, compression = $3, plaintext_length = $4 WHERE ctid = $1::tid`,
		arguments: []any{ctid, sealed.DataEnc, sealed.Compression, sealed.PlaintextLength}, restore: restore}
}

// mutateChunk changes one byte of a chunk and, so that the complete body
// still verifies, the SHA-256 of the bodies served from its stage.
func mutateChunk(t *testing.T, f *digestFixture, ctid string) mutation {
	var stage, compression string
	var seq int64
	var length int
	var enc []byte
	if err := f.store.readerDB.QueryRow(`SELECT stage, seq, compression, plaintext_length, data_enc FROM body_chunks WHERE ctid = $1::tid`, ctid).Scan(&stage, &seq, &compression, &length, &enc); err != nil {
		t.Fatal(err)
	}
	aad, _ := security.AAD(f.raw, "body_chunk_v2", stage, strconv.FormatInt(seq, 10), compression)
	encoded, err := f.cipher.Decrypt(aad, enc)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := bodycodec.Decode(encoded, compression, length)
	if err != nil {
		t.Fatal(err)
	}
	plaintext[0] ^= 1
	// Stored uncompressed: compression and encoded_length are storage
	// encoding, outside the digest.
	noneAAD, _ := security.AAD(f.raw, "body_chunk_v2", stage, strconv.FormatInt(seq, 10), "none")
	changed, err := f.cipher.Encrypt(noneAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	companions := captureCompanions(t, f.store, "body_chunks", ctid, "compression", "encoded_length")
	// The chunks of the stage, with this one changed, give the new body hash.
	rows, err := f.store.readerDB.Query(`SELECT seq, data_enc, compression, plaintext_length FROM body_chunks WHERE audit_id = $1 AND stage = $2 ORDER BY seq`, f.raw, stage)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	for rows.Next() {
		var chunkSeq int64
		var chunkEnc []byte
		var chunkCompression string
		var chunkLength int
		if err := rows.Scan(&chunkSeq, &chunkEnc, &chunkCompression, &chunkLength); err != nil {
			t.Fatal(err)
		}
		if chunkSeq == seq {
			digest.Write(plaintext)
			continue
		}
		chunkAAD, _ := security.AAD(f.raw, "body_chunk_v2", stage, strconv.FormatInt(chunkSeq, 10), chunkCompression)
		encoded, err := f.cipher.Decrypt(chunkAAD, chunkEnc)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := bodycodec.Decode(encoded, chunkCompression, chunkLength)
		if err != nil {
			t.Fatal(err)
		}
		digest.Write(decoded)
	}
	if err := closeRows(rows); err != nil {
		t.Fatal(err)
	}
	original := readBytes(t, f.store, `SELECT sha256 FROM body_streams WHERE audit_id = $1 AND stage = $2`, f.raw, stage)
	mustExecWriter(t, f.store, `UPDATE body_streams SET sha256 = $1 WHERE audit_id = $2 AND source_stage = $3`, digest.Sum(nil), f.raw, stage)
	return mutation{statement: `UPDATE body_chunks SET data_enc = $2, compression = 'none', encoded_length = $3 WHERE ctid = $1::tid`,
		arguments: []any{ctid, changed, len(plaintext)},
		restore: func(moved string) {
			companions(moved)
			mustExecWriter(t, f.store, `UPDATE body_streams SET sha256 = $1 WHERE audit_id = $2 AND source_stage = $3`, original, f.raw, stage)
		}}
}

func mutateTimeline(t *testing.T, f *digestFixture, ctid string) mutation {
	var stage, compression string
	var length int64
	var enc []byte
	if err := f.store.readerDB.QueryRow(`SELECT stage, compression, plaintext_length, timeline_enc FROM stream_timelines WHERE ctid = $1::tid`, ctid).Scan(&stage, &compression, &length, &enc); err != nil {
		t.Fatal(err)
	}
	aad, _ := security.AAD(f.turn, "stream_timeline_v1", stage, compression)
	encoded, err := f.cipher.Decrypt(aad, enc)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := bodycodec.Decode(encoded, compression, int(length))
	if err != nil {
		t.Fatal(err)
	}
	points, err := streamtimeline.Decode(plaintext, 100000)
	if err != nil || len(points) < 2 {
		t.Fatalf("fixture timeline: %d points, %v", len(points), err)
	}
	last := len(points) - 1
	if points[last].Offset-1 <= points[last-1].Offset {
		t.Skip("fixture timeline has no room to move its last offset")
	}
	points[last].Offset--
	changed, err := streamtimeline.Encode(points)
	if err != nil {
		t.Fatal(err)
	}
	noneAAD, _ := security.AAD(f.turn, "stream_timeline_v1", stage, "none")
	sealed, err := f.cipher.Encrypt(noneAAD, changed)
	if err != nil {
		t.Fatal(err)
	}
	restore := captureCompanions(t, f.store, "stream_timelines", ctid, "compression", "plaintext_length")
	return mutation{statement: `UPDATE stream_timelines SET timeline_enc = $2, compression = 'none', plaintext_length = $3 WHERE ctid = $1::tid`,
		arguments: []any{ctid, sealed, len(changed)}, restore: restore}
}

func mutateParsedJSON(t *testing.T, f *digestFixture, ctid string) mutation {
	enc, err := auditmodel.SealParsedResult(f.cipher, f.turn, "openai.chat_completions", []byte(`{"status":"ok","changed":true}`))
	if err != nil {
		t.Fatal(err)
	}
	return mutation{statement: `UPDATE parsed_results SET parsed_json_enc = $2 WHERE ctid = $1::tid`, arguments: []any{ctid, enc}}
}

func mutateExternalValue(t *testing.T, f *digestFixture, ctid string) mutation {
	var objectHash []byte
	var pointer, kind string
	if err := f.store.readerDB.QueryRow(`SELECT object_hash, json_pointer, ref_kind FROM content_external_refs WHERE ctid = $1::tid`, ctid).Scan(&objectHash, &pointer, &kind); err != nil {
		t.Fatal(err)
	}
	aad, _ := security.AAD("external_ref", fmt.Sprintf("%x", objectHash), pointer, kind)
	enc, err := f.cipher.Encrypt(aad, []byte("file-changed"))
	if err != nil {
		t.Fatal(err)
	}
	restore := captureCompanions(t, f.store, "content_external_refs", ctid, "value_hash")
	return mutation{statement: `UPDATE content_external_refs SET value_enc = $2, value_hash = $3 WHERE ctid = $1::tid`,
		arguments: []any{ctid, enc, auditmodel.ExternalValueHash(kind, "file-changed")}, restore: restore}
}

func mutateIdentity(t *testing.T, f *digestFixture, ctid string) mutation {
	aad, err := orgreport.IdentityAAD(f.turn, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := f.cipher.Encrypt(aad, []byte(`{"remotes":["example.com/other"]}`))
	if err != nil {
		t.Fatal(err)
	}
	return mutation{statement: `UPDATE audit_project_identity SET identity_enc = $2 WHERE ctid = $1::tid`, arguments: []any{ctid, enc}}
}

func mutateEventSequence(t *testing.T, f *digestFixture, ctid string) mutation {
	return mutation{statement: `UPDATE integrity_events SET sequence = sequence + 1000000 WHERE ctid = $1::tid`, arguments: []any{ctid}}
}
