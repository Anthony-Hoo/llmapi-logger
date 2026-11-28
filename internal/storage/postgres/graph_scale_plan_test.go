package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
)

// The turn-graph statements of the parsed-audit write, the object lookup, the
// payload digest and the detail rebuild are measured here on a graph of the
// size a long-running deployment reaches. Each statement the store sends is
// captured with its bound arguments by wrapping the real transaction, so what
// is explained is exactly what the store builds, not a copy of it.

const (
	scaleConversationCount = 700
	// scaleProbeAt is later than every seeded turn.
	scaleProbeAt = int64(1_000_000_000_000)
)

// Conversation lengths cycle through this list: most conversations are short
// and one in ten runs to 200 turns. With 700 conversations that is 20,580
// turns, whose request context averages a few hundred items, near the 220 a
// measured deployment has.
var scaleConversationLengths = []int{1, 1, 2, 3, 5, 8, 13, 21, 40, 200}

// Five in seven conversations are OpenAI with a conversation key; the rest are
// Anthropic and Gemini without one, which take the protocol-wide parent search.
var scaleProtocols = []string{"openai", "openai", "openai", "openai", "openai", "anthropic", "gemini"}

type scaleConversation struct {
	index          int
	protocol       string
	keyHash        []byte
	conversationID string
	turnIDs        []string
	lastRequest    []auditmodel.ObjectRef
	lastResponse   []auditmodel.ObjectRef
	lastResponseID string
	createdAt      []int64
	ops            int
	responseItems  int
}

type scaleFixture struct {
	conversations []*scaleConversation
	objects       map[string]auditmodel.ContentObject
	turns         int
	ops           int
	responseItems int
}

type scaleRows struct {
	auditIDs, auditProtocols                                      []string
	auditStarted                                                  []int64
	conversationIDs, conversationProtocols                        []string
	conversationKeys                                              [][]byte
	conversationCreated                                           []int64
	objectHashes, objectSemantic                                  [][]byte
	objectKinds                                                   []string
	objectLengths, objectCreated                                  []int64
	turnIDs, turnConversations, turnParents, turnBases            []string
	turnReasons, turnResponseIDs                                  []string
	turnRequestEnvelopes, turnResponseEnvelopes                   [][]byte
	turnRequestCounts, turnResponseCounts, turnCreated            []int64
	turnRequestSequences, turnResponseSequences, turnReconstructs [][]byte
	opTurns, opOperations, opSlots                                []string
	opIndexes, opCounts                                           []int64
	opObjects, opSemantic                                         [][]byte
	itemTurns, itemSlots                                          []string
	itemOrdinals                                                  []int64
	itemObjects, itemSemantic                                     [][]byte
}

func scaleHash(parts ...any) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprint(parts...)))
	return digest[:]
}

func scaleSlots(protocol string) (system, request, response string) {
	switch protocol {
	case "anthropic":
		return auditmodel.SlotSystem, auditmodel.SlotMessages, auditmodel.SlotContent
	case "gemini":
		return auditmodel.SlotSystemInstruction, auditmodel.SlotContents, auditmodel.SlotContents
	default:
		return auditmodel.SlotMessages, auditmodel.SlotMessages, auditmodel.SlotChoice
	}
}

// newObject registers one content object row and returns its reference.
func (fixture *scaleFixture) newObject(rows *scaleRows, slot, kind string, createdAt int64, label ...any) auditmodel.ObjectRef {
	hash := scaleHash(append([]any{"object"}, label...)...)
	semantic := scaleHash(append([]any{"semantic"}, label...)...)
	// Plaintext lengths from 120 to 1,019 bytes keep the rows as wide as small
	// messages are, so a full scan of the table is as expensive as it would be.
	length := int64(120 + len(fixture.objects)*37%900)
	fixture.objects[string(hash)] = auditmodel.ContentObject{
		Hash: hash, SemanticHash: semantic, Kind: kind, Compression: auditmodel.CompressionNone,
		PlaintextLength: length, EncodedLength: length, DataEnc: []byte{0x5a},
	}
	rows.objectHashes = append(rows.objectHashes, hash)
	rows.objectSemantic = append(rows.objectSemantic, semantic)
	rows.objectKinds = append(rows.objectKinds, kind)
	rows.objectLengths = append(rows.objectLengths, length)
	rows.objectCreated = append(rows.objectCreated, createdAt)
	return auditmodel.ObjectRef{Slot: slot, ObjectHash: hash, SemanticHash: semantic}
}

// seedTurnGraphAtScale writes a consistent turn graph: every turn's context
// ops rebuild exactly the request its counts and sequence hash record, so the
// real readers walk the seeded chains as they walk written ones. A root
// carries a system item, up to 24 items of earlier context and the first
// request; each later turn extends the previous turn's request and response
// by one to three items, the way a client resends its history.
func seedTurnGraphAtScale(t *testing.T, store *Store) *scaleFixture {
	t.Helper()
	fixture := &scaleFixture{objects: make(map[string]auditmodel.ContentObject)}
	rows := &scaleRows{}
	for index := 0; index < scaleConversationCount; index++ {
		conversation := &scaleConversation{index: index, protocol: scaleProtocols[index%len(scaleProtocols)]}
		length := scaleConversationLengths[index%len(scaleConversationLengths)]
		systemSlot, requestSlot, responseSlot := scaleSlots(conversation.protocol)
		firstAt := int64(1)*1_000_000_000 + int64(index)*1000
		if conversation.protocol == "openai" {
			conversation.keyHash = scaleHash("key", index)
			conversation.conversationID = "conv_" + hex.EncodeToString(conversation.keyHash)
		} else {
			conversation.conversationID = "conv_" + fmt.Sprintf("scale-%04d-%03d", index, 1)
		}
		rows.conversationIDs = append(rows.conversationIDs, conversation.conversationID)
		rows.conversationProtocols = append(rows.conversationProtocols, conversation.protocol)
		rows.conversationKeys = append(rows.conversationKeys, conversation.keyHash)
		rows.conversationCreated = append(rows.conversationCreated, firstAt)

		var base []auditmodel.ObjectRef
		for turn := 1; turn <= length; turn++ {
			turnID := fmt.Sprintf("scale-%04d-%03d", index, turn)
			createdAt := int64(turn)*1_000_000_000 + int64(index)*1000
			request := append([]auditmodel.ObjectRef(nil), base...)
			if turn == 1 {
				request = append(request, fixture.newObject(rows, systemSlot, "system_message", createdAt, index, "system"))
				for prior := 0; prior < index%25; prior++ {
					request = append(request, fixture.newObject(rows, requestSlot, "user_message", createdAt, index, "prior", prior))
				}
			}
			for added := 0; added < 1+turn%3; added++ {
				request = append(request, fixture.newObject(rows, requestSlot, "user_message", createdAt, index, turn, "request", added))
			}
			var response []auditmodel.ObjectRef
			for added := 0; added < 1+turn%2; added++ {
				response = append(response, fixture.newObject(rows, responseSlot, "assistant_message", createdAt, index, turn, "response", added))
			}
			requestEnvelope := fixture.newObject(rows, "envelope", "request_envelope", createdAt, index, turn, "request envelope")
			responseEnvelope := fixture.newObject(rows, "envelope", "response_envelope", createdAt, index, turn, "response envelope")

			parent, parentBase, reason := "", "root", "root"
			if turn > 1 {
				parent, parentBase, reason = conversation.turnIDs[turn-2], "post_turn", "continuation"
			}
			if conversation.protocol == "openai" && turn > 1 {
				reason = "conversation_key"
			}
			responseID := ""
			if conversation.protocol == "openai" {
				responseID = "scale-response-" + turnID
			}
			operations := auditmodel.BuildDelta(base, request)
			for opIndex, operation := range operations {
				rows.opTurns = append(rows.opTurns, turnID)
				rows.opIndexes = append(rows.opIndexes, int64(opIndex))
				rows.opOperations = append(rows.opOperations, operation.Operation)
				rows.opCounts = append(rows.opCounts, int64(operation.Count))
				if operation.Ref != nil {
					rows.opSlots = append(rows.opSlots, operation.Ref.Slot)
					rows.opObjects = append(rows.opObjects, operation.Ref.ObjectHash)
					rows.opSemantic = append(rows.opSemantic, operation.Ref.SemanticHash)
				} else {
					rows.opSlots = append(rows.opSlots, "")
					rows.opObjects = append(rows.opObjects, []byte{})
					rows.opSemantic = append(rows.opSemantic, []byte{})
				}
			}
			for ordinal, ref := range response {
				rows.itemTurns = append(rows.itemTurns, turnID)
				rows.itemOrdinals = append(rows.itemOrdinals, int64(ordinal))
				rows.itemSlots = append(rows.itemSlots, ref.Slot)
				rows.itemObjects = append(rows.itemObjects, ref.ObjectHash)
				rows.itemSemantic = append(rows.itemSemantic, ref.SemanticHash)
			}
			rows.auditIDs = append(rows.auditIDs, turnID)
			rows.auditProtocols = append(rows.auditProtocols, conversation.protocol)
			rows.auditStarted = append(rows.auditStarted, createdAt)
			rows.turnIDs = append(rows.turnIDs, turnID)
			rows.turnConversations = append(rows.turnConversations, conversation.conversationID)
			rows.turnParents = append(rows.turnParents, parent)
			rows.turnBases = append(rows.turnBases, parentBase)
			rows.turnReasons = append(rows.turnReasons, reason)
			rows.turnResponseIDs = append(rows.turnResponseIDs, responseID)
			rows.turnRequestEnvelopes = append(rows.turnRequestEnvelopes, requestEnvelope.ObjectHash)
			rows.turnResponseEnvelopes = append(rows.turnResponseEnvelopes, responseEnvelope.ObjectHash)
			rows.turnRequestCounts = append(rows.turnRequestCounts, int64(len(request)))
			rows.turnResponseCounts = append(rows.turnResponseCounts, int64(len(response)))
			rows.turnRequestSequences = append(rows.turnRequestSequences, auditmodel.SequenceHash(request))
			rows.turnResponseSequences = append(rows.turnResponseSequences, auditmodel.SequenceHash(response))
			rows.turnReconstructs = append(rows.turnReconstructs, scaleHash("reconstruction", turnID))
			rows.turnCreated = append(rows.turnCreated, createdAt)

			conversation.turnIDs = append(conversation.turnIDs, turnID)
			conversation.createdAt = append(conversation.createdAt, createdAt)
			conversation.lastRequest = request
			conversation.lastResponse = response
			conversation.lastResponseID = responseID
			conversation.ops += len(operations)
			conversation.responseItems += len(response)
			fixture.turns++
			fixture.ops += len(operations)
			fixture.responseItems += len(response)
			base = append(append([]auditmodel.ObjectRef(nil), request...), response...)
		}
		fixture.conversations = append(fixture.conversations, conversation)
	}

	ctx := context.Background()
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	type seedStatement struct {
		query     string
		arguments []any
	}
	statements := []seedStatement{
		{`INSERT INTO content_objects (object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns)
SELECT h, s, k, 'none', l, l, decode(repeat('5a', l::int), 'hex'), c
FROM unnest($1::bytea[], $2::bytea[], $3::text[], $4::bigint[], $5::bigint[]) AS u(h, s, k, l, c)`,
			[]any{rows.objectHashes, rows.objectSemantic, rows.objectKinds, rows.objectLengths, rows.objectCreated}},
		{`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status)
SELECT id, s, s + 1, 'route', p, 'parser', 'POST', '/v1/test', '\x01'::bytea, 'available', 'completed', 'complete', 'ok'
FROM unnest($1::text[], $2::bigint[], $3::text[]) AS u(id, s, p)`,
			[]any{rows.auditIDs, rows.auditStarted, rows.auditProtocols}},
		{`INSERT INTO conversations (conversation_id, protocol, key_hash, created_at_ns, updated_at_ns)
SELECT id, p, NULLIF(k, '\x'::bytea), c, c
FROM unnest($1::text[], $2::text[], $3::bytea[], $4::bigint[]) AS u(id, p, k, c)`,
			[]any{rows.conversationIDs, rows.conversationProtocols, nonNilHashes(rows.conversationKeys), rows.conversationCreated}},
		{`INSERT INTO turns (turn_id, audit_id, conversation_id, parent_turn_id, parent_base, link_reason, link_confidence,
    request_layout, response_layout, request_envelope_hash, response_envelope_hash,
    request_item_count, response_item_count, request_sequence_hash, response_sequence_hash,
    request_reconstruction_hash, response_reconstruction_hash, reconstruction_status, response_id, created_at_ns)
SELECT id, id, conv, NULLIF(parent, ''), base, reason, 95, 'marker_envelope', 'marker_envelope', req_env, resp_env,
    req_count, resp_count, req_seq, resp_seq, recon, recon, 'verified', NULLIF(resp_id, ''), created
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bytea[], $7::bytea[], $8::bigint[],
    $9::bigint[], $10::bytea[], $11::bytea[], $12::bytea[], $13::text[], $14::bigint[])
    AS u(id, conv, parent, base, reason, req_env, resp_env, req_count, resp_count, req_seq, resp_seq, recon, resp_id, created)`,
			[]any{rows.turnIDs, rows.turnConversations, rows.turnParents, rows.turnBases, rows.turnReasons,
				rows.turnRequestEnvelopes, rows.turnResponseEnvelopes, rows.turnRequestCounts, rows.turnResponseCounts,
				rows.turnRequestSequences, rows.turnResponseSequences, rows.turnReconstructs, rows.turnResponseIDs, rows.turnCreated}},
		{`INSERT INTO turn_context_ops (turn_id, op_index, operation, item_count, slot, object_hash, semantic_hash)
SELECT id, i, op, n, NULLIF(slot, ''), NULLIF(h, '\x'::bytea), NULLIF(s, '\x'::bytea)
FROM unnest($1::text[], $2::bigint[], $3::text[], $4::bigint[], $5::text[], $6::bytea[], $7::bytea[]) AS u(id, i, op, n, slot, h, s)`,
			[]any{rows.opTurns, rows.opIndexes, rows.opOperations, rows.opCounts, rows.opSlots, rows.opObjects, rows.opSemantic}},
		{`INSERT INTO turn_response_items (turn_id, ordinal, slot, object_hash, semantic_hash)
SELECT * FROM unnest($1::text[], $2::bigint[], $3::text[], $4::bytea[], $5::bytea[])`,
			[]any{rows.itemTurns, rows.itemOrdinals, rows.itemSlots, rows.itemObjects, rows.itemSemantic}},
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatalf("seed graph: %v", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"content_objects", "audit_records", "conversations", "turns", "turn_context_ops", "turn_response_items", "parsed_results", "body_streams"} {
		if _, err := store.writerConn.ExecContext(ctx, `ANALYZE `+table); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func nonNilHashes(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		if value == nil {
			value = []byte{}
		}
		result[index] = value
	}
	return result
}

// nextTurn prepares the turn that continues conversation: its request is the
// last turn's request and response plus one new item, as a client resending
// its history sends it. The objects it already shares carry the identity of
// their stored rows, as the preparation lookup would have returned them.
func (fixture *scaleFixture) nextTurn(t *testing.T, store *Store, conversation *scaleConversation, auditID string, withKey bool, previousResponseID string) ParsedAudit {
	t.Helper()
	_, requestSlot, responseSlot := scaleSlots(conversation.protocol)
	newObject := func(slot, kind, label string) (auditmodel.ObjectRef, auditmodel.ContentObject) {
		hash := scaleHash("probe", auditID, label)
		semantic := scaleHash("probe semantic", auditID, label)
		object := auditmodel.ContentObject{Hash: hash, SemanticHash: semantic, Kind: kind, Compression: auditmodel.CompressionNone,
			PlaintextLength: 200, EncodedLength: 200, DataEnc: []byte(strings.Repeat("z", 200))}
		return auditmodel.ObjectRef{Slot: slot, ObjectHash: hash, SemanticHash: semantic}, object
	}
	request := append(append([]auditmodel.ObjectRef(nil), conversation.lastRequest...), conversation.lastResponse...)
	question, questionObject := newObject(requestSlot, "user_message", "question")
	request = append(request, question)
	answer, answerObject := newObject(responseSlot, "assistant_message", "answer")
	requestEnvelope, requestEnvelopeObject := newObject("envelope", "request_envelope", "request envelope")
	responseEnvelope, responseEnvelopeObject := newObject("envelope", "response_envelope", "response envelope")
	objects := []auditmodel.ContentObject{requestEnvelopeObject, responseEnvelopeObject, questionObject, answerObject}
	for _, ref := range request[:len(request)-1] {
		stored, ok := fixture.objects[string(ref.ObjectHash)]
		if !ok {
			t.Fatalf("probe references an unseeded object")
		}
		objects = append(objects, stored)
	}
	turn := auditmodel.PreparedTurn{
		AuditID: auditID, Protocol: conversation.protocol, ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelopeHash: requestEnvelope.ObjectHash, ResponseEnvelopeHash: responseEnvelope.ObjectHash,
		RequestRefs: request, ResponseRefs: []auditmodel.ObjectRef{answer},
		RequestSequenceHash:        auditmodel.SequenceHash(request),
		ResponseSequenceHash:       auditmodel.SequenceHash([]auditmodel.ObjectRef{answer}),
		RequestReconstructionHash:  scaleHash("probe reconstruction", auditID),
		ResponseReconstructionHash: scaleHash("probe reconstruction", auditID),
		PreviousResponseID:         previousResponseID,
		CreatedAtNS:                scaleProbeAt,
		Objects:                    objects,
	}
	if withKey {
		turn.ConversationKeyHash = conversation.keyHash
	}
	insertRetentionAudit(t, store, auditID, scaleProbeAt, int64Pointer(scaleProbeAt+1), ParseProcessing, false)
	return ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "3", Status: ParseOK, ParsedAtNS: scaleProbeAt + 2},
		Turn:   &turn,
	}
}

// graphPlanNode is planNode with the buffer counters EXPLAIN (BUFFERS) adds.
type graphPlanNode struct {
	NodeType       string          `json:"Node Type"`
	RelationName   string          `json:"Relation Name"`
	IndexName      string          `json:"Index Name"`
	ActualRows     float64         `json:"Actual Rows"`
	ActualLoops    float64         `json:"Actual Loops"`
	RemovedFilter  float64         `json:"Rows Removed by Filter"`
	RemovedRecheck float64         `json:"Rows Removed by Index Recheck"`
	SharedHit      float64         `json:"Shared Hit Blocks"`
	SharedRead     float64         `json:"Shared Read Blocks"`
	Plans          []graphPlanNode `json:"Plans"`
}

type graphPlan struct {
	scans   map[string]*planScan
	buffers float64
}

func parseGraphPlan(t *testing.T, document string) graphPlan {
	t.Helper()
	var plans []struct {
		Plan graphPlanNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(document), &plans); err != nil || len(plans) != 1 {
		t.Fatalf("plan document: %v", err)
	}
	plan := graphPlan{scans: map[string]*planScan{}, buffers: plans[0].Plan.SharedHit + plans[0].Plan.SharedRead}
	var walk func(node graphPlanNode)
	walk = func(node graphPlanNode) {
		if node.RelationName != "" {
			scan := plan.scans[node.RelationName]
			if scan == nil {
				scan = &planScan{}
				plan.scans[node.RelationName] = scan
			}
			scan.nodeTypes = append(scan.nodeTypes, strings.TrimSpace(node.NodeType+" "+node.IndexName))
			scan.examined += (node.ActualRows + node.RemovedFilter + node.RemovedRecheck) * node.ActualLoops
		}
		for _, child := range node.Plans {
			walk(child)
		}
	}
	walk(plans[0].Plan)
	return plan
}

// explainedStatement is one read statement the store sent, explained twice
// against the state it ran on: with its bound arguments (the custom plan) and
// as a prepared statement forced to a generic plan. pgx caches prepared
// statements per connection, so after five executions PostgreSQL may switch
// to the generic plan, and both must stay on the indexes.
type explainedStatement struct {
	phase     string
	statement string
	arguments []any
	custom    graphPlan
	generic   graphPlan
}

// planRecorder is a dbTransaction that explains every read statement just
// before running it on the same transaction. The store never issues a
// statement while rows of another are open on its single connection, so the
// EXPLAIN fits between them.
type planRecorder struct {
	t          *testing.T
	ctx        context.Context
	tx         *sql.Tx
	phase      string
	statements []explainedStatement
}

var placeholderList = regexp.MustCompile(`\$\d+(\s*,\s*\$\d+)+`)
var spaceRun = regexp.MustCompile(`\s+`)

func normalizeStatement(query string) string {
	return strings.TrimSpace(spaceRun.ReplaceAllString(placeholderList.ReplaceAllString(query, "$$n..."), " "))
}

func (recorder *planRecorder) explain(query string, arguments []any) {
	trimmed := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(trimmed, "SELECT") && !strings.HasPrefix(trimmed, "WITH") {
		return
	}
	t := recorder.t
	t.Helper()
	var document string
	if err := recorder.tx.QueryRowContext(recorder.ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+query, arguments...).Scan(&document); err != nil {
		t.Fatalf("explain %s: %v", normalizeStatement(query), err)
	}
	explained := explainedStatement{phase: recorder.phase, statement: normalizeStatement(query), arguments: arguments, custom: parseGraphPlan(t, document)}
	literals := make([]string, len(arguments))
	for index, argument := range arguments {
		literals[index] = sqlLiteral(t, argument)
	}
	for _, step := range []string{`PREPARE graph_scale_probe AS ` + query, `SET LOCAL plan_cache_mode = force_generic_plan`} {
		if _, err := recorder.tx.ExecContext(recorder.ctx, step); err != nil {
			t.Fatalf("prepare generic plan of %s: %v", explained.statement, err)
		}
	}
	execute := `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE graph_scale_probe`
	if len(literals) > 0 {
		execute += "(" + strings.Join(literals, ", ") + ")"
	}
	if err := recorder.tx.QueryRowContext(recorder.ctx, execute).Scan(&document); err != nil {
		t.Fatalf("explain generic plan of %s: %v", explained.statement, err)
	}
	explained.generic = parseGraphPlan(t, document)
	for _, step := range []string{`SET LOCAL plan_cache_mode = auto`, `DEALLOCATE graph_scale_probe`} {
		if _, err := recorder.tx.ExecContext(recorder.ctx, step); err != nil {
			t.Fatal(err)
		}
	}
	recorder.statements = append(recorder.statements, explained)
}

func sqlLiteral(t *testing.T, value any) string {
	t.Helper()
	quote := func(text string) string { return "'" + strings.ReplaceAll(text, "'", "''") + "'" }
	switch typed := value.(type) {
	case nil:
		return "NULL"
	case string:
		return quote(typed)
	case []byte:
		if typed == nil {
			return "NULL"
		}
		return `'\x` + hex.EncodeToString(typed) + `'::bytea`
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case []string:
		quoted := make([]string, len(typed))
		for index, text := range typed {
			quoted[index] = quote(text)
		}
		return "ARRAY[" + strings.Join(quoted, ",") + "]::text[]"
	default:
		t.Fatalf("no literal for argument of type %T", value)
		return ""
	}
}

func (recorder *planRecorder) Exec(query string, arguments ...any) (sql.Result, error) {
	return recorder.tx.ExecContext(recorder.ctx, query, arguments...)
}

func (recorder *planRecorder) ExecContext(ctx context.Context, query string, arguments ...any) (sql.Result, error) {
	return recorder.tx.ExecContext(ctx, query, arguments...)
}

func (recorder *planRecorder) Query(query string, arguments ...any) (*sql.Rows, error) {
	recorder.explain(query, arguments)
	return recorder.tx.QueryContext(recorder.ctx, query, arguments...)
}

func (recorder *planRecorder) QueryContext(ctx context.Context, query string, arguments ...any) (*sql.Rows, error) {
	recorder.explain(query, arguments)
	return recorder.tx.QueryContext(ctx, query, arguments...)
}

func (recorder *planRecorder) QueryRow(query string, arguments ...any) *sql.Row {
	recorder.explain(query, arguments)
	return recorder.tx.QueryRowContext(recorder.ctx, query, arguments...)
}

func (recorder *planRecorder) QueryRowContext(ctx context.Context, query string, arguments ...any) *sql.Row {
	recorder.explain(query, arguments)
	return recorder.tx.QueryRowContext(ctx, query, arguments...)
}

// drain runs a captured-only read whose rows the probe does not need.
func (recorder *planRecorder) drain(query string, arguments ...any) {
	rows, err := recorder.Query(query, arguments...)
	if err != nil {
		recorder.t.Fatal(err)
	}
	for rows.Next() {
	}
	if err := closeRows(rows); err != nil {
		recorder.t.Fatal(err)
	}
}

// Copies of the two reads that run on the reader pool directly instead of on
// a dbTransaction, so the recorder cannot capture them: the detail summary row
// of queryAuditDetail without a scope, and LoadAnalysisAuditMeta. Only their
// turns lookups are of interest here.
const (
	scaleDetailSummaryQuery = `
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol,
       a.parser_name, a.method, a.path, a.mode, a.status_code, a.ttft_ns,
       a.forward_status, a.capture_status, a.parse_status, a.blocked_by,
       a.block_code, a.error_code, p.request_model, p.response_model,
       p.error_type, p.error_code, p.upstream_error_class,
       a.newapi_request_id, a.caller_status,
       t.newapi_user_id, t.username, t.newapi_token_id, t.token_name,
       tn.conversation_id,
       (SELECT COUNT(*) FROM turns AS tc WHERE tc.conversation_id = tn.conversation_id)
FROM audit_records AS a
LEFT JOIN parsed_results AS p ON p.audit_id = a.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
LEFT JOIN turns AS tn ON tn.audit_id = a.audit_id
WHERE a.audit_id = $1`
	scaleAnalysisMetaQuery = `
SELECT r.audit_id, r.started_at_ns, r.ended_at_ns, r.api_key_fpr,
       t.first_event_at_ns, t.last_event_at_ns, g.conversation_id
FROM audit_records AS r
LEFT JOIN body_streams AS b
  ON b.audit_id = r.audit_id AND b.stage = $1
LEFT JOIN stream_timelines AS t
  ON t.audit_id = b.audit_id AND t.stage = b.source_stage
LEFT JOIN turns AS g
  ON g.audit_id = r.audit_id
WHERE r.audit_id = $2`
)

// probeTurnWrite saves value through saveParsedAudit and then reads it back
// the way the object lookup, the detail view, the exports, the payload
// verification and the insights linker do, explaining every read, all inside
// one transaction that is rolled back so each probe sees the same seed.
func probeTurnWrite(t *testing.T, store *Store, value ParsedAudit) []explainedStatement {
	t.Helper()
	ctx := context.Background()
	if err := validateParsedAudit(value); err != nil {
		t.Fatal(err)
	}
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	recorder := &planRecorder{t: t, ctx: ctx, tx: transaction}
	auditID := value.Result.AuditID

	hashes := [][]byte{}
	for _, object := range value.Turn.Objects {
		hashes = append(hashes, object.Hash)
	}
	recorder.phase = "lookup"
	if _, err := readContentObjects(ctx, recorder, hashes, false); err != nil {
		t.Fatal(err)
	}
	recorder.phase = "save"
	if err := saveParsedAudit(recorder, value, nil); err != nil {
		t.Fatalf("save probe %s: %v", auditID, err)
	}
	recorder.phase = "detail"
	graph, err := readTurnGraph(ctx, recorder, auditID)
	if err != nil || graph == nil || len(graph.RequestRefs) != len(value.Turn.RequestRefs) {
		t.Fatalf("rebuild probe %s: %v", auditID, err)
	}
	recorder.drain(scaleDetailSummaryQuery, auditID)
	recorder.phase = "verify"
	if _, err := semanticPayloadDigest(ctx, recorder, newIntegrityGraphCache(), auditID); err != nil {
		t.Fatal(err)
	}
	recorder.phase = "insights"
	recorder.drain(scaleAnalysisMetaQuery, StageResponseReceived, auditID)
	return recorder.statements
}

// statementSummary folds the executions of one statement in one phase.
type statementSummary struct {
	phase, statement string
	executions       int
	nodeTypes        map[string]bool
	genericTypes     map[string]bool
	maxExamined      map[string]float64
	totalExamined    map[string]float64
	maxGeneric       map[string]float64
	buffers          float64
}

func summarizeStatements(statements []explainedStatement) []*statementSummary {
	byKey := map[string]*statementSummary{}
	var order []string
	for _, explained := range statements {
		key := explained.phase + "\x00" + explained.statement
		summary := byKey[key]
		if summary == nil {
			summary = &statementSummary{phase: explained.phase, statement: explained.statement,
				nodeTypes: map[string]bool{}, genericTypes: map[string]bool{}, maxExamined: map[string]float64{},
				totalExamined: map[string]float64{}, maxGeneric: map[string]float64{}}
			byKey[key] = summary
			order = append(order, key)
		}
		summary.executions++
		summary.buffers += explained.custom.buffers
		for table, scan := range explained.custom.scans {
			for _, nodeType := range scan.nodeTypes {
				summary.nodeTypes[table+": "+nodeType] = true
			}
			summary.maxExamined[table] = max(summary.maxExamined[table], scan.examined)
			summary.totalExamined[table] += scan.examined
		}
		for table, scan := range explained.generic.scans {
			for _, nodeType := range scan.nodeTypes {
				summary.genericTypes[table+": "+nodeType] = true
			}
			summary.maxGeneric[table] = max(summary.maxGeneric[table], scan.examined)
		}
	}
	result := make([]*statementSummary, 0, len(order))
	for _, key := range order {
		result = append(result, byKey[key])
	}
	return result
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (summary *statementSummary) String() string {
	label := summary.statement
	if len(label) > 150 {
		label = label[:150] + "..."
	}
	var examined []string
	for _, table := range sortedKeys(summary.maxExamined) {
		examined = append(examined, fmt.Sprintf("%s max %.0f total %.0f (generic max %.0f)", table,
			summary.maxExamined[table], summary.totalExamined[table], summary.maxGeneric[table]))
	}
	return fmt.Sprintf("[%s] x%d %s\n    plan: %v\n    generic: %v\n    rows: %s\n    buffers: %.0f",
		summary.phase, summary.executions, label, sortedKeys(summary.nodeTypes), sortedKeys(summary.genericTypes),
		strings.Join(examined, "; "), summary.buffers)
}

var scaleGraphTables = []string{"turns", "turn_context_ops", "turn_response_items", "content_objects", "conversations"}

func isScaleGraphTable(table string) bool {
	for _, candidate := range scaleGraphTables {
		if candidate == table {
			return true
		}
	}
	return false
}

// isKeylessCandidateStatement reports whether a captured statement is
// chooseTurnParent's protocol-wide search, taken by every turn without a
// conversation key (all Gemini turns and Anthropic or OpenAI turns whose
// client sends no session key), in its parameterised or per-protocol form.
func isKeylessCandidateStatement(statement string) bool {
	if statement == normalizeStatement(keylessCandidateQuery) {
		return true
	}
	for _, query := range keylessCandidateQueries {
		if statement == normalizeStatement(query) {
			return true
		}
	}
	return false
}

func tableRows(t *testing.T, store *Store, table string) float64 {
	t.Helper()
	var count float64
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// keylessCandidateWalk is how many turns the protocol-wide candidate search
// must read when it walks turns newest first: every seeded turn, by
// (created_at_ns, turn_id) descending, up to and including the 32nd one of the
// protocol. It depends on the seed alone.
func (fixture *scaleFixture) keylessCandidateWalk(protocol string, before int64) int {
	type seeded struct {
		createdAt int64
		turnID    string
		protocol  string
	}
	var turns []seeded
	for _, conversation := range fixture.conversations {
		for index, turnID := range conversation.turnIDs {
			if conversation.createdAt[index] < before {
				turns = append(turns, seeded{conversation.createdAt[index], turnID, conversation.protocol})
			}
		}
	}
	sort.Slice(turns, func(a, b int) bool {
		if turns[a].createdAt != turns[b].createdAt {
			return turns[a].createdAt > turns[b].createdAt
		}
		return turns[a].turnID > turns[b].turnID
	})
	found := 0
	for index, turn := range turns {
		if turn.protocol == protocol {
			if found++; found == parentCandidateLimit {
				return index + 1
			}
		}
	}
	return len(turns)
}

// Every statement on the write, lookup, rebuild and verification paths of one
// audit reads only what belongs to the turn: its own conversation's chain, or
// the 32 parent candidates chooseTurnParent evaluates and their chains. The
// protocol-wide candidate search walks turns_created_idx (migration 006)
// newest first and stops at the 32nd turn of the protocol; it is held to
// exactly the turns that walk must read.
//
// The assertions are on executed row counts, not timing, buffers or
// statistics counters, which depend on caching and on when the collector
// flushes. On 20,580 turns, 70,420 context ops and 122,780 objects with fresh
// statistics, an index probe costs a few pages against hundreds or thousands
// for any full scan, so the planner's choice does not flip between runs. The
// bound each statement is held to is the largest conversation's rows, about
// a hundredth of each table, so a statement that starts scanning fails it by
// two orders of magnitude.
func TestTurnGraphQueriesStayInsideTheTurnAtScale(t *testing.T) {
	store, _ := openTestStore(t)
	fixture := seedTurnGraphAtScale(t, store)
	counts := map[string]float64{}
	for _, table := range scaleGraphTables {
		counts[table] = tableRows(t, store, table)
	}
	t.Logf("seeded %d conversations, %d turns, %d context ops, %d response items, %d content objects",
		len(fixture.conversations), fixture.turns, fixture.ops, fixture.responseItems, len(fixture.objects))

	// A chain walk reads at most one conversation: its turns plus the 32
	// candidates the keyed search sorts, its context ops and the response
	// items of its post_turn parents, plus the probe's own rows.
	chainBound := map[string]float64{
		// An object batch carries at most graphHashQueryBatch hashes.
		"content_objects": graphHashQueryBatch,
		"conversations":   2,
	}
	for _, conversation := range fixture.conversations {
		chainBound["turns"] = max(chainBound["turns"], float64(len(conversation.turnIDs)+parentCandidateLimit+2))
		chainBound["turn_context_ops"] = max(chainBound["turn_context_ops"], float64(conversation.ops+4))
		chainBound["turn_response_items"] = max(chainBound["turn_response_items"], float64(conversation.responseItems+2))
	}
	t.Logf("chain bound per statement: %v of tables %v", chainBound, counts)

	latest := func(protocol string, keyed bool) *scaleConversation {
		var found *scaleConversation
		for _, conversation := range fixture.conversations {
			if conversation.protocol != protocol || len(conversation.turnIDs) != 200 || (len(conversation.keyHash) == 32) != keyed {
				continue
			}
			if found == nil || conversation.createdAt[len(conversation.createdAt)-1] > found.createdAt[len(found.createdAt)-1] {
				found = conversation
			}
		}
		if found == nil {
			t.Fatalf("no 200-turn %s conversation", protocol)
		}
		return found
	}
	openai := latest("openai", true)
	gemini := latest("gemini", false)
	anthropic := latest("anthropic", false)

	// chains is the number of conversations among the parent candidates.
	probes := []struct {
		name   string
		value  ParsedAudit
		chains int
	}{
		{"openai turn 201, conversation key", fixture.nextTurn(t, store, openai, "probe-keyed", true, ""), 1},
		{"openai turn 201, previous_response_id", fixture.nextTurn(t, store, openai, "probe-previous", false, openai.lastResponseID), 1},
		{"gemini turn 201, no key", fixture.nextTurn(t, store, gemini, "probe-gemini", false, ""), 10},
		{"anthropic turn 201, no key", fixture.nextTurn(t, store, anthropic, "probe-anthropic", false, ""), 10},
	}
	keylessSearches := 0
	for _, probe := range probes {
		statements := probeTurnWrite(t, store, probe.value)
		keylessTurns := 0.0
		perPhase := map[string]map[string]float64{}
		buffers := map[string]float64{}
		walks := map[string]int{}
		for _, summary := range summarizeStatements(statements) {
			t.Logf("%s: %s", probe.name, summary)
			if perPhase[summary.phase] == nil {
				perPhase[summary.phase] = map[string]float64{}
			}
			for table, rows := range summary.totalExamined {
				perPhase[summary.phase][table] += rows
			}
			buffers[summary.phase] += summary.buffers
			if strings.HasPrefix(summary.statement, "WITH RECURSIVE ancestors") {
				walks[summary.phase] += summary.executions
			}
			if isKeylessCandidateStatement(summary.statement) {
				if summary.statement != normalizeStatement(keylessCandidateQueries[probe.value.Turn.Protocol]) {
					t.Errorf("%s: the protocol-wide search did not use the %s statement: %s", probe.name, probe.value.Turn.Protocol, summary.statement)
				}
				// The walk is fixed by the data: the order (created_at_ns,
				// turn_id) is total and the Limit stops the nested loop at the
				// 32nd turn of the protocol. On this seed the walk reads a
				// hundredth of the table, against a scan of all of it plus a
				// sort, so neither plan form flips between runs. Each turn
				// read joins one conversation, which bounds that side.
				walk := float64(fixture.keylessCandidateWalk(probe.value.Turn.Protocol, probe.value.Turn.CreatedAtNS))
				keylessSearches++
				keylessTurns += summary.totalExamined["turns"]
				if !summary.nodeTypes["turns: Index Scan turns_created_idx"] || !summary.genericTypes["turns: Index Scan turns_created_idx"] ||
					summary.maxExamined["turns"] != walk || summary.maxGeneric["turns"] != walk ||
					summary.maxExamined["conversations"] > walk || summary.maxGeneric["conversations"] > walk {
					t.Errorf("%s: the protocol-wide candidate search does not walk turns_created_idx to the 32nd %s turn (%.0f of %.0f turns): %s",
						probe.name, probe.value.Turn.Protocol, walk, counts["turns"], summary)
				}
				continue
			}
			for _, types := range []map[string]bool{summary.nodeTypes, summary.genericTypes} {
				for nodeType := range types {
					if table, _, _ := strings.Cut(nodeType, ": "); isScaleGraphTable(table) && strings.Contains(nodeType, "Seq Scan") {
						t.Errorf("%s: sequential scan of %s: %s", probe.name, table, summary)
					}
				}
			}
			for _, table := range scaleGraphTables {
				if summary.maxExamined[table] > chainBound[table] || summary.maxGeneric[table] > chainBound[table] {
					t.Errorf("%s: %.0f (generic %.0f) rows of %s, above the chain bound %.0f: %s",
						probe.name, summary.maxExamined[table], summary.maxGeneric[table], table, chainBound[table], summary)
				}
			}
		}
		for _, phase := range sortedKeys(perPhase) {
			var totals []string
			for _, table := range scaleGraphTables {
				if rows := perPhase[phase][table]; rows > 0 {
					totals = append(totals, fmt.Sprintf("%s %.0f", table, rows))
				}
			}
			t.Logf("%s, %s total: %d ancestor header queries, %.0f buffers, rows %s", probe.name, phase, walks[phase], buffers[phase], strings.Join(totals, ", "))
		}
		// Choosing the parent walks each chain the candidates lie on about
		// once: one chain for a keyed conversation or a forced link, one per
		// conversation among the 32 newest turns of the protocol for a keyless
		// turn (ten here). The keyed candidate list reads its conversation once
		// more, and reconstruction and the digest add one turn. Walking once per
		// candidate, as before, read 30 times the chain and fails this.
		save := perPhase["save"]
		turnsRead := save["turns"] - keylessTurns // the protocol-wide search, held above
		allowed := float64(probe.chains + 2)
		if turnsRead > allowed*chainBound["turns"] || save["turn_context_ops"] > allowed*chainBound["turn_context_ops"] ||
			save["turn_response_items"] > allowed*chainBound["turn_response_items"] {
			t.Errorf("%s: saving read %.0f turns, %.0f context ops and %.0f response items, more than %v walks of a chain",
				probe.name, turnsRead, save["turn_context_ops"], save["turn_response_items"], allowed)
		}
	}
	if keylessSearches != 2 {
		t.Fatalf("%d probes took the protocol-wide candidate search, want the two keyless ones", keylessSearches)
	}
	measureCandidateChains(t, store, openai)
}

// measureCandidateChains loads the 32 parent candidates of a keyed 200-turn
// conversation as bestTurnParent does and reports what that reads and what
// it holds: the chain is walked once, and the memory is one request per
// candidate plus one frame per turn of the chain.
func measureCandidateChains(t *testing.T, store *Store, conversation *scaleConversation) {
	t.Helper()
	ctx := context.Background()
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	var candidates []turnCandidate
	for index := len(conversation.turnIDs) - 1; index >= len(conversation.turnIDs)-parentCandidateLimit; index-- {
		candidates = append(candidates, turnCandidate{turnID: conversation.turnIDs[index], conversationID: conversation.conversationID})
	}
	recorder := &planRecorder{t: t, ctx: ctx, tx: transaction}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	chains := loadCandidateChains(recorder, candidates)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if chains == nil {
		t.Fatal("the candidate chains fell back")
	}
	read := map[string]float64{}
	for _, explained := range recorder.statements {
		for table, scan := range explained.custom.scans {
			read[table] += scan.examined
		}
	}
	t.Logf("32 candidates of a 200-turn chain: read %v; hold %d requests of %d refs in all (%.0f per request), %d frames, %d bytes live",
		read, len(chains.refs), chains.total, float64(chains.total)/float64(len(chains.refs)), len(chains.frames), int64(after.HeapAlloc)-int64(before.HeapAlloc))
	if read["turn_context_ops"] > float64(conversation.ops+parentCandidateLimit) || len(chains.frames) != len(conversation.turnIDs) {
		t.Errorf("loading the candidates walked more than the chain once: %v, %d frames", read, len(chains.frames))
	}
	runtime.KeepAlive(chains)
}

// seedFlatTurns writes root turns of protocol at the given times, perConversation
// turns to a conversation, with the fewest rows the turns table needs: one
// shared envelope object and one audit per turn.
func seedFlatTurns(t *testing.T, store *Store, prefix, protocol string, createdAt []int64, perConversation int) {
	t.Helper()
	ids := make([]string, len(createdAt))
	conversations := make([]string, len(createdAt))
	for index := range createdAt {
		ids[index] = fmt.Sprintf("%s-%07d", prefix, index)
		conversations[index] = fmt.Sprintf("conv_%s_%06d", prefix, index/perConversation)
	}
	ctx := context.Background()
	transaction, err := store.writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	statements := []struct {
		query     string
		arguments []any
	}{
		{`INSERT INTO content_objects (object_hash, semantic_hash, kind, compression, plaintext_length, encoded_length, data_enc, created_at_ns)
VALUES (decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'), 'request_envelope', 'none', 1, 1, '\x5a'::bytea, 1)
ON CONFLICT DO NOTHING`, nil},
		{`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status)
SELECT id, s, s + 1, 'route', $3::text, 'parser', 'POST', '/v1/test', '\x01'::bytea, 'available', 'completed', 'complete', 'ok'
FROM unnest($1::text[], $2::bigint[]) AS u(id, s)`, []any{ids, createdAt, protocol}},
		{`INSERT INTO conversations (conversation_id, protocol, key_hash, created_at_ns, updated_at_ns)
SELECT DISTINCT c, $1::text, NULL::bytea, 1, 1 FROM unnest($2::text[]) AS u(c)`, []any{protocol, conversations}},
		{`INSERT INTO turns (turn_id, audit_id, conversation_id, parent_turn_id, parent_base, link_reason, link_confidence,
    request_layout, response_layout, request_envelope_hash, response_envelope_hash,
    request_item_count, response_item_count, request_sequence_hash, response_sequence_hash,
    request_reconstruction_hash, response_reconstruction_hash, reconstruction_status, response_id, created_at_ns)
SELECT id, id, c, NULL, 'root', 'root', 95, 'marker_envelope', 'marker_envelope',
    decode(repeat('11', 32), 'hex'), decode(repeat('11', 32), 'hex'), 1, 1,
    sha256(id::bytea), sha256(id::bytea), sha256(id::bytea), sha256(id::bytea), 'verified', NULL, s
FROM unnest($1::text[], $2::text[], $3::bigint[]) AS u(id, c, s)`, []any{ids, conversations, createdAt}},
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatalf("seed flat turns: %v", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

// A protocol with fewer than 32 earlier turns cannot stop the newest-first
// walk of turns_created_idx early. A plan that does not know the protocol, as
// the generic plan of a parameterised statement does not, walks the whole
// index then: 317,005 turns and about 140 ms on 317,000 turns, against a
// 39 ms sequential scan before the index. With the protocol written into the
// statement, both the custom and the forced generic plan start from the
// protocol's conversations and read only its turns, and the common protocol
// still walks the index to its 32nd turn. Row counts are fixed by the seed:
// the rare protocol's five turns are the oldest, so walking the index would
// read every turn, and the common protocol's newest 32 turns are contiguous.
func TestKeylessCandidateSearchKnowsTheProtocolAtScale(t *testing.T) {
	sizes := []int{20_000, 317_000}
	if testing.Short() || raceBuild {
		// The plan is checked at 20,000 turns as well; the race build leaves
		// out the 317,000-turn repetition, which seeds for most of the time.
		sizes = sizes[:1]
	}
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			store, _ := openTestStore(t)
			const base = int64(1_000_000_000)
			common := make([]int64, size)
			for index := range common {
				common[index] = base + int64(index+10)*1000
			}
			for start := 0; start < size; start += 50_000 {
				seedFlatTurns(t, store, fmt.Sprintf("openai%02d", start/50_000), "openai", common[start:min(start+50_000, size)], 10)
			}
			seedFlatTurns(t, store, "gemini", "gemini", []int64{base + 1000, base + 2000, base + 3000, base + 4000, base + 5000}, 5)
			for _, table := range []string{"turns", "conversations"} {
				if _, err := store.writerConn.ExecContext(context.Background(), `ANALYZE `+table); err != nil {
					t.Fatal(err)
				}
			}
			before := base + int64(size+100)*1000
			for _, probe := range []struct {
				protocol string
				turns    float64 // what the search must read
				walk     bool    // along turns_created_idx
			}{
				{"gemini", 5, false},
				{"anthropic", 0, false}, // no turns of it yet
				{"openai", parentCandidateLimit, true},
			} {
				ctx := context.Background()
				transaction, err := store.writerConn.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				recorder := &planRecorder{t: t, ctx: ctx, tx: transaction, phase: "keyless"}
				if _, err := listKeylessCandidates(recorder, probe.protocol, before); err != nil {
					t.Fatal(err)
				}
				_ = transaction.Rollback()
				summary := summarizeStatements(recorder.statements)[0]
				t.Logf("%d turns, %s: %s", size, probe.protocol, summary)
				walksIndex := summary.nodeTypes["turns: Index Scan turns_created_idx"] || summary.genericTypes["turns: Index Scan turns_created_idx"]
				if summary.maxExamined["turns"] != probe.turns || summary.maxGeneric["turns"] != probe.turns || walksIndex != probe.walk {
					t.Errorf("%d turns, %s: read %.0f (generic %.0f) turns, want %.0f, index walk %v: %s",
						size, probe.protocol, summary.maxExamined["turns"], summary.maxGeneric["turns"], probe.turns, walksIndex, summary)
				}
			}
		})
	}
}
