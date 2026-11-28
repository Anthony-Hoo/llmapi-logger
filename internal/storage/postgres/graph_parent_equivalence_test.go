package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

// The four functions below are saveParsedAudit, persistPreparedTurn,
// chooseTurnParent and bestTurnParent as they were before the parent
// candidates' chains were shared (commit 5df96c2), copied verbatim with only
// their names prefixed. Everything they call is unchanged, so they are the
// reference the present code is compared against.
func legacySaveParsedAudit(transaction dbTransaction, value ParsedAudit, signer *security.IntegritySigner) error {
	if err := upsertParsedResult(transaction, value.Result); err != nil {
		return err
	}

	graphVerified := false
	if value.Turn != nil {
		if err := legacyPersistPreparedTurn(transaction, *value.Turn); err != nil {
			return err
		}
		graphVerified = true
	}

	decision, err := decideRawRetention(transaction, value, graphVerified)
	if err != nil {
		return err
	}
	if err := applySideRetention(transaction, value.Result.AuditID, decision.ReleaseRequest, StageRequestReceived, StageRequestSent); err != nil {
		return err
	}
	if err := applySideRetention(transaction, value.Result.AuditID, decision.ReleaseResponse, StageResponseReceived, StageResponseSent); err != nil {
		return err
	}

	parent, err := transaction.Exec(`
UPDATE audit_records
SET parse_status = $1, parse_next_at_ns = NULL
WHERE audit_id = $2
  AND parser_name = $3
  AND parse_status = 'processing'
  AND forward_status <> 'rejected'`, value.Result.Status, value.Result.AuditID, value.Result.ParserName)
	if err != nil {
		return fmt.Errorf("postgres writer: finish parse status: %w", err)
	}
	if err := requireOneRow(parent, "finish parse status"); err != nil {
		return err
	}
	if graphVerified {
		// A nil cache means single-use: one write covers one audit, so there
		// is no ancestor chain to amortize across.
		payloadDigest, err := semanticPayloadDigest(context.Background(), transaction, nil, value.Result.AuditID)
		if err != nil {
			return err
		}
		if err := appendIntegrityEvent(transaction, signer, value.Result.AuditID, integritySemanticCompacted, payloadDigest, value.Result.ParsedAtNS); err != nil {
			return err
		}
	} else if value.Result.ErrorCode != nil && (*value.Result.ErrorCode == "reconstruction_failed" || *value.Result.ErrorCode == "normalization_failed") {
		payloadDigest, err := reconstructionFailurePayloadDigest(context.Background(), transaction, value.Result.AuditID)
		if err != nil {
			return err
		}
		if err := appendIntegrityEvent(transaction, signer, value.Result.AuditID, integrityReconstructionFailed, payloadDigest, value.Result.ParsedAtNS); err != nil {
			return err
		}
	}
	return nil
}

func legacyPersistPreparedTurn(transaction dbTransaction, turn auditmodel.PreparedTurn) error {
	if err := insertBinaryObjects(transaction, turn); err != nil {
		return err
	}
	if err := insertContentObjects(transaction, turn); err != nil {
		return err
	}
	parent, err := legacyChooseTurnParent(transaction, turn)
	if err != nil {
		return err
	}
	conversationID, err := ensureConversation(transaction, turn, parent)
	if err != nil {
		return err
	}
	base := []auditmodel.ObjectRef(nil)
	parentTurnID := any(nil)
	parentBase := "root"
	linkReason := "root"
	linkConfidence := 100
	if parent != nil {
		base = parent.Base
		parentTurnID = parent.TurnID
		parentBase = parent.BaseKind
		linkReason = parent.Reason
		linkConfidence = parent.Confidence
	}
	operations := auditmodel.BuildDelta(base, turn.RequestRefs)
	if err := insertTurn(transaction, turn, conversationID, parentTurnID, parentBase, linkReason, linkConfidence); err != nil {
		return err
	}
	if err := insertContextOperations(transaction, turn.AuditID, operations); err != nil {
		return err
	}
	if err := insertResponseItems(transaction, turn.AuditID, turn.ResponseRefs); err != nil {
		return err
	}
	if _, err := transaction.Exec(`UPDATE conversations SET updated_at_ns = GREATEST(updated_at_ns, $1) WHERE conversation_id = $2`, turn.CreatedAtNS, conversationID); err != nil {
		return fmt.Errorf("postgres writer: update conversation timestamp: %w", err)
	}

	memo := make(map[string][]auditmodel.ObjectRef)
	reconstructed, err := loadRequestRefs(transaction, turn.AuditID, memo, make(map[string]bool))
	if err != nil {
		return err
	}
	if len(reconstructed) != len(turn.RequestRefs) || !bytes.Equal(auditmodel.SequenceHash(reconstructed), turn.RequestSequenceHash) {
		return localWriteError("postgres writer: persisted request sequence failed reconstruction")
	}
	response, err := loadResponseRefs(transaction, turn.AuditID)
	if err != nil {
		return err
	}
	if len(response) != len(turn.ResponseRefs) || !bytes.Equal(auditmodel.SequenceHash(response), turn.ResponseSequenceHash) {
		return localWriteError("postgres writer: persisted response sequence failed reconstruction")
	}
	return nil
}

func legacyChooseTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn) (*turnParent, error) {
	if turn.PreviousResponseID != "" {
		candidate, err := loadCandidateByResponseID(transaction, turn.Protocol, turn.PreviousResponseID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if candidate != nil {
			return evaluateCandidate(transaction, turn, *candidate, "previous_response_id", 100, linkForced, make(map[string][]auditmodel.ObjectRef))
		}
	}
	if len(turn.ConversationKeyHash) == 32 {
		candidates, err := listTurnCandidates(transaction, `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND c.key_hash = $2 AND t.created_at_ns < $3
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $4`, turn.Protocol, turn.ConversationKeyHash, turn.CreatedAtNS, parentCandidateLimit)
		if err != nil {
			return nil, err
		}
		// A provider-side conversation is one chain whose requests carry only
		// the new input, so content cannot confirm the link; follow the latest
		// earlier turn as the provider does.
		if turn.ServerManagedContext {
			if len(candidates) == 0 {
				return nil, nil
			}
			return evaluateCandidate(transaction, turn, candidates[0], "conversation_key", 95, linkForced, make(map[string][]auditmodel.ObjectRef))
		}
		// A conversation key groups a client session, not one agent: Codex
		// sends the root session id as prompt_cache_key for the parent and
		// every sub-agent, and OpenCode sends a sub-agent's direct parent
		// session id, so the latest keyed turn may belong to a
		// concurrent sibling. Rank the session's recent turns by content
		// instead. When none qualifies, including the key's first turn, the
		// turn starts a new root in its own keyed conversation: the
		// protocol-wide search below would attach it to another session and
		// drop the key, so later turns with this key could not find it.
		return legacyBestTurnParent(transaction, turn, candidates, linkConversationKey)
	}

	candidates, err := listTurnCandidates(transaction, `
SELECT t.turn_id, t.conversation_id
FROM turns AS t
JOIN conversations AS c ON c.conversation_id = t.conversation_id
WHERE c.protocol = $1 AND t.created_at_ns < $2
ORDER BY t.created_at_ns DESC, t.turn_id DESC
LIMIT $3`, turn.Protocol, turn.CreatedAtNS, parentCandidateLimit)
	if err != nil {
		return nil, err
	}
	return legacyBestTurnParent(transaction, turn, candidates, linkInferred)
}

func legacyBestTurnParent(transaction dbTransaction, turn auditmodel.PreparedTurn, candidates []turnCandidate, mode linkMode) (*turnParent, error) {
	// Candidates usually share most of their ancestry, so one memo spares each
	// of them a full walk back to its root.
	memo := make(map[string][]auditmodel.ObjectRef)
	var best *turnParent
	for _, candidate := range candidates {
		evaluated, err := evaluateCandidate(transaction, turn, candidate, "", 0, mode, memo)
		if err != nil {
			return nil, err
		}
		if evaluated != nil && (best == nil || evaluated.cost < best.cost) {
			best = evaluated
		}
	}
	return best, nil
}

// equivalenceObjects is the object pool of the generated graphs: every hash
// keeps one identity, as content addressing guarantees.
type equivalenceObjects struct {
	next    int
	objects map[string]auditmodel.ContentObject
}

func (pool *equivalenceObjects) object(slot, kind string, semantic []byte) auditmodel.ObjectRef {
	pool.next++
	hash := scaleHash("equivalence object", pool.next)
	if semantic == nil {
		semantic = scaleHash("equivalence semantic", pool.next)
	}
	pool.objects[string(hash)] = auditmodel.ContentObject{Hash: hash, SemanticHash: semantic, Kind: kind,
		Compression: auditmodel.CompressionNone, PlaintextLength: 40, EncodedLength: 40, DataEnc: []byte("equivalence-object-ciphertext-padding.")}
	return auditmodel.ObjectRef{Slot: slot, ObjectHash: hash, SemanticHash: semantic}
}

type equivalenceTurn struct {
	request, response []auditmodel.ObjectRef
	responseID        string
	createdAt         int64
}

// equivalenceSnapshot is every row one save writes for its audit, as text.
func equivalenceSnapshot(t *testing.T, transaction *sql.Tx, auditID string) string {
	t.Helper()
	var parts []string
	for _, query := range []string{
		`SELECT row_to_json(t)::text FROM turns AS t WHERE t.audit_id = $1`,
		`SELECT COALESCE(json_agg(o ORDER BY o.op_index)::text, '') FROM turn_context_ops AS o WHERE o.turn_id = $1`,
		`SELECT COALESCE(json_agg(r ORDER BY r.ordinal)::text, '') FROM turn_response_items AS r WHERE r.turn_id = $1`,
		`SELECT COALESCE((SELECT row_to_json(c)::text FROM conversations AS c JOIN turns AS t ON t.conversation_id = c.conversation_id WHERE t.audit_id = $1), '')`,
		`SELECT row_to_json(p)::text FROM parsed_results AS p WHERE p.audit_id = $1`,
		`SELECT parse_status FROM audit_records WHERE audit_id = $1`,
		`SELECT COALESCE(json_agg(json_build_array(e.event_type, encode(e.previous_mac, 'hex'), encode(e.payload_digest, 'hex'), encode(e.event_mac, 'hex'), e.created_at_ns))::text, '')
FROM integrity_events AS e WHERE e.audit_id = $1`,
	} {
		var value sql.NullString
		if err := transaction.QueryRow(query, auditID).Scan(&value); err != nil && err != sql.ErrNoRows {
			t.Fatalf("snapshot %s: %v", auditID, err)
		}
		parts = append(parts, value.String)
	}
	return strings.Join(parts, "\n")
}

func equivalenceExec(t *testing.T, transaction *sql.Tx, statement string, arguments ...any) {
	t.Helper()
	if _, err := transaction.Exec(statement, arguments...); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestTurnParentChoiceMatchesTheLegacyWalks saves the turns of thousands of
// seeded random graphs twice in one savepoint, with the code from before the
// candidate chains were shared (kept above, verbatim but renamed) and with
// the present code, and requires the same outcome: the same error, or the
// same turn row (parent, base, reason, confidence, conversation), context
// ops, response items, conversation, parsed result and integrity event.
//
// The graphs mix keyed and keyless protocols, provider-managed context,
// previous_response_id (also unknown or shared ids), continuations, retries,
// branches, truncations, replaced and deleted middles, semantically equal
// re-encodings, request-only turns, equal timestamps and retention
// checkpoints, and several graphs share a conversation key. A last part
// lowers the preload limits and the chain ref limit so that walks are
// refused and the shared chains fall back, and requires the same refusals.
func TestTurnParentChoiceMatchesTheLegacyWalks(t *testing.T) {
	store, _ := openTestStore(t)
	signer, err := security.NewIntegritySigner(bytes.Repeat([]byte{0x59}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewPCG(59, 4))
	pool := &equivalenceObjects{objects: map[string]auditmodel.ContentObject{}}
	protocols := []string{"openai", "openai", "anthropic", "gemini"}
	clock := int64(1_000_000)
	outcomes := map[string]int{}

	runGraph := func(graph int) {
		protocol := protocols[random.IntN(len(protocols))]
		var keyHash []byte
		managed := false
		if protocol == "openai" && random.Float64() < 0.75 {
			keyHash = scaleHash("equivalence key", random.IntN(40))
			managed = random.Float64() < 0.1
		}
		slot, responseSlot := auditmodel.SlotMessages, auditmodel.SlotChoice
		if protocol == "gemini" {
			slot, responseSlot = auditmodel.SlotContents, auditmodel.SlotContents
		}
		length := 1 + random.IntN(12)
		if random.Float64() < 0.06 {
			length = 20 + random.IntN(25)
		}
		transaction, err := store.writerConn.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback()
		var turns []equivalenceTurn
		newItems := func() []auditmodel.ObjectRef {
			items := make([]auditmodel.ObjectRef, 1+random.IntN(3))
			for index := range items {
				items[index] = pool.object(slot, "user_message", nil)
			}
			return items
		}
		for step := 0; step < length; step++ {
			// Retention now and then deletes everything older than one of
			// this graph's turns, leaving checkpoints behind.
			if len(turns) > 1 && random.Float64() < 0.04 {
				cutoff := turns[random.IntN(len(turns))].createdAt
				equivalenceExec(t, transaction, `SAVEPOINT retention`)
				if err := deleteExpired(transaction, &retentionRequest{CutoffNS: cutoff, AuditLimit: 1 + random.IntN(RetentionBatchLimit), GapLimit: 1}); err != nil {
					equivalenceExec(t, transaction, `ROLLBACK TO SAVEPOINT retention`)
				}
				equivalenceExec(t, transaction, `RELEASE SAVEPOINT retention`)
			}
			var request []auditmodel.ObjectRef
			choice := random.Float64()
			switch {
			case len(turns) == 0 || choice < 0.05:
				request = append([]auditmodel.ObjectRef{pool.object(slot, "system_message", nil)}, newItems()...)
			case choice < 0.45:
				last := turns[len(turns)-1]
				request = append(append(append([]auditmodel.ObjectRef(nil), last.request...), last.response...), newItems()...)
			case choice < 0.55:
				request = append([]auditmodel.ObjectRef(nil), turns[random.IntN(len(turns))].request...)
			case choice < 0.65:
				earlier := turns[random.IntN(len(turns))]
				request = append(append(append([]auditmodel.ObjectRef(nil), earlier.request...), earlier.response...), newItems()...)
			case choice < 0.72:
				// The answer resent as a different object, as Anthropic does.
				last := turns[len(turns)-1]
				request = append([]auditmodel.ObjectRef(nil), last.request...)
				for range last.response {
					request = append(request, pool.object(slot, "assistant_message", nil))
				}
				request = append(request, newItems()...)
			default:
				base := turns[random.IntN(len(turns))]
				request = append(append([]auditmodel.ObjectRef(nil), base.request...), base.response...)
				if len(request) > 2 {
					middle := 1 + random.IntN(len(request)-2)
					switch random.IntN(4) {
					case 0:
						request = request[:middle]
					case 1:
						request = append(request[:middle], request[middle+1:]...)
					case 2:
						request[middle] = pool.object(slot, "user_message", nil)
					default:
						// Same meaning, different bytes.
						request[middle] = pool.object(request[middle].Slot, "user_message", request[middle].SemanticHash)
					}
				}
				request = append(request, newItems()...)
			}
			var response []auditmodel.ObjectRef
			if random.Float64() >= 0.1 {
				for range 1 + random.IntN(2) {
					response = append(response, pool.object(responseSlot, "assistant_message", nil))
				}
			}
			auditID := fmt.Sprintf("eq-%05d-%02d", graph, step)
			responseID := ""
			if protocol == "openai" {
				responseID = "response-" + auditID
				if len(turns) > 0 && random.Float64() < 0.05 {
					responseID = turns[random.IntN(len(turns))].responseID
				}
			}
			previousResponseID := ""
			if len(turns) > 0 && random.Float64() < 0.2 {
				previousResponseID = turns[random.IntN(len(turns))].responseID
				if random.Float64() < 0.1 {
					previousResponseID = "response-unknown"
				}
			}
			if random.Float64() >= 0.1 {
				clock++
			}
			objects := []auditmodel.ContentObject{}
			envelopes := []auditmodel.ObjectRef{pool.object("envelope", "request_envelope", nil), pool.object("envelope", "response_envelope", nil)}
			for _, ref := range append(append(append([]auditmodel.ObjectRef(nil), envelopes...), request...), response...) {
				objects = append(objects, pool.objects[string(ref.ObjectHash)])
			}
			responseLayout := auditmodel.LayoutMarkerEnvelope
			if len(response) == 0 {
				responseLayout = auditmodel.LayoutNone
			}
			turn := auditmodel.PreparedTurn{
				AuditID: auditID, Protocol: protocol, ParserName: "parser",
				RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: responseLayout,
				RequestEnvelopeHash: envelopes[0].ObjectHash, ResponseEnvelopeHash: envelopes[1].ObjectHash,
				RequestRefs: request, ResponseRefs: response,
				RequestSequenceHash: auditmodel.SequenceHash(request), ResponseSequenceHash: auditmodel.SequenceHash(response),
				RequestReconstructionHash: scaleHash("reconstruction", auditID), ResponseReconstructionHash: scaleHash("reconstruction", auditID),
				PreviousResponseID: previousResponseID, ResponseID: responseID, ConversationKeyHash: keyHash,
				ServerManagedContext: managed, CreatedAtNS: clock, Objects: objects,
			}
			equivalenceExec(t, transaction, `
INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status)
VALUES ($1, $2::bigint, $2::bigint + 1, 'route', $3, 'parser', 'POST', '/v1/test', '\x01'::bytea, 'available', 'completed', 'complete', 'processing')`,
				auditID, clock, protocol)
			value := ParsedAudit{
				Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "3", Status: ParseOK, ParsedAtNS: clock + 2},
				Turn:   &turn,
			}
			equivalenceExec(t, transaction, `SAVEPOINT save`)
			legacyErr := legacySaveParsedAudit(transaction, cloneParsedAudit(value), signer)
			legacySnapshot := ""
			if legacyErr == nil {
				legacySnapshot = equivalenceSnapshot(t, transaction, auditID)
			}
			equivalenceExec(t, transaction, `ROLLBACK TO SAVEPOINT save`)
			currentErr := saveParsedAudit(transaction, cloneParsedAudit(value), signer)
			if errorText(currentErr) != errorText(legacyErr) {
				t.Fatalf("%s: legacy error %v, current error %v", auditID, legacyErr, currentErr)
			}
			if currentErr != nil {
				outcomes["refused"]++
				equivalenceExec(t, transaction, `ROLLBACK TO SAVEPOINT save`)
			} else {
				if current := equivalenceSnapshot(t, transaction, auditID); current != legacySnapshot {
					t.Fatalf("%s: rows differ\nlegacy:\n%s\ncurrent:\n%s", auditID, legacySnapshot, current)
				}
				var reason string
				if err := transaction.QueryRow(`SELECT link_reason FROM turns WHERE audit_id = $1`, auditID).Scan(&reason); err != nil {
					t.Fatal(err)
				}
				outcomes[reason]++
			}
			equivalenceExec(t, transaction, `RELEASE SAVEPOINT save`)
			turns = append(turns, equivalenceTurn{request: request, response: response, responseID: responseID, createdAt: clock})
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	// The full run of 2,500 graphs (about 24,000 saves) takes around ten
	// minutes and was what proved the change; set
	// LLMAPI_TEST_PARENT_EQUIVALENCE=full to repeat it. The default keeps the
	// same generator and seeds and runs a prefix that still hits every
	// outcome, so the package stays quick.
	graphs, limitedGraphs := 120, 60
	if raceBuild {
		// The race build runs a shorter prefix of the same graphs; it still
		// reaches every outcome at both limits, which the end requires.
		graphs, limitedGraphs = 40, 30
	}
	if os.Getenv("LLMAPI_TEST_PARENT_EQUIVALENCE") == "full" {
		graphs, limitedGraphs = 2000, 500
	}
	// Every way a turn links is reached, so a shorter prefix (raceBuild)
	// cannot silently stop covering one.
	reasons := []string{"root", "continuation", "branch", "retry", "context_edit", "conversation_key", "previous_response_id"}
	requireReasons := func(limits string) {
		t.Helper()
		for _, reason := range reasons {
			if outcomes[reason] == 0 {
				t.Fatalf("no save at the %s limits linked by %s: %v", limits, reason, outcomes)
			}
		}
	}
	for graph := 0; graph < graphs; graph++ {
		runGraph(graph)
	}
	t.Logf("saves by outcome at the production limits: %v", outcomes)
	requireReasons("production")
	clear(outcomes)

	headers, references, chainRefs := maxAncestorHeaders, maxAncestorReferenceRows, candidateChainRefLimit
	defer func() {
		maxAncestorHeaders, maxAncestorReferenceRows, candidateChainRefLimit = headers, references, chainRefs
	}()
	maxAncestorHeaders, maxAncestorReferenceRows, candidateChainRefLimit = 6, 48, 64
	for graph := graphs; graph < graphs+limitedGraphs; graph++ {
		runGraph(graph)
	}
	t.Logf("saves by outcome at lowered limits: %v", outcomes)
	requireReasons("lowered")
	if outcomes["refused"] == 0 {
		t.Fatal("the lowered limits refused nothing")
	}
}
