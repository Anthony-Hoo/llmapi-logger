package sqlite

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/security"
)

type graphTestItem struct {
	kind  string
	value any
}

func TestTurnGraphSupportsRetryEditsSummaryParallelToolsAndBranches(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)

	developer := graphItem("developer_message", map[string]any{"role": "developer", "content": "follow policy"})
	userOne := graphItem("user_message", map[string]any{"role": "user", "content": "question one"})
	assistantOne := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer one"})
	userTwo := graphItem("user_message", map[string]any{"role": "user", "content": "question two"})
	assistantTwo := graphItem("assistant_message", map[string]any{"role": "assistant", "content": "answer two"})

	root := saveGraphTestTurn(t, store, cipher, "turn-root", "", "response-root", 100,
		[]graphTestItem{developer, userOne}, []graphTestItem{assistantOne})
	continuationRequest := []graphTestItem{developer, userOne, assistantOne, userTwo}
	continuation := saveGraphTestTurn(t, store, cipher, "turn-continuation", "response-root", "response-continuation", 200,
		continuationRequest, []graphTestItem{assistantTwo})
	retry := saveGraphTestTurn(t, store, cipher, "turn-retry", "response-root", "response-retry", 300,
		continuationRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "alternate answer"})})
	branch := saveGraphTestTurn(t, store, cipher, "turn-branch", "response-root", "response-branch", 400,
		[]graphTestItem{developer, userOne, assistantOne, graphItem("user_message", map[string]any{"role": "user", "content": "branch question"})},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "branch answer"})})

	summary := graphItem("summary", map[string]any{"type": "summary", "text": "Earlier context was compressed."})
	summaryRequest := []graphTestItem{developer, summary, graphItem("user_message", map[string]any{"role": "user", "content": "continue after summary"})}
	summaryTurn := saveGraphTestTurn(t, store, cipher, "turn-summary", "response-continuation", "response-summary", 500,
		summaryRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "summary continuation"})})
	truncated := saveGraphTestTurn(t, store, cipher, "turn-truncated", "response-continuation", "response-truncated", 600,
		[]graphTestItem{developer, userOne}, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after truncation"})})
	edited := saveGraphTestTurn(t, store, cipher, "turn-edited", "response-continuation", "response-edited", 700,
		[]graphTestItem{developer, graphItem("user_message", map[string]any{"role": "user", "content": "question one edited"}), assistantOne, userTwo},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after edit"})})
	rollback := saveGraphTestTurn(t, store, cipher, "turn-rollback", "response-continuation", "response-rollback", 800,
		[]graphTestItem{developer, userOne, assistantOne},
		[]graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "after rollback"})})

	toolCallOne := graphItem("function_call", map[string]any{"type": "function_call", "call_id": "call-one", "name": "lookup", "arguments": `{"id":1}`})
	toolCallTwo := graphItem("function_call", map[string]any{"type": "function_call", "call_id": "call-two", "name": "lookup", "arguments": `{"id":2}`})
	toolRequest := append(append([]graphTestItem(nil), summaryRequest...), summaryTurnResponseItem())
	toolTurn := saveGraphTestTurn(t, store, cipher, "turn-tools", "response-summary", "response-tools", 900,
		toolRequest, []graphTestItem{toolCallOne, toolCallTwo})
	toolResultOne := graphItem("function_call_output", map[string]any{"type": "function_call_output", "call_id": "call-one", "output": `{"value":"one"}`})
	toolResultTwo := graphItem("function_call_output", map[string]any{"type": "function_call_output", "call_id": "call-two", "output": `{"value":"two"}`})
	toolResultRequest := append(append([]graphTestItem(nil), toolRequest...), toolCallOne, toolCallTwo, toolResultTwo, toolResultOne)
	toolResultTurn := saveGraphTestTurn(t, store, cipher, "turn-tool-results", "response-tools", "response-tool-results", 1000,
		toolResultRequest, []graphTestItem{graphItem("assistant_message", map[string]any{"role": "assistant", "content": "combined result"})})

	assertStoredTurn(t, store, root, nil, "root")
	assertStoredTurn(t, store, continuation, graphStringPointer("turn-root"), "previous_response_id")
	assertStoredTurn(t, store, retry, graphStringPointer("turn-root"), "retry")
	assertStoredTurn(t, store, branch, graphStringPointer("turn-root"), "branch")
	assertStoredTurn(t, store, summaryTurn, graphStringPointer("turn-continuation"), "previous_response_id")
	assertStoredTurn(t, store, truncated, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, edited, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, rollback, graphStringPointer("turn-continuation"), "branch")
	assertStoredTurn(t, store, toolTurn, graphStringPointer("turn-summary"), "previous_response_id")
	assertStoredTurn(t, store, toolResultTurn, graphStringPointer("turn-tools"), "previous_response_id")

	var objectCount int
	if err := store.readerDB.QueryRow(`SELECT COUNT(*) FROM content_objects`).Scan(&objectCount); err != nil {
		t.Fatal(err)
	}
	totalPreparedObjects := len(root.Objects) + len(continuation.Objects) + len(retry.Objects) + len(branch.Objects) +
		len(summaryTurn.Objects) + len(truncated.Objects) + len(edited.Objects) + len(rollback.Objects) +
		len(toolTurn.Objects) + len(toolResultTurn.Objects)
	if objectCount >= totalPreparedObjects {
		t.Fatalf("content objects = %d, prepared copies = %d; expected cross-turn reuse", objectCount, totalPreparedObjects)
	}

}

func TestBinaryObjectsDeduplicateAcrossMediaLabelsAndBase64Spellings(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	data := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x51, 0x29}, 256)...)
	encoded := base64.StdEncoding.EncodeToString(data)
	wrapped := encoded[:32] + "\r\n" + encoded[32:]

	first := graphItem("image", map[string]any{"image_url": "data:image/png;base64," + encoded})
	second := graphItem("image", map[string]any{"image_url": "data:application/octet-stream;base64," + wrapped})
	firstTurn := saveGraphTestTurn(t, store, cipher, "turn-binary-one", "", "response-binary-one", 100, []graphTestItem{first}, nil)
	secondTurn := saveGraphTestTurn(t, store, cipher, "turn-binary-two", "", "response-binary-two", 200, []graphTestItem{second}, nil)
	if len(firstTurn.Binaries) != 1 || len(secondTurn.Binaries) != 1 ||
		!auditmodel.EqualHash(firstTurn.Binaries[0].Hash, secondTurn.Binaries[0].Hash) {
		t.Fatalf("binary hashes were not reused")
	}
	if firstTurn.Binaries[0].MediaType != "application/octet-stream" || secondTurn.Binaries[0].MediaType != "application/octet-stream" {
		t.Fatalf("binary object media types = %q and %q", firstTurn.Binaries[0].MediaType, secondTurn.Binaries[0].MediaType)
	}
	assertTableCount(t, store.readerDB, "binary_objects", 1)
	assertTableCount(t, store.readerDB, "content_binary_refs", 2)
}

func graphItem(kind string, value any) graphTestItem {
	return graphTestItem{kind: kind, value: value}
}

func summaryTurnResponseItem() graphTestItem {
	return graphItem("assistant_message", map[string]any{"role": "assistant", "content": "summary continuation"})
}

func saveGraphTestTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, previousResponseID, responseID string, createdAtNS int64, request, response []graphTestItem) auditmodel.PreparedTurn {
	t.Helper()
	parsed := buildGraphTestTurn(t, store, cipher, auditID, previousResponseID, responseID, createdAtNS, request, response)
	if err := store.SaveParsedAudit(context.Background(), parsed); err != nil {
		t.Fatalf("save %s: %v", auditID, err)
	}
	return *parsed.Turn
}

// buildGraphTestTurn records the capture-side rows and prepares the turn without
// saving it, so a caller that expects the save to be rejected can inspect the
// error itself.
func buildGraphTestTurn(t *testing.T, store *Store, cipher security.Cipher, auditID, previousResponseID, responseID string, createdAtNS int64, request, response []graphTestItem) ParsedAudit {
	t.Helper()
	endedAtNS := createdAtNS + 1
	insertRetentionAudit(t, store, auditID, createdAtNS, &endedAtNS, ParseProcessing, false)
	prepared := prepareGraphTestTurn(t, cipher, auditID, previousResponseID, responseID, createdAtNS, request, response)
	return ParsedAudit{
		Result: ParsedResult{AuditID: auditID, ParserName: "parser", ParserVersion: "2", Status: ParseOK, ParsedAtNS: endedAtNS + 1},
		Turn:   &prepared,
	}
}

// prepareGraphTestTurn builds the turn the writer would be handed without
// touching the store, so a caller can learn the object rows a save will produce.
func prepareGraphTestTurn(t *testing.T, cipher security.Cipher, auditID, previousResponseID, responseID string, createdAtNS int64, request, response []graphTestItem) auditmodel.PreparedTurn {
	t.Helper()
	requestItems, requestValues, requestMarkers := graphSide(request)
	responseItems, responseValues, responseMarkers := graphSide(response)
	prepared, err := auditmodel.Prepare(auditmodel.Turn{
		AuditID: auditID, Protocol: "openai", ParserName: "parser",
		RequestLayout: auditmodel.LayoutMarkerEnvelope, ResponseLayout: auditmodel.LayoutMarkerEnvelope,
		RequestEnvelope:  map[string]any{"model": "model-example", "items": requestMarkers},
		ResponseEnvelope: map[string]any{"id": responseID, "items": responseMarkers},
		RequestItems:     requestItems, ResponseItems: responseItems,
		RequestOriginal:    map[string]any{"model": "model-example", "items": requestValues},
		ResponseOriginal:   map[string]any{"id": responseID, "items": responseValues},
		PreviousResponseID: previousResponseID, ResponseID: responseID, CreatedAtNS: createdAtNS,
	}, cipher)
	if err != nil {
		t.Fatalf("prepare %s: %v", auditID, err)
	}
	return prepared
}

func graphSide(values []graphTestItem) ([]auditmodel.Item, []any, []any) {
	items := make([]auditmodel.Item, 0, len(values))
	original := make([]any, 0, len(values))
	markers := make([]any, 0, len(values))
	for index, value := range values {
		items = append(items, auditmodel.Item{Slot: auditmodel.SlotInput, Kind: value.kind, Value: value.value})
		original = append(original, value.value)
		markers = append(markers, auditmodel.ItemMarker(index))
	}
	return items, original, markers
}

func assertStoredTurn(t *testing.T, store *Store, prepared auditmodel.PreparedTurn, wantParent *string, wantReason string) {
	t.Helper()
	detail, err := store.QueryAuditDetail(context.Background(), prepared.AuditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph := detail.TurnGraph
	if graph == nil || !sameOptionalString(graph.ParentTurnID, wantParent) || graph.LinkReason != wantReason ||
		len(graph.RequestRefs) != len(prepared.RequestRefs) || len(graph.ResponseRefs) != len(prepared.ResponseRefs) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.RequestRefs), prepared.RequestSequenceHash) ||
		!auditmodel.EqualHash(auditmodel.SequenceHash(graph.ResponseRefs), prepared.ResponseSequenceHash) {
		t.Fatalf("stored graph %s = %+v", prepared.AuditID, graph)
	}
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func graphStringPointer(value string) *string {
	return &value
}

func graphTestCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x48}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// TestObjectsReuseRowsEncodedByADifferentCodecBuild seeds the store with object
// rows another build's codec would have written — compression flips and
// different gzip bytes at the same compression, with matching AAD — and then saves the
// same content twice. Both saves must reuse those rows, leave them in place, and
// leave every object openable under an intact integrity chain.
func TestObjectsReuseRowsEncodedByADifferentCodecBuild(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	cipher := graphTestCipher(t)
	request, response := graphObjectFixture()

	// Seeding before the first turn keeps the rows older than every recorded
	// digest, which is what lets integrity cover the reuse: rewriting rows a
	// turn had already been signed over would be plain tampering.
	plaintexts := seedForeignEncodedObjects(t, store, cipher, request, response)
	if err := store.EnableIntegrity(ctx, bytes.Repeat([]byte{0x2d}, security.KeySize)); err != nil {
		t.Fatal(err)
	}
	seeded := countGraphRows(t, store)

	saveGraphTestTurn(t, store, cipher, "turn-codec-one", "", "response-codec-one", 100, request, response)
	assertTableCount(t, store.readerDB, "content_objects", seeded.contentObjects)
	assertTableCount(t, store.readerDB, "binary_objects", seeded.binaryObjects)

	saveGraphTestTurn(t, store, cipher, "turn-codec-two", "", "response-codec-two", 200, request, response)
	// Only the response envelope differs between the two turns, so every other
	// object has to be reused instead of written again.
	assertTableCount(t, store.readerDB, "content_objects", seeded.contentObjects+1)
	assertTableCount(t, store.readerDB, "binary_objects", seeded.binaryObjects)

	for _, auditID := range []string{"turn-codec-one", "turn-codec-two"} {
		assertGraphObjectsOpen(t, store, cipher, auditID, plaintexts)
	}
	if err := store.VerifyIntegrityPayloads(ctx); err != nil {
		t.Fatalf("verify integrity payloads over reused rows: %v", err)
	}
}

// TestObjectIdentityMismatchRejectsTheSecondSave pins what the narrowed identity
// check still covers: each remaining field must reject reuse on its own, and the
// rejected save must leave no rows behind.
func TestObjectIdentityMismatchRejectsTheSecondSave(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		tamper string
	}{
		{name: "content kind", tamper: `UPDATE content_objects SET kind = 'assistant_message_v2' WHERE kind = 'assistant_message'`},
		{name: "content plaintext length", tamper: `UPDATE content_objects SET plaintext_length = plaintext_length + 1 WHERE kind = 'assistant_message'`},
		{name: "content semantic hash", tamper: `UPDATE content_objects SET semantic_hash = zeroblob(32) WHERE kind = 'assistant_message'`},
		{name: "binary media type", tamper: `UPDATE binary_objects SET media_type = 'image/png'`},
		{name: "binary plaintext length", tamper: `UPDATE binary_objects SET plaintext_length = plaintext_length + 1`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			store, _ := openTestStore(t)
			cipher := graphTestCipher(t)
			request, response := graphObjectFixture()
			saveGraphTestTurn(t, store, cipher, "turn-identity-one", "", "response-identity-one", 100, request, response)
			if _, err := store.writerDB.Exec(testCase.tamper); err != nil {
				t.Fatalf("tamper stored identity: %v", err)
			}
			before := countGraphRows(t, store)

			parsed := buildGraphTestTurn(t, store, cipher, "turn-identity-two", "", "response-identity-two", 200, request, response)
			err := store.SaveParsedAudit(context.Background(), parsed)
			if err == nil || !strings.Contains(err.Error(), "hash collision or corruption") {
				t.Fatalf("second save error = %v, want hash collision or corruption", err)
			}
			if after := countGraphRows(t, store); after != before {
				t.Fatalf("rows after rejected save = %+v, want %+v", after, before)
			}
			audit, err := store.LoadParserAudit(context.Background(), parsed.Result.AuditID)
			if err != nil || audit.ParseStatus != ParseProcessing {
				t.Fatalf("rejected save changed parse state: %+v, %v", audit, err)
			}
		})
	}
}

// graphObjectFixture pairs a compressible response with an already compressed
// image so one turn holds content objects on both sides of the compression
// threshold plus a binary object.
func graphObjectFixture() ([]graphTestItem, []graphTestItem) {
	image := map[string]any{"image_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(
		append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x51, 0x29}, 512)...))}
	question := map[string]any{"role": "user", "content": "short question"}
	answer := map[string]any{"role": "assistant", "content": strings.Repeat("compressible payload ", 64)}
	reasoning := map[string]any{"text": strings.Repeat("a different compressible reasoning payload ", 64)}
	return []graphTestItem{graphItem("image", image), graphItem("user_message", question)},
		[]graphTestItem{graphItem("assistant_message", answer), graphItem("reasoning", reasoning)}
}

// seedForeignEncodedObjects writes the object rows of one prepared turn as a
// build whose codec picked another representation would have written them:
// compression, encoded_length and data_enc are set together and the ciphertext is
// bound to AAD carrying the new compression. It returns the plaintext of every
// seeded row, keyed by hex hash.
func seedForeignEncodedObjects(t *testing.T, store *Store, cipher security.Cipher, request, response []graphTestItem) map[string][]byte {
	t.Helper()
	prepared := prepareGraphTestTurn(t, cipher, "turn-codec-one", "", "response-codec-one", 100, request, response)
	plaintexts := make(map[string][]byte)
	flips := make(map[string]int)
	seedForeignContent(t, store, cipher, prepared.Objects, plaintexts, flips)
	seedForeignBinaries(t, store, cipher, prepared.Binaries, plaintexts, flips)
	// A fixture landing every object on the same side of the threshold would
	// never exercise the gzip <-> none flip in both directions.
	if flips[auditmodel.CompressionNone] == 0 || flips[auditmodel.CompressionGZIP] == 0 {
		t.Fatalf("seeded rows per target compression = %v, want both directions", flips)
	}
	if flips["gzip_drift"] == 0 {
		t.Fatal("fixture must include same-compression gzip length drift")
	}
	return plaintexts
}

func seedForeignContent(t *testing.T, store *Store, cipher security.Cipher, objects []auditmodel.ContentObject, plaintexts map[string][]byte, flips map[string]int) {
	t.Helper()
	for _, object := range objects {
		plaintext := openSeedContent(t, cipher, object)
		compression := otherCompression(object.Compression)
		if object.Kind == "reasoning" {
			if object.Compression != auditmodel.CompressionGZIP {
				t.Fatal("reasoning fixture must be gzip encoded")
			}
			compression = auditmodel.CompressionGZIP
		}
		encoded := foreignEncode(t, compression, plaintext)
		if object.Kind == "reasoning" {
			if int64(len(encoded)) == object.EncodedLength {
				t.Fatal("foreign gzip must have a different encoded length")
			}
			flips["gzip_drift"]++
		}
		aad, err := security.AAD("content_object", hex.EncodeToString(object.Hash), object.Kind, compression)
		if err != nil {
			t.Fatal(err)
		}
		dataEnc, err := cipher.Encrypt(aad, encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.writerDB.Exec(`
INSERT INTO content_objects (
    object_hash, semantic_hash, kind, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			object.Hash, object.SemanticHash, object.Kind, compression,
			object.PlaintextLength, int64(len(encoded)), dataEnc, foreignSeedCreatedAtNS,
		); err != nil {
			t.Fatalf("seed content object %x: %v", object.Hash, err)
		}
		plaintexts[hex.EncodeToString(object.Hash)] = plaintext
		if object.Compression != compression {
			flips[compression]++
		}
	}
}

func seedForeignBinaries(t *testing.T, store *Store, cipher security.Cipher, binaries []auditmodel.BinaryObject, plaintexts map[string][]byte, flips map[string]int) {
	t.Helper()
	for _, binary := range binaries {
		plaintext, err := auditmodel.OpenBinary(cipher, auditmodel.StoredBinary{
			Hash: binary.Hash, MediaType: binary.MediaType, Compression: binary.Compression,
			PlaintextLength: binary.PlaintextLength, EncodedLength: binary.EncodedLength, DataEnc: binary.DataEnc,
		})
		if err != nil {
			t.Fatalf("open prepared binary object %x: %v", binary.Hash, err)
		}
		compression := otherCompression(binary.Compression)
		encoded := foreignEncode(t, compression, plaintext)
		aad, err := security.AAD("binary_object", hex.EncodeToString(binary.Hash), compression)
		if err != nil {
			t.Fatal(err)
		}
		dataEnc, err := cipher.Encrypt(aad, encoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.writerDB.Exec(`
INSERT INTO binary_objects (
    binary_hash, media_type, compression, plaintext_length,
    encoded_length, data_enc, created_at_ns
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			binary.Hash, binary.MediaType, compression, binary.PlaintextLength,
			int64(len(encoded)), dataEnc, foreignSeedCreatedAtNS,
		); err != nil {
			t.Fatalf("seed binary object %x: %v", binary.Hash, err)
		}
		plaintexts[hex.EncodeToString(binary.Hash)] = plaintext
		flips[compression]++
	}
}

// openSeedContent recovers the canonical plaintext a prepared content object was
// sealed from, so the seeded row can be re-encoded from the same bytes.
func openSeedContent(t *testing.T, cipher security.Cipher, object auditmodel.ContentObject) []byte {
	t.Helper()
	decoded, err := auditmodel.OpenObject(cipher, auditmodel.StoredContent{
		Hash: object.Hash, SemanticHash: object.SemanticHash, Kind: object.Kind, Compression: object.Compression,
		PlaintextLength: object.PlaintextLength, EncodedLength: object.EncodedLength, DataEnc: object.DataEnc,
	})
	if err != nil {
		t.Fatalf("open prepared content object %x: %v", object.Hash, err)
	}
	plaintext, err := auditmodel.CanonicalJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !auditmodel.EqualHash(auditmodel.ContentHash(plaintext), object.Hash) {
		t.Fatalf("content object %x did not round-trip to its own plaintext", object.Hash)
	}
	return plaintext
}

// foreignSeedCreatedAtNS predates every turn in these tests, so the seeded rows
// read as leftovers from an earlier build.
const foreignSeedCreatedAtNS = 50

func otherCompression(compression string) string {
	if compression == auditmodel.CompressionGZIP {
		return auditmodel.CompressionNone
	}
	return auditmodel.CompressionGZIP
}

// foreignEncode produces the encoded form another build would have stored: the
// plaintext itself for none, and gzip written at a level the codec never uses,
// so the bytes differ from anything Prepare produces.
func foreignEncode(t *testing.T, compression string, plaintext []byte) []byte {
	t.Helper()
	if compression == auditmodel.CompressionNone {
		return append([]byte(nil), plaintext...)
	}
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.HuffmanOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// assertGraphObjectsOpen opens every object one turn's graph exposes and checks
// it still yields the plaintext the row held before it was re-encoded.
func assertGraphObjectsOpen(t *testing.T, store *Store, cipher security.Cipher, auditID string, plaintexts map[string][]byte) {
	t.Helper()
	detail, err := store.QueryAuditDetail(context.Background(), auditID, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph := detail.TurnGraph
	if graph == nil || len(graph.Objects) == 0 || len(graph.Binaries) == 0 {
		t.Fatalf("turn %s graph = %+v, want content and binary objects", auditID, graph)
	}
	for _, object := range graph.Objects {
		decoded, err := auditmodel.OpenObject(cipher, object)
		if err != nil {
			t.Fatalf("open content object %x of %s: %v", object.Hash, auditID, err)
		}
		plaintext, err := auditmodel.CanonicalJSON(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if want, rewritten := plaintexts[hex.EncodeToString(object.Hash)]; rewritten && !bytes.Equal(plaintext, want) {
			t.Fatalf("content object %x of %s opened to a different plaintext", object.Hash, auditID)
		}
	}
	for _, binary := range graph.Binaries {
		plaintext, err := auditmodel.OpenBinary(cipher, binary)
		if err != nil {
			t.Fatalf("open binary object %x of %s: %v", binary.Hash, auditID, err)
		}
		if want, rewritten := plaintexts[hex.EncodeToString(binary.Hash)]; rewritten && !bytes.Equal(plaintext, want) {
			t.Fatalf("binary object %x of %s opened to a different plaintext", binary.Hash, auditID)
		}
	}
}

type graphRowCounts struct {
	parsedResults     int
	contentBinaryRefs int
	turns             int
	contentObjects    int
	binaryObjects     int
}

func countGraphRows(t *testing.T, store *Store) graphRowCounts {
	t.Helper()
	var counts graphRowCounts
	if err := store.readerDB.QueryRow(`
SELECT (SELECT COUNT(*) FROM turns),
       (SELECT COUNT(*) FROM content_objects),
       (SELECT COUNT(*) FROM binary_objects),
       (SELECT COUNT(*) FROM parsed_results),
       (SELECT COUNT(*) FROM content_binary_refs)`).Scan(&counts.turns, &counts.contentObjects, &counts.binaryObjects, &counts.parsedResults, &counts.contentBinaryRefs); err != nil {
		t.Fatal(err)
	}
	return counts
}
