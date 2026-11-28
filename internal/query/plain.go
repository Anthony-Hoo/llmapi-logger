package query

import (
	"context"
	"fmt"
	"io"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/storage"
)

// The functions in this file are the assembly half of the query layer: they
// produce the same outputs as Service from rows whose secrets are already
// plaintext, so a reader outside the database (the cold archive reader) and
// the database path share one implementation. They need no cipher and no
// store. Service decrypts and then runs the same code; the only difference
// between the two is where the plaintext comes from.
//
// What stays on the decrypting side only, because plaintext input has nothing
// to check it against: AEAD authentication, the encoded lengths of objects,
// binaries and chunks, the Header ValueLength of a version 1 row, the version
// 2 header block's stage set (headerblock.Expand), and the gunzip of
// parsed_json_enc.

// PlainDetail is storage.AuditQueryDetail with the encrypted columns opened.
// Audit.UserAgentEnc and ParsedResult.Summary.ParsedJSONEnc are not read.
type PlainDetail struct {
	Audit storage.AuditListRow
	// RequestURI is the decrypted request_uri_enc.
	RequestURI []byte
	Stages     []storage.HTTPStage
	// Headers is the flat list headerblock.Expand returns, in its order.
	Headers      []headerblock.Value
	Bodies       []storage.BodyStream
	ParsedResult *PlainParsedResult
	TurnGraph    *PlainTurnGraph
	TokenLink    *storage.TokenLinkSummary
}

// PlainParsedResult is a parsed_results row with parsed_json_enc opened.
type PlainParsedResult struct {
	// Summary holds the row's columns; its ParsedJSONEnc is not read.
	Summary storage.ParsedResultSummary
	// ParsedJSON is the decrypted and decompressed parsed_json_enc, the JSON
	// auditmodel.OpenParsedResult returns. It is nil exactly when the column
	// is NULL or empty; an empty but non-nil value is an integrity error, as
	// a stored value that opens to nothing is.
	ParsedJSON []byte
}

// PlainTurnGraph is storage.TurnGraph with its objects opened. The header
// fields come from the embedded TurnGraph, whose Objects and Binaries are not
// read.
type PlainTurnGraph struct {
	storage.TurnGraph
	Objects  []PlainObject
	Binaries []PlainBinary
}

// PlainObject is one content object: its stored address and metadata and its
// plaintext, the canonical JSON the content hash is taken over.
type PlainObject struct {
	Hash            []byte
	SemanticHash    []byte
	Kind            string
	PlaintextLength int64
	Plaintext       []byte
}

// PlainBinary is one binary object and its bytes.
type PlainBinary struct {
	Hash            []byte
	MediaType       string
	PlaintextLength int64
	Data            []byte
}

// PlainChunk is one owning raw body chunk and its plaintext bytes.
type PlainChunk struct {
	Seq             int64
	Offset          int64
	PlaintextLength int
	Data            []byte
}

// BuildDetail returns what Service.Get returns for the same audit.
func BuildDetail(plain PlainDetail) (Detail, error) {
	var turn func() (ReconstructedTurn, error)
	if plain.TurnGraph != nil {
		turn = func() (ReconstructedTurn, error) { return reconstructPlainAuditTurn(plain) }
	}
	return buildDetail(plain.row(), plain.RequestURI, plain.Headers, plain.openParsed, turn)
}

// BuildMetadata returns what Service.GetMetadata returns for the same audit.
func BuildMetadata(plain PlainDetail) Detail {
	return metadataDetail(plain.row())
}

// BuildSummary returns what Service.List returns for one row, given the
// opened inbound User-Agent values of the audit in stored order.
func BuildSummary(row storage.AuditListRow, userAgents []string) AuditSummary {
	summary := mapAudit(row)
	summary.UserAgent, _ = matchUserAgent(userAgents, "")
	return summary
}

// ReconstructPlainTurn returns what Service.ReconstructTurn returns for the
// same audit, including the partial response merge of a request-only turn,
// and ErrNoTurnGraph when the audit has no turn.
func ReconstructPlainTurn(plain PlainDetail) (ReconstructedTurn, error) {
	if plain.TurnGraph == nil {
		return ReconstructedTurn{}, ErrNoTurnGraph
	}
	return reconstructPlainAuditTurn(plain)
}

// PlainSessionConversation returns what Service.SessionConversation returns
// for the same audit.
func PlainSessionConversation(plain PlainDetail) (*conversation.Conversation, error) {
	var turn func() (ReconstructedTurn, error)
	if plain.TurnGraph != nil {
		turn = func() (ReconstructedTurn, error) { return reconstructPlainAuditTurn(plain) }
	}
	hasParsed := plain.ParsedResult != nil && plain.ParsedResult.ParsedJSON != nil
	return sessionConversation(turn, hasParsed, plain.openParsed)
}

// RawStages lists the stages whose body serves side, most preferred first.
// RawMeta, StreamRaw and Timeline use the first one that has a body_streams
// row.
func RawStages(side Side) ([]string, error) {
	return rawStagesForSide(side)
}

// TimelineFromPlain returns what Service.Timeline returns given the timeline
// row of the selected stage and its decrypted, decompressed plaintext.
// DataEnc and Compression of stored are not read.
func TimelineFromPlain(stored storage.StoredStreamTimeline, plaintext []byte) (StreamTimeline, error) {
	return timelineFromPlaintext(stored, plaintext)
}

// RawMetadataFromPlain returns what Service.RawMeta returns given the body
// metadata of the selected stage.
func RawMetadataFromPlain(metadata storage.RawBodyMetadata) (RawMetadata, error) {
	return rawMetadata(metadata)
}

// VerifyRaw writes the body to destination as Service.StreamRaw does, with
// the same checks and errors, given the body metadata of the selected stage
// and its owning chunks. chunks calls visit for each chunk in stored order
// and returns the first error visit returns.
func VerifyRaw(ctx context.Context, metadata storage.RawBodyMetadata, chunks func(visit func(PlainChunk) error) error, destination io.Writer) error {
	if ctx == nil {
		return invalid("nil context")
	}
	if destination == nil {
		return invalid("nil destination")
	}
	verifier, err := newRawVerifier(metadata)
	if err != nil {
		return err
	}
	err = chunks(func(chunk PlainChunk) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifier.accept(chunk.Seq, chunk.Offset, chunk.PlaintextLength); err != nil {
			return err
		}
		// bodycodec.Decode enforces this on the decrypting side.
		if chunk.PlaintextLength < 0 || len(chunk.Data) != chunk.PlaintextLength {
			return ErrIntegrity
		}
		return verifier.write(destination, chunk.Seq, chunk.Offset, chunk.Data)
	})
	if err != nil {
		return fmt.Errorf("query: stream raw body: %w", err)
	}
	return verifier.finish()
}

// row is the detail's non-secret columns in the form the shared assembly
// reads.
func (plain PlainDetail) row() storage.AuditQueryDetail {
	row := storage.AuditQueryDetail{
		Audit:     plain.Audit,
		Stages:    plain.Stages,
		Bodies:    plain.Bodies,
		TokenLink: plain.TokenLink,
	}
	if plain.ParsedResult != nil {
		summary := plain.ParsedResult.Summary
		row.ParsedResult = &summary
	}
	return row
}

func (plain PlainDetail) openParsed() (parsedEnvelope, error) {
	if plain.ParsedResult == nil || plain.ParsedResult.ParsedJSON == nil {
		return parsedEnvelope{}, nil
	}
	return decodeParsedEnvelope(plain.ParsedResult.ParsedJSON)
}

func reconstructPlainAuditTurn(plain PlainDetail) (ReconstructedTurn, error) {
	return completeAuditTurn(
		func() (ReconstructedTurn, error) {
			return assembleTurnGraph(plain.Audit.ParserName, &plain.TurnGraph.TurnGraph, plainGraphContent(plain.TurnGraph))
		},
		plain.openParsed,
	)
}

// plainGraphContent opens objects by decoding their plaintext, with the
// checks auditmodel.OpenObject and OpenBinary make after decryption: length,
// content address, schema version and kind. Every open decodes afresh.
func plainGraphContent(graph *PlainTurnGraph) graphContent {
	content := graphContent{
		objects:  make([]graphObject, 0, len(graph.Objects)),
		binaries: make([]graphBinary, 0, len(graph.Binaries)),
	}
	for _, object := range graph.Objects {
		content.objects = append(content.objects, graphObject{
			hash: object.Hash, semanticHash: object.SemanticHash, kind: object.Kind,
			wellFormed: len(object.Hash) == 32 && len(object.SemanticHash) == 32 && object.Kind != "" && object.PlaintextLength >= 0,
			open:       func() (auditmodel.DecodedObject, error) { return decodePlainObject(object) },
		})
	}
	for _, binary := range graph.Binaries {
		content.binaries = append(content.binaries, graphBinary{
			hash:       binary.Hash,
			wellFormed: len(binary.Hash) == 32 && binary.MediaType != "" && binary.PlaintextLength >= 0,
			open: func() ([]byte, error) {
				if int64(len(binary.Data)) != binary.PlaintextLength || !auditmodel.EqualHash(auditmodel.BinaryHash(binary.Data), binary.Hash) {
					return nil, auditmodel.ErrIntegrity
				}
				return binary.Data, nil
			},
		})
	}
	return content
}

func decodePlainObject(object PlainObject) (auditmodel.DecodedObject, error) {
	if int64(len(object.Plaintext)) != object.PlaintextLength || !auditmodel.EqualHash(auditmodel.ContentHash(object.Plaintext), object.Hash) {
		return auditmodel.DecodedObject{}, auditmodel.ErrIntegrity
	}
	var decoded auditmodel.DecodedObject
	if err := auditmodel.DecodeJSON(object.Plaintext, &decoded); err != nil || decoded.SchemaVersion != auditmodel.SchemaVersion || decoded.Kind != object.Kind {
		return auditmodel.DecodedObject{}, auditmodel.ErrIntegrity
	}
	return decoded, nil
}
