package parser

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/parser/handover"
	"llmapi-logger/internal/storage"
)

// The finalizer (issue #59 stage 3, design G) is this worker's goroutine
// with one more input: a job Submit took from the capture session after the
// audit was committed. Processing a job is process without the audit load and
// with the Input built from the job's evidence instead of the stored rows;
// the claim, parse, normalization, preparation, save and analysis are the
// same code, so the backfill watermark's invariants (backfill.go) hold for it
// as they do for a notified audit. The claim stays: SaveParsedAudit only
// updates a row that is processing.

// finalize parses a committed audit from the evidence its session handed
// over.
func (worker *Worker) finalize(ctx, jobCtx context.Context, audit storage.ParserAudit, evidence *handover.Evidence) {
	if !worker.mayClaim(audit.AuditID) || !worker.claim(ctx, jobCtx, audit.AuditID) {
		return
	}
	input, evidenceErr := worker.inputFromEvidence(audit, evidence)
	worker.parseClaimed(ctx, jobCtx, audit, input, evidenceErr)
}

// inputFromEvidence builds the Input loadInput builds from the stored rows of
// the same committed audit (design G.3): the bodies through assembleBody with
// its every check, the content headers and the allowlisted inbound headers
// with the rule of the capture version, the response status code.
func (worker *Worker) inputFromEvidence(audit storage.ParserAudit, evidence *handover.Evidence) (Input, error) {
	request, _, requestErr := worker.memoryBody(audit.AuditID, storage.StageRequestReceived, evidence.CaptureVersion, evidence.Request)
	response, statusCode, responseErr := worker.memoryBody(audit.AuditID, storage.StageResponseReceived, evidence.CaptureVersion, evidence.Response)
	// After the bodies: the version 2 selection clears the request's Header
	// fields it was given.
	headers, err := worker.memoryRequestHeaders(audit.AuditID, evidence, worker.headerNames())
	if err != nil {
		worker.logger.Warn("parser request headers load failed", "audit_id", audit.AuditID, "error_code", "request_headers_load_failed")
		headers = nil
	}
	return Input{
		AuditID:    audit.AuditID,
		Protocol:   audit.Protocol,
		Endpoint:   audit.Path,
		Request:    request,
		Response:   response,
		StatusCode: statusCode,
		Headers:    headers,
	}, errors.Join(requestErr, responseErr)
}

// memoryBody is loadBody on a handed-over stage.
func (worker *Worker) memoryBody(auditID, stageName string, captureVersion int, stage handover.Stage) (BodySource, *int, error) {
	if !stage.Present {
		return BodySource{}, nil, nil
	}
	statusCode := cloneInt(stage.StatusCode)
	if stage.Body == nil {
		return BodySource{}, statusCode, nil
	}
	source := BodySource{Present: true, Complete: true}
	if captureVersion == storage.CaptureVersion2 {
		// The values the stage row stores (C.6) are chosen from these fields
		// by this function.
		contentType, contentEncoding := headerblock.ContentHeaders(stage.Headers)
		if contentType != nil {
			source.ContentType = *contentType
		}
		if contentEncoding != nil {
			source.ContentEncoding = *contentEncoding
		}
	} else if err := worker.decryptContentHeaders(auditID, stageName, contentHeaderRows(stage.HeaderRows), &source); err != nil {
		source.Complete = false
		source.ErrorCode = "capture_integrity_error"
		return source, statusCode, err
	}
	raw, complete, errorCode, err := assembleBody(*stage.Body, memoryChunks(stage.Chunks))
	source, err = decodeBody(source, raw, complete, errorCode, err)
	return source, statusCode, err
}

// contentHeaderRows selects what LoadParserStage reads for version 1: the
// stage's Header rows named content-type or content-encoding in any case,
// ordered by lower-case name, then value_index.
func contentHeaderRows(rows []storage.HTTPHeader) []storage.HTTPHeader {
	selected := make([]storage.HTTPHeader, 0, 2)
	for _, row := range rows {
		if lowered := strings.ToLower(row.Name); row.Kind == storage.HeaderKindHeader && (lowered == "content-type" || lowered == "content-encoding") {
			selected = append(selected, row)
		}
	}
	sortHeaderRows(selected, func(index int) (string, int) { return selected[index].Name, selected[index].ValueIndex })
	return selected
}

// memoryRequestHeaders is loadRequestHeaders on handed-over evidence: version
// 1 decrypts the sealed rows the allowlist selects, in the query's order;
// version 2 filters the Header fields as an opened block is filtered.
func (worker *Worker) memoryRequestHeaders(auditID string, evidence *handover.Evidence, names []string) (http.Header, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if evidence.CaptureVersion == storage.CaptureVersion2 {
		values := headerblock.Flatten([]headerblock.Stage{{Name: storage.StageRequestReceived, Headers: evidence.Request.Headers}})
		return selectAllowlisted(values, names), nil
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		if lowered := strings.ToLower(strings.TrimSpace(name)); lowered != "" {
			allowed[lowered] = true
		}
	}
	rows := make([]storage.HeaderEvidence, 0, len(allowed))
	for _, row := range evidence.Request.HeaderRows {
		if row.Kind == storage.HeaderKindHeader && allowed[strings.ToLower(row.Name)] {
			rows = append(rows, storage.HeaderEvidence{
				Stage: storage.StageRequestReceived, Kind: row.Kind, Name: row.Name,
				ValueIndex: row.ValueIndex, ValueLength: row.ValueLength, ValueEnc: row.ValueEnc,
			})
		}
	}
	sortHeaderRows(rows, func(index int) (string, int) { return rows[index].Name, rows[index].ValueIndex })
	return worker.decryptRequestHeaderRows(auditID, rows)
}

// sortHeaderRows orders rows as the stores' queries do: lower-case name, then
// value_index. The stored name breaks a tie, which the queries leave open.
func sortHeaderRows[Row any](rows []Row, key func(int) (string, int)) {
	sort.SliceStable(rows, func(left, right int) bool {
		leftName, leftIndex := key(left)
		rightName, rightIndex := key(right)
		if lowerLeft, lowerRight := strings.ToLower(leftName), strings.ToLower(rightName); lowerLeft != lowerRight {
			return lowerLeft < lowerRight
		}
		if leftIndex != rightIndex {
			return leftIndex < rightIndex
		}
		return leftName < rightName
	})
}

// memoryChunks is the chunk source of a handed-over body: the plaintext of
// its stored chunks, in seq order.
type memoryChunks []handover.Chunk

func (chunks memoryChunks) page(afterSeq int64) ([]assembledChunk, error) {
	page := make([]assembledChunk, 0, min(len(chunks), parserChunkPage))
	for _, chunk := range chunks {
		if chunk.Seq <= afterSeq {
			continue
		}
		page = append(page, assembledChunk{seq: chunk.Seq, offset: chunk.Offset, plaintext: chunk.Data})
		if len(page) == parserChunkPage {
			break
		}
	}
	return page, nil
}

func (memoryChunks) plaintext(chunk assembledChunk) ([]byte, error) {
	return chunk.plaintext, nil
}
