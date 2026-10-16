package parser

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	parserChunkPage    = 128
	maxEncodedBodySize = MaxDecodedBodyBytes * 2
)

func (worker *Worker) loadInput(ctx context.Context, audit sqlite.ParserAudit) (Input, error) {
	request, _, requestErr := worker.loadBody(ctx, audit.AuditID, sqlite.StageRequestReceived)
	response, statusCode, responseErr := worker.loadBody(ctx, audit.AuditID, sqlite.StageResponseReceived)
	// Headers only feed derived analysis. A failure here is logged and must
	// not downgrade the body evidence status.
	headers, err := worker.loadRequestHeaders(ctx, audit.AuditID, worker.headerNames())
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

// loadRequestHeaders decrypts the allowlisted inbound request headers with the
// same AAD the query service verifies. Any failure discards the partial set.
func (worker *Worker) loadRequestHeaders(ctx context.Context, auditID string, names []string) (http.Header, error) {
	if len(names) == 0 {
		return nil, nil
	}
	evidence, err := worker.store.LoadParserRequestHeaders(ctx, auditID, names)
	if err != nil {
		return nil, err
	}
	if len(evidence) == 0 {
		return nil, nil
	}
	headers := make(http.Header, len(evidence))
	for _, header := range evidence {
		aad, err := security.AAD(auditID, "header", header.Stage, header.Kind, header.Name, strconv.Itoa(header.ValueIndex))
		if err != nil {
			return nil, fmt.Errorf("parser: request header AAD: %w", err)
		}
		plaintext, err := worker.cipher.Decrypt(aad, header.ValueEnc)
		if err != nil || len(plaintext) != header.ValueLength {
			clear(plaintext)
			return nil, errors.New("parser: request header integrity failure")
		}
		headers.Add(header.Name, string(plaintext))
		clear(plaintext)
	}
	return headers, nil
}

func (worker *Worker) loadBody(ctx context.Context, auditID, stageName string) (BodySource, *int, error) {
	stage, err := worker.store.LoadParserStage(ctx, auditID, stageName)
	if errors.Is(err, sql.ErrNoRows) {
		return BodySource{}, nil, nil
	}
	if err != nil {
		return BodySource{ErrorCode: "evidence_read_error"}, nil, err
	}
	statusCode := cloneInt(stage.Stage.StatusCode)
	if stage.Body == nil {
		return BodySource{}, statusCode, nil
	}

	source := BodySource{Present: true, Complete: true}
	if err := worker.decryptContentHeaders(auditID, stageName, stage.Headers, &source); err != nil {
		source.Complete = false
		source.ErrorCode = "capture_integrity_error"
		return source, statusCode, err
	}

	raw, complete, errorCode, err := worker.readRawBody(ctx, auditID, stageName, *stage.Body)
	source.Complete = complete
	source.ErrorCode = errorCode
	if err != nil && len(raw) == 0 {
		return source, statusCode, err
	}

	decoded, decodeCode, decodeErr := decodeContent(raw, source.ContentEncoding)
	source.Data = decoded
	if decodeCode != "" {
		source.Complete = false
		source.ErrorCode = selectEvidenceCode(source.ErrorCode, decodeCode)
	}
	return source, statusCode, errors.Join(err, decodeErr)
}

func (worker *Worker) decryptContentHeaders(auditID, stageName string, headers []sqlite.HTTPHeader, source *BodySource) error {
	for _, header := range headers {
		lowerName := strings.ToLower(header.Name)
		if header.Kind != sqlite.HeaderKindHeader || (lowerName != "content-type" && lowerName != "content-encoding") {
			continue
		}
		aad, err := security.AAD(auditID, "header", stageName, header.Kind, header.Name, strconv.Itoa(header.ValueIndex))
		if err != nil {
			return fmt.Errorf("parser: header AAD: %w", err)
		}
		plaintext, err := worker.cipher.Decrypt(aad, header.ValueEnc)
		if err != nil {
			return fmt.Errorf("parser: decrypt content header: %w", err)
		}
		if len(plaintext) != header.ValueLength {
			return errors.New("parser: content header length mismatch")
		}
		switch lowerName {
		case "content-type":
			if source.ContentType == "" {
				source.ContentType = string(plaintext)
			}
		case "content-encoding":
			if source.ContentEncoding == "" {
				source.ContentEncoding = string(plaintext)
			}
		}
	}
	return nil
}

func (worker *Worker) readRawBody(ctx context.Context, auditID, stageName string, body sqlite.BodyStream) ([]byte, bool, string, error) {
	initialCapacity := int(min(int64(maxEncodedBodySize), body.StoredLength))
	buffer := bytes.NewBuffer(make([]byte, 0, initialCapacity))
	expectedSeq := int64(0)
	expectedOffset := int64(0)
	afterSeq := int64(-1)
	complete := body.State == sqlite.StageStateComplete && body.HashComplete && body.EOFSeen && body.StoredLength == body.ObservedLength

	for {
		chunks, err := worker.store.ReadParserChunks(ctx, auditID, stageName, afterSeq, parserChunkPage)
		if err != nil {
			return buffer.Bytes(), false, "evidence_read_error", err
		}
		if len(chunks) == 0 {
			break
		}
		for _, chunk := range chunks {
			if chunk.Seq != expectedSeq || chunk.Offset != expectedOffset {
				return buffer.Bytes(), false, "capture_integrity_error", errors.New("parser: body chunk sequence or offset mismatch")
			}
			compression := chunk.Compression
			if compression == "" {
				compression = bodycodec.CompressionNone
			}
			aad, err := security.AAD(auditID, "body_chunk_v2", chunk.Stage, strconv.FormatInt(chunk.Seq, 10), compression)
			if err != nil {
				return buffer.Bytes(), false, "capture_integrity_error", fmt.Errorf("parser: body chunk AAD: %w", err)
			}
			encoded, err := worker.cipher.Decrypt(aad, chunk.DataEnc)
			if err != nil && compression == bodycodec.CompressionNone {
				legacyAAD, legacyErr := security.AAD(auditID, "body_chunk", chunk.Stage, strconv.FormatInt(chunk.Seq, 10))
				if legacyErr == nil {
					encoded, err = worker.cipher.Decrypt(legacyAAD, chunk.DataEnc)
				}
			}
			if err != nil {
				return buffer.Bytes(), false, "capture_integrity_error", fmt.Errorf("parser: decrypt body chunk: %w", err)
			}
			if chunk.EncodedLength > 0 && len(encoded) != chunk.EncodedLength {
				clear(encoded)
				return buffer.Bytes(), false, "capture_integrity_error", errors.New("parser: body chunk encoded length mismatch")
			}
			plaintext, decodeErr := bodycodec.Decode(encoded, compression, chunk.PlaintextLength)
			clear(encoded)
			if decodeErr != nil {
				return buffer.Bytes(), false, "capture_integrity_error", errors.New("parser: body chunk decompression failed")
			}
			if buffer.Len()+len(plaintext) > maxEncodedBodySize {
				remaining := maxEncodedBodySize - buffer.Len()
				if remaining > 0 {
					_, _ = buffer.Write(plaintext[:remaining])
				}
				return buffer.Bytes(), false, "body_too_large", errors.New("parser: encoded body exceeds limit")
			}
			_, _ = buffer.Write(plaintext)
			expectedSeq++
			expectedOffset += int64(len(plaintext))
			afterSeq = chunk.Seq
		}
		if len(chunks) < parserChunkPage {
			break
		}
	}

	raw := buffer.Bytes()
	if int64(len(raw)) != body.StoredLength || expectedOffset != body.StoredLength {
		return raw, false, "capture_integrity_error", errors.New("parser: stored body length mismatch")
	}
	if body.HashComplete && len(body.SHA256) == sha256.Size {
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], body.SHA256) {
			return raw, false, "capture_integrity_error", errors.New("parser: body digest mismatch")
		}
	}
	if !complete {
		errorCode := "capture_partial"
		if body.ErrorCode != nil && *body.ErrorCode != "" {
			errorCode = *body.ErrorCode
		}
		return raw, false, errorCode, nil
	}
	return raw, true, "", nil
}

func decodeContent(raw []byte, contentEncoding string) ([]byte, string, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	switch encoding {
	case "", "identity":
		if len(raw) > MaxDecodedBodyBytes {
			return append([]byte(nil), raw[:MaxDecodedBodyBytes]...), "body_too_large", errors.New("parser: decoded body exceeds limit")
		}
		return append([]byte(nil), raw...), "", nil
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "gzip_invalid", fmt.Errorf("parser: open gzip body: %w", err)
		}
		ratioLimit := int64(len(raw)) * MaxGzipRatio
		if ratioLimit < 1 {
			ratioLimit = 1
		}
		readLimit := min(int64(MaxDecodedBodyBytes), ratioLimit)
		decoded, readErr := io.ReadAll(io.LimitReader(reader, readLimit+1))
		closeErr := reader.Close()
		if int64(len(decoded)) > readLimit {
			decoded = decoded[:readLimit]
			if readLimit == ratioLimit && ratioLimit < MaxDecodedBodyBytes {
				return decoded, "gzip_ratio_exceeded", errors.New("parser: gzip expansion ratio exceeded")
			}
			return decoded, "body_too_large", errors.New("parser: decoded body exceeds limit")
		}
		if readErr != nil || closeErr != nil {
			return decoded, "gzip_invalid", errors.Join(readErr, closeErr)
		}
		return decoded, "", nil
	default:
		return nil, "unsupported_content_encoding", fmt.Errorf("parser: unsupported content encoding %q", encoding)
	}
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
