package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"llmapi-logger/internal/storage"
)

// digestSchema names the tables a payload digest reads (D.3).
type digestSchema int

const (
	// schemaLive is a store the proxy opened: every derived migration is
	// applied and audit_records has capture_version.
	schemaLive digestSchema = iota
	// schemaBaseline is the offline import target, which holds the 001
	// tables alone. Every audit there is capture version 1.
	schemaBaseline
)

// capturePayloadDigestFor is the one entry point of the capture_finalized
// digest: the writer (finishAudit), startup recovery and verification all use
// it. It reads capture_version on a live schema and dispatches: version 1 to
// capturePayloadDigest, which is kept byte for byte as it was before version
// 2 existed, version 2 to capturePayloadDigestV2. Any other value is an
// error, so tampering with the column fails payload verification. On the
// import baseline there is no column to read and the version is 1.
func capturePayloadDigestFor(ctx context.Context, transaction dbTransaction, auditID string, schema digestSchema) ([]byte, error) {
	if schema == schemaBaseline {
		return capturePayloadDigest(ctx, transaction, auditID)
	}
	var version int64
	if err := transaction.QueryRowContext(ctx, `SELECT capture_version FROM audit_records WHERE audit_id = $1`, auditID).Scan(&version); err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture version: %w", err)
	}
	switch version {
	case storage.CaptureVersion1:
		return capturePayloadDigest(ctx, transaction, auditID)
	case storage.CaptureVersion2:
		return capturePayloadDigestV2(ctx, transaction, auditID)
	default:
		return nil, fmt.Errorf("postgres integrity: unknown capture version %d", version)
	}
}

// capturePayloadDigestV2 is the capture_finalized digest of a version 2
// audit, the byte sequence of doc/design/issue-59-stage3-write-path.md D.2:
//
//	"llmapi-logger/capture-payload/v2\x00"
//	F(audit_id) I(started_at_ns) I(ended_at_ns)
//	F(route_id) F(protocol) F(parser_name) F(method) F(path) F(mode)
//	F(forward_status) F(capture_status)
//	CD(sha256(request_uri_enc))
//	NI(status_code) NI(ttft_ns) NT(blocked_by) NT(block_code) NT(error_code)
//	NT(newapi_request_id)
//	CD(sha256(user_agent_enc))
//	per http_stages row in stage order:
//	  F("stage") F(stage) F(state) F(proto) F(method) F(host)
//	  NI(status_code) NI(content_length) I(started_at_ns) NI(ended_at_ns)
//	  NT(error_code) NT(content_type) NT(content_encoding)
//	F("header_block") NT(compression) NI(plaintext_length) CD(sha256(block_enc))
//	per body_streams row in stage order, as version 1:
//	  F("body") F(stage) F(source_stage) I(observed_length) F(sha256 or nil)
//	  I(hash_complete) I(eof_seen) F(state) NI(first_observed_at_ns)
//	  NI(last_observed_at_ns) NT(error_code)
//
// where F(x) = u64be(len(x)) || x, I(v) = F(u64be(v)), NI and NT write F(nil)
// for NULL, and CD writes the ciphertext's SHA-256 computed in the database,
// or F(nil) for NULL or empty ciphertext. Without a block row the three block
// fields are each F(nil). capture_version is not a field: the domain string
// binds it. http_headers rows are not covered; a version 2 audit has none and
// headerblock.Expand rejects one that has.
func capturePayloadDigestV2(ctx context.Context, transaction dbTransaction, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(capturePayloadDomainV2)
	encoder.text(auditID)
	var startedAt, endedAt int64
	var routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus string
	var requestURIDigest, userAgentDigest, blockDigest []byte
	var statusCode, ttft, blockLength sql.NullInt64
	var blockedBy, blockCode, errorCode, requestID, blockCompression sql.NullString
	if err := transaction.QueryRowContext(ctx, `
SELECT a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol, a.parser_name,
       a.method, a.path,
       CASE WHEN octet_length(a.request_uri_enc) > 0 THEN sha256(a.request_uri_enc) END,
       a.mode, a.status_code, a.ttft_ns,
       a.forward_status, a.capture_status, a.blocked_by, a.block_code, a.error_code,
       a.newapi_request_id,
       CASE WHEN octet_length(a.user_agent_enc) > 0 THEN sha256(a.user_agent_enc) END,
       b.compression, b.plaintext_length,
       CASE WHEN octet_length(b.block_enc) > 0 THEN sha256(b.block_enc) END
FROM audit_records AS a
LEFT JOIN http_header_blocks AS b ON b.audit_id = a.audit_id
WHERE a.audit_id = $1`, auditID).Scan(
		&startedAt, &endedAt, &routeID, &protocol, &parserName,
		&method, &path, &requestURIDigest, &mode, &statusCode, &ttft,
		&forwardStatus, &captureStatus, &blockedBy, &blockCode, &errorCode,
		&requestID, &userAgentDigest, &blockCompression, &blockLength, &blockDigest,
	); err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture audit: %w", err)
	}
	encoder.integer(startedAt)
	encoder.integer(endedAt)
	for _, value := range []string{routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus} {
		encoder.text(value)
	}
	encoder.ciphertextDigest(requestURIDigest)
	encoder.nullableInteger(statusCode)
	encoder.nullableInteger(ttft)
	encoder.nullableText(blockedBy)
	encoder.nullableText(blockCode)
	encoder.nullableText(errorCode)
	encoder.nullableText(requestID)
	encoder.ciphertextDigest(userAgentDigest)

	stageRows, err := transaction.QueryContext(ctx, `
SELECT stage, state, proto, method, host, status_code, content_length,
       started_at_ns, ended_at_ns, error_code, content_type, content_encoding
FROM http_stages
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture stages: %w", err)
	}
	for stageRows.Next() {
		var stage, state, proto, stageMethod, host string
		var stageStatus, contentLength, stageEnded sql.NullInt64
		var stageStarted int64
		var stageError, contentType, contentEncoding sql.NullString
		if err := stageRows.Scan(&stage, &state, &proto, &stageMethod, &host, &stageStatus, &contentLength, &stageStarted, &stageEnded, &stageError, &contentType, &contentEncoding); err != nil {
			_ = stageRows.Close()
			return nil, err
		}
		encoder.text("stage")
		for _, value := range []string{stage, state, proto, stageMethod, host} {
			encoder.text(value)
		}
		encoder.nullableInteger(stageStatus)
		encoder.nullableInteger(contentLength)
		encoder.integer(stageStarted)
		encoder.nullableInteger(stageEnded)
		encoder.nullableText(stageError)
		encoder.nullableText(contentType)
		encoder.nullableText(contentEncoding)
	}
	if err := closeRows(stageRows); err != nil {
		return nil, err
	}

	encoder.text("header_block")
	encoder.nullableText(blockCompression)
	encoder.nullableInteger(blockLength)
	encoder.ciphertextDigest(blockDigest)

	bodyRows, err := transaction.QueryContext(ctx, `
SELECT stage, source_stage, observed_length, sha256, hash_complete,
       eof_seen, state, first_observed_at_ns, last_observed_at_ns, error_code
FROM body_streams
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres integrity: read capture bodies: %w", err)
	}
	for bodyRows.Next() {
		var stage, sourceStage, state string
		var observed int64
		var digest []byte
		var hashComplete, eofSeen int64
		var first, last sql.NullInt64
		var bodyError sql.NullString
		if err := bodyRows.Scan(&stage, &sourceStage, &observed, &digest, &hashComplete, &eofSeen, &state, &first, &last, &bodyError); err != nil {
			_ = bodyRows.Close()
			return nil, err
		}
		encoder.text("body")
		encoder.text(stage)
		encoder.text(sourceStage)
		encoder.integer(observed)
		encoder.field(digest)
		encoder.integer(hashComplete)
		encoder.integer(eofSeen)
		encoder.text(state)
		encoder.nullableInteger(first)
		encoder.nullableInteger(last)
		encoder.nullableText(bodyError)
	}
	if err := closeRows(bodyRows); err != nil {
		return nil, err
	}
	return encoder.sum(), nil
}
