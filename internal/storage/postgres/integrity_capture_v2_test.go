package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

// referenceCapturePayloadDigestV2 is the in-process counterpart of
// capturePayloadDigestV2, in the style of integrity_reference_test.go: every
// ciphertext column is carried into the process and hashed there. It must not
// be refactored onto the production function.
func referenceCapturePayloadDigestV2(ctx context.Context, transaction dbTransaction, auditID string) ([]byte, error) {
	encoder := newDigestEncoder(capturePayloadDomainV2)
	encoder.text(auditID)
	var startedAt, endedAt int64
	var routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus string
	var requestURI, userAgent, block []byte
	var statusCode, ttft, blockLength sql.NullInt64
	var blockedBy, blockCode, errorCode, requestID, blockCompression sql.NullString
	if err := transaction.QueryRowContext(ctx, `
SELECT a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol, a.parser_name,
       a.method, a.path, a.request_uri_enc, a.mode, a.status_code, a.ttft_ns,
       a.forward_status, a.capture_status, a.blocked_by, a.block_code, a.error_code,
       a.newapi_request_id, a.user_agent_enc, b.compression, b.plaintext_length, b.block_enc
FROM audit_records AS a
LEFT JOIN http_header_blocks AS b ON b.audit_id = a.audit_id
WHERE a.audit_id = $1`, auditID).Scan(
		&startedAt, &endedAt, &routeID, &protocol, &parserName,
		&method, &path, &requestURI, &mode, &statusCode, &ttft,
		&forwardStatus, &captureStatus, &blockedBy, &blockCode, &errorCode,
		&requestID, &userAgent, &blockCompression, &blockLength, &block,
	); err != nil {
		return nil, fmt.Errorf("reference: read capture audit: %w", err)
	}
	encoder.integer(startedAt)
	encoder.integer(endedAt)
	for _, value := range []string{routeID, protocol, parserName, method, path, mode, forwardStatus, captureStatus} {
		encoder.text(value)
	}
	referenceBlobDigest(encoder, requestURI)
	encoder.nullableInteger(statusCode)
	encoder.nullableInteger(ttft)
	encoder.nullableText(blockedBy)
	encoder.nullableText(blockCode)
	encoder.nullableText(errorCode)
	encoder.nullableText(requestID)
	referenceBlobDigest(encoder, userAgent)

	stageRows, err := transaction.QueryContext(ctx, `
SELECT stage, state, proto, method, host, status_code, content_length,
       started_at_ns, ended_at_ns, error_code, content_type, content_encoding
FROM http_stages
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, err
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
	referenceBlobDigest(encoder, block)

	bodyRows, err := transaction.QueryContext(ctx, `
SELECT stage, source_stage, observed_length, sha256, hash_complete,
       eof_seen, state, first_observed_at_ns, last_observed_at_ns, error_code
FROM body_streams
WHERE audit_id = $1
ORDER BY `+stageOrderSQL, auditID)
	if err != nil {
		return nil, err
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

// The fixed test vector of the version 2 capture payload digest (design D.2).
//
// Fixture "vector-v2" (every value below is stored exactly so):
//
//	audit_records: audit_id "vector-v2", started_at_ns 1000, ended_at_ns 2000,
//	  route_id "chat", protocol "openai", parser_name "openai.chat_completions",
//	  method "POST", path "/v1/chat/completions", mode "available",
//	  forward_status "completed", capture_status "complete",
//	  request_uri_enc the 14 bytes "uri-ciphertext", status_code 200,
//	  ttft_ns 50, blocked_by, block_code and error_code NULL,
//	  newapi_request_id "req-1", capture_version 2,
//	  user_agent_enc the 13 bytes "ua-ciphertext"
//	http_stages, in stage order:
//	  request_for_newapi_received_from_nginx: state "complete", proto
//	    "HTTP/1.1", method "POST", host "proxy.example.com", status_code
//	    NULL, content_length 17, started_at_ns 1001, ended_at_ns 1500,
//	    error_code NULL, content_type "application/json", content_encoding NULL
//	  response_received_from_newapi: state "partial", proto "HTTP/1.1",
//	    method "", host "", status_code 200, content_length NULL,
//	    started_at_ns 1600, ended_at_ns 1900, error_code "process_exit",
//	    content_type "text/event-stream", content_encoding "gzip"
//	http_header_blocks: compression "gzip", plaintext_length 321,
//	  block_enc the 16 bytes "block-ciphertext"
//	body_streams, in stage order:
//	  request_for_newapi_received_from_nginx: source_stage itself,
//	    observed_length 17, sha256 32 bytes of 0x11, hash_complete 1,
//	    eof_seen 1, state "complete", first 1100, last 1200, error_code NULL
//	  response_received_from_newapi: source_stage itself, observed_length 64,
//	    sha256 NULL, hash_complete 0, eof_seen 0, state "partial", first and
//	    last NULL, error_code "process_exit"
//
// Fixture "vector-v2-bare" differs: no block row, user_agent_enc NULL,
// ended_at_ns 1500, forward_status "client_cancelled", capture_status
// "partial", status_code and ttft_ns NULL, error_code "client_cancelled",
// newapi_request_id NULL, a single request_for_newapi_received_from_nginx
// stage (state "partial", proto "HTTP/2.0", method "GET", host
// "proxy.example.com", status_code NULL, content_length -1, started_at_ns
// 1001, ended_at_ns 1400, error_code "client_cancelled", both content columns
// NULL) and no body rows.
const (
	captureV2VectorDigest     = "7d919981bd470e8fd6889a35e6fec56dee3aca8715eb0ce446c46bdaac71fad2"
	captureV2BareVectorDigest = "61321b162f603cf951d17ce47daf28cbd140dc4c4365a87b0839374730c89f23"
)

// vectorPreimage writes the D.2 encoding by hand, with helpers of its own, so
// a second implementation can check itself against the bytes as well as the
// digest.
type vectorPreimage struct{ bytes.Buffer }

func (preimage *vectorPreimage) f(value []byte) {
	_ = binary.Write(&preimage.Buffer, binary.BigEndian, uint64(len(value)))
	preimage.Write(value)
}
func (preimage *vectorPreimage) s(value string) { preimage.f([]byte(value)) }
func (preimage *vectorPreimage) i(value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	preimage.f(encoded[:])
}
func (preimage *vectorPreimage) null() { preimage.f(nil) }
func (preimage *vectorPreimage) hashOf(value string) {
	sum := sha256.Sum256([]byte(value))
	preimage.f(sum[:])
}

func captureV2VectorPreimage() []byte {
	var p vectorPreimage
	p.WriteString("llmapi-logger/capture-payload/v2\x00")
	p.s("vector-v2")
	p.i(1000)
	p.i(2000)
	for _, value := range []string{"chat", "openai", "openai.chat_completions", "POST", "/v1/chat/completions", "available", "completed", "complete"} {
		p.s(value)
	}
	p.hashOf("uri-ciphertext")
	p.i(200)     // status_code
	p.i(50)      // ttft_ns
	p.null()     // blocked_by
	p.null()     // block_code
	p.null()     // error_code
	p.s("req-1") // newapi_request_id
	p.hashOf("ua-ciphertext")
	p.s("stage")
	for _, value := range []string{"request_for_newapi_received_from_nginx", "complete", "HTTP/1.1", "POST", "proxy.example.com"} {
		p.s(value)
	}
	p.null() // status_code
	p.i(17)
	p.i(1001)
	p.i(1500)
	p.null() // error_code
	p.s("application/json")
	p.null() // content_encoding
	p.s("stage")
	for _, value := range []string{"response_received_from_newapi", "partial", "HTTP/1.1", "", ""} {
		p.s(value)
	}
	p.i(200)
	p.null() // content_length
	p.i(1600)
	p.i(1900)
	p.s("process_exit")
	p.s("text/event-stream")
	p.s("gzip")
	p.s("header_block")
	p.s("gzip")
	p.i(321)
	p.hashOf("block-ciphertext")
	p.s("body")
	p.s("request_for_newapi_received_from_nginx")
	p.s("request_for_newapi_received_from_nginx")
	p.i(17)
	p.f(bytes.Repeat([]byte{0x11}, 32))
	p.i(1)
	p.i(1)
	p.s("complete")
	p.i(1100)
	p.i(1200)
	p.null()
	p.s("body")
	p.s("response_received_from_newapi")
	p.s("response_received_from_newapi")
	p.i(64)
	p.null() // sha256
	p.i(0)
	p.i(0)
	p.s("partial")
	p.null()
	p.null()
	p.s("process_exit")
	return p.Bytes()
}

func captureV2BareVectorPreimage() []byte {
	var p vectorPreimage
	p.WriteString("llmapi-logger/capture-payload/v2\x00")
	p.s("vector-v2-bare")
	p.i(1000)
	p.i(1500)
	for _, value := range []string{"chat", "openai", "openai.chat_completions", "POST", "/v1/chat/completions", "available", "client_cancelled", "partial"} {
		p.s(value)
	}
	p.hashOf("uri-ciphertext")
	p.null() // status_code
	p.null() // ttft_ns
	p.null() // blocked_by
	p.null() // block_code
	p.s("client_cancelled")
	p.null() // newapi_request_id
	p.null() // user_agent_enc
	p.s("stage")
	for _, value := range []string{"request_for_newapi_received_from_nginx", "partial", "HTTP/2.0", "GET", "proxy.example.com"} {
		p.s(value)
	}
	p.null() // status_code
	p.i(-1)
	p.i(1001)
	p.i(1400)
	p.s("client_cancelled")
	p.null() // content_type
	p.null() // content_encoding
	p.s("header_block")
	p.null() // compression
	p.null() // plaintext_length
	p.null() // block_enc
	return p.Bytes()
}

func TestCaptureV2VectorPreimage(t *testing.T) {
	for _, vector := range []struct {
		name     string
		preimage []byte
		want     string
	}{
		{"vector-v2", captureV2VectorPreimage(), captureV2VectorDigest},
		{"vector-v2-bare", captureV2BareVectorPreimage(), captureV2BareVectorDigest},
	} {
		sum := sha256.Sum256(vector.preimage)
		if got := hex.EncodeToString(sum[:]); got != vector.want {
			t.Errorf("%s: digest of the hand-built preimage = %s, constant %s", vector.name, got, vector.want)
		}
	}
}

// insertCaptureV2Vector stores the two fixtures of the test vector.
func insertCaptureV2Vector(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	for _, statement := range []string{
		`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
		    request_uri_enc, mode, status_code, ttft_ns, forward_status, capture_status, parse_status,
		    newapi_request_id, caller_status, caller_next_at_ns, caller_updated_at_ns, capture_version, user_agent_enc)
		 VALUES ('vector-v2', 1000, 2000, 'chat', 'openai', 'openai.chat_completions', 'POST', '/v1/chat/completions',
		    'uri-ciphertext'::bytea, 'available', 200, 50, 'completed', 'complete', 'pending',
		    'req-1', 'pending', 2000, 2000, 2, 'ua-ciphertext'::bytea)`,
		`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, status_code, content_length, started_at_ns, ended_at_ns, error_code, content_type, content_encoding)
		 VALUES ('vector-v2', 'request_for_newapi_received_from_nginx', 'complete', 'HTTP/1.1', 'POST', 'proxy.example.com', NULL, 17, 1001, 1500, NULL, 'application/json', NULL),
		        ('vector-v2', 'response_received_from_newapi', 'partial', 'HTTP/1.1', '', '', 200, NULL, 1600, 1900, 'process_exit', 'text/event-stream', 'gzip')`,
		`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ('vector-v2', 'gzip', 321, 'block-ciphertext'::bytea)`,
		`INSERT INTO body_streams (audit_id, stage, source_stage, observed_length, stored_length, sha256, hash_complete, eof_seen, state, retention_state, first_observed_at_ns, last_observed_at_ns, error_code)
		 VALUES ('vector-v2', 'request_for_newapi_received_from_nginx', 'request_for_newapi_received_from_nginx', 17, 17, decode(repeat('11', 32), 'hex'), 1, 1, 'complete', 'full', 1100, 1200, NULL),
		        ('vector-v2', 'response_received_from_newapi', 'response_received_from_newapi', 64, 0, NULL, 0, 0, 'partial', 'full', NULL, NULL, 'process_exit')`,
		`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
		    request_uri_enc, mode, forward_status, capture_status, parse_status, error_code, capture_version)
		 VALUES ('vector-v2-bare', 1000, 1500, 'chat', 'openai', 'openai.chat_completions', 'POST', '/v1/chat/completions',
		    'uri-ciphertext'::bytea, 'available', 'client_cancelled', 'partial', 'pending', 'client_cancelled', 2)`,
		`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, status_code, content_length, started_at_ns, ended_at_ns, error_code)
		 VALUES ('vector-v2-bare', 'request_for_newapi_received_from_nginx', 'partial', 'HTTP/2.0', 'GET', 'proxy.example.com', NULL, -1, 1001, 1400, 'client_cancelled')`,
	} {
		if _, err := store.writerConn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("vector fixture: %v\n%s", err, statement)
		}
	}
}

// The production digest of the described fixtures equals the fixed vector,
// and so does the in-process reference.
func TestCapturePayloadDigestV2Vector(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _ := openTestStore(t)
	insertCaptureV2Vector(t, store)
	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for auditID, want := range map[string]string{"vector-v2": captureV2VectorDigest, "vector-v2-bare": captureV2BareVectorDigest} {
		got, err := capturePayloadDigestFor(ctx, transaction, auditID, schemaLive)
		if err != nil {
			t.Fatal(err)
		}
		reference, err := referenceCapturePayloadDigestV2(ctx, transaction, auditID)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != want || !bytes.Equal(got, reference) {
			t.Fatalf("%s: production %x, reference %x, vector %s", auditID, got, reference, want)
		}
	}
}

// insertDigestCaptureV2 writes the capture rows of one terminal version 2
// audit directly: two stages with content columns, a body each, and, when
// full, a User-Agent and a header block. Ciphertext is synthetic.
func insertDigestCaptureV2(t *testing.T, store *Store, auditID string, startedAt int64, full bool) {
	t.Helper()
	ctx := context.Background()
	var userAgent any
	if full {
		userAgent = []byte("ua-ciphertext-" + auditID)
	}
	statements := []struct {
		query     string
		arguments []any
	}{
		{`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
		    request_uri_enc, mode, status_code, ttft_ns, forward_status, capture_status, parse_status, capture_version, user_agent_enc)
		 VALUES ($1, $2, $3, 'route', 'openai', 'parser', 'POST', '/v1/test', $4, 'available', 200, 7, 'completed', 'complete', 'error', 2, $5)`,
			[]any{auditID, startedAt, startedAt + 1, []byte("uri-ciphertext-" + auditID), userAgent}},
		{`INSERT INTO http_stages (audit_id, stage, state, proto, method, host, status_code, started_at_ns, ended_at_ns, content_type, content_encoding)
		 VALUES ($1, 'request_for_newapi_received_from_nginx', 'complete', 'HTTP/1.1', 'POST', 'proxy.example.com', NULL, $2, $3, 'application/json', NULL),
		        ($1, 'response_received_from_newapi', 'complete', 'HTTP/1.1', '', '', 200, $2, $3, 'text/event-stream', 'gzip')`,
			[]any{auditID, startedAt, startedAt + 1}},
		{`INSERT INTO body_streams (audit_id, stage, source_stage, observed_length, stored_length, sha256, hash_complete, eof_seen, state, retention_state)
		 SELECT $1, stage, stage, 64, 64, decode(repeat('44', 32), 'hex'), 1, 1, 'complete', 'full' FROM http_stages WHERE audit_id = $1`,
			[]any{auditID}},
	}
	if full {
		statements = append(statements, struct {
			query     string
			arguments []any
		}{`INSERT INTO http_header_blocks (audit_id, compression, plaintext_length, block_enc) VALUES ($1, 'gzip', 777, $2)`,
			[]any{auditID, []byte("block-ciphertext-" + auditID)}})
	}
	for _, statement := range statements {
		if _, err := store.writerConn.ExecContext(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatalf("%s: %v", auditID, err)
		}
	}
}
