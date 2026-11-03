package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ListAudits reads only the narrow columns needed by the audit list. limit is
// the requested page size; one extra row is read to determine HasMore.
func (store *Store) ListAudits(ctx context.Context, filter AuditQueryFilter, cursor AuditQueryCursor, limit int) (AuditListPage, error) {
	if ctx == nil {
		return AuditListPage{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return AuditListPage{}, ErrClosed
	}
	if limit < 1 || limit > 200 {
		return AuditListPage{}, fmt.Errorf("postgres: query limit must be between 1 and 200")
	}
	if (cursor.BeforeStartedAtNS == 0) != (cursor.BeforeID == "") {
		return AuditListPage{}, errors.New("postgres: incomplete audit cursor")
	}
	if filter.Scope != nil {
		if err := filter.Scope.Validate(); err != nil {
			return AuditListPage{}, err
		}
	}

	var statement strings.Builder
	arguments := make([]any, 0, 16)
	statement.WriteString(`
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol,
       a.parser_name, a.method, a.path, a.mode, a.status_code, a.ttft_ns,
       a.forward_status, a.capture_status, a.parse_status, a.blocked_by,
       a.block_code, a.error_code, p.request_model, p.response_model,
       p.error_type, p.error_code, p.upstream_error_class,
       a.newapi_request_id, a.caller_status,
       t.newapi_user_id, t.username, t.newapi_token_id, t.token_name,
       tn.conversation_id,`)
	if filter.Scope == nil {
		statement.WriteString(`
       (SELECT COUNT(*) FROM turns AS tc WHERE tc.conversation_id = tn.conversation_id)`)
	} else {
		condition, values := scopeConditionWithAliases(filter.Scope, "ac", "tlc", len(arguments))
		statement.WriteString(`
       (SELECT COUNT(*)
        FROM turns AS tc
        JOIN audit_records AS ac ON ac.audit_id = tc.audit_id
        LEFT JOIN token_links AS tlc ON tlc.audit_id = ac.audit_id
        WHERE tc.conversation_id = tn.conversation_id
          AND ` + condition + `)`)
		arguments = append(arguments, values...)
	}
	statement.WriteString(`
FROM audit_records AS a
LEFT JOIN parsed_results AS p ON p.audit_id = a.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
LEFT JOIN turns AS tn ON tn.audit_id = a.audit_id
WHERE 1 = 1`)
	appendCondition := func(condition string, values ...any) {
		statement.WriteString("\n  AND ")
		statement.WriteString(condition)
		arguments = append(arguments, values...)
	}
	if filter.FromNS != nil {
		appendCondition("a.started_at_ns >= "+parameter(len(arguments)+1), *filter.FromNS)
	}
	if filter.ToNS != nil {
		appendCondition("a.started_at_ns <= "+parameter(len(arguments)+1), *filter.ToNS)
	}
	if filter.Protocol != "" {
		appendCondition("a.protocol = "+parameter(len(arguments)+1), filter.Protocol)
	}
	if filter.Path != "" {
		appendCondition("a.path = "+parameter(len(arguments)+1), filter.Path)
	}
	if filter.Model != "" {
		appendCondition("(p.request_model = "+parameter(len(arguments)+1)+" OR p.response_model = "+parameter(len(arguments)+2)+")", filter.Model, filter.Model)
	}
	if filter.UpstreamErrorClass != "" {
		appendCondition("p.upstream_error_class = "+parameter(len(arguments)+1), filter.UpstreamErrorClass)
	}
	if filter.StatusCode != nil {
		appendCondition("a.status_code = "+parameter(len(arguments)+1), *filter.StatusCode)
	}
	switch filter.StatusClass {
	case "4xx":
		appendCondition("a.status_code BETWEEN 400 AND 499")
	case "5xx":
		appendCondition("a.status_code BETWEEN 500 AND 599")
	case "error":
		appendCondition("a.status_code >= 400")
	}
	if filter.ForwardStatus != "" {
		appendCondition("a.forward_status = "+parameter(len(arguments)+1), filter.ForwardStatus)
	}
	if filter.BlockedBy != "" {
		appendCondition("a.blocked_by = "+parameter(len(arguments)+1), filter.BlockedBy)
	}
	if filter.BlockCode != "" {
		appendCondition("a.block_code = "+parameter(len(arguments)+1), filter.BlockCode)
	}
	if filter.CaptureStatus != "" {
		appendCondition("a.capture_status = "+parameter(len(arguments)+1), filter.CaptureStatus)
	}
	if filter.NewAPIUserID != nil {
		appendCondition("t.newapi_user_id = "+parameter(len(arguments)+1), *filter.NewAPIUserID)
	}
	if filter.Username != "" {
		appendCondition("t.username = "+parameter(len(arguments)+1), filter.Username)
	}
	if filter.NewAPITokenID != nil {
		appendCondition("t.newapi_token_id = "+parameter(len(arguments)+1), *filter.NewAPITokenID)
	}
	if filter.TokenName != "" {
		appendCondition("t.token_name = "+parameter(len(arguments)+1), filter.TokenName)
	}
	if filter.ConversationID != "" {
		appendCondition("tn.conversation_id = "+parameter(len(arguments)+1), filter.ConversationID)
	}
	if filter.CollapseConversations && filter.ConversationID == "" {
		condition := `(tn.conversation_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM turns AS t2
    JOIN audit_records AS a2 ON a2.audit_id = t2.audit_id
`
		var values []any
		if filter.Scope != nil {
			condition += "    LEFT JOIN token_links AS tl2 ON tl2.audit_id = a2.audit_id\n"
		}
		condition += `    WHERE t2.conversation_id = tn.conversation_id
      AND (a2.started_at_ns > a.started_at_ns
        OR (a2.started_at_ns = a.started_at_ns AND a2.audit_id > a.audit_id))`
		if filter.Scope != nil {
			scopeCondition, scopeValues := scopeConditionWithAliases(filter.Scope, "a2", "tl2", len(arguments))
			condition += "\n      AND " + scopeCondition
			values = scopeValues
		}
		condition += "))"
		appendCondition(condition, values...)
	}
	if filter.Scope != nil {
		condition, values := scopeCondition(filter.Scope, len(arguments))
		appendCondition(condition, values...)
	}
	if cursor.BeforeID != "" {
		appendCondition("(a.started_at_ns < "+parameter(len(arguments)+1)+" OR (a.started_at_ns = "+parameter(len(arguments)+2)+" AND a.audit_id < "+parameter(len(arguments)+3)+"))", cursor.BeforeStartedAtNS, cursor.BeforeStartedAtNS, cursor.BeforeID)
	}
	statement.WriteString("\nORDER BY a.started_at_ns DESC, a.audit_id DESC\nLIMIT " + parameter(len(arguments)+1))
	arguments = append(arguments, limit+1)

	rows, err := store.readerDB.QueryContext(ctx, statement.String(), arguments...)
	if err != nil {
		return AuditListPage{}, fmt.Errorf("postgres: list audits: %w", err)
	}
	defer rows.Close()

	result := AuditListPage{Rows: make([]AuditListRow, 0, limit)}
	for rows.Next() {
		var row AuditListRow
		if err := scanAuditListRow(rows, &row); err != nil {
			return AuditListPage{}, fmt.Errorf("postgres: scan audit list: %w", err)
		}
		if len(result.Rows) == limit {
			result.HasMore = true
			break
		}
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return AuditListPage{}, fmt.Errorf("postgres: iterate audit list: %w", err)
	}
	return result, nil
}

// QueryAuditDetail reads one transactionally consistent detail projection. It
// loads the encrypted request URI, Header values, and parsed conversation for
// the authenticated query service, but never loads Body chunks.
func (store *Store) QueryAuditDetail(ctx context.Context, auditID string, scope *AuditScope) (AuditQueryDetail, error) {
	if ctx == nil {
		return AuditQueryDetail{}, errors.New("postgres: nil context")
	}
	if auditID == "" {
		return AuditQueryDetail{}, errors.New("postgres: empty audit id")
	}
	if store == nil || store.isClosed() {
		return AuditQueryDetail{}, ErrClosed
	}
	if scope != nil {
		if err := scope.Validate(); err != nil {
			return AuditQueryDetail{}, err
		}
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return AuditQueryDetail{}, fmt.Errorf("postgres: begin query detail: %w", err)
	}
	defer transaction.Rollback()

	detail := AuditQueryDetail{}
	var statement strings.Builder
	arguments := make([]any, 0, 5)
	statement.WriteString(`
SELECT a.audit_id, a.started_at_ns, a.ended_at_ns, a.route_id, a.protocol,
       a.parser_name, a.method, a.path, a.mode, a.status_code, a.ttft_ns,
       a.forward_status, a.capture_status, a.parse_status, a.blocked_by,
       a.block_code, a.error_code, p.request_model, p.response_model,
       p.error_type, p.error_code, p.upstream_error_class,
       a.newapi_request_id, a.caller_status,
       t.newapi_user_id, t.username, t.newapi_token_id, t.token_name,
       tn.conversation_id,`)
	if scope == nil {
		statement.WriteString(`
       (SELECT COUNT(*) FROM turns AS tc WHERE tc.conversation_id = tn.conversation_id)`)
	} else {
		condition, values := scopeConditionWithAliases(scope, "ac", "tlc", len(arguments))
		statement.WriteString(`
       (SELECT COUNT(*)
        FROM turns AS tc
        JOIN audit_records AS ac ON ac.audit_id = tc.audit_id
        LEFT JOIN token_links AS tlc ON tlc.audit_id = ac.audit_id
        WHERE tc.conversation_id = tn.conversation_id
          AND ` + condition + `)`)
		arguments = append(arguments, values...)
	}
	statement.WriteString(`
FROM audit_records AS a
LEFT JOIN parsed_results AS p ON p.audit_id = a.audit_id
LEFT JOIN token_links AS t ON t.audit_id = a.audit_id
LEFT JOIN turns AS tn ON tn.audit_id = a.audit_id
WHERE a.audit_id = ` + parameter(len(arguments)+1))
	arguments = append(arguments, auditID)
	if err := scanAuditListRow(transaction.QueryRowContext(ctx, statement.String(), arguments...), &detail.Audit); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuditQueryDetail{}, sql.ErrNoRows
		}
		return AuditQueryDetail{}, fmt.Errorf("postgres: read query detail: %w", err)
	}
	if err := transaction.QueryRowContext(ctx, `
SELECT request_uri_enc
FROM audit_records
WHERE audit_id = $1`, auditID).Scan(&detail.RequestURIEnc); err != nil {
		return AuditQueryDetail{}, fmt.Errorf("postgres: read encrypted request URI: %w", err)
	}
	detail.RequestURIEnc = cloneBytes(detail.RequestURIEnc)
	if detail.Stages, err = readStages(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.Headers, err = readHeaderEvidence(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.Bodies, err = readBodies(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.ParsedResult, err = readParsedResultSummary(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.TurnGraph, err = readTurnGraph(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if detail.TokenLink, err = readTokenLinkSummary(ctx, transaction, auditID); err != nil {
		return AuditQueryDetail{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AuditQueryDetail{}, fmt.Errorf("postgres: commit query detail: %w", err)
	}
	return detail, nil
}

// QueryRequestHeaderEvidence returns only the inbound User-Agent used by the
// audit list and its optional substring filter. Values remain encrypted until
// the query service verifies their AAD and decrypts them in memory.
func (store *Store) QueryRequestHeaderEvidence(ctx context.Context, auditID string) ([]HeaderEvidence, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if auditID == "" {
		return nil, errors.New("postgres: empty audit id")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = $1
  AND stage = $2
  AND kind = 'header'
  AND lower(name) = 'user-agent'
ORDER BY lower(name), value_index`, auditID, StageRequestReceived)
	if err != nil {
		return nil, fmt.Errorf("postgres: query request filter headers: %w", err)
	}
	defer rows.Close()
	result := make([]HeaderEvidence, 0)
	for rows.Next() {
		var header HeaderEvidence
		if err := rows.Scan(&header.Stage, &header.Kind, &header.Name, &header.ValueIndex, &header.ValueLength, &header.ValueEnc); err != nil {
			return nil, fmt.Errorf("postgres: scan request filter header: %w", err)
		}
		header.ValueEnc = cloneBytes(header.ValueEnc)
		result = append(result, header)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate request filter headers: %w", err)
	}
	return result, nil
}

// RawBodyMeta returns the aggregate metadata needed before starting an HTTP
// raw-body response.
func (store *Store) RawBodyMeta(ctx context.Context, auditID, stage string) (RawBodyMetadata, error) {
	if ctx == nil {
		return RawBodyMetadata{}, errors.New("postgres: nil context")
	}
	if auditID == "" || !validStage(stage) {
		return RawBodyMetadata{}, errors.New("postgres: invalid raw body identity")
	}
	if store == nil || store.isClosed() {
		return RawBodyMetadata{}, ErrClosed
	}

	var metadata RawBodyMetadata
	var digest []byte
	var hashComplete, eofSeen int
	var errorCode sql.NullString
	err := store.readerDB.QueryRowContext(ctx, `
SELECT audit_id, stage, source_stage, retention_state,
       observed_length, stored_length, sha256,
       hash_complete, eof_seen, state, error_code
FROM body_streams
WHERE audit_id = $1 AND stage = $2`, auditID, stage).Scan(
		&metadata.AuditID,
		&metadata.Stage,
		&metadata.SourceStage,
		&metadata.RetentionState,
		&metadata.ObservedLength,
		&metadata.StoredLength,
		&digest,
		&hashComplete,
		&eofSeen,
		&metadata.State,
		&errorCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RawBodyMetadata{}, sql.ErrNoRows
		}
		return RawBodyMetadata{}, fmt.Errorf("postgres: read raw body metadata: %w", err)
	}
	metadata.SHA256 = cloneBytes(digest)
	metadata.HashComplete = hashComplete != 0
	metadata.EOFSeen = eofSeen != 0
	metadata.ErrorCode = nullStringPointer(errorCode)
	return metadata, nil
}

// StreamBodyChunks iterates encrypted owning chunks in sequence order without
// collecting the complete Body in memory. The callback must not retain the
// DataEnc slice after it returns.
func (store *Store) StreamBodyChunks(ctx context.Context, auditID, stage string, visit func(BodyChunk) error) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if auditID == "" || !validStage(stage) {
		return errors.New("postgres: invalid raw body identity")
	}
	if visit == nil {
		return errors.New("postgres: nil chunk visitor")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}

	transaction, err := store.readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer transaction.Rollback()

	var sourceStage string
	if err := transaction.QueryRowContext(ctx, `SELECT source_stage FROM body_streams WHERE audit_id = $1 AND stage = $2`, auditID, stage).Scan(&sourceStage); err != nil {
		return fmt.Errorf("postgres: resolve raw chunk source: %w", err)
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT audit_id, stage, seq, "offset", plaintext_length, encoded_length,
       observed_at_ns, compression, data_enc
FROM body_chunks
WHERE audit_id = $1 AND stage = $2
ORDER BY seq`, auditID, sourceStage)
	if err != nil {
		return fmt.Errorf("postgres: stream body chunks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var chunk BodyChunk
		if err := rows.Scan(
			&chunk.AuditID,
			&chunk.Stage,
			&chunk.Seq,
			&chunk.Offset,
			&chunk.PlaintextLength,
			&chunk.EncodedLength,
			&chunk.ObservedAtNS,
			&chunk.Compression,
			&chunk.DataEnc,
		); err != nil {
			return fmt.Errorf("postgres: scan body chunk: %w", err)
		}
		if err := visit(chunk); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate body chunks: %w", err)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	return transaction.Commit()
}

func scanAuditListRow(row rowScanner, destination *AuditListRow) error {
	var endedAt, statusCode, ttftNS, newAPIUserID, newAPITokenID, conversationTurns sql.NullInt64
	var blockedBy, blockCode, errorCode, requestModel, responseModel, requestID, username, tokenName, conversationID sql.NullString
	var parsedErrorType, parsedErrorCode, upstreamErrorClass sql.NullString
	if err := row.Scan(
		&destination.AuditID,
		&destination.StartedAtNS,
		&endedAt,
		&destination.RouteID,
		&destination.Protocol,
		&destination.ParserName,
		&destination.Method,
		&destination.Path,
		&destination.Mode,
		&statusCode,
		&ttftNS,
		&destination.ForwardStatus,
		&destination.CaptureStatus,
		&destination.ParseStatus,
		&blockedBy,
		&blockCode,
		&errorCode,
		&requestModel,
		&responseModel,
		&parsedErrorType,
		&parsedErrorCode,
		&upstreamErrorClass,
		&requestID,
		&destination.CallerStatus,
		&newAPIUserID,
		&username,
		&newAPITokenID,
		&tokenName,
		&conversationID,
		&conversationTurns,
	); err != nil {
		return err
	}
	destination.EndedAtNS = nullInt64Pointer(endedAt)
	destination.StatusCode = nullIntPointer(statusCode)
	destination.TTFTNS = nullInt64Pointer(ttftNS)
	destination.BlockedBy = nullStringPointer(blockedBy)
	destination.BlockCode = nullStringPointer(blockCode)
	destination.ErrorCode = nullStringPointer(errorCode)
	destination.RequestModel = nullStringPointer(requestModel)
	destination.ResponseModel = nullStringPointer(responseModel)
	destination.ParsedErrorType = nullStringPointer(parsedErrorType)
	destination.ParsedErrorCode = nullStringPointer(parsedErrorCode)
	destination.UpstreamErrorClass = nullStringPointer(upstreamErrorClass)
	destination.NewAPIRequestID = nullStringPointer(requestID)
	destination.ConversationID = nullStringPointer(conversationID)
	if destination.ConversationID != nil {
		destination.ConversationTurns = nullInt64Pointer(conversationTurns)
	}
	destination.NewAPIUserID = nullInt64Pointer(newAPIUserID)
	destination.Username = nullStringPointer(username)
	destination.NewAPITokenID = nullInt64Pointer(newAPITokenID)
	destination.TokenName = nullStringPointer(tokenName)
	return nil
}

func readHeaderEvidence(ctx context.Context, transaction dbTransaction, auditID string) ([]HeaderEvidence, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT stage, kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = $1
ORDER BY `+stageOrderSQL+`, kind, name, value_index`, auditID)
	if err != nil {
		return nil, fmt.Errorf("postgres: read header evidence: %w", err)
	}
	defer rows.Close()

	headers := make([]HeaderEvidence, 0)
	for rows.Next() {
		var header HeaderEvidence
		if err := rows.Scan(&header.Stage, &header.Kind, &header.Name, &header.ValueIndex, &header.ValueLength, &header.ValueEnc); err != nil {
			return nil, fmt.Errorf("postgres: scan header evidence: %w", err)
		}
		header.ValueEnc = cloneBytes(header.ValueEnc)
		headers = append(headers, header)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate header evidence: %w", err)
	}
	return headers, nil
}

func readParsedResultSummary(ctx context.Context, transaction dbTransaction, auditID string) (*ParsedResultSummary, error) {
	var result ParsedResultSummary
	var requestedStream, observedStream, hasToolCall sql.NullInt64
	var requestModel, responseModel, responseID, errorType, errorCode, upstreamErrorClass sql.NullString
	var usageInput, usageOutput, usageTotal, messageCount, toolCallCount sql.NullInt64
	var parsedJSONEnc []byte
	err := transaction.QueryRowContext(ctx, `
SELECT parser_name, parser_version, status, request_model, response_model,
       requested_stream, observed_stream, response_id, usage_input,
       usage_output, usage_total, error_type, error_code, upstream_error_class,
       message_count, tool_call_count, has_tool_call, parsed_json_enc, parsed_at_ns
FROM parsed_results
WHERE audit_id = $1`, auditID).Scan(
		&result.ParserName,
		&result.ParserVersion,
		&result.Status,
		&requestModel,
		&responseModel,
		&requestedStream,
		&observedStream,
		&responseID,
		&usageInput,
		&usageOutput,
		&usageTotal,
		&errorType,
		&errorCode,
		&upstreamErrorClass,
		&messageCount,
		&toolCallCount,
		&hasToolCall,
		&parsedJSONEnc,
		&result.ParsedAtNS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: read parsed result summary: %w", err)
	}
	result.RequestModel = nullStringPointer(requestModel)
	result.ResponseModel = nullStringPointer(responseModel)
	result.RequestedStream = nullBoolPointer(requestedStream)
	result.ObservedStream = nullBoolPointer(observedStream)
	result.ResponseID = nullStringPointer(responseID)
	result.UsageInput = nullInt64Pointer(usageInput)
	result.UsageOutput = nullInt64Pointer(usageOutput)
	result.UsageTotal = nullInt64Pointer(usageTotal)
	result.ErrorType = nullStringPointer(errorType)
	result.ErrorCode = nullStringPointer(errorCode)
	result.UpstreamErrorClass = nullStringPointer(upstreamErrorClass)
	result.MessageCount = nullInt64Pointer(messageCount)
	result.ToolCallCount = nullInt64Pointer(toolCallCount)
	result.HasToolCall = nullBoolPointer(hasToolCall)
	result.ParsedJSONEnc = cloneBytes(parsedJSONEnc)
	return &result, nil
}

func readTokenLinkSummary(ctx context.Context, transaction dbTransaction, auditID string) (*TokenLinkSummary, error) {
	var result TokenLinkSummary
	var quota, prompt, completion sql.NullInt64
	var quotaPerUnit sql.NullFloat64
	err := transaction.QueryRowContext(ctx, `
SELECT a.newapi_request_id, t.newapi_user_id, t.username,
       t.newapi_token_id, t.token_name, t.linked_at_ns,
       t.billing_state, t.quota, t.quota_per_unit,
       t.billed_prompt_tokens, t.billed_completion_tokens
FROM token_links AS t
JOIN audit_records AS a ON a.audit_id = t.audit_id
WHERE t.audit_id = $1`, auditID).Scan(
		&result.NewAPIRequestID,
		&result.NewAPIUserID,
		&result.Username,
		&result.NewAPITokenID,
		&result.TokenName,
		&result.LinkedAtNS,
		&result.BillingState,
		&quota,
		&quotaPerUnit,
		&prompt,
		&completion,
	)
	result.Quota = nullInt64Pointer(quota)
	result.BilledPromptTokens = nullInt64Pointer(prompt)
	result.BilledCompletionTokens = nullInt64Pointer(completion)
	if quotaPerUnit.Valid {
		value := quotaPerUnit.Float64
		result.QuotaPerUnit = &value
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: read token link summary: %w", err)
	}
	return &result, nil
}

func nullBoolPointer(value sql.NullInt64) *bool {
	if !value.Valid {
		return nil
	}
	converted := value.Int64 != 0
	return &converted
}
