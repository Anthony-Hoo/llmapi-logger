package parser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

const defaultScanInterval = 30 * time.Second

// Worker owns one bounded queue and one parser goroutine. Queue saturation is
// intentionally non-blocking; pending rows are picked up by later scans.
type Worker struct {
	store   Store
	cipher  security.Cipher
	parsers map[string]Parser
	logger  *slog.Logger
	queue   chan string

	scanInterval time.Duration
	now          func() time.Time

	mu      sync.Mutex
	started bool
	closed  bool
	cancel  context.CancelFunc
	wait    sync.WaitGroup
}

// NewWorker validates and indexes the configured protocol parsers.
func NewWorker(store Store, cipher security.Cipher, parsers []Parser, logger *slog.Logger) (*Worker, error) {
	if store == nil {
		return nil, errors.New("parser: nil store")
	}
	if cipher == nil {
		return nil, errors.New("parser: nil cipher")
	}
	if logger == nil {
		logger = slog.Default()
	}
	indexed := make(map[string]Parser, len(parsers))
	for _, implementation := range parsers {
		if implementation == nil || strings.TrimSpace(implementation.Name()) == "" || strings.TrimSpace(implementation.Version()) == "" {
			return nil, errors.New("parser: invalid parser registration")
		}
		if _, exists := indexed[implementation.Name()]; exists {
			return nil, fmt.Errorf("parser: duplicate parser %q", implementation.Name())
		}
		indexed[implementation.Name()] = implementation
	}
	return &Worker{
		store:        store,
		cipher:       cipher,
		parsers:      indexed,
		logger:       logger,
		queue:        make(chan string, QueueCapacity),
		scanInterval: defaultScanInterval,
		now:          time.Now,
	}, nil
}

// Start resets interrupted processing rows, performs the startup pending scan,
// and starts exactly one worker goroutine.
func (worker *Worker) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("parser: nil context")
	}
	if worker == nil {
		return errors.New("parser: nil worker")
	}

	worker.mu.Lock()
	if worker.closed {
		worker.mu.Unlock()
		return errors.New("parser: worker is closed")
	}
	if worker.started {
		worker.mu.Unlock()
		return errors.New("parser: worker already started")
	}
	if err := worker.store.ResetProcessingParses(ctx); err != nil {
		worker.mu.Unlock()
		return fmt.Errorf("parser: reset interrupted work: %w", err)
	}
	runContext, cancel := context.WithCancel(ctx)
	worker.started = true
	worker.cancel = cancel
	worker.wait.Add(1)
	go worker.run(runContext)
	worker.mu.Unlock()

	worker.scan(runContext)
	return nil
}

// Notify tries to enqueue a completed audit without waiting. False means the
// queue is full or the worker has been closed; the DB row remains pending.
func (worker *Worker) Notify(auditID string) bool {
	if worker == nil || strings.TrimSpace(auditID) == "" {
		return false
	}
	worker.mu.Lock()
	closed := worker.closed
	worker.mu.Unlock()
	if closed {
		return false
	}
	select {
	case worker.queue <- auditID:
		return true
	default:
		return false
	}
}

// QueueLength returns the current in-memory backlog for readiness reporting.
func (worker *Worker) QueueLength() int {
	if worker == nil {
		return 0
	}
	return len(worker.queue)
}

// Close stops background scans and waits for the current parse operation. It
// is safe before Start and safe to call more than once.
func (worker *Worker) Close() {
	if worker == nil {
		return
	}
	worker.mu.Lock()
	if worker.closed {
		worker.mu.Unlock()
		return
	}
	worker.closed = true
	cancel := worker.cancel
	worker.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	worker.wait.Wait()
}

func (worker *Worker) run(ctx context.Context) {
	defer worker.wait.Done()
	ticker := time.NewTicker(worker.scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case auditID := <-worker.queue:
			worker.process(ctx, auditID)
		case <-ticker.C:
			worker.scan(ctx)
		}
	}
}

func (worker *Worker) scan(ctx context.Context) {
	ids, err := worker.store.ListPendingParseIDs(ctx, QueueCapacity)
	if err != nil {
		worker.logger.Warn("parser pending scan failed", "error_code", "pending_scan_failed")
		return
	}
	for _, auditID := range ids {
		if !worker.Notify(auditID) {
			return
		}
	}
}

func (worker *Worker) process(ctx context.Context, auditID string) {
	audit, err := worker.store.LoadParserAudit(ctx, auditID)
	if err != nil {
		worker.logger.Warn("parser audit load failed", "audit_id", auditID, "error_code", "audit_load_failed")
		return
	}
	claimed, err := worker.store.ClaimPendingParse(ctx, auditID)
	if err != nil {
		worker.logger.Warn("parser claim failed", "audit_id", auditID, "error_code", "parse_claim_failed")
		return
	}
	if !claimed {
		return
	}

	implementation := worker.parsers[audit.ParserName]
	input, evidenceErr := worker.loadInput(ctx, audit)
	result := Result{}
	if implementation == nil {
		result.Status = StatusSkipped
		result.ErrorCode = "parser_not_registered"
	} else if !input.Request.Present && !input.Response.Present && evidenceErr == nil {
		result.Status = StatusSkipped
		result.ErrorCode = "no_body"
	} else {
		result = parseSafely(ctx, implementation, input)
	}
	worker.normalizeResult(&result, input, evidenceErr)
	if err := worker.persistResult(ctx, audit, implementation, result); err != nil {
		worker.logger.Warn("parser result save failed", "audit_id", audit.AuditID, "error_code", "parsed_result_save_failed")
		releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if releaseErr := worker.store.ReleaseProcessingParse(releaseContext, audit.AuditID); releaseErr != nil {
			worker.logger.Warn("parser retry release failed", "audit_id", audit.AuditID, "error_code", "parse_release_failed")
		}
	}
}

func parseSafely(ctx context.Context, implementation Parser, input Input) (result Result) {
	defer func() {
		if recover() != nil {
			result = Result{Status: StatusError, ErrorCode: "parser_panic"}
		}
	}()
	return implementation.Parse(ctx, input)
}

func (worker *Worker) normalizeResult(result *Result, input Input, evidenceErr error) {
	if result.Status == "" {
		if result.IsUsable() {
			result.Status = StatusOK
		} else {
			result.Status = StatusError
			result.ErrorCode = "empty_parser_result"
		}
	} else if result.Status != StatusOK && result.Status != StatusPartial && result.Status != StatusError && result.Status != StatusSkipped {
		result.Status = StatusError
		result.ErrorCode = "invalid_parser_status"
	}

	evidenceCode := selectEvidenceCode(input.Request.ErrorCode, input.Response.ErrorCode)
	evidenceProblem := evidenceErr != nil || (!input.Request.Complete && input.Request.Present) || (!input.Response.Complete && input.Response.Present)
	if evidenceProblem && !(result.Status == StatusSkipped && result.ErrorCode == "parser_not_registered") {
		if onlyUnsupportedEncoding(input) {
			result.Status = StatusSkipped
		} else if result.Status == StatusOK {
			if result.IsUsable() {
				result.Status = StatusPartial
			} else {
				result.Status = StatusError
			}
		}
		if !preserveParserFailure(result.ErrorCode) {
			result.ErrorCode = firstNonEmpty(evidenceCode, "evidence_error")
		}
	}
	if result.Status == StatusError && result.ErrorCode == "" {
		result.ErrorCode = "parse_error"
	}
	if len(result.ParsedJSON) == 0 {
		result.ParsedJSON, _ = json.Marshal(compactResultJSON(*result))
	}
}

func (worker *Worker) persistResult(ctx context.Context, audit sqlite.ParserAudit, implementation Parser, result Result) error {
	parserVersion := "1"
	if implementation != nil {
		parserVersion = implementation.Version()
	}
	aad, err := security.AAD(audit.AuditID, "parsed_json", audit.ParserName)
	if err != nil {
		worker.logger.Warn("parser result AAD failed", "audit_id", audit.AuditID, "error_code", "parsed_json_aad_failed")
		result.Status = StatusError
		result.ErrorCode = "parsed_json_aad_failed"
	}
	var encrypted []byte
	plaintext := result.ParsedJSON
	generatedPlaintext := false
	if result.Conversation != nil {
		var envelope map[string]any
		if unmarshalErr := json.Unmarshal(result.ParsedJSON, &envelope); unmarshalErr != nil || envelope == nil {
			envelope = make(map[string]any)
		}
		envelope["conversation"] = result.Conversation
		if encoded, marshalErr := json.Marshal(envelope); marshalErr == nil {
			plaintext = encoded
			generatedPlaintext = true
		}
	}
	if err == nil {
		encrypted, err = worker.cipher.Encrypt(aad, plaintext)
		if err != nil {
			worker.logger.Warn("parser result encryption failed", "audit_id", audit.AuditID, "error_code", "parsed_json_encryption_failed")
			result.Status = StatusError
			result.ErrorCode = "parsed_json_encryption_failed"
		}
	}
	if generatedPlaintext {
		clear(plaintext)
	}

	storageResult := sqlite.ParsedResult{
		AuditID:         audit.AuditID,
		ParserName:      audit.ParserName,
		ParserVersion:   parserVersion,
		Status:          result.Status,
		RequestModel:    optionalString(result.RequestModel),
		ResponseModel:   optionalString(result.ResponseModel),
		RequestedStream: cloneBool(result.RequestedStream),
		ObservedStream:  cloneBool(result.ObservedStream),
		ResponseID:      optionalString(result.ResponseID),
		UsageInput:      cloneInt64(result.Usage.Input),
		UsageOutput:     cloneInt64(result.Usage.Output),
		UsageTotal:      cloneInt64(result.Usage.Total),
		ErrorType:       optionalString(result.ErrorType),
		ErrorCode:       optionalString(result.ErrorCode),
		MessageCount:    cloneInt(result.MessageCount),
		ToolCallCount:   cloneInt(result.ToolCallCount),
		HasToolCall:     cloneBool(result.HasToolCall),
		ParsedJSONEnc:   encrypted,
		ParsedAtNS:      worker.now().UnixNano(),
	}
	return worker.store.SaveParsedResult(ctx, storageResult)
}

func onlyUnsupportedEncoding(input Input) bool {
	found := false
	for _, source := range []BodySource{input.Request, input.Response} {
		if !source.Present {
			continue
		}
		if source.ErrorCode != "unsupported_content_encoding" || len(source.Data) != 0 {
			return false
		}
		found = true
	}
	return found
}

func preserveParserFailure(errorCode string) bool {
	switch errorCode {
	case "parser_not_registered", "parser_panic", "empty_parser_result", "invalid_parser_status":
		return true
	default:
		return false
	}
}

func selectEvidenceCode(values ...string) string {
	for _, preferred := range []string{
		"capture_integrity_error",
		"evidence_read_error",
		"body_encryption_failed",
		"add_chunk_failed",
		"body_too_large",
		"gzip_ratio_exceeded",
		"gzip_invalid",
		"unsupported_content_encoding",
		"body_read_error",
		"body_write_error",
		"capture_partial",
	} {
		for _, value := range values {
			if value == preferred {
				return value
			}
		}
	}
	return firstNonEmpty(values...)
}

func compactResultJSON(result Result) map[string]any {
	return map[string]any{
		"status":           result.Status,
		"request_model":    result.RequestModel,
		"response_model":   result.ResponseModel,
		"requested_stream": result.RequestedStream,
		"observed_stream":  result.ObservedStream,
		"response_id":      result.ResponseID,
		"usage":            result.Usage,
		"error_type":       result.ErrorType,
		"error_code":       result.ErrorCode,
		"message_count":    result.MessageCount,
		"tool_call_count":  result.ToolCallCount,
		"has_tool_call":    result.HasToolCall,
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	cloned := value
	return &cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
