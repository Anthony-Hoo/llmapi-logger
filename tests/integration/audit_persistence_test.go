package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/app"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"

	_ "modernc.org/sqlite"
)

const (
	stageRequestReceived  = "request_for_newapi_received_from_nginx"
	stageRequestSent      = "request_sent_to_newapi"
	stageResponseReceived = "response_received_from_newapi"
	stageResponseSent     = "response_from_newapi_sent_to_nginx"
	bodyChunkSize         = 32 << 10
)

type persistedAudit struct {
	auditID       string
	statusCode    sql.NullInt64
	forwardStatus string
	captureStatus string
	parseStatus   string
	blockedBy     sql.NullString
	blockCode     sql.NullString
	requestURIEnc []byte
}

type persistedStage struct {
	stage      string
	state      string
	statusCode sql.NullInt64
}

type persistedBody struct {
	stage          string
	observedLength int64
	storedLength   int64
	digest         []byte
	hashComplete   bool
	eofSeen        bool
	state          string
}

type runningApp struct {
	baseURL  string
	adminURL string
	cancel   context.CancelFunc
	done     chan error
	once     sync.Once
	stopErr  error
}

type adminAuditSummary struct {
	AuditID       string  `json:"audit_id"`
	StartedAtNS   string  `json:"started_at_ns"`
	ParseStatus   string  `json:"parse_status"`
	RequestModel  *string `json:"request_model"`
	ResponseModel *string `json:"response_model"`
}

type adminListPage struct {
	Items []adminAuditSummary `json:"items"`
}

type adminAuditDetail struct {
	RequestURI   string                     `json:"request_uri"`
	Conversation *conversation.Conversation `json:"conversation"`
	Headers      []struct {
		Stage       string `json:"stage"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		ValueIndex  int    `json:"value_index"`
		ValueLength int    `json:"value_length"`
		Value       string `json:"value"`
	} `json:"headers"`
	ParsedResult *struct {
		Status       string `json:"status"`
		UsageInput   *int64 `json:"usage_input"`
		UsageOutput  *int64 `json:"usage_output"`
		UsageTotal   *int64 `json:"usage_total"`
		MessageCount *int64 `json:"message_count"`
	} `json:"parsed_result"`
}

func TestNonLLMPassthroughDoesNotBypassAuditedRoutes(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/models":
			if request.URL.RawQuery != "source=integration" {
				http.Error(response, "query changed", http.StatusBadRequest)
				return
			}
			if request.Header.Get("Authorization") != "Bearer models-test-token" {
				http.Error(response, "authorization changed", http.StatusBadRequest)
				return
			}
			response.Header().Set("X-NewAPI-Models", "preserved")
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"data":[{"id":"test-model"}]}`)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/chat/completions":
			response.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(response, `{"id":"completion"}`)
		default:
			http.Error(response, "unexpected upstream request", http.StatusTeapot)
		}
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	cfg.Routes = append(cfg.Routes, config.RouteConfig{
		ID:     "gemini-generate",
		Method: http.MethodPost,
		Path:   "/v1beta/models/{model}:generateContent",
		Match:  "template",
		Parser: "gemini.generate_content",
	})
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}

	modelsRequest, err := http.NewRequest(http.MethodGet, running.baseURL+"/v1/models?source=integration", http.NoBody)
	if err != nil {
		t.Fatalf("new models request: %v", err)
	}
	modelsRequest.Header.Set("Authorization", "Bearer models-test-token")
	modelsResponse, err := client.Do(modelsRequest)
	if err != nil {
		t.Fatalf("send models request: %v", err)
	}
	modelsBody, readErr := io.ReadAll(modelsResponse.Body)
	modelsResponse.Body.Close()
	if readErr != nil {
		t.Fatalf("read models response: %v", readErr)
	}
	if modelsResponse.StatusCode != http.StatusOK || string(modelsBody) != `{"data":[{"id":"test-model"}]}` {
		t.Fatalf("models response = %d %q, want transparent upstream response", modelsResponse.StatusCode, modelsBody)
	}
	if modelsResponse.Header.Get("X-NewAPI-Models") != "preserved" {
		t.Fatal("models response header was not preserved")
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls after models request = %d, want 1", got)
	}
	if got := auditRecordCount(t, cfg.DBPath); got != 0 {
		t.Fatalf("audit records after models passthrough = %d, want 0", got)
	}

	encodedRequest, err := http.NewRequest(
		http.MethodPost,
		running.baseURL+"/v1/chat/%63ompletions",
		strings.NewReader(`{"model":"test-model"}`),
	)
	if err != nil {
		t.Fatalf("new encoded route request: %v", err)
	}
	encodedResponse, err := client.Do(encodedRequest)
	if err != nil {
		t.Fatalf("send encoded route request: %v", err)
	}
	_, _ = io.Copy(io.Discard, encodedResponse.Body)
	encodedResponse.Body.Close()
	if encodedResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("encoded route status = %d, want %d", encodedResponse.StatusCode, http.StatusNotFound)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("encoded route reached upstream: calls = %d, want 1", got)
	}
	if got := auditRecordCount(t, cfg.DBPath); got != 0 {
		t.Fatalf("encoded rejected route created %d audit records, want 0", got)
	}

	blockedVariants := []struct {
		name   string
		method string
		path   string
	}{
		{name: "wrong method", method: http.MethodGet, path: "/v1/chat/completions"},
		{name: "exact trailing slash", method: http.MethodPost, path: "/v1/chat/completions/"},
		{name: "template near miss", method: http.MethodPost, path: "/v1beta/models/a+b:generateContent"},
		{name: "template trailing slash", method: http.MethodPost, path: "/v1beta/models/gemini:generateContent/"},
	}
	for _, blocked := range blockedVariants {
		t.Run(blocked.name, func(t *testing.T) {
			request, err := http.NewRequest(blocked.method, running.baseURL+blocked.path, http.NoBody)
			if err != nil {
				t.Fatalf("new blocked request: %v", err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("send blocked request: %v", err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNotFound)
			}
		})
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("protected route variants reached upstream: calls = %d, want 1", got)
	}
	if got := auditRecordCount(t, cfg.DBPath); got != 0 {
		t.Fatalf("protected rejected routes created %d audit records, want 0", got)
	}

	auditedResponse, err := client.Post(
		running.baseURL+"/v1/chat/completions",
		"application/json",
		strings.NewReader(`{"model":"test-model"}`),
	)
	if err != nil {
		t.Fatalf("send audited route request: %v", err)
	}
	_, _ = io.Copy(io.Discard, auditedResponse.Body)
	auditedResponse.Body.Close()
	if auditedResponse.StatusCode != http.StatusCreated {
		t.Fatalf("audited route status = %d, want %d", auditedResponse.StatusCode, http.StatusCreated)
	}
	audit := waitForFinishedAudit(t, cfg.DBPath)
	if audit.forwardStatus != "completed" || !audit.statusCode.Valid || audit.statusCode.Int64 != http.StatusCreated {
		t.Fatalf("audited route record = %+v, want completed 201", audit)
	}
	if got := auditRecordCount(t, cfg.DBPath); got != 1 {
		t.Fatalf("audit records after audited route = %d, want 1", got)
	}
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls after audited route = %d, want 2", got)
	}
}

func TestTrailingSlashNonLLMPathUsesPassthrough(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		if request.Method != http.MethodGet || request.URL.EscapedPath() != "/api/user/" {
			http.Error(response, "unexpected upstream request", http.StatusTeapot)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(response, `{"message":"authentication required","success":false}`)
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}

	response, err := client.Get(running.baseURL + "/api/user/")
	if err != nil {
		t.Fatalf("send trailing-slash passthrough request: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read trailing-slash passthrough response: %v", readErr)
	}
	if response.StatusCode != http.StatusUnauthorized || string(body) != `{"message":"authentication required","success":false}` {
		t.Fatalf("response = %d %q, want transparent upstream 401", response.StatusCode, body)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if got := auditRecordCount(t, cfg.DBPath); got != 0 {
		t.Fatalf("trailing-slash passthrough created %d audit records, want 0", got)
	}
}

func TestAuditPersistsFourEncryptedBodyStages(t *testing.T) {
	uriSecret := "uri-plaintext-7db9476f"
	headerSecret := "header-plaintext-1a739f62"
	responseTrailerSecret := "response-trailer-plaintext-409bd3b7"
	requestMarker := []byte("request-body-plaintext-6df09f6e")
	responseMarker := []byte("response-body-plaintext-aa8c42d1")
	requestBody := append(bytes.Repeat([]byte("q"), bodyChunkSize+731), requestMarker...)
	responseBody := append(bytes.Repeat([]byte("r"), bodyChunkSize+1291), responseMarker...)

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(response, "read request", http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, requestBody) {
			http.Error(response, "request body changed", http.StatusBadRequest)
			return
		}
		if got := request.Header.Get("X-Audit-Secret"); got != headerSecret {
			http.Error(response, "request header changed", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("X-Upstream-Secret", "response-header-plaintext-c37fd91a")
		response.Header().Set("Trailer", "X-Upstream-Trailer-Secret")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write(responseBody)
		response.Header().Set("X-Upstream-Trailer-Secret", responseTrailerSecret)
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	running := startApp(t, cfg)

	requestURI := "/v1/chat/completions?audit_uri_secret=" + uriSecret
	request, err := http.NewRequest(http.MethodPost, running.baseURL+requestURI, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new audited request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer audit-token-plaintext-5bda73a4")
	request.Header.Set("X-Audit-Secret", headerSecret)
	client := &http.Client{Timeout: integrationTimeout}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send audited request: %v", err)
	}
	gotResponseBody, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read audited response: %v", readErr)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("response status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	if !bytes.Equal(gotResponseBody, responseBody) {
		t.Fatal("response body changed while auditing")
	}

	audit := waitForFinishedAudit(t, cfg.DBPath)
	if audit.forwardStatus != "completed" {
		t.Errorf("forward_status = %q, want completed", audit.forwardStatus)
	}
	if audit.captureStatus != "complete" {
		t.Errorf("capture_status = %q, want complete", audit.captureStatus)
	}
	if !audit.statusCode.Valid || audit.statusCode.Int64 != http.StatusCreated {
		t.Errorf("status_code = %+v, want %d", audit.statusCode, http.StatusCreated)
	}
	if audit.blockedBy.Valid || audit.blockCode.Valid {
		t.Errorf("allowed audit block fields = %+v/%+v, want NULL/NULL", audit.blockedBy, audit.blockCode)
	}

	database := openAuditDatabase(t, cfg.DBPath)
	defer database.Close()
	stages := readStages(t, database, audit.auditID)
	wantStages := []string{stageRequestReceived, stageRequestSent, stageResponseReceived, stageResponseSent}
	if len(stages) != len(wantStages) {
		t.Fatalf("stage count = %d, want %d: %+v", len(stages), len(wantStages), stages)
	}
	for _, stageName := range wantStages {
		stage, ok := stages[stageName]
		if !ok {
			t.Errorf("missing actually triggered stage %q", stageName)
			continue
		}
		if stage.state != "complete" {
			t.Errorf("stage %s state = %q, want complete", stageName, stage.state)
		}
	}

	bodies := readBodies(t, database, audit.auditID)
	wantBodies := map[string][]byte{
		stageRequestReceived:  requestBody,
		stageRequestSent:      requestBody,
		stageResponseReceived: responseBody,
		stageResponseSent:     responseBody,
	}
	if len(bodies) != len(wantBodies) {
		t.Fatalf("body stream count = %d, want %d: %+v", len(bodies), len(wantBodies), bodies)
	}
	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		t.Fatalf("read audit key: %v", err)
	}
	cipher, err := security.NewAESGCM(key)
	if err != nil {
		t.Fatalf("construct audit cipher: %v", err)
	}
	for stageName, plaintext := range wantBodies {
		body, ok := bodies[stageName]
		if !ok {
			t.Errorf("missing body stream for %s", stageName)
			continue
		}
		assertBodyAggregate(t, body, plaintext)
		assertEncryptedChunks(t, database, cipher, audit.auditID, stageName, plaintext)
	}

	uriAAD, err := security.AAD(audit.auditID, "request_uri")
	if err != nil {
		t.Fatalf("build request URI AAD: %v", err)
	}
	decryptedURI, err := cipher.Decrypt(uriAAD, audit.requestURIEnc)
	if err != nil {
		t.Fatalf("decrypt request URI: %v", err)
	}
	if string(decryptedURI) != requestURI {
		t.Errorf("decrypted Request-URI = %q, want %q", decryptedURI, requestURI)
	}
	assertEncryptedHeader(t, database, cipher, audit.auditID, stageRequestReceived, "X-Audit-Secret", headerSecret)
	assertEncryptedTrailer(t, database, cipher, audit.auditID, stageResponseReceived, "X-Upstream-Trailer-Secret", responseTrailerSecret)
	assertEncryptedTrailer(t, database, cipher, audit.auditID, stageResponseSent, "X-Upstream-Trailer-Secret", responseTrailerSecret)

	markers := [][]byte{
		[]byte(uriSecret),
		[]byte(headerSecret),
		requestMarker,
		responseMarker,
		[]byte("audit-token-plaintext-5bda73a4"),
		[]byte("response-header-plaintext-c37fd91a"),
		[]byte(responseTrailerSecret),
	}
	assertSQLiteFilesDoNotContain(t, cfg.DBPath, markers)
	if err := running.stop(); err != nil {
		t.Fatalf("stop audited app: %v", err)
	}
	assertSQLiteFilesDoNotContain(t, cfg.DBPath, markers)
}

func TestAuditPersistsInterceptorRejectionWithoutUnreachedStages(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", true)
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}
	response, err := client.Post(
		running.baseURL+"/v1/chat/completions?rejected=audit-reject-uri-plaintext",
		"application/json",
		strings.NewReader(`{"prompt":"audit-reject-body-plaintext"}`),
	)
	if err != nil {
		t.Fatalf("send rejected audited request: %v", err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read rejected audited response: %v", readErr)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}

	audit := waitForFinishedAudit(t, cfg.DBPath)
	if audit.forwardStatus != "rejected" {
		t.Errorf("forward_status = %q, want rejected", audit.forwardStatus)
	}
	if !audit.statusCode.Valid || audit.statusCode.Int64 != http.StatusUnauthorized {
		t.Errorf("status_code = %+v, want %d", audit.statusCode, http.StatusUnauthorized)
	}
	if !audit.blockedBy.Valid || audit.blockedBy.String != "credential" {
		t.Errorf("blocked_by = %+v, want credential", audit.blockedBy)
	}
	if !audit.blockCode.Valid || audit.blockCode.String != "credential_required" {
		t.Errorf("block_code = %+v, want credential_required", audit.blockCode)
	}
	if audit.parseStatus != "skipped" {
		t.Errorf("parse_status = %q, want skipped", audit.parseStatus)
	}

	database := openAuditDatabase(t, cfg.DBPath)
	defer database.Close()
	stages := readStages(t, database, audit.auditID)
	if len(stages) != 1 {
		t.Fatalf("rejected stage count = %d, want 1: %+v", len(stages), stages)
	}
	if _, ok := stages[stageRequestReceived]; !ok {
		t.Errorf("rejected audit stages = %+v, want only %q", stages, stageRequestReceived)
	}
	for _, stageName := range []string{stageRequestSent, stageResponseReceived, stageResponseSent} {
		if _, ok := stages[stageName]; ok {
			t.Errorf("rejected audit unexpectedly contains unreached stage %q", stageName)
		}
	}
	var unreachedBodies, unreachedChunks int
	if err := database.QueryRow(`
SELECT
    (SELECT count(*) FROM body_streams WHERE audit_id = ? AND stage IN (?, ?, ?)),
    (SELECT count(*) FROM body_chunks WHERE audit_id = ? AND stage IN (?, ?, ?))
`, audit.auditID, stageRequestSent, stageResponseReceived, stageResponseSent,
		audit.auditID, stageRequestSent, stageResponseReceived, stageResponseSent,
	).Scan(&unreachedBodies, &unreachedChunks); err != nil {
		t.Fatalf("count rejected unreachable bodies: %v", err)
	}
	if unreachedBodies != 0 || unreachedChunks != 0 {
		t.Errorf("rejected unreachable body streams/chunks = %d/%d, want 0/0", unreachedBodies, unreachedChunks)
	}

	if err := running.stop(); err != nil {
		t.Fatalf("stop rejected audit app: %v", err)
	}
}

func TestAdminAPIRequiresBearerAndServesParsedAudit(t *testing.T) {
	requestURI := "/v1/chat/completions?request_uri_secret=admin-uri-secret"
	requestBody := []byte(`{"model":"gpt-personal","stream":false,"messages":[{"role":"user","content":"admin-api-prompt-secret"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-local","model":"gpt-personal-result","choices":[{"message":{"role":"assistant","content":"admin-api-response-secret"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)

	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(response, "read request", http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, requestBody) {
			http.Error(response, "request body changed", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody)
	}))
	defer upstream.Close()

	cfg := loadConfig(t, upstream.URL, "/v1/chat/completions", false)
	running := startApp(t, cfg)
	client := &http.Client{Timeout: integrationTimeout}

	request, err := http.NewRequest(http.MethodPost, running.baseURL+requestURI, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new parsed request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer downstream-admin-api-secret")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send parsed request: %v", err)
	}
	gotResponse, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read parsed response: %v", readErr)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(gotResponse, responseBody) {
		t.Fatalf("proxied response = %d %q", response.StatusCode, gotResponse)
	}

	unauthorized, err := client.Get(running.adminURL + "/healthz")
	if err != nil {
		t.Fatalf("request unauthenticated health: %v", err)
	}
	_, _ = io.Copy(io.Discard, unauthorized.Body)
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated health status = %d, want 401", unauthorized.StatusCode)
	}

	uiResponse, err := client.Get(running.adminURL + "/ui/")
	if err != nil {
		t.Fatalf("load anonymous UI shell: %v", err)
	}
	uiBody, uiReadErr := io.ReadAll(uiResponse.Body)
	uiResponse.Body.Close()
	if uiReadErr != nil {
		t.Fatalf("read anonymous UI shell: %v", uiReadErr)
	}
	if uiResponse.StatusCode != http.StatusOK || !bytes.Contains(uiBody, []byte(`<div id="root"></div>`)) {
		t.Fatalf("anonymous UI response = %d %q", uiResponse.StatusCode, uiBody)
	}
	for _, secret := range [][]byte{requestBody, responseBody, []byte("integration-admin-token")} {
		if bytes.Contains(uiBody, secret) {
			t.Fatalf("anonymous UI shell contains runtime secret %q", secret)
		}
	}

	summary, listBody := waitForParsedAdminAudit(t, client, running.adminURL)
	if summary.StartedAtNS == "" {
		t.Fatal("admin list started_at_ns must be a decimal JSON string")
	}
	if summary.RequestModel == nil || *summary.RequestModel != "gpt-personal" {
		t.Errorf("request model = %v, want gpt-personal", summary.RequestModel)
	}
	if summary.ResponseModel == nil || *summary.ResponseModel != "gpt-personal-result" {
		t.Errorf("response model = %v, want gpt-personal-result", summary.ResponseModel)
	}
	for _, secret := range [][]byte{[]byte("admin-api-prompt-secret"), []byte("admin-api-response-secret"), []byte("downstream-admin-api-secret"), []byte("admin-uri-secret")} {
		if bytes.Contains(listBody, secret) {
			t.Fatalf("admin list leaked secret %q", secret)
		}
	}

	detailBody := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+summary.AuditID)
	var detail adminAuditDetail
	if err := json.Unmarshal(detailBody, &detail); err != nil {
		t.Fatalf("decode admin detail: %v\n%s", err, detailBody)
	}
	if detail.ParsedResult == nil || detail.ParsedResult.Status != "ok" {
		t.Fatalf("parsed result = %+v, want ok", detail.ParsedResult)
	}
	if detail.ParsedResult.UsageInput == nil || *detail.ParsedResult.UsageInput != 3 ||
		detail.ParsedResult.UsageOutput == nil || *detail.ParsedResult.UsageOutput != 4 ||
		detail.ParsedResult.UsageTotal == nil || *detail.ParsedResult.UsageTotal != 7 {
		t.Errorf("parsed usage = %+v, want 3/4/7", detail.ParsedResult)
	}
	if detail.ParsedResult.MessageCount == nil || *detail.ParsedResult.MessageCount != 1 {
		t.Errorf("parsed message count = %v, want 1", detail.ParsedResult.MessageCount)
	}
	if detail.RequestURI != requestURI {
		t.Errorf("admin detail request_uri = %q, want %q", detail.RequestURI, requestURI)
	}
	var authorizationValues []string
	for _, header := range detail.Headers {
		if strings.EqualFold(header.Name, "Authorization") {
			authorizationValues = append(authorizationValues, header.Value)
		}
	}
	if len(authorizationValues) == 0 {
		t.Fatal("admin detail omitted saved Authorization values")
	}
	for _, value := range authorizationValues {
		if value != "Bearer downstream-admin-api-secret" {
			t.Errorf("admin detail Authorization = %q", value)
		}
	}
	if detail.Conversation == nil || detail.Conversation.SchemaVersion != conversation.SchemaVersion || len(detail.Conversation.Messages) != 2 {
		t.Fatalf("admin conversation = %+v", detail.Conversation)
	}
	if detail.Conversation.Messages[0].Role != conversation.RoleUser || detail.Conversation.Messages[0].Content[0].Text != "admin-api-prompt-secret" ||
		detail.Conversation.Messages[1].Role != conversation.RoleAssistant || detail.Conversation.Messages[1].Content[0].Text != "admin-api-response-secret" {
		t.Fatalf("admin conversation messages = %+v", detail.Conversation.Messages)
	}

	rawRequest := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+summary.AuditID+"/raw/request")
	if !bytes.Equal(rawRequest, requestBody) {
		t.Fatal("raw request download differs from bytes sent to NewAPI")
	}
	rawResponse := authorizedAdminGET(t, client, running.adminURL+"/api/v1/audits/"+summary.AuditID+"/raw/response")
	if !bytes.Equal(rawResponse, responseBody) {
		t.Fatal("raw response download differs from bytes received from NewAPI")
	}
}

func waitForParsedAdminAudit(t *testing.T, client *http.Client, adminURL string) (adminAuditSummary, []byte) {
	t.Helper()
	deadline := time.Now().Add(integrationTimeout)
	for time.Now().Before(deadline) {
		body := authorizedAdminGET(t, client, adminURL+"/api/v1/audits?limit=50")
		var page adminListPage
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode admin list: %v\n%s", err, body)
		}
		if len(page.Items) != 0 && page.Items[0].ParseStatus == "ok" {
			return page.Items[0], body
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for asynchronous parser result")
	return adminAuditSummary{}, nil
}

func authorizedAdminGET(t *testing.T, client *http.Client, url string) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new admin request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer integration-admin-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send admin request: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read admin response: %v", readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin response status = %d, want 200: %s", response.StatusCode, body)
	}
	return body
}

func startApp(t *testing.T, cfg config.Config) *runningApp {
	t.Helper()
	address := reserveAddress(t)
	adminAddress := reserveAddress(t)
	cfg.Listen = address
	cfg.AdminListen = adminAddress

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	application, err := app.New(cfg, logger)
	if err != nil {
		t.Fatalf("assemble audited app: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &runningApp{
		baseURL:  "http://" + address,
		adminURL: "http://" + adminAddress,
		cancel:   cancel,
		done:     make(chan error, 1),
	}
	go func() {
		running.done <- application.Run(ctx)
	}()

	deadline := time.Now().Add(integrationTimeout)
	for {
		connection, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case runErr := <-running.done:
			cancel()
			t.Fatalf("audited app exited before listening: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("timed out waiting for audited app on %s: %v", address, dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Cleanup(func() {
		if err := running.stop(); err != nil {
			t.Errorf("stop audited app: %v", err)
		}
	})
	return running
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return address
}

func (running *runningApp) stop() error {
	running.once.Do(func() {
		running.cancel()
		select {
		case running.stopErr = <-running.done:
		case <-time.After(integrationTimeout):
			running.stopErr = fmt.Errorf("timed out waiting for app shutdown")
		}
	})
	return running.stopErr
}

func waitForFinishedAudit(t *testing.T, path string) persistedAudit {
	t.Helper()
	deadline := time.Now().Add(integrationTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			time.Sleep(10 * time.Millisecond)
			continue
		}
		database, err := sql.Open("sqlite", path)
		if err != nil {
			lastErr = err
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var audit persistedAudit
		var endedAt sql.NullInt64
		err = database.QueryRow(`
SELECT audit_id, ended_at_ns, status_code, forward_status, capture_status,
       parse_status, blocked_by, block_code, request_uri_enc
FROM audit_records
ORDER BY started_at_ns DESC, audit_id DESC
LIMIT 1
`).Scan(
			&audit.auditID,
			&endedAt,
			&audit.statusCode,
			&audit.forwardStatus,
			&audit.captureStatus,
			&audit.parseStatus,
			&audit.blockedBy,
			&audit.blockCode,
			&audit.requestURIEnc,
		)
		_ = database.Close()
		if err == nil && endedAt.Valid {
			return audit
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for finished audit in %s: %v", path, lastErr)
	return persistedAudit{}
}

func openAuditDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec("PRAGMA query_only=ON"); err != nil {
		_ = database.Close()
		t.Fatalf("enable query-only audit database: %v", err)
	}
	return database
}

func auditRecordCount(t *testing.T, path string) int {
	t.Helper()
	database := openAuditDatabase(t, path)
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT count(*) FROM audit_records").Scan(&count); err != nil {
		t.Fatalf("count audit records: %v", err)
	}
	return count
}

func readStages(t *testing.T, database *sql.DB, auditID string) map[string]persistedStage {
	t.Helper()
	rows, err := database.Query(`
SELECT stage, state, status_code
FROM http_stages
WHERE audit_id = ?
`, auditID)
	if err != nil {
		t.Fatalf("query audit stages: %v", err)
	}
	defer rows.Close()
	stages := make(map[string]persistedStage)
	for rows.Next() {
		var stage persistedStage
		if err := rows.Scan(&stage.stage, &stage.state, &stage.statusCode); err != nil {
			t.Fatalf("scan audit stage: %v", err)
		}
		stages[stage.stage] = stage
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit stages: %v", err)
	}
	return stages
}

func readBodies(t *testing.T, database *sql.DB, auditID string) map[string]persistedBody {
	t.Helper()
	rows, err := database.Query(`
SELECT stage, observed_length, stored_length, sha256, hash_complete, eof_seen, state
FROM body_streams
WHERE audit_id = ?
`, auditID)
	if err != nil {
		t.Fatalf("query audit bodies: %v", err)
	}
	defer rows.Close()
	bodies := make(map[string]persistedBody)
	for rows.Next() {
		var body persistedBody
		if err := rows.Scan(
			&body.stage,
			&body.observedLength,
			&body.storedLength,
			&body.digest,
			&body.hashComplete,
			&body.eofSeen,
			&body.state,
		); err != nil {
			t.Fatalf("scan audit body: %v", err)
		}
		bodies[body.stage] = body
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit bodies: %v", err)
	}
	return bodies
}

func assertBodyAggregate(t *testing.T, body persistedBody, plaintext []byte) {
	t.Helper()
	if body.observedLength != int64(len(plaintext)) || body.storedLength != int64(len(plaintext)) {
		t.Errorf(
			"stage %s observed/stored length = %d/%d, want %d/%d",
			body.stage,
			body.observedLength,
			body.storedLength,
			len(plaintext),
			len(plaintext),
		)
	}
	digest := sha256.Sum256(plaintext)
	if !bytes.Equal(body.digest, digest[:]) {
		t.Errorf("stage %s SHA-256 = %x, want %x", body.stage, body.digest, digest)
	}
	if !body.hashComplete || !body.eofSeen || body.state != "complete" {
		t.Errorf(
			"stage %s hash_complete/eof_seen/state = %v/%v/%q, want true/true/complete",
			body.stage,
			body.hashComplete,
			body.eofSeen,
			body.state,
		)
	}
}

func assertEncryptedChunks(
	t *testing.T,
	database *sql.DB,
	cipher *security.AESGCM,
	auditID string,
	stage string,
	want []byte,
) {
	t.Helper()
	rows, err := database.Query(`
SELECT seq, "offset", plaintext_length, data_enc
FROM body_chunks
WHERE audit_id = ? AND stage = ?
ORDER BY seq
`, auditID, stage)
	if err != nil {
		t.Fatalf("query %s chunks: %v", stage, err)
	}
	defer rows.Close()

	var reconstructed []byte
	var chunkCount int
	for rows.Next() {
		var seq, offset int64
		var plaintextLength int
		var encrypted []byte
		if err := rows.Scan(&seq, &offset, &plaintextLength, &encrypted); err != nil {
			t.Fatalf("scan %s chunk: %v", stage, err)
		}
		if seq != int64(chunkCount) {
			t.Errorf("stage %s chunk seq = %d, want %d", stage, seq, chunkCount)
		}
		if offset != int64(len(reconstructed)) {
			t.Errorf("stage %s chunk offset = %d, want %d", stage, offset, len(reconstructed))
		}
		if plaintextLength <= 0 || plaintextLength > bodyChunkSize {
			t.Errorf("stage %s chunk plaintext length = %d, want 1..%d", stage, plaintextLength, bodyChunkSize)
		}
		if len(encrypted) != plaintextLength+security.NonceSize+16 {
			t.Errorf(
				"stage %s encrypted chunk length = %d, want %d",
				stage,
				len(encrypted),
				plaintextLength+security.NonceSize+16,
			)
		}
		aad, err := security.AAD(auditID, "body_chunk", stage, strconv.FormatInt(seq, 10))
		if err != nil {
			t.Fatalf("build %s chunk AAD: %v", stage, err)
		}
		plaintext, err := cipher.Decrypt(aad, encrypted)
		if err != nil {
			t.Fatalf("decrypt %s chunk %d: %v", stage, seq, err)
		}
		if len(plaintext) != plaintextLength {
			t.Errorf("stage %s chunk %d decrypted length = %d, want %d", stage, seq, len(plaintext), plaintextLength)
		}
		reconstructed = append(reconstructed, plaintext...)
		chunkCount++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s chunks: %v", stage, err)
	}
	if chunkCount < 2 {
		t.Errorf("stage %s chunk count = %d, want at least 2 for a >32 KiB body", stage, chunkCount)
	}
	if !bytes.Equal(reconstructed, want) {
		t.Errorf("stage %s decrypted chunks do not reconstruct the observed body", stage)
	}
}

func assertEncryptedHeader(
	t *testing.T,
	database *sql.DB,
	cipher *security.AESGCM,
	auditID string,
	stage string,
	name string,
	want string,
) {
	t.Helper()
	var kind, storedName string
	var valueIndex, valueLength int
	var encrypted []byte
	err := database.QueryRow(`
SELECT kind, name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ? AND stage = ? AND lower(name) = lower(?)
ORDER BY value_index
LIMIT 1
`, auditID, stage, name).Scan(&kind, &storedName, &valueIndex, &valueLength, &encrypted)
	if err != nil {
		t.Fatalf("read encrypted header %s/%s: %v", stage, name, err)
	}
	if valueLength != len(want) {
		t.Errorf("encrypted header value length = %d, want %d", valueLength, len(want))
	}
	aad, err := security.AAD(
		auditID,
		"header",
		stage,
		kind,
		storedName,
		strconv.Itoa(valueIndex),
	)
	if err != nil {
		t.Fatalf("build encrypted header AAD: %v", err)
	}
	plaintext, err := cipher.Decrypt(aad, encrypted)
	if err != nil {
		t.Fatalf("decrypt header %s/%s: %v", stage, name, err)
	}
	if string(plaintext) != want {
		t.Errorf("decrypted header value = %q, want %q", plaintext, want)
	}
}

func assertEncryptedTrailer(
	t *testing.T,
	database *sql.DB,
	cipher *security.AESGCM,
	auditID string,
	stage string,
	name string,
	want string,
) {
	t.Helper()
	var storedName string
	var valueIndex, valueLength int
	var encrypted []byte
	err := database.QueryRow(`
SELECT name, value_index, value_length, value_enc
FROM http_headers
WHERE audit_id = ? AND stage = ? AND kind = 'trailer' AND lower(name) = lower(?)
ORDER BY value_index
LIMIT 1
`, auditID, stage, name).Scan(&storedName, &valueIndex, &valueLength, &encrypted)
	if err != nil {
		t.Fatalf("read encrypted trailer %s/%s: %v", stage, name, err)
	}
	if valueLength != len(want) {
		t.Errorf("encrypted trailer value length = %d, want %d", valueLength, len(want))
	}
	aad, err := security.AAD(
		auditID,
		"header",
		stage,
		"trailer",
		storedName,
		strconv.Itoa(valueIndex),
	)
	if err != nil {
		t.Fatalf("build encrypted trailer AAD: %v", err)
	}
	plaintext, err := cipher.Decrypt(aad, encrypted)
	if err != nil {
		t.Fatalf("decrypt trailer %s/%s: %v", stage, name, err)
	}
	if string(plaintext) != want {
		t.Errorf("decrypted trailer value = %q, want %q", plaintext, want)
	}
}

func assertSQLiteFilesDoNotContain(t *testing.T, databasePath string, markers [][]byte) {
	t.Helper()
	for _, path := range []string{databasePath, databasePath + "-wal"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			if errorsIsNotExist(err) {
				continue
			}
			t.Fatalf("read SQLite file %s: %v", filepath.Base(path), err)
		}
		for _, marker := range markers {
			if bytes.Contains(contents, marker) {
				t.Errorf("SQLite file %s contains plaintext marker %q", filepath.Base(path), marker)
			}
		}
	}
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err)
}
