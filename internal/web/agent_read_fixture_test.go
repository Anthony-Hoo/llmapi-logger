package web

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentaccess/agentaccesstest"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/insights/models"
	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/storage/sqlite"
	"llmapi-logger/internal/uaguard"
)

// The shared fixture of the read facade tests. Every service whose rules
// decide what a developer may read is real (insights over SQLite, orgreport,
// session analysis over an in-memory store) or delegates the decision to the
// real rule (scopedAudits applies storage.AuditScope.Allows), so the D-rule
// and parity tests exercise the rules, not a stand-in.

// Credential values planted in the fixture; none may appear in any facade
// response.
const (
	plantedBearer     = "sk-planted-bearer-value-0001"
	plantedBareAuth   = "planted-bare-authorization-0002"
	plantedAPIKey     = "planted-x-api-key-0003"
	plantedGoogKey    = "planted-x-goog-api-key-0004"
	plantedQueryKey   = "planted-query-key-0005"
	plantedUserAgent  = "codex_cli_rs/0.50.0 (planted-ua)"
	plantedSessionID  = "planted-agent-session-0006"
	plantedOneapiID   = "planted-oneapi-request-0007"
	plantedAgentName  = "planted-agent-name"
	plantedAgentRole  = "planted-agent-role"
	plantedAgentID    = "planted-agent-id"
	plantedParentID   = "planted-parent-id"
	plantedProject    = "planted-project"
	analysisOwnID     = "0101010101010101010101010101010101010101010101010101010101010101"
	analysisForeignID = "0202020202020202020202020202020202020202020202020202020202020202"
)

var plantedCredentials = []string{plantedBearer, plantedBareAuth, plantedAPIKey, plantedGoogKey, plantedQueryKey}

var plantedVisible = []string{plantedUserAgent, plantedSessionID, plantedOneapiID, plantedAgentName, plantedAgentRole,
	plantedAgentID, plantedParentID, plantedProject}

// auditRecord is one audit of scopedAudits with its ownership columns.
type auditRecord struct {
	detail query.Detail
	row    storage.AuditScopeRow
}

// scopedAudits is an AuditQuery whose every scoped read goes through
// storage.AuditScope.Allows, the rule the SQL stores implement.
type scopedAudits struct {
	mu      sync.Mutex
	records []auditRecord
	// listCalls counts List calls, to prove a refused request never reached it.
	listCalls int
}

func (audits *scopedAudits) visible(record auditRecord, scope *query.Scope) bool {
	if scope == nil {
		return true
	}
	return (&storage.AuditScope{Fingerprint: scope.Fingerprint, TokenID: scope.TokenID}).Allows(record.row)
}

func (audits *scopedAudits) find(auditID string, scope *query.Scope) (auditRecord, error) {
	for _, record := range audits.records {
		if record.detail.Audit.AuditID == auditID {
			if !audits.visible(record, scope) {
				return auditRecord{}, query.ErrNotFound
			}
			return record, nil
		}
	}
	return auditRecord{}, query.ErrNotFound
}

func (audits *scopedAudits) Healthy() bool { return true }

func (audits *scopedAudits) List(_ context.Context, filter query.Filter, cursor query.Cursor, limit int) (query.Page, error) {
	audits.mu.Lock()
	audits.listCalls++
	audits.mu.Unlock()
	if limit == 0 {
		limit = query.DefaultLimit
	}
	page := query.Page{Items: []query.AuditSummary{}}
	for _, record := range audits.records {
		summary := record.detail.Audit
		if !audits.visible(record, filter.Scope) {
			continue
		}
		if cursor.BeforeID != "" && (summary.StartedAtNS > cursor.BeforeStartedAtNS ||
			summary.StartedAtNS == cursor.BeforeStartedAtNS && summary.AuditID >= cursor.BeforeID) {
			continue
		}
		if filter.FromNS != nil && summary.StartedAtNS < *filter.FromNS || filter.ToNS != nil && summary.StartedAtNS > *filter.ToNS {
			continue
		}
		if filter.NewAPIUserID != nil && (summary.NewAPIUserID == nil || *summary.NewAPIUserID != *filter.NewAPIUserID) {
			continue
		}
		if filter.ForwardStatus != "" && summary.ForwardStatus != filter.ForwardStatus {
			continue
		}
		// Exactly as the stores match it (a.protocol = $n).
		if filter.Protocol != "" && summary.Protocol != filter.Protocol {
			continue
		}
		if len(page.Items) == limit {
			last := page.Items[len(page.Items)-1]
			page.NextCursor = &query.Cursor{BeforeStartedAtNS: last.StartedAtNS, BeforeID: last.AuditID}
			break
		}
		page.Items = append(page.Items, summary)
	}
	return page, nil
}

func (audits *scopedAudits) Authorize(_ context.Context, auditID string, scope *query.Scope) error {
	_, err := audits.find(auditID, scope)
	return err
}

func (audits *scopedAudits) Get(_ context.Context, auditID string, scope *query.Scope) (query.Detail, error) {
	record, err := audits.find(auditID, scope)
	return record.detail, err
}

// The services below do not check ownership themselves: the web and the
// facade must call Authorize first. They answer for any id that exists, and
// only for content the record has, as query.Service does: a reconstruction
// only with a turn, a timeline only for a body with stream events, a raw
// body only when there is one.
func (audits *scopedAudits) ReconstructTurn(_ context.Context, auditID string) (query.ReconstructedTurn, error) {
	record, err := audits.find(auditID, nil)
	if err != nil {
		return query.ReconstructedTurn{}, err
	}
	if record.detail.Turn == nil {
		return query.ReconstructedTurn{}, query.ErrNoTurnGraph
	}
	return query.ReconstructedTurn{Request: map[string]any{"model": "gpt-test", "owner": auditID}, Response: map[string]any{"id": "resp-" + auditID}}, nil
}

func (audits *scopedAudits) Timeline(_ context.Context, auditID string, side query.Side) (query.StreamTimeline, error) {
	record, err := audits.find(auditID, nil)
	if err != nil {
		return query.StreamTimeline{}, err
	}
	body := fixtureSideBody(record, side)
	if body == nil || body.StreamEventCount == 0 {
		return query.StreamTimeline{}, query.ErrNotFound
	}
	first := fixtureBase.UnixNano()
	// The stored timeline's completeness is the body's
	// stream_timeline_complete, as query.Service.Timeline reads it.
	return query.StreamTimeline{Stage: string(side), ObservedLength: 4, EventCount: 1, FirstEventAtNS: &first, LastEventAtNS: &first,
		Complete: body.StreamTimelineComplete, Points: []query.TimelinePoint{{Offset: 0, AtNS: first}}}, nil
}

func (audits *scopedAudits) RawMeta(_ context.Context, auditID string, side query.Side) (query.RawMetadata, error) {
	if side != query.SideRequest && side != query.SideResponse {
		return query.RawMetadata{}, query.ErrInvalidQuery
	}
	record, err := audits.find(auditID, nil)
	if err != nil {
		return query.RawMetadata{}, err
	}
	body := fixtureSideBody(record, side)
	switch {
	case body == nil:
		return query.RawMetadata{}, query.ErrNotFound
	case body.State == storage.StageStateStreaming, body.RetentionState == storage.RetentionPending:
		return query.RawMetadata{}, query.ErrNotReady
	case body.RetentionState == storage.RetentionMetadata:
		return query.RawMetadata{}, query.ErrNotRetained
	}
	// Complete by query.Service.RawMeta's rule, from the body's own columns.
	complete := body.State == storage.StageStateComplete && body.HashComplete && body.EOFSeen && body.StoredLength == body.ObservedLength
	return query.RawMetadata{ObservedLength: body.ObservedLength, StoredLength: body.StoredLength, Complete: complete, SHA256: "abc"}, nil
}

// StreamRaw writes stored_length bytes (the audit id repeated), so the body
// matches the Content-Length RawMeta announces.
func (audits *scopedAudits) StreamRaw(_ context.Context, auditID string, side query.Side, writer io.Writer) error {
	record, err := audits.find(auditID, nil)
	if err != nil {
		return err
	}
	body := fixtureSideBody(record, side)
	if body == nil {
		return query.ErrNotFound
	}
	content := bytes.Repeat([]byte(auditID), int(body.StoredLength)/len(auditID)+1)[:body.StoredLength]
	_, err = writer.Write(content)
	return err
}

// fixtureSideBody is the body the query service reads for side.
func fixtureSideBody(record auditRecord, side query.Side) *query.Body {
	stages := []string{storage.StageRequestSent, storage.StageRequestReceived}
	if side == query.SideResponse {
		stages = []string{storage.StageResponseReceived, storage.StageResponseSent}
	}
	for _, stage := range stages {
		for index := range record.detail.Bodies {
			if record.detail.Bodies[index].Stage == stage {
				return &record.detail.Bodies[index]
			}
		}
	}
	return nil
}

var fixtureBase = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func fixtureAudit(id string, offset time.Duration, fingerprint []byte, tokenID int64, forward string, blockCode *string) auditRecord {
	started := fixtureBase.Add(offset).UnixNano()
	ended := started + int64(time.Second)
	ttft := int64(250 * time.Millisecond)
	status := 200
	userID, username, tokenName := int64(7), "dev-user", "dev-token"
	model, requestID, userAgent := "gpt-test", plantedOneapiID, plantedUserAgent
	if tokenID != 42 {
		userID, username, tokenName = 8, "other-user", "other-token"
	}
	summary := query.AuditSummary{
		AuditID: id, StartedAtNS: started, EndedAtNS: &ended, RouteID: "gemini", Protocol: "gemini", ParserName: "gemini.generate",
		Method: "POST", Path: "/v1beta/models/gemini:generateContent", Mode: "available", StatusCode: &status, TTFTNS: &ttft,
		ForwardStatus: forward, CaptureStatus: storage.CaptureComplete, ParseStatus: storage.ParseOK, BlockCode: blockCode,
		RequestModel: &model, ResponseModel: &model, UserAgent: &userAgent, NewAPIRequestID: &requestID,
		CallerStatus: storage.CallerResolved, NewAPIUserID: &userID, Username: &username, NewAPITokenID: &tokenID, TokenName: &tokenName,
	}
	quota, cost := int64(500), 0.001
	parsedAt := started + 5
	messages, toolCalls := int64(2), int64(1)
	detail := query.Detail{
		Audit:      summary,
		RequestURI: "/v1beta/models/gemini:generateContent?key=" + plantedQueryKey + "&alt=sse",
		Stages: []query.Stage{{Stage: storage.StageRequestReceived, State: storage.StageStateComplete, Proto: "HTTP/1.1", Method: "POST",
			Host: "proxy.example.com", StartedAtNS: started, EndedAtNS: &ended}},
		Headers: fixtureHeaders(),
		Bodies: []query.Body{{Stage: storage.StageRequestReceived, SourceStage: storage.StageRequestReceived, ObservedLength: 10, StoredLength: 10,
			HashComplete: true, EOFSeen: true, State: storage.StageStateComplete, RetentionState: storage.RetentionFull, FirstObservedAtNS: &started}},
		ParsedResult: &query.ParsedResult{ParserName: "gemini.generate", ParserVersion: "1", Status: storage.ParseOK, RequestModel: &model,
			MessageCount: &messages, ToolCallCount: &toolCalls, ParsedAtNS: parsedAt},
		Turn: &query.Turn{TurnID: "turn-" + id, ConversationID: "conv-" + id, CreatedAtNS: parsedAt},
		Conversation: &conversation.Conversation{SchemaVersion: conversation.SchemaVersion, Messages: []conversation.Message{
			{Index: 0, Role: conversation.RoleUser, Phase: conversation.PhaseRequest, Direction: conversation.DirectionClientToUpstream,
				Content: []conversation.Part{{Index: 0, Type: conversation.PartText, Text: "hello"}}},
			{Index: 1, Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient,
				Content: []conversation.Part{{Index: 0, Type: conversation.PartToolCall, Name: "shell"}}},
		}},
		TokenLink: &query.TokenLink{NewAPIRequestID: requestID, NewAPIUserID: userID, Username: username, NewAPITokenID: tokenID,
			TokenName: tokenName, LinkedAtNS: parsedAt, BillingState: storage.BillingBilled, NewAPIQuota: &quota, CostUSD: &cost},
	}
	if forward == storage.ForwardRejected {
		// A locally blocked record was never forwarded: no parse, no
		// reconstruction, no response (what the proxy stores for it).
		detail.Audit.ParseStatus = storage.ParseSkipped
		detail.ParsedResult, detail.Turn, detail.Conversation = nil, nil, nil
	} else {
		// The streamed response the proxy received, with its timeline.
		detail.Bodies = append(detail.Bodies, query.Body{Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived,
			ObservedLength: 4, StoredLength: 4, HashComplete: true, EOFSeen: true, State: storage.StageStateComplete,
			RetentionState: storage.RetentionFull, FirstObservedAtNS: &started, StreamEventCount: 1, StreamTimelineComplete: true})
	}
	return auditRecord{detail: detail, row: storage.AuditScopeRow{APIKeyFPR: fingerprint, NewAPITokenID: &tokenID, ForwardStatus: forward, BlockCode: blockCode}}
}

func fixtureHeaders() []query.Header {
	headers := []query.Header{}
	add := func(stage, name, value string) {
		headers = append(headers, query.Header{Stage: stage, Kind: storage.HeaderKindHeader, Name: name, ValueLength: len(value), Value: value})
	}
	inbound, sent := storage.StageRequestReceived, storage.StageRequestSent
	add(inbound, "Authorization", "Bearer "+plantedBearer)
	add(inbound, "X-Api-Key", plantedAPIKey)
	add(inbound, "X-Goog-Api-Key", plantedGoogKey)
	add(inbound, "User-Agent", plantedUserAgent)
	add(inbound, "X-Agent-Session-Id", plantedSessionID)
	add(inbound, "X-Agent-Id", plantedAgentID)
	add(inbound, "X-Agent-Parent-Id", plantedParentID)
	add(inbound, "X-Agent-Role", plantedAgentRole)
	add(inbound, "X-Agent-Name", plantedAgentName)
	add(inbound, "X-Agent-Project", plantedProject)
	add(sent, "Authorization", plantedBareAuth)
	add(storage.StageResponseReceived, "X-Oneapi-Request-Id", plantedOneapiID)
	return headers
}

// memoryAnalysisStore is an in-memory sessionanalysis.QueryStore driving the
// real QueryService, so its ownership, D8 and D9 rules are the real ones.
type memoryAnalysisStore struct {
	mu        sync.Mutex
	cipher    security.Cipher
	signals   []storage.SessionSignals
	packs     map[string]storage.SessionPack
	facets    map[string]storage.SessionFacet
	views     []storage.AnalysisView
	failViews bool
	run       *storage.SessionAnalysisRun
}

func scopeOwns(scope *storage.AuditScope, fingerprint []byte, tokenID *int64) bool {
	if scope == nil {
		return true
	}
	if len(fingerprint) != 0 && bytes.Equal(fingerprint, scope.Fingerprint) {
		return true
	}
	return scope.TokenID != nil && tokenID != nil && *scope.TokenID == *tokenID
}

func (store *memoryAnalysisStore) matching(filter storage.SessionSignalFilter) []storage.SessionSignals {
	out := []storage.SessionSignals{}
	for _, row := range store.signals {
		if row.LastNS < filter.FromNS || row.LastNS >= filter.ToNS || !scopeOwns(filter.Scope, row.APIKeyFPR, row.NewAPITokenID) {
			continue
		}
		if filter.UserIDs != nil {
			found := false
			for _, id := range filter.UserIDs {
				found = found || row.NewAPIUserID != nil && *row.NewAPIUserID == id
			}
			if !found {
				continue
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastNS > out[j].LastNS })
	return out
}

func (store *memoryAnalysisStore) ListSessionSignals(_ context.Context, filter storage.SessionSignalFilter, _ storage.SessionSignalCursor, limit int) (storage.SessionSignalPage, error) {
	rows := store.matching(filter)
	page := storage.SessionSignalPage{Rows: rows}
	if len(rows) > limit {
		page.Rows, page.HasMore = rows[:limit], true
	}
	return page, nil
}

func (store *memoryAnalysisStore) SessionSignalTotals(_ context.Context, filter storage.SessionSignalFilter) (storage.SessionSignalTotals, error) {
	rows := store.matching(filter)
	return storage.SessionSignalTotals{Sessions: int64(len(rows)), AgentSessions: int64(len(rows))}, nil
}

func (store *memoryAnalysisStore) SessionSignalTotalsByUser(_ context.Context, filter storage.SessionSignalFilter) ([]storage.SessionUserTotals, error) {
	out := []storage.SessionUserTotals{}
	for _, row := range store.matching(filter) {
		out = append(out, storage.SessionUserTotals{UserID: row.NewAPIUserID, LastNS: row.LastNS, Totals: storage.SessionSignalTotals{Sessions: 1}})
	}
	return out, nil
}

func (store *memoryAnalysisStore) LatestSessionAnalysisRun(context.Context) (storage.SessionAnalysisRun, error) {
	if store.run == nil {
		return storage.SessionAnalysisRun{}, sql.ErrNoRows
	}
	return *store.run, nil
}

func (store *memoryAnalysisStore) LoadSessionPack(_ context.Context, key []byte) (storage.SessionPack, error) {
	pack, ok := store.packs[hex.EncodeToString(key)]
	if !ok {
		return storage.SessionPack{}, sql.ErrNoRows
	}
	return pack, nil
}

func (store *memoryAnalysisStore) RecordAnalysisView(_ context.Context, view storage.AnalysisView) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.failViews {
		return storage.ErrClosed
	}
	store.views = append(store.views, view)
	return nil
}

func (store *memoryAnalysisStore) LoadSessionFacet(_ context.Context, key []byte) (storage.SessionFacet, error) {
	facet, ok := store.facets[hex.EncodeToString(key)]
	if !ok {
		return storage.SessionFacet{}, sql.ErrNoRows
	}
	return facet, nil
}

func (store *memoryAnalysisStore) SaveFacetCalibration(context.Context, storage.FacetCalibration) error {
	return nil
}

func (store *memoryAnalysisStore) LatestFacetCalibration(context.Context, string, string) (storage.FacetCalibration, error) {
	return storage.FacetCalibration{}, sql.ErrNoRows
}

func (store *memoryAnalysisStore) viewCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.views)
}

func (store *memoryAnalysisStore) addSession(t *testing.T, id string, fingerprint []byte, userID, tokenID int64) {
	t.Helper()
	key, _ := hex.DecodeString(id)
	last := fixtureBase.UnixNano()
	store.signals = append(store.signals, storage.SessionSignals{SessionKey: key, Kind: sessionanalysis.KindAgent, APIKeyFPR: fingerprint,
		NewAPIUserID: &userID, NewAPITokenID: &tokenID, FirstNS: last - int64(time.Hour), LastNS: last, LastAuditID: "own-1",
		Client: "codex", ProjectID: int64Pointer(3)})
	packAAD, err := sessionanalysis.PackAAD(key)
	if err != nil {
		t.Fatal(err)
	}
	packEnc, err := store.cipher.Encrypt(packAAD, []byte("[pack] "+id))
	if err != nil {
		t.Fatal(err)
	}
	store.packs[id] = storage.SessionPack{SessionKey: key, Kind: sessionanalysis.KindAgent, APIKeyFPR: fingerprint, NewAPITokenID: &tokenID,
		PackEnc: packEnc, RefMap: `{"E1":"own-1"}`, BuiltAtNS: last}
	facetAAD, err := sessionanalysis.FacetAAD(key)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := json.Marshal(map[string]any{"goal": "fix the build", "instructions": []string{"run tests"}, "evidence": map[string][]string{"goal": {"E1"}}})
	textEnc, err := store.cipher.Encrypt(facetAAD, text)
	if err != nil {
		t.Fatal(err)
	}
	store.facets[id] = storage.SessionFacet{SessionKey: key, Kind: sessionanalysis.KindAgent, APIKeyFPR: fingerprint, NewAPITokenID: &tokenID,
		LastNS: last, Status: "ok", TaskType: "bugfix", WorkRelevance: "work", Friction: `[]`,
		Items: `[{"ref":"a","task_type":"bugfix","work_relevance":"work"}]`, InvalidFields: `[]`, TextEnc: textEnc, CreatedAtNS: last}
}

// reportingAnalysis is the real QueryService with a canned weekly report:
// the report reads thirteen store methods that this fixture does not model.
// Ownership of the report (D8) is the service's and is not exercised here.
type reportingAnalysis struct {
	*sessionanalysis.QueryService
	stats *sessionanalysis.WeeklyStats
}

func (analysis *reportingAnalysis) Report(_ context.Context, week string, scope *query.Scope, target sessionanalysis.ReportTarget) (sessionanalysis.ReportResponse, error) {
	if week != "" && week != "current" && week != "previous" {
		return sessionanalysis.ReportResponse{}, query.ErrInvalidQuery
	}
	at := fixtureBase.UnixNano()
	response := sessionanalysis.ReportResponse{WeekStartNS: at, Scope: "all", Stats: analysis.stats, Narrative: "a steady week",
		NarrativeSource: "model", ComputedNS: at, Optimizations: []sessionanalysis.SessionItem{},
		Suggestions: []sessionanalysis.SuggestionItem{{ID: 1, Kind: "skill", Text: "write a skill", Sessions: 2, Status: "open",
			FirstSeenNS: at, LastSeenNS: at, Evidence: []string{"E1"}}}}
	if scope != nil {
		response.Scope = "person"
	}
	if target.UserID != 0 {
		response.Scope, response.ScopeID = "user", target.UserID
	}
	return response, nil
}

// readFixture is a handler with every module enabled and one token of each
// kind.
type readFixture struct {
	agentEnv
	audits         *scopedAudits
	analysis       *memoryAnalysisStore
	reports        *reportingAnalysis
	adminRead      string
	adminWrite     string
	developer      string
	developerWeb   *http.Cookie
	adminWeb       *http.Cookie
	ownFingerprint []byte
}

func newReadFixture(t *testing.T) *readFixture {
	t.Helper()
	return newReadFixtureWrites(t, true)
}

// newReadFixtureWrites builds the fixture with agent_access.allow_write set
// to allowWrite; the write token is issued either way, as one issued before
// the switch was turned off.
func newReadFixtureWrites(t *testing.T, allowWrite bool) *readFixture {
	t.Helper()
	own := testFingerprinter(t).Fingerprint(testDeveloperKey)
	other := bytes.Repeat([]byte{0x77}, len(own))
	blocked, tooLarge := "content_policy", "body_too_large"
	audits := &scopedAudits{records: []auditRecord{
		fixtureAudit("own-1", 0, own, 42, storage.ForwardCompleted, nil),
		fixtureAudit("token-only", time.Second, other, 42, storage.ForwardCompleted, nil),
		fixtureAudit("foreign", 2*time.Second, other, 99, storage.ForwardCompleted, nil),
		fixtureAudit("blocked-own", 3*time.Second, own, 42, storage.ForwardRejected, &blocked),
		fixtureAudit("too-large-own", 4*time.Second, own, 42, storage.ForwardRejected, &tooLarge),
	}}
	// newest first, as the stores list
	sort.Slice(audits.records, func(i, j int) bool {
		return audits.records[i].detail.Audit.StartedAtNS > audits.records[j].detail.Audit.StartedAtNS
	})

	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x5a}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	seedAPIStep(t, store, cipher, "own-1", fixtureBase, own, apiSessionShared, repeated(0xa0), repeated(0x11), true, 250000)
	seedAPIStep(t, store, cipher, "other-in-shared", fixtureBase.Add(time.Second), other, apiSessionShared, repeated(0xa0), repeated(0x12), true, 1000000)
	seedAPIStep(t, store, cipher, "other-only", fixtureBase.Add(2*time.Second), other, apiSessionForeign, repeated(0xb0), repeated(0x14), true, 0)
	seedSubagentStep(t, store, cipher, "own-sub", fixtureBase.Add(3*time.Second), own, repeated(0xa0), repeated(0x13), repeated(0x12))
	windows, err := models.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	insightsService, err := query.NewInsights(store, cipher, windows, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	analysis := &memoryAnalysisStore{cipher: cipher, packs: map[string]storage.SessionPack{}, facets: map[string]storage.SessionFacet{}}
	analysis.addSession(t, analysisOwnID, own, 7, 42)
	analysis.addSession(t, analysisForeignID, other, 8, 99)
	analysisService, err := sessionanalysis.NewQueryService(analysis, nil, cipher, "local-model")
	if err != nil {
		t.Fatal(err)
	}
	reports := &reportingAnalysis{QueryService: analysisService, stats: &sessionanalysis.WeeklyStats{WeekStartNS: fixtureBase.UnixNano(),
		Totals: sessionanalysis.SignalTotals{Sessions: 1}, TaskTypes: map[string]int64{"bugfix": 1}}}

	org, _ := newOrgTestService(t)
	rules, err := uaguard.New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	agentStore := agentaccesstest.NewStore()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	service, err := agentaccess.New(agentaccess.Options{AdminToken: testAdminToken, Store: agentStore, AllowWrite: allowWrite, DeveloperLogins: true, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	handlerValue, err := NewHandler(Options{
		AdminToken: testAdminToken, Developer: developerOptions(t, agentTestIdentity, nil), Query: audits, Insights: insightsService,
		Users: fakeUserCatalog{snapshot: newapi.UserSnapshot{Users: []newapi.User{{ID: 7, Username: "dev-user", DisplayName: "Dev"}},
			RefreshedAt: fixtureBase}},
		Rules: rules, Policies: &fakeContentPolicyRules{items: []contentpolicy.Rule{{ID: 1, Name: "r", Enabled: true, Action: "block",
			Keywords: []string{"secret-word"}, UpdatedAtNS: 9}}},
		Org: org, SessionAnalysis: reports, SessionAnalysisSettings: &fakeAnalysisSettings{},
		AgentAccess: service, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	env := agentEnv{handler: handlerValue.(*managementHandler), service: service, store: agentStore, logs: logs}
	fixture := &readFixture{agentEnv: env, audits: audits, analysis: analysis, reports: reports, ownFingerprint: own}
	fixture.adminRead = issueAgentAdmin(t, env, agentapi.TierRead)
	fixture.adminWrite = agentaccesstest.IssueAdmin(t, mustService(t, env, true), agentapi.TierWrite).Token
	fixture.developer, fixture.developerWeb = issueAgentDeveloper(t, env)
	fixture.adminWeb = adminSignIn(t, env.handler)
	return fixture
}

// facade calls one facade path with token.
func (fixture *readFixture) facade(method, path, body, token string) *httptest.ResponseRecorder {
	return fixture.do(method, agentapi.PathPrefix+path, body, agentCaller{bearer: token})
}

// web calls one management path with a web session cookie.
func (fixture *readFixture) web(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	return fixture.do(method, path, body, agentCaller{cookie: cookie})
}

// fixtureWindow is a from/to pair around the fixture's data.
const fixtureWindow = "from=2026-10-10T11:00:00Z&to=2026-10-10T13:00:00Z"

var fixtureWindowNS = "from_ns=" + itoa(fixtureBase.Add(-time.Hour).UnixNano()) + "&to_ns=" + itoa(fixtureBase.Add(time.Hour).UnixNano())

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

// seedSubagentStep writes one analysed subagent audit whose parent node is
// parent, so a scope that cannot see the parent gets a placeholder (D6).
func seedSubagentStep(t *testing.T, store *sqlite.Store, cipher security.Cipher, id string, at time.Time, key, root, node, parent []byte) {
	t.Helper()
	ctx := context.Background()
	if err := store.BeginAudit(ctx, sqlite.AuditRecord{
		AuditID: id, StartedAtNS: at.UnixNano(), RouteID: "openai-chat", Protocol: "openai", ParserName: "openai.chat_completions",
		Method: "POST", Path: "/v1/chat/completions", RequestURIEnc: []byte{1}, Mode: "available", APIKeyFPR: key,
	}); err != nil {
		t.Fatal(err)
	}
	status := 200
	if err := store.FinishAudit(ctx, sqlite.AuditFinish{AuditID: id, EndedAtNS: at.UnixNano() + 1000, StatusCode: &status,
		ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK}); err != nil {
		t.Fatal(err)
	}
	model, role, client, session := "gpt-4.1", "subagent", "custom", "agt_dddddddddddddddddddddddd"
	uncached, output := int64(50), int64(5)
	row := sqlite.AnalysisRow{
		AuditID: id, AnalysisVersion: 1, AnalyzedAtNS: at.UnixNano() + 1, Protocol: "openai", Model: &model, StartedAtNS: at.UnixNano(),
		UncachedInput: &uncached, Output: &output, EstSystem: 40, EstUser: 10, AnalysisSessionID: &session,
		AgentClient: &client, AgentRole: &role, AgentRootFPR: root, AgentNodeFPR: node, AgentParentFPR: parent,
	}
	if err := store.SaveAnalysis(ctx, row); err != nil {
		t.Fatal(err)
	}
}
