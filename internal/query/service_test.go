package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func TestStreamRawDecryptsAndVerifiesCompleteBody(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-raw"
	stage := sqlite.StageRequestSent
	parts := [][]byte{[]byte("hello "), []byte("world")}
	hash := sha256.Sum256(bytes.Join(parts, nil))
	store := &fakeStore{healthy: true, rawMeta: sqlite.RawBodyMetadata{
		AuditID: auditID, Stage: stage, ObservedLength: 11, StoredLength: 11,
		SHA256: hash[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete,
	}}
	var offset int64
	for sequence, part := range parts {
		aad, err := security.AAD(auditID, "body_chunk", stage, strconv.Itoa(sequence))
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, part)
		if err != nil {
			t.Fatal(err)
		}
		store.chunks = append(store.chunks, sqlite.BodyChunk{
			AuditID: auditID, Stage: stage, Seq: int64(sequence), Offset: offset,
			PlaintextLength: len(part), DataEnc: encrypted,
		})
		offset += int64(len(part))
	}

	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := service.RawMeta(context.Background(), auditID, SideRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.Complete || metadata.StoredLength != 11 || metadata.SHA256 == "" {
		t.Fatalf("raw metadata = %+v", metadata)
	}
	var output bytes.Buffer
	if err := service.StreamRaw(context.Background(), auditID, SideRequest, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "hello world" {
		t.Fatalf("raw output = %q", output.String())
	}
}

func TestStreamRawRejectsTamperedCiphertextWithoutPlaintext(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-tampered"
	stage := sqlite.StageResponseReceived
	plaintext := []byte("top secret prompt")
	digest := sha256.Sum256(plaintext)
	aad, err := security.AAD(auditID, "body_chunk", stage, "0")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	store := &fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: auditID, Stage: stage, ObservedLength: int64(len(plaintext)), StoredLength: int64(len(plaintext)),
			SHA256: digest[:], HashComplete: true, EOFSeen: true, State: sqlite.StageStateComplete,
		},
		chunks: []sqlite.BodyChunk{{
			AuditID: auditID, Stage: stage, Seq: 0, Offset: 0,
			PlaintextLength: len(plaintext), DataEnc: encrypted,
		}},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = service.StreamRaw(context.Background(), auditID, SideResponse, &output)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("StreamRaw error = %v, want ErrIntegrity", err)
	}
	if output.Len() != 0 {
		t.Fatalf("tampered stream wrote %d bytes", output.Len())
	}
}

func TestStreamRawRejectsChunkGapEvenForPartialCapture(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-partial-gap"
	stage := sqlite.StageRequestSent
	plaintext := []byte("partial")
	aad, err := security.AAD(auditID, "body_chunk", stage, "1")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: auditID, Stage: stage, ObservedLength: int64(len(plaintext)), StoredLength: int64(len(plaintext)),
			HashComplete: false, EOFSeen: false, State: sqlite.StageStatePartial,
		},
		chunks: []sqlite.BodyChunk{{
			AuditID: auditID, Stage: stage, Seq: 1, Offset: 0,
			PlaintextLength: len(plaintext), DataEnc: encrypted,
		}},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = service.StreamRaw(context.Background(), auditID, SideRequest, &output)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("StreamRaw error = %v, want ErrIntegrity", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid partial stream wrote %d bytes", output.Len())
	}
}

func TestRawRejectsEvidenceThatIsStillStreaming(t *testing.T) {
	t.Parallel()

	service, err := New(&fakeStore{
		healthy: true,
		rawMeta: sqlite.RawBodyMetadata{
			AuditID: "audit-streaming", Stage: sqlite.StageRequestSent,
			ObservedLength: 7, StoredLength: 7, State: sqlite.StageStateStreaming,
		},
	}, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RawMeta(context.Background(), "audit-streaming", SideRequest); !errors.Is(err, ErrNotReady) {
		t.Fatalf("RawMeta error = %v, want ErrNotReady", err)
	}
	var output bytes.Buffer
	if err := service.StreamRaw(context.Background(), "audit-streaming", SideRequest, &output); !errors.Is(err, ErrNotReady) {
		t.Fatalf("StreamRaw error = %v, want ErrNotReady", err)
	}
	if output.Len() != 0 {
		t.Fatalf("streaming evidence wrote %d bytes", output.Len())
	}
}

func TestListMapsCursorAndRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	ended := int64(9_007_199_254_740_995)
	tokenID := int64(42)
	tokenName := "personal"
	maskedKey := "sk-...1234"
	store := &fakeStore{
		healthy: true,
		listPage: sqlite.AuditListPage{
			Rows: []sqlite.AuditListRow{{
				AuditID: "audit-page", StartedAtNS: ended - 1, EndedAtNS: &ended,
				RouteID: "route", Protocol: "openai", ParserName: "openai.responses",
				Method: "POST", Path: "/v1/responses", Mode: "available",
				ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete,
				ParseStatus: sqlite.ParseOK, NewAPITokenID: &tokenID, TokenName: &tokenName, MaskedKey: &maskedKey,
			}},
			HasMore: true,
		},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), Filter{}, Cursor{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == nil || page.NextCursor.BeforeID != "audit-page" || page.NextCursor.BeforeStartedAtNS != ended-1 {
		t.Fatalf("page cursor = %+v", page.NextCursor)
	}
	if len(page.Items) != 1 || page.Items[0].MaskedKey == nil || *page.Items[0].MaskedKey != maskedKey {
		t.Fatalf("mapped token snapshot = %+v", page.Items)
	}
	if _, err := service.List(context.Background(), Filter{}, Cursor{BeforeID: "audit-page"}, 1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("incomplete cursor error = %v", err)
	}
	if _, err := service.List(context.Background(), Filter{Path: "not-absolute"}, Cursor{}, 1); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("invalid path error = %v", err)
	}
}

func TestListFiltersUserAgentSubstringWithoutReturningHeaderPlaintext(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	header := func(auditID, name, value string) sqlite.HeaderEvidence {
		t.Helper()
		aad, err := security.AAD(auditID, "header", sqlite.StageRequestReceived, sqlite.HeaderKindHeader, name, "0")
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return sqlite.HeaderEvidence{
			Stage: sqlite.StageRequestReceived, Kind: sqlite.HeaderKindHeader, Name: name,
			ValueIndex: 0, ValueLength: len(value), ValueEnc: encrypted,
		}
	}
	rows := []sqlite.AuditListRow{
		{AuditID: "audit-match", StartedAtNS: 3, ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK},
		{AuditID: "audit-wrong-agent", StartedAtNS: 2, ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK},
	}
	store := &fakeStore{
		healthy:  true,
		listPage: sqlite.AuditListPage{Rows: rows},
		requestHeaders: map[string][]sqlite.HeaderEvidence{
			"audit-match": {
				header("audit-match", "User-Agent", "Codex-CLI/1.2 Windows"),
				header("audit-match", "Authorization", "Bearer secret-that-must-not-be-read"),
			},
			"audit-wrong-agent": {
				header("audit-wrong-agent", "User-Agent", "curl/8"),
			},
		},
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), Filter{UserAgent: "CoDeX-cLi"}, Cursor{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].AuditID != "audit-match" || page.NextCursor != nil {
		t.Fatalf("filtered page = %+v", page)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("Codex-CLI")) || bytes.Contains(encoded, []byte("secret-that-must-not-be-read")) {
		t.Fatalf("filtered response leaked header material: %s", encoded)
	}
}

func TestListHeaderFilterRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-filter-tamper"
	aad, err := security.AAD(auditID, "header", sqlite.StageRequestReceived, sqlite.HeaderKindHeader, "User-Agent", "0")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt(aad, []byte("Codex/1"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	service, err := New(&fakeStore{
		healthy: true,
		listPage: sqlite.AuditListPage{Rows: []sqlite.AuditListRow{{
			AuditID: auditID, StartedAtNS: 1, ForwardStatus: sqlite.ForwardCompleted,
		}}},
		requestHeaders: map[string][]sqlite.HeaderEvidence{auditID: {{
			Stage: sqlite.StageRequestReceived, Kind: sqlite.HeaderKindHeader, Name: "User-Agent",
			ValueLength: len("Codex/1"), ValueEnc: encrypted,
		}}},
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(context.Background(), Filter{UserAgent: "codex"}, Cursor{}, 10); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered filter error = %v, want ErrIntegrity", err)
	}
}

func TestListHeaderFilterPaginationDoesNotSkipOrRepeatMatches(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	rows := []sqlite.AuditListRow{
		{AuditID: "audit-5", StartedAtNS: 5, ForwardStatus: sqlite.ForwardCompleted},
		{AuditID: "audit-4", StartedAtNS: 4, ForwardStatus: sqlite.ForwardCompleted},
		{AuditID: "audit-3", StartedAtNS: 3, ForwardStatus: sqlite.ForwardCompleted},
		{AuditID: "audit-2", StartedAtNS: 2, ForwardStatus: sqlite.ForwardCompleted},
		{AuditID: "audit-1", StartedAtNS: 1, ForwardStatus: sqlite.ForwardCompleted},
	}
	headers := make(map[string][]sqlite.HeaderEvidence, len(rows))
	for _, row := range rows {
		value := "curl/8"
		if row.AuditID == "audit-4" || row.AuditID == "audit-3" || row.AuditID == "audit-1" {
			value = "Codex/1"
		}
		aad, err := security.AAD(row.AuditID, "header", sqlite.StageRequestReceived, sqlite.HeaderKindHeader, "User-Agent", "0")
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := cipher.Encrypt(aad, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		headers[row.AuditID] = []sqlite.HeaderEvidence{{
			Stage: sqlite.StageRequestReceived, Kind: sqlite.HeaderKindHeader, Name: "User-Agent",
			ValueLength: len(value), ValueEnc: encrypted,
		}}
	}
	store := &fakeStore{healthy: true, requestHeaders: headers}
	store.listFunc = func(_ sqlite.AuditQueryFilter, cursor sqlite.AuditQueryCursor, limit int) (sqlite.AuditListPage, error) {
		start := 0
		if cursor.BeforeID != "" {
			for index, row := range rows {
				if row.AuditID == cursor.BeforeID && row.StartedAtNS == cursor.BeforeStartedAtNS {
					start = index + 1
					break
				}
			}
		}
		end := min(len(rows), start+limit)
		return sqlite.AuditListPage{Rows: append([]sqlite.AuditListRow(nil), rows[start:end]...), HasMore: end < len(rows)}, nil
	}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	cursor := Cursor{}
	var got []string
	for {
		page, err := service.List(context.Background(), Filter{UserAgent: "codex"}, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			got = append(got, item.AuditID)
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if strings.Join(got, ",") != "audit-4,audit-3,audit-1" {
		t.Fatalf("paginated matches = %v", got)
	}
}

func TestGetDecryptsRequestURIAndEveryHeaderValue(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-sensitive-detail"
	requestURI := "/v1/chat/completions?trace=private-value"
	requestURIAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestURIAAD, []byte(requestURI))
	if err != nil {
		t.Fatal(err)
	}
	header := func(stage, kind, name string, index int, value string) sqlite.HeaderEvidence {
		t.Helper()
		aad, aadErr := security.AAD(auditID, "header", stage, kind, name, strconv.Itoa(index))
		if aadErr != nil {
			t.Fatal(aadErr)
		}
		encrypted, encryptErr := cipher.Encrypt(aad, []byte(value))
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		return sqlite.HeaderEvidence{
			Stage: stage, Kind: kind, Name: name, ValueIndex: index,
			ValueLength: len(value), ValueEnc: encrypted,
		}
	}
	wantHeaders := []Header{
		{Stage: sqlite.StageRequestSent, Kind: sqlite.HeaderKindHeader, Name: "X-Multi", ValueIndex: 0, ValueLength: 5, Value: "first"},
		{Stage: sqlite.StageRequestSent, Kind: sqlite.HeaderKindHeader, Name: "X-Multi", ValueIndex: 1, ValueLength: 6, Value: "second"},
		{Stage: sqlite.StageResponseReceived, Kind: sqlite.HeaderKindTrailer, Name: "X-Trailer", ValueIndex: 0, ValueLength: 4, Value: "done"},
	}
	store := &fakeStore{healthy: true, detail: sqlite.AuditQueryDetail{
		Audit: sqlite.AuditListRow{
			AuditID: auditID, StartedAtNS: 1, RouteID: "route", Protocol: "openai",
			ParserName: "openai.chat_completions", Method: "POST", Path: "/v1/chat/completions",
			Mode: "available", ForwardStatus: sqlite.ForwardCompleted,
			CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK,
		},
		RequestURIEnc: requestURIEnc,
		Headers: []sqlite.HeaderEvidence{
			header(sqlite.StageRequestSent, sqlite.HeaderKindHeader, "X-Multi", 0, "first"),
			header(sqlite.StageRequestSent, sqlite.HeaderKindHeader, "X-Multi", 1, "second"),
			header(sqlite.StageResponseReceived, sqlite.HeaderKindTrailer, "X-Trailer", 0, "done"),
		},
		TokenLink: &sqlite.TokenLinkSummary{
			NewAPITokenID: 42, TokenName: "personal", MaskedKey: "sk-...1234", LinkedAtNS: 3,
		},
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Get(context.Background(), auditID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.RequestURI != requestURI {
		t.Fatalf("request_uri = %q, want %q", detail.RequestURI, requestURI)
	}
	if len(detail.Headers) != len(wantHeaders) {
		t.Fatalf("headers = %+v", detail.Headers)
	}
	for index := range wantHeaders {
		if detail.Headers[index] != wantHeaders[index] {
			t.Errorf("header %d = %+v, want %+v", index, detail.Headers[index], wantHeaders[index])
		}
	}
	if detail.TokenLink == nil || detail.TokenLink.MaskedKey != "sk-...1234" {
		t.Fatalf("token link = %+v", detail.TokenLink)
	}

	pageJSON, err := json.Marshal(Page{Items: []AuditSummary{detail.Audit}})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-value", "first", "second", "done"} {
		if strings.Contains(string(pageJSON), secret) {
			t.Fatalf("list projection leaked %q: %s", secret, pageJSON)
		}
	}
}

func TestGetDecryptsConversationWithoutAddingItToListProjection(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-conversation-detail"
	parserName := "openai.chat_completions"
	requestAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestAAD, []byte("/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	want := conversation.New()
	want.Append(conversation.Message{
		Role: conversation.RoleUser, Phase: conversation.PhaseRequest,
		Direction: conversation.DirectionClientToUpstream,
		Content:   []conversation.Part{conversation.Text("conversation-secret")},
	})
	want.Append(conversation.Message{
		Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse,
		Direction: conversation.DirectionUpstreamToClient,
		Content: []conversation.Part{{
			Type: conversation.PartToolCall, ID: "call-1", Name: "lookup", Arguments: `{"q":"secret"}`,
		}},
	})
	plaintext, err := json.Marshal(map[string]any{"protocol": "openai", "conversation": want})
	if err != nil {
		t.Fatal(err)
	}
	parsedAAD, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	parsedJSONEnc, err := cipher.Encrypt(parsedAAD, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{healthy: true, detail: sqlite.AuditQueryDetail{
		Audit: sqlite.AuditListRow{
			AuditID: auditID, StartedAtNS: 1, ParserName: parserName,
			ForwardStatus: sqlite.ForwardCompleted, CaptureStatus: sqlite.CaptureComplete, ParseStatus: sqlite.ParseOK,
		},
		RequestURIEnc: requestURIEnc,
		ParsedResult: &sqlite.ParsedResultSummary{
			ParserName: parserName, ParserVersion: "2", Status: sqlite.ParseOK,
			ParsedJSONEnc: parsedJSONEnc, ParsedAtNS: 2,
		},
	}}
	service, err := New(store, cipher)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Get(context.Background(), auditID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Conversation == nil || len(detail.Conversation.Messages) != 2 ||
		detail.Conversation.Messages[0].Content[0].Text != "conversation-secret" ||
		detail.Conversation.Messages[1].Content[0].Arguments != `{"q":"secret"}` {
		t.Fatalf("conversation = %+v", detail.Conversation)
	}
	pageJSON, err := json.Marshal(Page{Items: []AuditSummary{detail.Audit}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pageJSON), "conversation-secret") || strings.Contains(string(pageJSON), `{"q":"secret"}`) {
		t.Fatalf("list projection leaked conversation: %s", pageJSON)
	}
}

func TestGetRejectsTamperedOrInvalidEncryptedConversation(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-invalid-conversation"
	parserName := "openai.responses"
	requestAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestAAD, []byte("/v1/responses"))
	if err != nil {
		t.Fatal(err)
	}
	parsedAAD, err := security.AAD(auditID, "parsed_json", parserName)
	if err != nil {
		t.Fatal(err)
	}
	validPlaintext := []byte(`{"conversation":{"schema_version":1,"messages":[{"index":0,"role":"user","phase":"request","direction":"client_to_upstream","content":[{"index":0,"type":"text","text":"secret"}]}]}}`)
	validCiphertext, err := cipher.Encrypt(parsedAAD, validPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	invalidCiphertext, err := cipher.Encrypt(parsedAAD, []byte(`{"conversation":{"schema_version":99,"messages":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), validCiphertext...)
	tampered[len(tampered)-1] ^= 0xff
	for _, test := range []struct {
		name       string
		ciphertext []byte
	}{
		{name: "tampered", ciphertext: tampered},
		{name: "invalid schema", ciphertext: invalidCiphertext},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, serviceErr := New(&fakeStore{healthy: true, detail: sqlite.AuditQueryDetail{
				Audit:         sqlite.AuditListRow{AuditID: auditID},
				RequestURIEnc: requestURIEnc,
				ParsedResult: &sqlite.ParsedResultSummary{
					ParserName: parserName, ParserVersion: "2", Status: sqlite.ParseOK,
					ParsedJSONEnc: test.ciphertext, ParsedAtNS: 2,
				},
			}}, cipher)
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			_, getErr := service.Get(context.Background(), auditID)
			if !errors.Is(getErr, ErrIntegrity) || getErr.Error() != ErrIntegrity.Error() || strings.Contains(getErr.Error(), "secret") {
				t.Fatalf("Get error = %q, want safe ErrIntegrity", getErr)
			}
		})
	}
}

func TestGetRejectsInvalidEncryptedDetailWithoutLeakingEvidence(t *testing.T) {
	t.Parallel()

	cipher := testCipher(t)
	auditID := "audit-invalid-detail"
	requestAAD, err := security.AAD(auditID, "request_uri")
	if err != nil {
		t.Fatal(err)
	}
	requestURIEnc, err := cipher.Encrypt(requestAAD, []byte("/v1/responses?secret=request-uri-secret"))
	if err != nil {
		t.Fatal(err)
	}
	headerAAD, err := security.AAD(auditID, "header", sqlite.StageRequestSent, sqlite.HeaderKindHeader, "Authorization", "0")
	if err != nil {
		t.Fatal(err)
	}
	headerEnc, err := cipher.Encrypt(headerAAD, []byte("Bearer header-secret"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*sqlite.AuditQueryDetail)
	}{
		{
			name: "tampered request URI",
			mutate: func(detail *sqlite.AuditQueryDetail) {
				detail.RequestURIEnc[len(detail.RequestURIEnc)-1] ^= 0xff
			},
		},
		{
			name: "tampered header",
			mutate: func(detail *sqlite.AuditQueryDetail) {
				detail.Headers[0].ValueEnc[len(detail.Headers[0].ValueEnc)-1] ^= 0xff
			},
		},
		{
			name: "header length mismatch",
			mutate: func(detail *sqlite.AuditQueryDetail) {
				detail.Headers[0].ValueLength++
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			base := sqlite.AuditQueryDetail{
				Audit:         sqlite.AuditListRow{AuditID: auditID},
				RequestURIEnc: append([]byte(nil), requestURIEnc...),
				Headers: []sqlite.HeaderEvidence{{
					Stage: sqlite.StageRequestSent, Kind: sqlite.HeaderKindHeader,
					Name: "Authorization", ValueIndex: 0,
					ValueLength: len("Bearer header-secret"), ValueEnc: append([]byte(nil), headerEnc...),
				}},
			}
			test.mutate(&base)
			service, serviceErr := New(&fakeStore{healthy: true, detail: base}, cipher)
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			_, getErr := service.Get(context.Background(), auditID)
			if !errors.Is(getErr, ErrIntegrity) {
				t.Fatalf("Get error = %v, want ErrIntegrity", getErr)
			}
			if getErr.Error() != ErrIntegrity.Error() || strings.Contains(getErr.Error(), "secret") {
				t.Fatalf("unsafe integrity error = %q", getErr)
			}
		})
	}
}

func TestRawNotFoundIsNormalized(t *testing.T) {
	t.Parallel()

	service, err := New(&fakeStore{healthy: true, rawErr: sql.ErrNoRows}, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RawMeta(context.Background(), "missing", SideRequest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RawMeta error = %v, want ErrNotFound", err)
	}
	if err := service.StreamRaw(context.Background(), "missing", SideRequest, io.Discard); !errors.Is(err, ErrNotFound) {
		t.Fatalf("StreamRaw error = %v, want ErrNotFound", err)
	}
}

type fakeStore struct {
	healthy          bool
	listPage         sqlite.AuditListPage
	listErr          error
	listFunc         func(sqlite.AuditQueryFilter, sqlite.AuditQueryCursor, int) (sqlite.AuditListPage, error)
	detail           sqlite.AuditQueryDetail
	detailErr        error
	rawMeta          sqlite.RawBodyMetadata
	rawErr           error
	chunks           []sqlite.BodyChunk
	chunkErr         error
	requestHeaders   map[string][]sqlite.HeaderEvidence
	requestHeaderErr error
}

func (store *fakeStore) Healthy() bool { return store.healthy }

func (store *fakeStore) ListAudits(_ context.Context, filter sqlite.AuditQueryFilter, cursor sqlite.AuditQueryCursor, limit int) (sqlite.AuditListPage, error) {
	if store.listFunc != nil {
		return store.listFunc(filter, cursor, limit)
	}
	return store.listPage, store.listErr
}

func (store *fakeStore) QueryRequestHeaderEvidence(_ context.Context, auditID string) ([]sqlite.HeaderEvidence, error) {
	return store.requestHeaders[auditID], store.requestHeaderErr
}

func (store *fakeStore) QueryAuditDetail(context.Context, string) (sqlite.AuditQueryDetail, error) {
	return store.detail, store.detailErr
}

func (store *fakeStore) RawBodyMeta(context.Context, string, string) (sqlite.RawBodyMetadata, error) {
	return store.rawMeta, store.rawErr
}

func (store *fakeStore) StreamBodyChunks(_ context.Context, _, _ string, visit func(sqlite.BodyChunk) error) error {
	for _, chunk := range store.chunks {
		if err := visit(chunk); err != nil {
			return err
		}
	}
	return store.chunkErr
}

func testCipher(t *testing.T) *security.AESGCM {
	t.Helper()
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{0x42}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
