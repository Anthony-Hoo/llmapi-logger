// Package newapi contains the small read-only NewAPI management integration
// used to identify callers after a proxied request has completed.
package newapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	pageSize             = 100
	lookupPageSize       = 10
	requestTimeout       = 10 * time.Second
	maxResponseBodyBytes = 1 << 20
	maxCatalogPages      = 10_000
	maxRequestIDLength   = 128
)

var (
	ErrInvalidConfig    = errors.New("newapi client: invalid configuration")
	ErrRequestFailed    = errors.New("newapi client: request failed")
	ErrUnexpectedStatus = errors.New("newapi client: unexpected HTTP status")
	ErrResponseTooLarge = errors.New("newapi client: response body too large")
	ErrInvalidResponse  = errors.New("newapi client: invalid response")
)

// Config contains the administrator credential used for read-only user and
// system-log requests. The credential stays in memory and is never returned
// through the management API or persisted in the audit database.
type Config struct {
	BaseURL     string
	AccessToken string
	UserID      int64
	HTTPClient  *http.Client
}

// User is the safe subset of a NewAPI user returned to the local dashboard.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      int    `json:"status"`
	Group       string `json:"group"`
}

// UserSnapshot is a defensive copy of the most recently refreshed user list.
type UserSnapshot struct {
	Users       []User    `json:"users"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

// NewAPI log types used by the billing rules (doc/features/21-newapi-billing.md).
const (
	logTypeConsume = 2
)

// RequestLog is what this project keeps of NewAPI's log rows for one request
// ID: the non-secret ownership metadata plus the actual billing of the consume
// rows. It deliberately excludes log content, IP, channel, the "other"
// diagnostics, and every credential value.
type RequestLog struct {
	RequestID string
	UserID    int64
	Username  string
	TokenID   int64
	TokenName string
	ModelName string

	// ConsumeRows counts the type 2 (consume) rows; Quota and the token
	// counts are their sums. Zero consume rows means NewAPI has not billed
	// the request (only error rows so far, or none at all).
	ConsumeRows      int
	Quota            int64
	PromptTokens     int64
	CompletionTokens int64
	// Complete is false when NewAPI reported more rows than one lookup page
	// returned, so the billing sums may be missing rows.
	Complete bool
}

// Billed reports whether the log carries a complete consume record.
func (log RequestLog) Billed() bool {
	return log.ConsumeRows > 0 && log.Complete
}

type userSnapshot struct {
	users       []User
	byID        map[int64]User
	refreshedAt time.Time
}

// Client performs the read-only NewAPI operations needed by this project:
// refreshing the global user directory, reading the public quota conversion
// from /api/status, and resolving a request ID through the administrator log
// endpoint.
type Client struct {
	baseURL     *url.URL
	accessToken string
	userID      string
	client      *http.Client
	users       atomic.Pointer[userSnapshot]
	// quotaPerUnit holds math.Float64bits of the last valid quota_per_unit;
	// zero means none has been read yet.
	quotaPerUnit atomic.Uint64
	// lastStatusTry is the UnixNano of the last on-demand /api/status read.
	lastStatusTry atomic.Int64
}

// statusRetryInterval throttles on-demand quota_per_unit reads.
const statusRetryInterval = 10 * time.Second

// NewClient validates a read-only NewAPI management client configuration.
func NewClient(config Config) (*Client, error) {
	baseURL, err := parseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	accessToken := strings.TrimSpace(config.AccessToken)
	if accessToken == "" || strings.ContainsAny(accessToken, "\r\n") || config.UserID <= 0 {
		return nil, ErrInvalidConfig
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Transport: directTransport(), Timeout: requestTimeout}
	} else if client.Transport == nil {
		clone := *client
		clone.Transport = directTransport()
		client = &clone
	}

	result := &Client{
		baseURL:     baseURL,
		accessToken: accessToken,
		userID:      strconv.FormatInt(config.UserID, 10),
		client:      client,
	}
	result.users.Store(newUserSnapshot(nil, time.Time{}))
	return result, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return nil, ErrInvalidConfig
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, ErrInvalidConfig
	}
	return parsed, nil
}

func directTransport() http.RoundTripper {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		return clone
	}
	return &http.Transport{Proxy: nil}
}

// RefreshUsers fetches every global user page and atomically publishes only
// the safe directory fields. A failed refresh keeps the last good snapshot.
func (client *Client) RefreshUsers(ctx context.Context) error {
	if client == nil || ctx == nil {
		return ErrInvalidConfig
	}
	users, err := client.fetchAllUsers(ctx)
	if err != nil {
		return err
	}
	client.users.Store(newUserSnapshot(users, time.Now().UTC()))
	return nil
}

func (client *Client) fetchAllUsers(ctx context.Context) ([]User, error) {
	users := make([]User, 0)
	seenIDs := make(map[int64]struct{})
	expectedTotal := -1
	for pageNumber := 0; pageNumber < maxCatalogPages; pageNumber++ {
		var envelope apiEnvelope[apiPage[apiUser]]
		if err := client.get(ctx, client.pageURL("/api/user/", pageNumber, pageSize, nil), &envelope); err != nil {
			return nil, pageError(err, pageNumber)
		}
		page := envelope.Data
		if !envelope.Success || page.Total < 0 || len(page.Items) > pageSize {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
		if expectedTotal == -1 {
			expectedTotal = page.Total
		} else if page.Total != expectedTotal {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
		if len(users)+len(page.Items) > expectedTotal {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
		for _, item := range page.Items {
			if item.ID <= 0 || !safeText(item.Username, 512) || strings.TrimSpace(item.Username) == "" ||
				!safeText(item.DisplayName, 512) || !safeText(item.Group, 512) {
				return nil, pageError(ErrInvalidResponse, pageNumber)
			}
			if _, duplicate := seenIDs[item.ID]; duplicate {
				return nil, pageError(ErrInvalidResponse, pageNumber)
			}
			seenIDs[item.ID] = struct{}{}
			users = append(users, User{
				ID: item.ID, Username: item.Username, DisplayName: item.DisplayName,
				Status: item.Status, Group: item.Group,
			})
		}
		if len(users) == expectedTotal {
			return users, nil
		}
		if len(page.Items) == 0 {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
	}
	return nil, ErrInvalidResponse
}

// LookupRequest resolves an exact NewAPI request ID through the global log
// endpoint. A missing log is reported as found=false because log insertion can
// lag behind delivery of the upstream response. A log with only error rows is
// found (the identity is known) but not billed; the caller decides whether to
// wait for a consume row.
func (client *Client) LookupRequest(ctx context.Context, requestID string) (RequestLog, bool, error) {
	if client == nil || ctx == nil || !validRequestID(requestID) {
		return RequestLog{}, false, ErrInvalidConfig
	}
	query := url.Values{"request_id": []string{requestID}}
	var envelope apiEnvelope[apiPage[apiLog]]
	if err := client.get(ctx, client.pageURL("/api/log/", 0, lookupPageSize, query), &envelope); err != nil {
		return RequestLog{}, false, err
	}
	page := envelope.Data
	if !envelope.Success || page.Total < 0 || len(page.Items) > lookupPageSize || len(page.Items) > page.Total {
		return RequestLog{}, false, ErrInvalidResponse
	}
	if page.Total == 0 {
		if len(page.Items) != 0 {
			return RequestLog{}, false, ErrInvalidResponse
		}
		return RequestLog{}, false, nil
	}
	if len(page.Items) == 0 {
		return RequestLog{}, false, ErrInvalidResponse
	}

	var record RequestLog
	for _, item := range page.Items {
		if item.RequestID != requestID || item.UserID <= 0 || item.TokenID < 0 ||
			!safeText(item.Username, 512) || !safeText(item.TokenName, 512) || !safeText(item.ModelName, 512) ||
			item.Quota < 0 || item.PromptTokens < 0 || item.CompletionTokens < 0 {
			return RequestLog{}, false, ErrInvalidResponse
		}
		if record.RequestID == "" {
			record = RequestLog{
				RequestID: item.RequestID,
				UserID:    item.UserID, Username: item.Username,
				TokenID: item.TokenID, TokenName: item.TokenName, ModelName: item.ModelName,
			}
		} else if record.UserID != item.UserID || record.TokenID != item.TokenID ||
			record.Username != item.Username || record.TokenName != item.TokenName {
			return RequestLog{}, false, ErrInvalidResponse
		}
		if item.Type != logTypeConsume {
			continue
		}
		quota, okQuota := addNonNegative(record.Quota, item.Quota)
		prompt, okPrompt := addNonNegative(record.PromptTokens, item.PromptTokens)
		completion, okCompletion := addNonNegative(record.CompletionTokens, item.CompletionTokens)
		if !okQuota || !okPrompt || !okCompletion {
			return RequestLog{}, false, ErrInvalidResponse
		}
		record.ConsumeRows++
		record.Quota, record.PromptTokens, record.CompletionTokens = quota, prompt, completion
	}
	record.Complete = len(page.Items) == page.Total
	return record, true, nil
}

func addNonNegative(left, right int64) (int64, bool) {
	if right > math.MaxInt64-left {
		return 0, false
	}
	return left + right, true
}

// RefreshStatus reads quota_per_unit, the quota that equals one US dollar,
// from NewAPI's public /api/status endpoint. The endpoint needs no credential
// and none is sent. A failed or invalid read keeps the previous value.
func (client *Client) RefreshStatus(ctx context.Context) error {
	if client == nil || ctx == nil {
		return ErrInvalidConfig
	}
	var envelope apiEnvelope[apiStatus]
	if err := fetchJSON(ctx, client.client, client.pageEndpoint("/api/status"), nil, &envelope); err != nil {
		return err
	}
	value := envelope.Data.QuotaPerUnit
	if !envelope.Success || value == nil || !validQuotaPerUnit(*value) {
		return ErrInvalidResponse
	}
	client.quotaPerUnit.Store(math.Float64bits(*value))
	return nil
}

// QuotaPerUnit returns the last valid quota_per_unit, or false before one has
// been read.
func (client *Client) QuotaPerUnit() (float64, bool) {
	if client == nil {
		return 0, false
	}
	bits := client.quotaPerUnit.Load()
	if bits == 0 {
		return 0, false
	}
	return math.Float64frombits(bits), true
}

// EnsureQuotaPerUnit returns quota_per_unit, reading /api/status first when no
// value is held yet. A failed startup read would otherwise leave billed lookups
// without a rate until the next periodic refresh; the on-demand read is
// throttled so an unreachable NewAPI is not asked once per lookup.
func (client *Client) EnsureQuotaPerUnit(ctx context.Context) (float64, bool) {
	if rate, ok := client.QuotaPerUnit(); ok || client == nil || ctx == nil {
		return rate, ok
	}
	now := time.Now().UnixNano()
	last := client.lastStatusTry.Load()
	if now-last < int64(statusRetryInterval) || !client.lastStatusTry.CompareAndSwap(last, now) {
		return 0, false
	}
	_ = client.RefreshStatus(ctx)
	return client.QuotaPerUnit()
}

func validQuotaPerUnit(value float64) bool {
	return value > 0 && !math.IsInf(value, 0) && !math.IsNaN(value)
}

func (client *Client) get(ctx context.Context, endpoint string, destination any) error {
	return fetchJSON(ctx, client.client, endpoint, func(request *http.Request) {
		request.Header.Set("Authorization", client.accessToken)
		request.Header.Set("New-Api-User", client.userID)
	}, destination)
}

// fetchJSON performs one bounded read-only NewAPI GET. The caller supplies the
// credential because the administrator endpoints and the token endpoint
// authenticate differently.
func fetchJSON(ctx context.Context, httpClient *http.Client, endpoint string, authorize func(*http.Request), destination any) error {
	return fetchBody(ctx, httpClient, endpoint, authorize, func(reader io.Reader) error {
		body, err := io.ReadAll(io.LimitReader(reader, maxResponseBodyBytes+1))
		if err != nil {
			return ErrRequestFailed
		}
		if len(body) > maxResponseBodyBytes {
			return ErrResponseTooLarge
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(destination); err != nil {
			return ErrInvalidResponse
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return ErrInvalidResponse
		}
		return nil
	})
}

// fetchBody performs the authenticated GET and hands the still-open body to
// consume. Callers that can bound a response up front buffer it through
// fetchJSON; the token log cannot be bounded and reads the body as a stream.
func fetchBody(ctx context.Context, httpClient *http.Client, endpoint string, authorize func(*http.Request), consume func(io.Reader) error) error {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ErrRequestFailed
	}
	request.Header.Set("Accept", "application/json")
	if authorize != nil {
		authorize(request)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return ErrRequestFailed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return unexpectedStatusError{status: response.StatusCode}
	}
	return consume(response.Body)
}

// ceilingReader fails the read once the response has produced more than the
// caller allowed, so an upstream that never stops sending cannot be streamed
// forever. It reports the condition as an error value rather than as EOF so a
// truncated read is not mistaken for a malformed document.
type ceilingReader struct {
	reader    io.Reader
	remaining int64
}

func (reader *ceilingReader) Read(buffer []byte) (int, error) {
	if reader.remaining <= 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	read, err := reader.reader.Read(buffer)
	reader.remaining -= int64(read)
	return read, err
}

// unexpectedStatusError keeps the upstream status available so key validation
// can separate "this key was refused" from "NewAPI is unhealthy", while still
// matching errors.Is(err, ErrUnexpectedStatus).
type unexpectedStatusError struct {
	status int
}

func (err unexpectedStatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d", ErrUnexpectedStatus, err.status)
}

func (unexpectedStatusError) Unwrap() error { return ErrUnexpectedStatus }

func (client *Client) pageEndpoint(path string) string {
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	return endpoint.String()
}

func (client *Client) pageURL(path string, pageNumber, size int, extra url.Values) string {
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawPath = ""
	query := make(url.Values, len(extra)+2)
	for name, values := range extra {
		query[name] = append([]string(nil), values...)
	}
	query.Set("p", strconv.Itoa(pageNumber))
	query.Set("size", strconv.Itoa(size))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

// Snapshot returns a copy callers may safely modify.
func (client *Client) Snapshot() UserSnapshot {
	if client == nil {
		return UserSnapshot{Users: []User{}}
	}
	snapshot := client.users.Load()
	if snapshot == nil {
		return UserSnapshot{Users: []User{}}
	}
	return UserSnapshot{Users: append([]User(nil), snapshot.users...), RefreshedAt: snapshot.refreshedAt}
}

// User returns a safe user-directory entry when the last refresh contained it.
func (client *Client) User(id int64) (User, bool) {
	if client == nil {
		return User{}, false
	}
	snapshot := client.users.Load()
	if snapshot == nil {
		return User{}, false
	}
	user, ok := snapshot.byID[id]
	return user, ok
}

func newUserSnapshot(users []User, refreshedAt time.Time) *userSnapshot {
	owned := append([]User(nil), users...)
	byID := make(map[int64]User, len(owned))
	for _, user := range owned {
		byID[user.ID] = user
	}
	return &userSnapshot{users: owned, byID: byID, refreshedAt: refreshedAt}
}

func validRequestID(value string) bool {
	return value != "" && len(value) <= maxRequestIDLength && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func safeText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsRune(value, '\x00')
}

func pageError(kind error, pageNumber int) error {
	return fmt.Errorf("%w: page %d", kind, pageNumber)
}

type apiEnvelope[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
}

type apiPage[T any] struct {
	Total int `json:"total"`
	Items []T `json:"items"`
}

type apiUser struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      int    `json:"status"`
	Group       string `json:"group"`
}

// apiLog decodes only the log fields this project uses. "other", "content",
// "ip" and "channel" are deliberately absent so they are never read.
type apiLog struct {
	UserID           int64  `json:"user_id"`
	Username         string `json:"username"`
	TokenID          int64  `json:"token_id"`
	TokenName        string `json:"token_name"`
	ModelName        string `json:"model_name"`
	RequestID        string `json:"request_id"`
	CreatedAt        int64  `json:"created_at"`
	Type             int    `json:"type"`
	Quota            int64  `json:"quota"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
}

// apiStatus decodes only quota_per_unit from /api/status.
type apiStatus struct {
	QuotaPerUnit *float64 `json:"quota_per_unit"`
}
