// Package newapi provides the small read-only NewAPI integration used by the
// audit proxy. It intentionally keeps access credentials in memory only.
package newapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	pageSize             = 100
	requestTimeout       = 10 * time.Second
	maxResponseBodyBytes = 1 << 20
	maxCatalogPages      = 10_000
)

var (
	ErrInvalidConfig    = errors.New("newapi catalog: invalid configuration")
	ErrRequestFailed    = errors.New("newapi catalog: request failed")
	ErrUnexpectedStatus = errors.New("newapi catalog: unexpected HTTP status")
	ErrResponseTooLarge = errors.New("newapi catalog: response body too large")
	ErrInvalidResponse  = errors.New("newapi catalog: invalid response")
)

// Config contains the credentials used only for NewAPI's read-only token API.
// HTTPClient is injectable for tests and custom transports. When it is nil, or
// when its Transport is nil, Catalog installs an explicit direct transport that
// does not consult proxy-related environment variables.
type Config struct {
	BaseURL     string
	AccessToken string
	UserID      int64
	HTTPClient  *http.Client
}

// Token is the non-secret subset returned by NewAPI's token list endpoint.
// MaskedKey is validated against NewAPI v1.0.0-rc.21's masking algorithm.
type Token struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	MaskedKey      string `json:"masked_key"`
	Status         int    `json:"status"`
	Group          string `json:"group"`
	UnlimitedQuota bool   `json:"unlimited_quota"`
}

// Snapshot is a defensive copy of the most recently refreshed catalog.
type Snapshot struct {
	Tokens      []Token   `json:"tokens"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

type catalogSnapshot struct {
	tokens      []Token
	byMaskedKey map[string]Token
	refreshedAt time.Time
}

// Catalog keeps an immutable token snapshot that can be read without blocking
// an in-progress refresh.
type Catalog struct {
	baseURL     *url.URL
	accessToken string
	userID      string
	client      *http.Client
	snapshot    atomic.Pointer[catalogSnapshot]
}

// New validates a NewAPI token catalog configuration.
func New(config Config) (*Catalog, error) {
	baseURL, err := parseBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	accessToken := strings.TrimSpace(config.AccessToken)
	if accessToken == "" || strings.ContainsAny(accessToken, "\r\n") {
		return nil, ErrInvalidConfig
	}
	if config.UserID <= 0 {
		return nil, ErrInvalidConfig
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Transport: directTransport(),
			Timeout:   requestTimeout,
		}
	} else if client.Transport == nil {
		clone := *client
		clone.Transport = directTransport()
		client = &clone
	}

	catalog := &Catalog{
		baseURL:     baseURL,
		accessToken: accessToken,
		userID:      strconv.FormatInt(config.UserID, 10),
		client:      client,
	}
	catalog.snapshot.Store(newCatalogSnapshot(nil, time.Time{}))
	return catalog, nil
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

// Refresh fetches every token page and atomically publishes the result. A
// failed refresh leaves the previous successful snapshot untouched.
func (catalog *Catalog) Refresh(ctx context.Context) error {
	if catalog == nil || ctx == nil {
		return ErrInvalidConfig
	}
	tokens, err := catalog.fetchAll(ctx)
	if err != nil {
		return err
	}
	catalog.snapshot.Store(newCatalogSnapshot(tokens, time.Now().UTC()))
	return nil
}

func (catalog *Catalog) fetchAll(ctx context.Context) ([]Token, error) {
	tokens := make([]Token, 0)
	seenIDs := make(map[int64]struct{})
	expectedTotal := -1

	for pageNumber := 0; pageNumber < maxCatalogPages; pageNumber++ {
		page, err := catalog.fetchPage(ctx, pageNumber)
		if err != nil {
			return nil, err
		}
		if page.Total < 0 || len(page.Items) > pageSize {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
		if expectedTotal == -1 {
			expectedTotal = page.Total
		} else if page.Total != expectedTotal {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
		if len(tokens)+len(page.Items) > expectedTotal {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}

		for _, item := range page.Items {
			if item.ID <= 0 || item.Key == "" || MaskTokenKey(item.Key) != item.Key {
				return nil, pageError(ErrInvalidResponse, pageNumber)
			}
			if _, duplicate := seenIDs[item.ID]; duplicate {
				return nil, pageError(ErrInvalidResponse, pageNumber)
			}
			seenIDs[item.ID] = struct{}{}
			tokens = append(tokens, Token{
				ID:             item.ID,
				Name:           item.Name,
				MaskedKey:      item.Key,
				Status:         item.Status,
				Group:          item.Group,
				UnlimitedQuota: item.UnlimitedQuota,
			})
		}

		if len(tokens) == expectedTotal {
			return tokens, nil
		}
		if len(page.Items) == 0 {
			return nil, pageError(ErrInvalidResponse, pageNumber)
		}
	}

	return nil, ErrInvalidResponse
}

type apiEnvelope struct {
	Success bool    `json:"success"`
	Data    apiPage `json:"data"`
}

type apiPage struct {
	Total int        `json:"total"`
	Items []apiToken `json:"items"`
}

type apiToken struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Key            string `json:"key"`
	Status         int    `json:"status"`
	Group          string `json:"group"`
	UnlimitedQuota bool   `json:"unlimited_quota"`
}

func (catalog *Catalog) fetchPage(ctx context.Context, pageNumber int) (apiPage, error) {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, catalog.pageURL(pageNumber), nil)
	if err != nil {
		return apiPage{}, pageError(ErrRequestFailed, pageNumber)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", catalog.accessToken)
	request.Header.Set("New-Api-User", catalog.userID)

	response, err := catalog.client.Do(request)
	if err != nil {
		return apiPage{}, pageError(ErrRequestFailed, pageNumber)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return apiPage{}, fmt.Errorf("%w: page %d returned HTTP %d", ErrUnexpectedStatus, pageNumber, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil {
		return apiPage{}, pageError(ErrRequestFailed, pageNumber)
	}
	if len(body) > maxResponseBodyBytes {
		return apiPage{}, pageError(ErrResponseTooLarge, pageNumber)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	var envelope apiEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return apiPage{}, pageError(ErrInvalidResponse, pageNumber)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return apiPage{}, pageError(ErrInvalidResponse, pageNumber)
	}
	if !envelope.Success {
		return apiPage{}, pageError(ErrInvalidResponse, pageNumber)
	}
	return envelope.Data, nil
}

func (catalog *Catalog) pageURL(pageNumber int) string {
	endpoint := *catalog.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/token/"
	endpoint.RawPath = ""
	query := make(url.Values, 2)
	query.Set("p", strconv.Itoa(pageNumber))
	query.Set("size", strconv.Itoa(pageSize))
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func pageError(kind error, pageNumber int) error {
	return fmt.Errorf("%w: page %d", kind, pageNumber)
}

func newCatalogSnapshot(tokens []Token, refreshedAt time.Time) *catalogSnapshot {
	ownedTokens := append([]Token(nil), tokens...)
	index := make(map[string]Token, len(ownedTokens))
	ambiguous := make(map[string]struct{})
	for _, token := range ownedTokens {
		if token.MaskedKey == "" {
			continue
		}
		if _, conflict := ambiguous[token.MaskedKey]; conflict {
			continue
		}
		if existing, exists := index[token.MaskedKey]; exists && existing.ID != token.ID {
			delete(index, token.MaskedKey)
			ambiguous[token.MaskedKey] = struct{}{}
			continue
		}
		index[token.MaskedKey] = token
	}
	return &catalogSnapshot{
		tokens:      ownedTokens,
		byMaskedKey: index,
		refreshedAt: refreshedAt,
	}
}

// Snapshot returns a copy that callers can modify without affecting lookups.
func (catalog *Catalog) Snapshot() Snapshot {
	if catalog == nil {
		return Snapshot{Tokens: []Token{}}
	}
	snapshot := catalog.snapshot.Load()
	if snapshot == nil {
		return Snapshot{Tokens: []Token{}}
	}
	return Snapshot{
		Tokens:      append([]Token(nil), snapshot.tokens...),
		RefreshedAt: snapshot.refreshedAt,
	}
}

// List returns a defensive copy of the current token list.
func (catalog *Catalog) List() []Token {
	return catalog.Snapshot().Tokens
}
