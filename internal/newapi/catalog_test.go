package newapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testCatalogAccessToken = "catalog-access-token-canary"

func TestCatalogRefreshPaginatesAndSendsAuthenticationHeaders(t *testing.T) {
	allItems := make([]apiToken, 0, 101)
	for index := 0; index < 101; index++ {
		rawKey := fmt.Sprintf("k%03dmiddlesecretz%03d", index, index)
		allItems = append(allItems, apiToken{
			ID:             int64(index + 1),
			Name:           fmt.Sprintf("token-%03d", index),
			Key:            MaskTokenKey(rawKey),
			Status:         1,
			Group:          "default",
			UnlimitedQuota: index%2 == 0,
		})
	}

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		if request.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", request.Method)
			http.Error(writer, "wrong method", http.StatusBadRequest)
			return
		}
		if request.URL.Path != "/newapi/api/token/" {
			t.Errorf("path = %q, want /newapi/api/token/", request.URL.Path)
			http.Error(writer, "wrong path", http.StatusBadRequest)
			return
		}
		if request.URL.Query().Get("size") != "100" {
			t.Errorf("size = %q, want 100", request.URL.Query().Get("size"))
			http.Error(writer, "wrong size", http.StatusBadRequest)
			return
		}
		if request.Header.Get("Authorization") != testCatalogAccessToken {
			t.Error("Authorization did not contain the configured raw access token")
			http.Error(writer, "wrong authorization", http.StatusUnauthorized)
			return
		}
		if request.Header.Get("New-Api-User") != "73" {
			t.Errorf("New-Api-User = %q, want 73", request.Header.Get("New-Api-User"))
			http.Error(writer, "wrong user", http.StatusUnauthorized)
			return
		}

		switch request.URL.Query().Get("p") {
		case "0":
			writeAPIPage(t, writer, 101, allItems[:100])
		case "1":
			writeAPIPage(t, writer, 101, allItems[100:])
		default:
			t.Errorf("unexpected page %q", request.URL.Query().Get("p"))
			http.Error(writer, "wrong page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	catalog, err := New(Config{
		BaseURL:     server.URL + "/newapi/",
		AccessToken: testCatalogAccessToken,
		UserID:      73,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := catalog.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if requestCount.Load() != 2 {
		t.Fatalf("request count = %d, want 2", requestCount.Load())
	}
	snapshot := catalog.Snapshot()
	if snapshot.RefreshedAt.IsZero() {
		t.Fatal("successful refresh did not set RefreshedAt")
	}
	if len(snapshot.Tokens) != 101 {
		t.Fatalf("token count = %d, want 101", len(snapshot.Tokens))
	}
	last := snapshot.Tokens[100]
	if last.ID != 101 || last.Name != "token-100" || last.MaskedKey != allItems[100].Key ||
		last.Status != 1 || last.Group != "default" || !last.UnlimitedQuota {
		t.Fatalf("last token = %#v", last)
	}

	snapshot.Tokens[0].Name = "caller mutation"
	if got := catalog.List()[0].Name; got != "token-000" {
		t.Fatalf("List exposed mutable snapshot storage: name = %q", got)
	}
}

func TestCatalogUsesInjectedClientWithTenSecondRequestDeadline(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok {
			t.Fatal("request context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 9*time.Second || remaining > requestTimeout {
			t.Fatalf("request deadline remaining = %s, want approximately 10s", remaining)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"data":{"total":0,"items":[]}}`)),
			Request:    request,
		}, nil
	})
	client := &http.Client{Transport: transport}
	catalog, err := New(Config{
		BaseURL:     "https://newapi.example.test",
		AccessToken: testCatalogAccessToken,
		UserID:      1,
		HTTPClient:  client,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if catalog.client != client {
		t.Fatal("custom HTTP client was not retained")
	}
	if err := catalog.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestCatalogInstallsDirectTransportWhenCallerDoesNotProvideOne(t *testing.T) {
	tests := []struct {
		name   string
		client *http.Client
	}{
		{name: "default client"},
		{name: "injected client without transport", client: &http.Client{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := New(Config{
				BaseURL:     "https://newapi.example.test",
				AccessToken: testCatalogAccessToken,
				UserID:      1,
				HTTPClient:  test.client,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			transport, ok := catalog.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport type = %T, want *http.Transport", catalog.client.Transport)
			}
			if transport.Proxy != nil {
				t.Fatal("direct transport unexpectedly configured an environment proxy callback")
			}
			if test.client != nil && catalog.client == test.client {
				t.Fatal("constructor mutated an injected client with nil Transport")
			}
		})
	}
}

func TestCatalogRefreshFailureKeepsPreviousSnapshot(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"success":false,"message":"`+testCatalogAccessToken+`","data":null}`)
			return
		}
		writeAPIPage(t, writer, 1, []apiToken{{
			ID:     41,
			Name:   "kept",
			Key:    MaskTokenKey("keep000000000000tail"),
			Status: 1,
		}})
	}))
	defer server.Close()

	catalog := mustCatalog(t, server.URL, nil)
	if err := catalog.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	before := catalog.Snapshot()

	fail.Store(true)
	err := catalog.Refresh(context.Background())
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("failed Refresh() error = %v, want ErrInvalidResponse", err)
	}
	if strings.Contains(err.Error(), testCatalogAccessToken) {
		t.Fatal("refresh error exposed the NewAPI access token")
	}
	after := catalog.Snapshot()
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("failed refresh changed snapshot:\nbefore = %#v\nafter  = %#v", before, after)
	}
}

func TestCatalogRejectsAbnormalResponsesWithoutLeakingCredentials(t *testing.T) {
	masked := MaskTokenKey("valid000000000000tail")
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr error
	}{
		{
			name: "http status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, testCatalogAccessToken, http.StatusBadGateway)
			},
			wantErr: ErrUnexpectedStatus,
		},
		{
			name: "api failure with secret message",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, `{"success":false,"message":"`+testCatalogAccessToken+`"}`)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "malformed json",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, `{"success":true,"data":`)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "trailing json",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, `{"success":true,"data":{"total":0,"items":[]}} {}`)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "oversized body",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, strings.Repeat("x", maxResponseBodyBytes+1))
			},
			wantErr: ErrResponseTooLarge,
		},
		{
			name: "negative total",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeAPIPage(t, writer, -1, nil)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "more items than total",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeAPIPage(t, writer, 0, []apiToken{{ID: 1, Key: masked}})
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "unmasked key",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeAPIPage(t, writer, 1, []apiToken{{ID: 1, Key: "full-credential-must-not-enter-snapshot"}})
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "empty page before total",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("p") == "0" {
					writeAPIPage(t, writer, 2, []apiToken{{ID: 1, Key: masked}})
					return
				}
				writeAPIPage(t, writer, 2, nil)
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "total changes between pages",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("p") == "0" {
					writeAPIPage(t, writer, 2, []apiToken{{ID: 1, Key: masked}})
					return
				}
				writeAPIPage(t, writer, 3, []apiToken{{ID: 2, Key: MaskTokenKey("next000000000000tail")}})
			},
			wantErr: ErrInvalidResponse,
		},
		{
			name: "duplicate id between pages",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("p") == "0" {
					writeAPIPage(t, writer, 2, []apiToken{{ID: 1, Key: masked}})
					return
				}
				writeAPIPage(t, writer, 2, []apiToken{{ID: 1, Key: MaskTokenKey("other00000000000tail")}})
			},
			wantErr: ErrInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			catalog := mustCatalog(t, server.URL, nil)
			err := catalog.Refresh(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Refresh() error = %v, want %v", err, test.wantErr)
			}
			if strings.Contains(err.Error(), testCatalogAccessToken) {
				t.Fatal("refresh error exposed the NewAPI access token")
			}
			if got := catalog.List(); len(got) != 0 {
				t.Fatalf("failed initial refresh published %d tokens", len(got))
			}
		})
	}
}

func TestNewRejectsInvalidConfigurationWithoutEchoingAccessToken(t *testing.T) {
	tests := []Config{
		{BaseURL: "", AccessToken: testCatalogAccessToken, UserID: 1},
		{BaseURL: "ftp://newapi.example.test", AccessToken: testCatalogAccessToken, UserID: 1},
		{BaseURL: "https://user:password@newapi.example.test", AccessToken: testCatalogAccessToken, UserID: 1},
		{BaseURL: "https://newapi.example.test?token=query", AccessToken: testCatalogAccessToken, UserID: 1},
		{BaseURL: "https://newapi.example.test", AccessToken: "", UserID: 1},
		{BaseURL: "https://newapi.example.test", AccessToken: "bad\r\nvalue", UserID: 1},
		{BaseURL: "https://newapi.example.test", AccessToken: testCatalogAccessToken, UserID: 0},
	}
	for index, config := range tests {
		_, err := New(config)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d: New() error = %v, want ErrInvalidConfig", index, err)
		}
		if strings.Contains(err.Error(), testCatalogAccessToken) {
			t.Fatalf("case %d: error exposed the access token", index)
		}
	}
}

func writeAPIPage(t *testing.T, writer http.ResponseWriter, total int, items []apiToken) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(apiEnvelope{
		Success: true,
		Data: apiPage{
			Total: total,
			Items: items,
		},
	}); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func mustCatalog(t *testing.T, baseURL string, client *http.Client) *Catalog {
	t.Helper()
	catalog, err := New(Config{
		BaseURL:     baseURL,
		AccessToken: testCatalogAccessToken,
		UserID:      73,
		HTTPClient:  client,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return catalog
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestPageURLStartsAtZero(t *testing.T) {
	catalog := mustCatalog(t, "https://newapi.example.test", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.URL.Query().Get("p"); got != "0" {
			t.Fatalf("first page = %q, want 0", got)
		}
		if got := request.URL.Query().Get("size"); got != strconv.Itoa(pageSize) {
			t.Fatalf("page size = %q, want %d", got, pageSize)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"data":{"total":0,"items":[]}}`)),
			Request:    request,
		}, nil
	})})
	if err := catalog.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
}
