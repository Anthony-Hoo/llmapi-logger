package newapi

import (
	"context"
	"encoding/json"
	"errors"
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

const testAccessToken = "management-access-token-canary"

func TestClientRefreshesGlobalUsersAndSendsAdminHeaders(t *testing.T) {
	all := make([]apiUser, 0, 101)
	for index := 0; index < 101; index++ {
		all = append(all, apiUser{
			ID: int64(index + 1), Username: "user-" + strconv.Itoa(index),
			DisplayName: "User " + strconv.Itoa(index), Status: 1, Group: "default",
		})
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Path != "/newapi/api/user/" || request.Header.Get("Authorization") != testAccessToken ||
			request.Header.Get("New-Api-User") != "73" || request.URL.Query().Get("size") != "100" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		switch request.URL.Query().Get("p") {
		case "0":
			writeEnvelope(t, writer, apiPage[apiUser]{Total: 101, Items: all[:100]})
		case "1":
			writeEnvelope(t, writer, apiPage[apiUser]{Total: 101, Items: all[100:]})
		default:
			http.Error(writer, "bad page", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := mustClient(t, server.URL+"/newapi/", nil)
	if err := client.RefreshUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	snapshot := client.Snapshot()
	if len(snapshot.Users) != 101 || snapshot.RefreshedAt.IsZero() || snapshot.Users[100].Username != "user-100" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	snapshot.Users[0].Username = "mutated"
	if got, _ := client.User(1); got.Username != "user-0" {
		t.Fatalf("snapshot exposed mutable storage: %+v", got)
	}
}

func TestClientLooksUpExactRequestIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/log/" || request.URL.Query().Get("request_id") != "req-exact" ||
			request.URL.Query().Get("p") != "0" || request.URL.Query().Get("size") != "10" {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		writeEnvelope(t, writer, apiPage[apiLog]{Total: 1, Items: []apiLog{{
			UserID: 7, Username: "alice", TokenID: 42, TokenName: "codex",
			ModelName: "gpt-test", RequestID: "req-exact",
		}}})
	}))
	defer server.Close()

	identity, found, err := mustClient(t, server.URL, nil).LookupRequest(context.Background(), "req-exact")
	if err != nil || !found {
		t.Fatalf("LookupRequest found=%v err=%v", found, err)
	}
	want := RequestIdentity{
		RequestID: "req-exact", UserID: 7, Username: "alice", TokenID: 42,
		TokenName: "codex", ModelName: "gpt-test",
	}
	if !reflect.DeepEqual(identity, want) {
		t.Fatalf("identity = %+v, want %+v", identity, want)
	}
}

func TestClientReportsDelayedLogAsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, apiPage[apiLog]{Total: 0, Items: []apiLog{}})
	}))
	defer server.Close()
	identity, found, err := mustClient(t, server.URL, nil).LookupRequest(context.Background(), "req-later")
	if err != nil || found || identity != (RequestIdentity{}) {
		t.Fatalf("LookupRequest = %+v, %v, %v", identity, found, err)
	}
}

func TestClientRejectsConflictingLogOwners(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, apiPage[apiLog]{Total: 2, Items: []apiLog{
			{UserID: 1, Username: "one", TokenID: 10, TokenName: "a", RequestID: "req-conflict"},
			{UserID: 2, Username: "two", TokenID: 20, TokenName: "b", RequestID: "req-conflict"},
		}})
	}))
	defer server.Close()
	_, _, err := mustClient(t, server.URL, nil).LookupRequest(context.Background(), "req-conflict")
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestClientFailureKeepsUserSnapshotAndDoesNotLeakCredential(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			_, _ = io.WriteString(writer, `{"success":false,"message":"`+testAccessToken+`"}`)
			return
		}
		writeEnvelope(t, writer, apiPage[apiUser]{Total: 1, Items: []apiUser{{ID: 1, Username: "kept"}}})
	}))
	defer server.Close()
	client := mustClient(t, server.URL, nil)
	if err := client.RefreshUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := client.Snapshot()
	fail.Store(true)
	err := client.RefreshUsers(context.Background())
	if !errors.Is(err, ErrInvalidResponse) || strings.Contains(err.Error(), testAccessToken) {
		t.Fatalf("unsafe error = %v", err)
	}
	if after := client.Snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("snapshot changed: before=%+v after=%+v", before, after)
	}
}

func TestClientUsesInjectedTransportAndTenSecondDeadline(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) <= 9*time.Second || time.Until(deadline) > requestTimeout {
			t.Fatalf("deadline = %v, ok=%v", deadline, ok)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: request,
			Body: io.NopCloser(strings.NewReader(`{"success":true,"data":{"total":0,"items":[]}}`)),
		}, nil
	})
	httpClient := &http.Client{Transport: transport}
	client := mustClient(t, "https://newapi.example", httpClient)
	if client.client != httpClient {
		t.Fatal("custom client was not retained")
	}
	if err := client.RefreshUsers(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientRejectsInvalidConfiguration(t *testing.T) {
	for _, config := range []Config{
		{},
		{BaseURL: "ftp://example", AccessToken: testAccessToken, UserID: 1},
		{BaseURL: "https://example", AccessToken: "", UserID: 1},
		{BaseURL: "https://example", AccessToken: testAccessToken, UserID: 0},
	} {
		client, err := NewClient(config)
		if client != nil || !errors.Is(err, ErrInvalidConfig) || strings.Contains(fmtError(err), testAccessToken) {
			t.Fatalf("NewClient(%+v) = %v, %v", config, client, err)
		}
	}
}

func mustClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	client, err := NewClient(Config{
		BaseURL: baseURL, AccessToken: testAccessToken, UserID: 73, HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeEnvelope[T any](t *testing.T, writer http.ResponseWriter, data T) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(apiEnvelope[T]{Success: true, Data: data}); err != nil {
		t.Error(err)
	}
}

func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
