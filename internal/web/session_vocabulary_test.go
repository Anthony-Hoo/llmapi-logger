package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestSessionCarriesInjectedUserTextPrefixes(t *testing.T) {
	t.Parallel()
	prefixes := []string{"<environment_context", "# agents.md"}
	handler, err := NewHandler(Options{AdminToken: testAdminToken, InjectedUserTextPrefixes: prefixes})
	if err != nil {
		t.Fatal(err)
	}
	// The handler keeps its own copy of the list.
	prefixes[0] = "changed"

	read := func(response *httptest.ResponseRecorder) map[string]json.RawMessage {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d %s", response.Code, response.Body.String())
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	want := []string{"<environment_context", "# agents.md"}
	check := func(name string, decoded map[string]json.RawMessage) {
		t.Helper()
		var got []string
		if err := json.Unmarshal(decoded["injected_user_text_prefixes"], &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: injected_user_text_prefixes = %s, want %q", name, decoded["injected_user_text_prefixes"], want)
		}
	}

	info := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	info.Header.Set("Authorization", "Bearer "+testAdminToken)
	infoResponse := httptest.NewRecorder()
	handler.ServeHTTP(infoResponse, info)
	check("session info", read(infoResponse))

	login := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader(`{"token":"`+testAdminToken+`"}`))
	login.Header.Set("Content-Type", "application/json")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, login)
	check("admin login", read(loginResponse))
}

func TestSessionOmitsEmptyInjectedUserTextPrefixes(t *testing.T) {
	t.Parallel()
	handler, err := NewHandler(Options{AdminToken: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "injected_user_text_prefixes") {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
}
