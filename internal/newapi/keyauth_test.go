package newapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDeveloperKey = "sk-test-developer-key"

func newTokenLogServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/log/token" {
			t.Errorf("unexpected path %q", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+testDeveloperKey {
			t.Errorf("Authorization = %q, want the submitted key as a bearer token", got)
		}
		// The token endpoint authenticates with the key alone; sending the
		// administrator identity header here would be a credential leak.
		if got := request.Header.Get("New-Api-User"); got != "" {
			t.Errorf("New-Api-User = %q, want it absent", got)
		}
		handler(writer, request)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestValidateTokenKeyResolvesTokenIdentity(t *testing.T) {
	t.Parallel()
	server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":[
            {"user_id":7,"username":"developer","token_id":42,"token_name":"agent-token","model_name":"model-example","request_id":"req-1"},
            {"user_id":7,"username":"developer","token_id":42,"token_name":"agent-token","model_name":"model-example","request_id":"req-2"}
        ]}`))
	})

	identity, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
	if err != nil {
		t.Fatal(err)
	}
	want := TokenIdentity{UserID: 7, Username: "developer", TokenID: 42, TokenName: "agent-token", HasIdentity: true}
	if identity != want {
		t.Fatalf("identity = %+v, want %+v", identity, want)
	}
}

func TestValidateTokenKeyAcceptsRenamedToken(t *testing.T) {
	t.Parallel()
	// Every row carries the labels as they read when that request was served,
	// so a token renamed at some point has older rows holding the older name.
	// That is one token with one history, not a corrupted response, and the
	// name reported back is the current one regardless of row order.
	server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":[
            {"user_id":7,"username":"developer","token_id":42,"token_name":"old-name","model_name":"model-example","request_id":"req-1","created_at":1000},
            {"user_id":7,"username":"developer","token_id":42,"token_name":"current-name","model_name":"model-example","request_id":"req-2","created_at":3000},
            {"user_id":7,"username":"developer","token_id":42,"token_name":"old-name","model_name":"model-example","request_id":"req-3","created_at":2000}
        ]}`))
	})

	identity, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
	if err != nil {
		t.Fatal(err)
	}
	want := TokenIdentity{UserID: 7, Username: "developer", TokenID: 42, TokenName: "current-name", HasIdentity: true}
	if identity != want {
		t.Fatalf("identity = %+v, want %+v", identity, want)
	}
}

func TestValidateTokenKeyRejectsDisagreeingOwners(t *testing.T) {
	t.Parallel()
	// Renaming is tolerated, but rows resolving to different owners are not:
	// the endpoint filters by the authenticated token, so that cannot happen
	// for a response this code is entitled to trust.
	for name, body := range map[string]string{
		"different token": `{"success":true,"data":[
            {"user_id":7,"username":"developer","token_id":42,"token_name":"agent","created_at":1000},
            {"user_id":7,"username":"developer","token_id":43,"token_name":"agent","created_at":2000}
        ]}`,
		"different user": `{"success":true,"data":[
            {"user_id":7,"username":"developer","token_id":42,"token_name":"agent","created_at":1000},
            {"user_id":8,"username":"developer","token_id":42,"token_name":"agent","created_at":2000}
        ]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(body))
			})

			identity, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v, want ErrInvalidResponse", err)
			}
			if identity != (TokenIdentity{}) {
				t.Fatalf("identity = %+v, want the zero identity", identity)
			}
		})
	}
}

func TestValidateTokenKeyAcceptsUnusedKeyWithoutIdentity(t *testing.T) {
	t.Parallel()
	server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"success":true,"data":[]}`))
	})

	// A freshly created key is valid but has produced no logs yet, so NewAPI
	// reveals no owner. The session still authenticates and scopes by
	// fingerprint alone.
	identity, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
	if err != nil {
		t.Fatal(err)
	}
	if identity.HasIdentity || identity != (TokenIdentity{}) {
		t.Fatalf("identity = %+v, want the zero identity", identity)
	}
}

func TestValidateTokenKeyRejectsRefusedKeys(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name    string
		status  int
		payload string
	}{
		{name: "unknown or disabled token", status: http.StatusUnauthorized, payload: `{"success":false,"message":"token invalid"}`},
		{name: "banned user", status: http.StatusForbidden, payload: `{"success":false,"message":"user banned"}`},
		{name: "success false with 200", status: http.StatusOK, payload: `{"success":false,"message":"token invalid"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.payload))
			})
			_, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
			if !errors.Is(err, ErrKeyRejected) {
				t.Fatalf("error = %v, want ErrKeyRejected", err)
			}
		})
	}

	for _, raw := range []string{"", "   ", "sk-bad\nkey"} {
		if _, err := ValidateTokenKey(context.Background(), "http://127.0.0.1:1", nil, raw); !errors.Is(err, ErrKeyRejected) {
			t.Fatalf("ValidateTokenKey(%q) error = %v, want ErrKeyRejected", raw, err)
		}
	}
}

func TestValidateTokenKeySeparatesUpstreamFailuresFromRejection(t *testing.T) {
	t.Parallel()
	t.Run("server error", func(t *testing.T) {
		server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusBadGateway)
		})
		_, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
		if !errors.Is(err, ErrUnexpectedStatus) || errors.Is(err, ErrKeyRejected) {
			t.Fatalf("error = %v, want ErrUnexpectedStatus and not ErrKeyRejected", err)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		server := newTokenLogServer(t, func(http.ResponseWriter, *http.Request) {})
		address := server.URL
		server.Close()
		_, err := ValidateTokenKey(context.Background(), address, http.DefaultClient, testDeveloperKey)
		if !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("error = %v, want ErrRequestFailed", err)
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"success":true,"data":[{"user_id":7,"username":"` +
				strings.Repeat("x", maxResponseBodyBytes+16) + `","token_id":42,"token_name":"t"}]}`))
		})
		_, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("error = %v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("conflicting owners", func(t *testing.T) {
		server := newTokenLogServer(t, func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"success":true,"data":[
                {"user_id":7,"username":"developer","token_id":42,"token_name":"agent-token"},
                {"user_id":8,"username":"other","token_id":43,"token_name":"other-token"}
            ]}`))
		})
		_, err := ValidateTokenKey(context.Background(), server.URL, server.Client(), testDeveloperKey)
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error = %v, want ErrInvalidResponse", err)
		}
	})

	t.Run("malformed base url", func(t *testing.T) {
		if _, err := ValidateTokenKey(context.Background(), "not-a-url", nil, testDeveloperKey); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("error = %v, want ErrInvalidConfig", err)
		}
	})
}
