package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// A query string that does not decode is refused before any other check
// (contract section 0.1 item 188): URL.Query drops the pair that fails, so
// ?from=%zz used to read the unfiltered list, and the dropped key escaped the
// unknown-key and repeated-key checks.
func TestAgentFacadeRefusesAQueryStringThatDoesNotDecode(t *testing.T) {
	fixture := newReadFixture(t)
	for _, path := range []string{
		"/requests?from=%zz",
		"/requests?limit=1&x=%",
		"/requests?limit=1;from=2026-01-01",
		"/requests?limit=1&limit=%zz",
		"/status?zz=%zz",
		"/status?a;b",
		"/callers?%",
	} {
		before := fixture.audits.listCalls
		response := fixture.facade(http.MethodGet, path, "", fixture.adminRead)
		decoded := decodeAgent(t, response)
		if response.Code != http.StatusBadRequest || decoded.Error == nil || decoded.Error.Code != agentapi.CodeInvalidArgument {
			t.Errorf("%s = %d %s", path, response.Code, response.Body.String())
			continue
		}
		if decoded.Error.Details["field"] != "query" || decoded.Error.Details["reason"] != reasonInvalidFormat ||
			!strings.Contains(decoded.Error.Message, "percent-encoded") {
			t.Errorf("%s: error = %+v", path, decoded.Error)
		}
		if fixture.audits.listCalls != before {
			t.Errorf("%s reached the list service", path)
		}
	}
	// The same filter, correctly encoded, still works.
	for _, path := range []string{
		"/requests?from=2026-10-10T11%3A00%3A00Z&limit=1",
		"/requests?user_agent=a%25b",
		"/status",
	} {
		if response := fixture.facade(http.MethodGet, path, "", fixture.adminRead); response.Code != http.StatusOK {
			t.Errorf("%s = %d %s", path, response.Code, response.Body.String())
		}
	}
}

// The administrator's change list applies the same rule in its own error
// style.
func TestAgentChangesRefusesAQueryStringThatDoesNotDecode(t *testing.T) {
	fixture := newWriteFixture(t)
	for _, query := range []string{"?limit=%zz", "?limit=1;x=2", "?%"} {
		response := fixture.web(http.MethodGet, "/api/v1/agent-access/changes"+query, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"field":"query"`) {
			t.Errorf("changes%s = %d %s", query, response.Code, response.Body.String())
		}
	}
	if response := fixture.web(http.MethodGet, "/api/v1/agent-access/changes?limit=1", ""); response.Code != http.StatusOK {
		t.Errorf("changes?limit=1 = %d %s", response.Code, response.Body.String())
	}
}

// since is compared before it is multiplied (contract section 0.1 item 187):
// seven digits of hours, days or weeks overflow time.Duration, and the wrapped
// value used to pass the maximum check, so the query silently read another
// range.
func TestParseSinceRefusesValuesThatOverflow(t *testing.T) {
	const maximum = maxSinceDays * 24 * time.Hour
	for _, value := range []string{
		"30501w",   // wraps to about 72h
		"9999999w", // wraps negative
		"213504d",  // wraps to about 25 minutes
		"9999999d",
		"5124096h", // wraps to about 25 minutes
		"9999999h",
		"523w", "3661d", "87841h", "5270401m", "9999999m",
	} {
		if duration, err := parseSince(value); err == nil {
			t.Errorf("since=%s accepted as %v", value, duration)
		}
	}
	for value, want := range map[string]time.Duration{
		"522w":     522 * 7 * 24 * time.Hour,
		"3660d":    maximum,
		"87840h":   maximum,
		"5270400m": maximum,
		"9999999s": 9999999 * time.Second,
		"30m":      30 * time.Minute,
		"2w":       14 * 24 * time.Hour,
	} {
		if duration, err := parseSince(value); err != nil || duration != want {
			t.Errorf("since=%s = %v, %v; want %v", value, duration, err, want)
		}
	}
	fixture := newReadFixture(t)
	decoded := decodeAgent(t, fixture.facade(http.MethodGet, "/requests?since=30501w", "", fixture.adminRead))
	if decoded.Error == nil || decoded.Error.Code != agentapi.CodeInvalidArgument || decoded.Error.Details["field"] != "since" {
		t.Fatalf("since=30501w through the facade = %+v", decoded)
	}
}
