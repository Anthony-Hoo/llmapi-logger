package protofixture

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func send(t *testing.T, server *httptest.Server, upstream *Upstream, exchange *Exchange) (*http.Response, string) {
	t.Helper()
	id := upstream.Register(exchange)
	request, err := http.NewRequest(exchange.Method, server.URL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(ExchangeHeader, id)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response, id
}

func TestUpstreamServesRegisteredExchange(t *testing.T) {
	t.Parallel()
	upstream := NewUpstream("fx")
	server := httptest.NewServer(upstream)
	defer server.Close()
	for _, value := range []Case{{OpenAIResponses, ScenarioBasic, true}, {Gemini, ScenarioError429, false}} {
		exchanges, _ := Build(value, Options{Seed: 1})
		exchange := exchanges[0]
		response, id := send(t, server, upstream, &exchange)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || !bytes.Equal(body, exchange.Response.Body()) || response.StatusCode != exchange.Response.Status {
			t.Fatalf("%s: response %d err=%v", value, response.StatusCode, err)
		}
		if response.Header.Get(NewAPIRequestIDHeader) != id {
			t.Fatalf("%s: request id header = %q, want %q", value, response.Header.Get(NewAPIRequestIDHeader), id)
		}
	}
	if stats := upstream.Stats(); stats.Served != 2 || stats.Mismatched != 0 || stats.Unknown != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestUpstreamAbortsAtCut(t *testing.T) {
	t.Parallel()
	upstream := NewUpstream("fx")
	server := httptest.NewServer(upstream)
	defer server.Close()
	exchanges, _ := Build(Case{AnthropicMessages, ScenarioUpstreamCut, true}, Options{Seed: 1})
	exchange := exchanges[0]
	response, _ := send(t, server, upstream, &exchange)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err == nil {
		t.Fatal("aborted stream ended cleanly")
	}
	if !bytes.Equal(body, exchange.Response.Seen()) {
		t.Fatalf("received %d bytes, want the %d bytes before the cut", len(body), exchange.Response.CutAt)
	}
}

func TestUpstreamWaitsForClientCancel(t *testing.T) {
	t.Parallel()
	upstream := NewUpstream("fx")
	server := httptest.NewServer(upstream)
	defer server.Close()
	exchanges, _ := Build(Case{OpenAIChat, ScenarioClientCancel, true}, Options{Seed: 1})
	exchange := exchanges[0]
	id := upstream.Register(&exchange)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, exchange.Method, server.URL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(ExchangeHeader, id)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, exchange.Response.CutAt)
	if _, err := io.ReadFull(response.Body, prefix); err != nil {
		t.Fatal(err)
	}
	cancel()
	response.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for upstream.Stats().Cancelled == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if upstream.Stats().Cancelled != 1 {
		t.Fatalf("upstream did not observe the client going away: %+v", upstream.Stats())
	}
	if !bytes.Equal(prefix, exchange.Response.Seen()) {
		t.Fatal("bytes before the cut differ")
	}
}

func TestUpstreamCountsMismatchAndUnknown(t *testing.T) {
	t.Parallel()
	upstream := NewUpstream("fx")
	server := httptest.NewServer(upstream)
	defer server.Close()
	exchanges, _ := Build(Case{OpenAIChat, ScenarioBasic, false}, Options{Seed: 1})
	exchange := exchanges[0]
	changed := exchange
	changed.RequestBody = append([]byte(nil), exchange.RequestBody...)
	changed.RequestBody[len(changed.RequestBody)-2] = ' '
	id := upstream.Register(&exchange)
	request, _ := http.NewRequest(exchange.Method, server.URL+exchange.Path, bytes.NewReader(changed.RequestBody))
	request.Header.Set(ExchangeHeader, id)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	unknown, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", nil)
	response, err = server.Client().Do(unknown)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if stats := upstream.Stats(); stats.Mismatched != 1 || stats.Unknown != 1 || response.StatusCode != http.StatusNotFound {
		t.Fatalf("stats = %+v status = %d", stats, response.StatusCode)
	}
}
