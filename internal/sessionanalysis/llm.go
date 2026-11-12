package sessionanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"llmapi-logger/internal/config"
)

// ChatMessage is one OpenAI-compatible chat message.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Completion is the text and usage of one model call.
type Completion struct {
	Content      string
	InputTokens  int64
	OutputTokens int64
	Latency      time.Duration
	// Truncated reports that the model stopped at the output limit
	// (finish_reason "length"), so Content may be cut off.
	Truncated bool
}

// Completer calls a model; the LLM client implements it and tests fake it.
type Completer interface {
	Complete(ctx context.Context, messages []ChatMessage, schema map[string]any) (Completion, error)
	// CompleteText asks for free prose: no response_format is sent.
	CompleteText(ctx context.Context, messages []ChatMessage) (Completion, error)
	Model() string
}

// ErrNonLocalPeer is returned when the model endpoint resolves to an address
// outside loopback and private ranges while allow_non_local is false.
var ErrNonLocalPeer = errors.New("sessionanalysis: model endpoint resolved to a non-local address")

// Resolver looks up the addresses of a host name.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// LLMClient is the OpenAI-compatible chat client of the local model
// (doc 24 sections 4 and 7.2). It never uses environment proxies and, unless
// allow_non_local is set, re-checks every resolved peer address at dial time.
type LLMClient struct {
	config     config.SessionAnalysisLLM
	endpoint   string
	httpClient *http.Client
	// noThinkingParams is set after the server rejected the thinking switches.
	noThinkingParams atomic.Bool
}

// NewLLMClient builds the client. resolve may be nil (system resolver).
func NewLLMClient(configuration config.SessionAnalysisLLM, resolve Resolver) (*LLMClient, error) {
	if strings.TrimSpace(configuration.Model) == "" || configuration.BaseURL == "" {
		return nil, errors.New("sessionanalysis: llm model and base_url are required")
	}
	if resolve == nil {
		resolve = defaultResolver
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	allowAny := configuration.AllowNonLocal
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			candidates := make([]netip.Addr, 0, 2)
			if literal, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
				candidates = append(candidates, literal)
			} else {
				resolved, err := resolve(ctx, host)
				if err != nil {
					return nil, err
				}
				candidates = resolved
			}
			var lastErr error = ErrNonLocalPeer
			for _, candidate := range candidates {
				if !allowAny && !config.LocalModelAddress(candidate) {
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(configuration.TimeoutSeconds) * time.Second,
	}
	timeout := time.Duration(configuration.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &LLMClient{
		config:     configuration,
		endpoint:   strings.TrimRight(configuration.BaseURL, "/") + "/chat/completions",
		httpClient: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// Model returns the configured model name.
func (client *LLMClient) Model() string { return client.config.Model }

// Complete sends one chat completion at temperature 0.
func (client *LLMClient) Complete(ctx context.Context, messages []ChatMessage, schema map[string]any) (Completion, error) {
	return client.complete(ctx, messages, schema, false)
}

// CompleteText sends one chat completion for free prose.
func (client *LLMClient) CompleteText(ctx context.Context, messages []ChatMessage) (Completion, error) {
	return client.complete(ctx, messages, nil, true)
}

func (client *LLMClient) complete(ctx context.Context, messages []ChatMessage, schema map[string]any, text bool) (Completion, error) {
	thinking := client.config.DisableThinking && !client.noThinkingParams.Load()
	completion, status, err := client.post(ctx, messages, schema, thinking, text)
	if err != nil && thinking && status == http.StatusBadRequest {
		// Some servers reject unknown request fields: retry once without the
		// thinking switches and stop sending them.
		client.noThinkingParams.Store(true)
		completion, _, err = client.post(ctx, messages, schema, false, text)
	}
	return completion, err
}

func (client *LLMClient) requestBody(messages []ChatMessage, schema map[string]any, thinking, text bool) ([]byte, error) {
	body := map[string]any{
		"model":       client.config.Model,
		"messages":    messages,
		"temperature": 0,
		"max_tokens":  client.config.MaxOutputTokens,
		"stream":      false,
	}
	switch {
	case text:
	case client.config.StructuredOutput == "json_schema":
		if schema != nil {
			body["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "session_facet", "schema": schema, "strict": true}}
		}
	case client.config.StructuredOutput == "json_object":
		body["response_format"] = map[string]any{"type": "json_object"}
	}
	if thinking {
		// vLLM / SGLang chat templates, Ollama's think switch, and the
		// thinking object of DeepSeek-style APIs. Reasoning tokens count
		// against max_tokens, so a model left thinking truncates its answer.
		body["chat_template_kwargs"] = map[string]any{"enable_thinking": false}
		body["think"] = false
		body["thinking"] = map[string]any{"type": "disabled"}
	}
	return json.Marshal(body)
}

func (client *LLMClient) post(ctx context.Context, messages []ChatMessage, schema map[string]any, thinking, text bool) (Completion, int, error) {
	payload, err := client.requestBody(messages, schema, thinking, text)
	if err != nil {
		return Completion{}, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Completion{}, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if client.config.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+client.config.APIKey)
	}
	started := time.Now()
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Completion{}, 0, fmt.Errorf("sessionanalysis: model request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return Completion{}, response.StatusCode, fmt.Errorf("sessionanalysis: read model response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return Completion{}, response.StatusCode, fmt.Errorf("sessionanalysis: model returned status %d", response.StatusCode)
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Choices) == 0 {
		return Completion{}, response.StatusCode, errors.New("sessionanalysis: malformed model response")
	}
	return Completion{
		Content:      decoded.Choices[0].Message.Content,
		InputTokens:  decoded.Usage.PromptTokens,
		OutputTokens: decoded.Usage.CompletionTokens,
		Latency:      time.Since(started),
		Truncated:    decoded.Choices[0].FinishReason == "length",
	}, response.StatusCode, nil
}

var thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>`)
var codeFence = regexp.MustCompile("(?s)^\\s*```(?:json)?\\s*(.*?)\\s*```\\s*$")

// cleanModelOutput strips <think> sections and a surrounding code fence.
func cleanModelOutput(content string) string {
	content = thinkBlock.ReplaceAllString(content, "")
	if index := strings.Index(content, "</think>"); index >= 0 {
		content = content[index+len("</think>"):] // an unopened block before the answer
	}
	content = strings.TrimSpace(content)
	if match := codeFence.FindStringSubmatch(content); match != nil {
		content = match[1]
	}
	return strings.TrimSpace(content)
}
