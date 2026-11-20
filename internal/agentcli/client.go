package agentcli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/agentapi"
)

// maxEnvelopeBytes bounds an envelope read into memory; exports stream to a
// file instead.
const maxEnvelopeBytes = 256 << 20

// serverEnvelope is a decoded response envelope. Data and Meta stay raw.
type serverEnvelope struct {
	OK          *bool               `json:"ok"`
	Data        json.RawMessage     `json:"data"`
	Meta        json.RawMessage     `json:"meta"`
	NextActions []string            `json:"next_actions"`
	WebPath     string              `json:"web_path"`
	Notice      string              `json:"notice"`
	Error       *agentapi.ErrorBody `json:"error"`
}

// client talks to the facade for one command.
type client struct {
	env     *Env
	server  string
	token   string
	command string
	http    *http.Client
}

// newClient builds a client for server; token may be empty (code exchange).
// fix is loadConfig's.
func newClient(env *Env, server, token, command string, fix bool) (*client, error) {
	config, err := loadConfig(env, fix)
	if err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(env, config)
	if err != nil {
		return nil, err
	}
	return &client{env: env, server: server, token: token, command: command, http: httpClient}, nil
}

// client loads the saved credentials and builds a client for the command.
// A loose mode of the user's own credential store is tightened first.
func (inv *invocation) client() (*client, error) {
	return inv.clientWith(true)
}

// clientWith is client; fix false only checks the credential store and
// changes nothing (version).
func (inv *invocation) clientWith(fix bool) (*client, error) {
	creds, err := loadCredentials(inv.env, fix)
	if err != nil {
		return nil, err
	}
	inv.creds = creds
	return newClient(inv.env, creds.Server, creds.Token, inv.spec.header(), fix)
}

func newHTTPClient(env *Env, config localConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.CAFile != "" {
		// A CA file in the state directory was read by loadConfig through the
		// handle it checked; only one elsewhere is read here.
		pemData := config.caData
		if !config.caInState {
			var err error
			if pemData, err = os.ReadFile(config.CAFile); err != nil {
				return nil, localFileError("cannot read the CA file named in config.json", nil)
			}
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, localFileError("the CA file named in config.json holds no PEM certificate", nil)
		}
		tlsConfig.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	}
	if env.DialContext != nil {
		transport.DialContext = env.DialContext
		transport.Proxy = nil
	}
	return &http.Client{
		Transport: transport,
		// Never follow a redirect: the 3xx response comes back and is refused.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// checkDeclared refuses to send a query parameter or body field the route
// does not declare, so Routes() always tells the truth.
func (inv *invocation) checkDeclared(route *routeSpec, query url.Values, bodyFields []string) error {
	declared := inv.spec.route(route)
	allowed := func(list []string, name string) bool {
		for _, item := range list {
			if item == name {
				return true
			}
		}
		return false
	}
	for name := range query {
		if !allowed(declared.Query, name) {
			return internalError("undeclared query parameter " + name)
		}
	}
	for _, name := range bodyFields {
		if !allowed(declared.Body, name) {
			return internalError("undeclared body field " + name)
		}
	}
	return nil
}

// bodyFieldsOf lists the top-level keys of a body map; the keys of an args
// object are listed as args.<key>.
func bodyFieldsOf(body map[string]any) []string {
	var fields []string
	for key, value := range body {
		if key == "args" {
			if args, ok := value.(map[string]any); ok {
				for name := range args {
					fields = append(fields, "args."+name)
				}
				continue
			}
		}
		fields = append(fields, key)
	}
	return fields
}

// send performs one request. A redirect, a too-old client and transport
// failures become errors; any other response is returned open.
func (c *client) send(ctx context.Context, method, path string, query url.Values, body []byte) (*http.Response, error) {
	target := c.server + agentapi.PathPrefix + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, &cliError{Code: agentapi.CodeNetworkError, Message: "the saved server address is not usable; ask the user to run `llmaudit login --server <url>`"}
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set(agentapi.HeaderCLIVersion, Version)
	request.Header.Set(agentapi.HeaderCommand, c.command)
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, transportError(ctx, err)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		details := map[string]any{"http_status": response.StatusCode}
		if location := response.Header.Get("Location"); location != "" {
			details["location"] = location
		}
		return nil, &cliError{Code: agentapi.CodeRedirectRefused, Details: details,
			Hint: "Check the server address; the user may need to run `llmaudit login --server <url>` with the final address."}
	}
	if minimum, ok := agentapi.ParseVersion(response.Header.Get(agentapi.HeaderMin)); ok {
		if own, ownOK := agentapi.ParseVersion(Version); ownOK && agentapi.CompareVersions(own, minimum) < 0 {
			response.Body.Close()
			return nil, &cliError{Code: agentapi.CodeClientTooOld, Status: http.StatusUpgradeRequired,
				Details: map[string]any{"client_version": Version, "min_version": response.Header.Get(agentapi.HeaderMin)}}
		}
	}
	return response, nil
}

func transportError(ctx context.Context, err error) *cliError {
	var netErr net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &cliError{Code: agentapi.CodeTimeout, Message: "the request to the server timed out", Details: map[string]any{"source": "client"}}
	}
	reason := "connect"
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &record) {
		reason = "tls"
	}
	message := "could not connect to the server"
	if reason == "tls" {
		message = "the server's TLS certificate could not be verified"
	}
	return &cliError{Code: agentapi.CodeNetworkError, Message: message, Details: map[string]any{"reason": reason}}
}

// call sends a request and decodes the envelope. route.Meta requires meta.
func (c *client) call(ctx context.Context, inv *invocation, route *routeSpec, path string, query url.Values, body map[string]any) (*serverEnvelope, error) {
	var encoded []byte
	if body != nil {
		if err := inv.checkDeclared(route, query, bodyFieldsOf(body)); err != nil {
			return nil, err
		}
		data, err := json.Marshal(body)
		if err != nil {
			return nil, internalError("cannot encode the request")
		}
		encoded = data
	} else if err := inv.checkDeclared(route, query, nil); err != nil {
		return nil, err
	}
	return c.callRaw(ctx, route, path, query, encoded)
}

// callRaw sends an already encoded body (the caller checked it).
func (c *client) callRaw(ctx context.Context, route *routeSpec, path string, query url.Values, body []byte) (*serverEnvelope, error) {
	response, err := c.send(ctx, route.Method, path, query, body)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := readLimited(ctx, response.Body)
	if err != nil {
		return nil, err
	}
	return decodeEnvelope(response, data, route.Meta)
}

func readLimited(ctx context.Context, body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxEnvelopeBytes+1))
	if err != nil {
		return nil, transportError(ctx, err)
	}
	if len(data) > maxEnvelopeBytes {
		return nil, &cliError{Code: agentapi.CodeInvalidResponse, Message: "the server response is too large"}
	}
	return data, nil
}

func invalidResponse(status int, message string) *cliError {
	return &cliError{Code: agentapi.CodeInvalidResponse, Message: message, Details: map[string]any{"http_status": status}}
}

// decodeEnvelope validates an envelope. A failure envelope becomes a
// cliError carrying the server's code and HTTP status.
func decodeEnvelope(response *http.Response, data []byte, requireMeta bool) (*serverEnvelope, error) {
	status := response.StatusCode
	var envelope serverEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&envelope); err != nil || envelope.OK == nil {
		return nil, invalidResponse(status, "the server response is not a valid envelope")
	}
	if decoder.More() {
		return nil, invalidResponse(status, "the server response has data after the envelope")
	}
	if !*envelope.OK {
		if envelope.Error == nil || envelope.Error.Code == "" {
			return nil, invalidResponse(status, "the server failure envelope has no error code")
		}
		failure := &cliError{Code: envelope.Error.Code, Message: envelope.Error.Message, Hint: envelope.Error.Hint, Details: envelope.Error.Details, Status: status}
		if failure.Message == "" {
			failure.Message = "the server reported " + string(failure.Code)
		}
		if retry := response.Header.Get("Retry-After"); retry != "" && failure.Code == agentapi.CodeRateLimited {
			if seconds, err := strconv.Atoi(strings.TrimSpace(retry)); err == nil {
				if failure.Details == nil {
					failure.Details = map[string]any{}
				}
				if _, exists := failure.Details["retry_after_seconds"]; !exists {
					failure.Details["retry_after_seconds"] = seconds
				}
			}
		}
		return nil, failure
	}
	if status != http.StatusOK {
		return nil, invalidResponse(status, fmt.Sprintf("the server answered HTTP %d with a success envelope", status))
	}
	if len(envelope.Data) == 0 {
		return nil, invalidResponse(status, "the success envelope has no data")
	}
	if requireMeta && !validMeta(envelope.Meta) {
		return nil, invalidResponse(status, "the read result has no complete meta (state, complete, incomplete_reason)")
	}
	return &envelope, nil
}

// validMeta checks that the three meta fields are present with their types;
// a zero value is fine, an absent key is not.
func validMeta(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return false
	}
	var state, reason string
	var complete bool
	stateRaw, hasState := fields["state"]
	completeRaw, hasComplete := fields["complete"]
	reasonRaw, hasReason := fields["incomplete_reason"]
	return hasState && hasComplete && hasReason &&
		json.Unmarshal(stateRaw, &state) == nil && !isNull(stateRaw) &&
		json.Unmarshal(completeRaw, &complete) == nil && !isNull(completeRaw) &&
		json.Unmarshal(reasonRaw, &reason) == nil && !isNull(reasonRaw)
}

func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}
