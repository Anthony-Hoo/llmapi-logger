package interceptor

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

const (
	// MinBodyBytes and MaxBodyBytes bound the per-request buffering an
	// interceptor may request.
	MinBodyBytes int64 = 1 << 20
	MaxBodyBytes int64 = 16 << 20
)

// Requirements describe which parts of a request an Interceptor needs.
// Metadata-only interceptors must leave MaxBodyBytes at zero.
type Requirements struct {
	NeedsBody    bool
	MaxBodyBytes int64
}

// Decision is the result of an interceptor check. An allowed decision must
// have no status or block code. A rejected decision must contain a 4xx status
// and a stable block code.
type Decision struct {
	Allow      bool
	StatusCode int
	BlockCode  string
}

// Interceptor checks an immutable view of an inbound request. Instances are
// shared by concurrent requests and therefore must be safe for concurrent use.
type Interceptor interface {
	Requirements() Requirements
	Check(context.Context, RequestView) (Decision, error)
}

// Factory constructs one named interceptor instance from its type-specific
// configuration.
type Factory func(id string, raw map[string]any) (Interceptor, error)

// RequestView is a request snapshot. Its map-backed values are kept private;
// accessors return fresh copies so an interceptor cannot mutate the HTTP
// request or affect a later interceptor in the chain.
type RequestView struct {
	RouteID       string
	Method        string
	EscapedPath   string
	Host          string
	ContentLength int64

	headers    http.Header
	query      url.Values
	pathParams map[string]string
	body       *BodyView
}

// Headers returns a copy of the inbound headers.
func (v RequestView) Headers() http.Header {
	return v.headers.Clone()
}

// Query returns a copy of the decoded inbound query values.
func (v RequestView) Query() url.Values {
	return cloneValues(v.query)
}

// PathParams returns a copy of the parameters captured by the route matcher.
func (v RequestView) PathParams() map[string]string {
	return cloneStrings(v.pathParams)
}

// Body returns the read-only buffered request body when the interceptor
// declared NeedsBody. Metadata-only interceptors receive no body view.
func (v RequestView) Body() (BodyView, bool) {
	if v.body == nil {
		return BodyView{}, false
	}
	return *v.body, true
}

// BodyView exposes only the size and independent readers over the buffered
// bytes. It never exposes the backing slice.
type BodyView struct {
	data []byte
}

// Len returns the buffered body size in bytes.
func (v BodyView) Len() int64 {
	return int64(len(v.data))
}

// Open returns a new reader positioned at the beginning of the body.
func (v BodyView) Open() io.Reader {
	return newReadOnlyBytesReader(v.data)
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}

	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func cloneStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}

	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
