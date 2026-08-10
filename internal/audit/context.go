package audit

import "context"

type sessionContextKey struct{}

// ContextWithSession makes the audit Session available to ReverseProxy
// Rewrite, ModifyResponse, and ErrorHandler callbacks.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// SessionFromContext returns the Session carried across ReverseProxy request
// clones.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	if ctx == nil {
		return nil, false
	}
	session, ok := ctx.Value(sessionContextKey{}).(*Session)
	return session, ok && session != nil
}
