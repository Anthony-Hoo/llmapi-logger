package web

import (
	"context"
	"errors"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
)

// Role-dependent read rules shared by the web handlers and the agent facade
// (doc/features/25-agent-access.md section 7.2). Each function takes the
// caller and returns a decision; it never writes a response, so each
// transport maps the decision onto its own wire format. The facade must call
// these rather than restate them, which is what keeps "authorization
// unchanged" structural.

// errAdministratorOnly is the decision "this selector or resource needs an
// administrator". The web answers it 403; the facade FORBIDDEN_ROLE.
var errAdministratorOnly = errors.New("web: administrator only")

// callerReadScope is the scope every audit, insights and session analysis
// read of caller is confined to: nil for an administrator, never nil for a
// developer.
func callerReadScope(caller principal) *query.Scope {
	return caller.Scope
}

// callerMayFilterByCaller reports whether caller may select audits by NewAPI
// identity (user id, username, token id, token name). A scoped session is
// pinned to one key already, so it may not (contract D4). The web and the
// facade use different parameter names and each rejects on key presence.
func callerMayFilterByCaller(caller principal) bool {
	return callerReadScope(caller) == nil
}

// scopeAuditFilter pins filter to caller's scope. It runs after parsing, so no
// query parameter can reach or replace the scope.
func scopeAuditFilter(caller principal, filter *query.Filter) {
	filter.Scope = callerReadScope(caller)
}

// authorizeAuditRead is the one ownership gate in front of every per-audit
// resource (detail, raw, reconstructed, timeline, composition and every
// facade export). An administrator always passes without a lookup; a
// developer asking for another key's audit, a locally blocked one or a
// missing one gets query.ErrNotFound alike (contract D1-D3).
func authorizeAuditRead(ctx context.Context, audits AuditQuery, caller principal, auditID string) error {
	scope := callerReadScope(caller)
	if scope == nil {
		return nil
	}
	return audits.Authorize(ctx, auditID, scope)
}

// requireAdministratorSelector refuses a selector that reads somebody else's
// data (session analysis user_id, project_id, group_id) unless caller is an
// administrator. Callers validate the selector's value first, as the web
// always has.
func requireAdministratorSelector(caller principal, selected bool) error {
	if selected && caller.Role != roleAdmin {
		return errAdministratorOnly
	}
	return nil
}

// analysisViewer describes caller for the session analysis view log. Anything
// but a developer principal is logged as an administrator, as before.
func analysisViewer(caller principal, known bool) sessionanalysis.Viewer {
	if !known || caller.Role != roleDeveloper {
		return sessionanalysis.Viewer{Role: "admin"}
	}
	viewer := sessionanalysis.Viewer{Role: "developer", TokenID: caller.Identity.TokenID}
	if caller.Identity.UserID != 0 {
		userID := caller.Identity.UserID
		viewer.UserID = &userID
	}
	return viewer
}

// selfWeeklyUserID is the NewAPI user whose "my week" row caller reads. It
// comes from the signed identity, never from the request; an administrator
// and a developer whose identity is unknown read user 0, which the service
// answers with an empty row (contract D7).
func selfWeeklyUserID(caller principal) int64 {
	if caller.Role == roleDeveloper {
		return caller.Identity.UserID
	}
	return 0
}
