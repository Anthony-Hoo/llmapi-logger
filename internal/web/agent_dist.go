package web

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentdist"
	"llmapi-logger/internal/storage"
)

// Distribution of the llmapi-audit Skill (contract section 5): the
// web-side install-links endpoint and the anonymous signed download on the
// facade. Both delegate to agentdist; this file only adds the web plumbing,
// the server address and the audit rows.

const (
	agentInstallLinksPath = agentAccessPathPrefix + "install-links"
	maxInstallLinkBody    = 4 << 10
	// agentPackageObject is the object_kind of link_issued and
	// package_downloaded rows; object_id is the package (or manifest) file.
	agentPackageObject = "agent_package"
	// agentPackagesMissingMessage is what the page shows when the deployment
	// ships without packages (stable, so the page and the docs can name it).
	agentPackagesMissingMessage = "安装包未随本次部署提供"
)

// serveAgentDownload answers GET /api/agent/v1/dl/{signature}/{file}. The
// dispatcher has answered FEATURE_DISABLED and the version check already;
// the endpoint is anonymous, so no token quota applies and the per-link
// download limit lives in agentdist. Only a served file is audited: every
// other answer can be produced by anyone at the request rate, and recording
// it would let an anonymous client grow the audit table without bound.
func (handler *managementHandler) serveAgentDownload(writer http.ResponseWriter, request *http.Request, call agentCall) {
	if _, err := agentCallParams(request, call); err != nil {
		argument := err.(agentArgError)
		writeAgentFailure(writer, agentapi.CodeInvalidArgument, argument.message, "", argument.details())
		return
	}
	if handler.agentDist == nil {
		writeAgentFailure(writer, agentapi.CodeNotFound, "not found",
			"Ask the user to generate a new install prompt on the Agent access page of the web UI.", nil)
		return
	}
	result := handler.agentDist.ServeDownload(writer, request, call.Params["signature"], call.Params["file"])
	if !result.Served {
		return
	}
	handler.agent.RecordAudit(request.Context(), storage.AgentAuditEntry{
		Event: agentaccess.EventPackageDownloaded, ObjectKind: agentPackageObject, ObjectID: result.File,
		Outcome: agentaccess.OutcomeOK,
	})
}

type agentInstallLinkRequest struct {
	Agent     string `json:"agent"`
	Platform  string `json:"platform"`
	SkillsDir string `json:"skills_dir"`
}

// serveAgentInstallLink answers POST /api/v1/agent-access/install-links for
// both roles: the install prompt with a freshly signed download link.
func (handler *managementHandler) serveAgentInstallLink(writer http.ResponseWriter, request *http.Request) {
	caller, ok := principalFrom(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxInstallLinkBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body agentInstallLinkRequest
	if err := decoder.Decode(&body); err != nil {
		writeAgentFieldError(writer, "body")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeAgentFieldError(writer, "body")
		return
	}
	if handler.agentDist == nil {
		writePackagesMissing(writer)
		return
	}
	serverURL := handler.agentPublicURL
	if serverURL == "" {
		serverURL = browsingBaseURL(request)
	}
	linkRequest := agentdist.InstallLinkRequest{Agent: body.Agent, Platform: body.Platform, SkillsDir: body.SkillsDir}
	// A request that cannot issue a link (bad arguments, no package, an
	// unusable address) is answered before it is counted.
	if err := handler.agentDist.CheckInstallLink(serverURL, linkRequest); err != nil {
		writeInstallLinkError(writer, err)
		return
	}
	// At most 20 links per web session identity in 10 minutes (contract
	// section 7): each link writes a link_issued row, and only an issued
	// link counts.
	if allowed, wait := handler.agentDist.AllowInstallLink(installLinkKey(caller)); !allowed {
		seconds := int(math.Ceil(wait.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		writer.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(writer, http.StatusTooManyRequests, "too_many_requests", "安装链接生成得太频繁，请稍后再试")
		return
	}
	link, err := handler.agentDist.InstallLink(serverURL, linkRequest)
	if err != nil {
		writeInstallLinkError(writer, err)
		return
	}
	handler.agent.RecordAudit(request.Context(), storage.AgentAuditEntry{
		Event: agentaccess.EventLinkIssued, Role: string(agentViewer(caller).Role), Command: "web",
		ObjectKind: agentPackageObject, ObjectID: link.File, Outcome: agentaccess.OutcomeOK,
	})
	writeJSON(writer, http.StatusOK, link)
}

// installLinkKey is the web session identity install links are counted by.
// Sessions carry no server-side id, so it is what a session stands for: the
// administrator (every administrator session and the admin token share one
// budget) or one developer's key fingerprint and NewAPI token.
func installLinkKey(caller principal) string {
	if caller.Role != roleDeveloper || caller.Scope == nil {
		return "admin"
	}
	key := "developer:" + hex.EncodeToString(caller.Scope.Fingerprint)
	if caller.Scope.TokenID != nil {
		key += ":" + strconv.FormatInt(*caller.Scope.TokenID, 10)
	}
	return key
}

// writeInstallLinkError answers an error of CheckInstallLink or InstallLink.
func writeInstallLinkError(writer http.ResponseWriter, err error) {
	var input *agentdist.InputError
	switch {
	case errors.As(err, &input):
		writeJSON(writer, http.StatusBadRequest, map[string]any{
			"error": map[string]string{"code": "invalid_argument", "message": input.Message, "field": input.Field},
		})
	case errors.Is(err, agentdist.ErrNoPackages):
		writePackagesMissing(writer)
	default:
		// The only other failure is a server address that cannot be put into
		// a shell command. public_url is validated at startup with the same
		// rule, so this is the browser's address.
		writeJSON(writer, http.StatusBadRequest, map[string]any{
			"error": map[string]string{
				"code":    "server_url_unusable",
				"message": "无法用当前访问地址生成安装链接，请管理员在配置里设置 agent_access.public_url",
			},
		})
	}
}

func writePackagesMissing(writer http.ResponseWriter) {
	writeError(writer, http.StatusServiceUnavailable, "packages_unavailable", agentPackagesMissingMessage)
}

// browsingBaseURL is the address the browser used for this request: the
// connection's scheme and the Host header. Forwarded headers are not read,
// because any client can set them; a deployment behind a TLS-terminating
// proxy or below a path prefix sets agent_access.public_url instead.
func browsingBaseURL(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host
}
