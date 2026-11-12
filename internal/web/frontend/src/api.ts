import type {
  AuditCursor,
  AuditDetail,
  AuditFilters,
  AuditListPage,
  CompositionResponse,
  ContentPolicyRule,
  ContentPolicyRuleInput,
  ContentPolicyRuleList,
  NewAPIUserList,
  OverviewQuery,
  OverviewResponse,
  SessionsQuery,
  SessionsResponse,
  TreeResponse,
  TrendResponse,
  RawBodyDownload,
  RawSide,
  ReconstructedBodyDownload,
  SessionInfo,
  StreamTimeline,
  UserAgentRule,
  UserAgentRuleInput,
  UserAgentRuleList,
} from "./types";
import type {
  OrgCatalog,
  OrgGroup,
  OrgGroupInput,
  OrgMember,
  OrgPreviewInput,
  OrgPreviewResult,
  OrgPrincipal,
  OrgProject,
  OrgProjectInput,
  OrgProjectReport,
  OrgSelfReport,
  OrgSettings,
  OrgTrendReport,
  OrgUnattributedEntry,
  OrgWeeklyQuery,
  OrgWeeklyReport,
  PrincipalClass,
  PrincipalKind,
} from "./lib/org/types";

import { hasRowFilters } from "./filters";
import type {
  AnalysisCalibration,
  AnalysisCalibrationLabel,
  AnalysisFacet,
  AnalysisOverview,
  AnalysisPack,
  AnalysisReport,
  AnalysisReportTarget,
  AnalysisSessionsPage,
  AnalysisSessionsQuery,
  AnalysisUsers,
} from "./lib/session-analysis/types";
import type { AnalysisProbeResult, AnalysisSettingsUpdate, AnalysisSettingsView, OrgEditableSettings, OrgSettingsView } from "./lib/settings/types";

const API_BASE = "/api/v1";

/** A weekly report settings view always carries its client list. */
function withClients(view: OrgSettingsView): OrgSettingsView {
  return { ...view, clients: view.clients ?? [] };
}

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type FetchLike = typeof fetch;

export interface ApiClient {
  getSession: (signal?: AbortSignal) => Promise<SessionInfo | null>;
  createSession: (token: string, signal?: AbortSignal) => Promise<SessionInfo>;
  createDeveloperSession: (apiKey: string, signal?: AbortSignal) => Promise<SessionInfo>;
  deleteSession: (signal?: AbortSignal) => Promise<void>;
  listNewAPICallers: (signal?: AbortSignal) => Promise<NewAPIUserList>;
  listAudits: (
    filters?: AuditFilters,
    cursor?: AuditCursor | null,
    signal?: AbortSignal,
  ) => Promise<AuditListPage>;
  getAudit: (auditID: string, signal?: AbortSignal) => Promise<AuditDetail>;
  getRawBody: (auditID: string, side: RawSide, signal?: AbortSignal) => Promise<RawBodyDownload>;
  getReconstructedBody: (auditID: string, side: RawSide, signal?: AbortSignal) => Promise<ReconstructedBodyDownload>;
  getStreamTimeline: (auditID: string, side: RawSide, signal?: AbortSignal) => Promise<StreamTimeline>;
  listUserAgentRules: (signal?: AbortSignal) => Promise<UserAgentRuleList>;
  createUserAgentRule: (input: UserAgentRuleInput, signal?: AbortSignal) => Promise<UserAgentRule>;
  updateUserAgentRule: (id: number, input: UserAgentRuleInput, signal?: AbortSignal) => Promise<UserAgentRule>;
  deleteUserAgentRule: (id: number, signal?: AbortSignal) => Promise<void>;
  listContentPolicyRules: (signal?: AbortSignal) => Promise<ContentPolicyRuleList>;
  createContentPolicyRule: (input: ContentPolicyRuleInput, signal?: AbortSignal) => Promise<ContentPolicyRule>;
  updateContentPolicyRule: (id: number, input: ContentPolicyRuleInput, signal?: AbortSignal) => Promise<ContentPolicyRule>;
  deleteContentPolicyRule: (id: number, signal?: AbortSignal) => Promise<void>;
  getInsightsOverview: (query: OverviewQuery, signal?: AbortSignal) => Promise<OverviewResponse>;
  listInsightsSessions: (query: SessionsQuery, signal?: AbortSignal) => Promise<SessionsResponse>;
  getSessionTrend: (sessionID: string, signal?: AbortSignal) => Promise<TrendResponse>;
  getAgentTree: (treeID: string, signal?: AbortSignal) => Promise<TreeResponse>;
  /** Rejects with ApiError(404) while the audit has not been analyzed yet. */
  getComposition: (auditID: string, signal?: AbortSignal) => Promise<CompositionResponse>;
  // Session analysis (doc/features/24-session-analysis.md).
  getAnalysisOverview: (range: { from_ns: string; to_ns: string }, signal?: AbortSignal, userID?: number) => Promise<AnalysisOverview>;
  /** Administrators only: the session analysis settings in use and where they come from. */
  getAnalysisSettings: (signal?: AbortSignal) => Promise<AnalysisSettingsView>;
  /** Saves settings that override the configuration file from the next run on. */
  saveAnalysisSettings: (update: AnalysisSettingsUpdate, signal?: AbortSignal) => Promise<AnalysisSettingsView>;
  /** Drops the saved settings; the configuration file applies again. */
  resetAnalysisSettings: (signal?: AbortSignal) => Promise<AnalysisSettingsView>;
  /** Validates unsaved settings and sends one synthetic request to the model endpoint. */
  testAnalysisSettings: (update: AnalysisSettingsUpdate, signal?: AbortSignal) => Promise<AnalysisProbeResult>;
  /** Administrators only: the weekly report settings in use and where they come from. */
  getOrgReportSettings: (signal?: AbortSignal) => Promise<OrgSettingsView>;
  /** Saves weekly report settings that override the configuration file at once. */
  saveOrgReportSettings: (update: OrgEditableSettings, signal?: AbortSignal) => Promise<OrgSettingsView>;
  /** Drops the saved weekly report settings; the configuration file applies again. */
  resetOrgReportSettings: (signal?: AbortSignal) => Promise<OrgSettingsView>;
  /** Administrators only: session totals of a period per NewAPI user. */
  listAnalysisUsers: (range: { from_ns: string; to_ns: string }, signal?: AbortSignal) => Promise<AnalysisUsers>;
  listAnalysisSessions: (query: AnalysisSessionsQuery, signal?: AbortSignal) => Promise<AnalysisSessionsPage>;
  /** Administrator only; rejects with ApiError(409) while a run is in progress. */
  triggerAnalysisRun: (signal?: AbortSignal) => Promise<void>;
  /** Every successful read is recorded in the analysis view log. */
  getAnalysisPack: (sessionID: string, signal?: AbortSignal) => Promise<AnalysisPack>;
  /** Every successful read is recorded in the analysis view log. */
  getAnalysisFacet: (sessionID: string, signal?: AbortSignal) => Promise<AnalysisFacet>;
  /** Administrator only. */
  calibrateAnalysis: (labels: AnalysisCalibrationLabel[], signal?: AbortSignal) => Promise<AnalysisCalibration>;
  /** target (administrator, organisation reports) opens one project or group. */
  getAnalysisReport: (week: "current" | "previous", signal?: AbortSignal, target?: AnalysisReportTarget) => Promise<AnalysisReport>;
  /** Administrator only; all-keys and project suggestions. */
  dismissAnalysisSuggestion: (id: number, signal?: AbortSignal) => Promise<void>;
  /** Organisation reports (doc/features/23); every route 404s when disabled. */
  org: OrgApi;
}

export interface OrgApi {
  settings: (signal?: AbortSignal) => Promise<OrgSettings>;
  catalog: (signal?: AbortSignal) => Promise<OrgCatalog>;
  createGroup: (input: OrgGroupInput, signal?: AbortSignal) => Promise<OrgGroup>;
  updateGroup: (id: number, input: OrgGroupInput, signal?: AbortSignal) => Promise<OrgGroup>;
  deleteGroup: (id: number, signal?: AbortSignal) => Promise<void>;
  createProject: (input: OrgProjectInput, signal?: AbortSignal) => Promise<OrgProject>;
  updateProject: (id: number, input: OrgProjectInput, signal?: AbortSignal) => Promise<OrgProject>;
  deleteProject: (id: number, signal?: AbortSignal) => Promise<void>;
  setMember: (userID: number, groupID: number, signal?: AbortSignal) => Promise<OrgMember>;
  deleteMember: (userID: number, signal?: AbortSignal) => Promise<void>;
  setPrincipal: (kind: PrincipalKind, id: number, principalClass: PrincipalClass, signal?: AbortSignal) => Promise<OrgPrincipal>;
  deletePrincipal: (kind: PrincipalKind, id: number, signal?: AbortSignal) => Promise<void>;
  preview: (input: OrgPreviewInput, signal?: AbortSignal) => Promise<OrgPreviewResult>;
  unattributed: (week: string | undefined, limit: number, signal?: AbortSignal) => Promise<{ items: OrgUnattributedEntry[] }>;
  weekly: (query: OrgWeeklyQuery, signal?: AbortSignal) => Promise<OrgWeeklyReport>;
  trend: (weeks: number, groupID: number | undefined, signal?: AbortSignal) => Promise<OrgTrendReport>;
  projectWeekly: (projectID: number, week: string | undefined, signal?: AbortSignal) => Promise<OrgProjectReport>;
  regenerate: (week: string, signal?: AbortSignal) => Promise<void>;
  self: (signal?: AbortSignal) => Promise<OrgSelfReport>;
}

export function createApiClient(
  onUnauthorized: () => void,
  fetchImpl: FetchLike = fetch,
): ApiClient {
  async function sessionFetch(path: string, init: RequestInit = {}, notifyUnauthorized = true): Promise<Response> {
    const headers = new Headers(init.headers);
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    const response = await fetchImpl(path, { ...init, credentials: "same-origin", headers });
    if (notifyUnauthorized && response.status === 401) {
      onUnauthorized();
      throw new ApiError(401, "管理令牌无效或已失效，请重新输入。");
    }
    return response;
  }

  async function requestJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
    const response = await sessionFetch(path, { signal });
    if (!response.ok) {
      throw await responseError(response);
    }
    return (await response.json()) as T;
  }

  async function mutateJSON<T>(path: string, method: string, body: unknown, signal?: AbortSignal): Promise<T> {
    const response = await sessionFetch(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
    if (!response.ok) {
      throw await responseError(response);
    }
    return (await response.json()) as T;
  }

  async function deleteResource(path: string, signal?: AbortSignal): Promise<void> {
    const response = await sessionFetch(path, { method: "DELETE", signal });
    if (!response.ok) {
      throw await responseError(response);
    }
  }

  const orgBase = `${API_BASE}/org`;
  const id = (value: number) => encodeURIComponent(String(value));
  const org: OrgApi = {
    settings: (signal) => requestJSON<OrgSettings>(`${orgBase}/settings`, signal),
    catalog: (signal) => requestJSON<OrgCatalog>(`${orgBase}/catalog`, signal),
    createGroup: (input, signal) => mutateJSON<OrgGroup>(`${orgBase}/groups`, "POST", input, signal),
    updateGroup: (groupID, input, signal) => mutateJSON<OrgGroup>(`${orgBase}/groups/${id(groupID)}`, "PUT", input, signal),
    deleteGroup: (groupID, signal) => deleteResource(`${orgBase}/groups/${id(groupID)}`, signal),
    createProject: (input, signal) => mutateJSON<OrgProject>(`${orgBase}/projects`, "POST", input, signal),
    updateProject: (projectID, input, signal) => mutateJSON<OrgProject>(`${orgBase}/projects/${id(projectID)}`, "PUT", input, signal),
    deleteProject: (projectID, signal) => deleteResource(`${orgBase}/projects/${id(projectID)}`, signal),
    setMember: (userID, groupID, signal) => mutateJSON<OrgMember>(`${orgBase}/members/${id(userID)}`, "PUT", { group_id: groupID }, signal),
    deleteMember: (userID, signal) => deleteResource(`${orgBase}/members/${id(userID)}`, signal),
    setPrincipal: (kind, principalID, principalClass, signal) =>
      mutateJSON<OrgPrincipal>(`${orgBase}/principals/${kind}/${id(principalID)}`, "PUT", { class: principalClass }, signal),
    deletePrincipal: (kind, principalID, signal) => deleteResource(`${orgBase}/principals/${kind}/${id(principalID)}`, signal),
    preview: (input, signal) => mutateJSON<OrgPreviewResult>(`${orgBase}/projects/preview`, "POST", input, signal),
    unattributed: (week, limit, signal) => {
      const params = new URLSearchParams({ limit: String(limit) });
      if (week) {
        params.set("week", week);
      }
      return requestJSON<{ items: OrgUnattributedEntry[] }>(`${orgBase}/unattributed?${params}`, signal);
    },
    weekly: (query, signal) => {
      const params = new URLSearchParams();
      if (query.week) {
        params.set("week", query.week);
      }
      if (query.group_id !== undefined) {
        params.set("group_id", String(query.group_id));
      }
      if (query.metric) {
        params.set("metric", query.metric);
      }
      const suffix = params.size > 0 ? `?${params}` : "";
      return requestJSON<OrgWeeklyReport>(`${orgBase}/weekly${suffix}`, signal);
    },
    trend: (weeks, groupID, signal) => {
      const params = new URLSearchParams({ weeks: String(weeks) });
      if (groupID !== undefined) {
        params.set("group_id", String(groupID));
      }
      return requestJSON<OrgTrendReport>(`${orgBase}/weekly/trend?${params}`, signal);
    },
    projectWeekly: (projectID, week, signal) =>
      requestJSON<OrgProjectReport>(`${orgBase}/projects/${id(projectID)}/weekly${week ? `?week=${encodeURIComponent(week)}` : ""}`, signal),
    regenerate: async (week, signal) => {
      const response = await sessionFetch(`${orgBase}/weekly/regenerate?week=${encodeURIComponent(week)}`, { method: "POST", signal });
      if (!response.ok) {
        throw await responseError(response);
      }
    },
    self: (signal) => requestJSON<OrgSelfReport>(`${orgBase}/me/weekly`, signal),
  };

  async function login(credentials: Record<string, string>, signal?: AbortSignal): Promise<SessionInfo> {
    const response = await sessionFetch(
      `${API_BASE}/session`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
        signal,
      },
      false,
    );
    if (!response.ok) {
      throw await responseError(response);
    }
    return (await response.json()) as SessionInfo;
  }

  return {
    org,
    // Returns null rather than throwing when nobody is signed in: an anonymous
    // visitor is an expected state during start-up, not an error.
    async getSession(signal) {
      const response = await sessionFetch(`${API_BASE}/session`, { signal }, false);
      if (response.status === 401) {
        return null;
      }
      if (!response.ok) {
        throw await responseError(response);
      }
      return (await response.json()) as SessionInfo;
    },

    createSession(token, signal) {
      return login({ token }, signal);
    },

    createDeveloperSession(apiKey, signal) {
      return login({ api_key: apiKey }, signal);
    },

    async deleteSession(signal) {
      const response = await sessionFetch(`${API_BASE}/session`, { method: "DELETE", signal }, false);
      if (!response.ok && response.status !== 401) {
        throw await responseError(response);
      }
    },

    listNewAPICallers(signal) {
      return requestJSON<NewAPIUserList>(`${API_BASE}/newapi/callers`, signal);
    },

    listUserAgentRules(signal) {
      return requestJSON<UserAgentRuleList>(`${API_BASE}/user-agent-rules`, signal);
    },

    createUserAgentRule(input, signal) {
      return mutateJSON<UserAgentRule>(`${API_BASE}/user-agent-rules`, "POST", input, signal);
    },

    updateUserAgentRule(id, input, signal) {
      return mutateJSON<UserAgentRule>(`${API_BASE}/user-agent-rules/${encodeURIComponent(String(id))}`, "PUT", input, signal);
    },

    async deleteUserAgentRule(id, signal) {
      const response = await sessionFetch(
        `${API_BASE}/user-agent-rules/${encodeURIComponent(String(id))}`,
        { method: "DELETE", signal },
      );
      if (!response.ok) {
        throw await responseError(response);
      }
    },

    listContentPolicyRules(signal) {
      return requestJSON<ContentPolicyRuleList>(`${API_BASE}/content-policy-rules`, signal);
    },

    createContentPolicyRule(input, signal) {
      return mutateJSON<ContentPolicyRule>(`${API_BASE}/content-policy-rules`, "POST", input, signal);
    },

    updateContentPolicyRule(id, input, signal) {
      return mutateJSON<ContentPolicyRule>(`${API_BASE}/content-policy-rules/${encodeURIComponent(String(id))}`, "PUT", input, signal);
    },

    async deleteContentPolicyRule(id, signal) {
      const response = await sessionFetch(
        `${API_BASE}/content-policy-rules/${encodeURIComponent(String(id))}`,
        { method: "DELETE", signal },
      );
      if (!response.ok) {
        throw await responseError(response);
      }
    },

    async listAudits(filters = {}, cursor = null, signal) {
      const query = new URLSearchParams({ limit: "50" });
      if (filters.path?.trim()) {
        query.set("path", filters.path.trim());
      }
      if (filters.model?.trim()) {
        query.set("model", filters.model.trim());
      }
      if (filters.user_agent?.trim()) {
        query.set("user_agent", filters.user_agent.trim());
      }
      if (filters.newapi_user_id?.trim()) {
		query.set("newapi_user_id", filters.newapi_user_id.trim());
	  }
      if (filters.newapi_token_id?.trim()) {
        query.set("newapi_token_id", filters.newapi_token_id.trim());
      }
      if (filters.forward_status) {
        query.set("forward_status", filters.forward_status);
      }
      if (filters.status_class) {
        query.set("status_class", filters.status_class);
      }
      if (filters.status_code?.trim()) {
        query.set("status_code", filters.status_code.trim());
      }
      if (filters.upstream_error_class?.trim()) {
        query.set("upstream_error_class", filters.upstream_error_class.trim());
      }
      if (filters.conversation?.trim()) {
        query.set("conversation", filters.conversation.trim());
      } else if (filters.collapse && !hasRowFilters(filters)) {
        query.set("collapse", "conversation");
      }
      if (cursor) {
        query.set("before_started_at_ns", String(cursor.before_started_at_ns));
        query.set("before_id", cursor.before_id);
      }
      return requestJSON<AuditListPage>(`${API_BASE}/audits?${query}`, signal);
    },

    getAudit(auditID, signal) {
      return requestJSON<AuditDetail>(`${API_BASE}/audits/${encodeURIComponent(auditID)}`, signal);
    },

    async getRawBody(auditID, side, signal) {
      const response = await sessionFetch(
        `${API_BASE}/audits/${encodeURIComponent(auditID)}/raw/${side}`,
        { headers: { Accept: "application/octet-stream" }, signal },
      );
      if (!response.ok) {
        throw await responseError(response);
      }

      return {
        blob: await response.blob(),
        filename: filenameFromResponse(response, `${auditID}-${side}.bin`),
        contentType: response.headers.get("Content-Type") ?? "application/octet-stream",
        observedLength: response.headers.get("X-Audit-Observed-Length"),
        storedLength: response.headers.get("X-Audit-Stored-Length"),
        sha256: response.headers.get("X-Audit-SHA256"),
        complete: response.headers.get("X-Audit-Complete")?.toLowerCase() === "true",
        missingChunks: response.headers.get("X-Audit-Missing-Chunks")?.toLowerCase() === "true",
      };
    },

    async getReconstructedBody(auditID, side, signal) {
      const response = await sessionFetch(
        `${API_BASE}/audits/${encodeURIComponent(auditID)}/reconstructed/${side}`,
        { headers: { Accept: "application/json" }, signal },
      );
      if (!response.ok) {
        throw await responseError(response);
      }
      return {
        blob: await response.blob(),
        filename: filenameFromResponse(response, `${auditID}-reconstructed-${side}.json`),
        contentType: response.headers.get("Content-Type") ?? "application/json",
      };
    },

    // The insights payloads come from Go structs, where an empty slice can be
    // serialized as null; normalize so callers can map without guards.
    async getInsightsOverview(query, signal) {
      const params = new URLSearchParams({
        from_ns: query.from_ns,
        to_ns: query.to_ns,
        tz_offset_min: String(query.tz_offset_min),
        group_by: query.group_by,
      });
      const result = await requestJSON<OverviewResponse>(`${API_BASE}/insights/overview?${params}`, signal);
      return { ...result, daily: result.daily ?? [], heatmap: result.heatmap ?? [], groups: result.groups ?? [] };
    },

    async listInsightsSessions(query, signal) {
      const params = new URLSearchParams();
      if (query.from_ns) {
        params.set("from_ns", query.from_ns);
      }
      if (query.to_ns) {
        params.set("to_ns", query.to_ns);
      }
      params.set("sort", query.sort ?? "recent");
      params.set("limit", String(query.limit ?? 20));
      if (query.cursor) {
        params.set("cursor", query.cursor);
      }
      const result = await requestJSON<SessionsResponse>(`${API_BASE}/insights/sessions?${params}`, signal);
      return { ...result, items: (result.items ?? []).map((item) => ({ ...item, models: item.models ?? [] })) };
    },

    async getSessionTrend(sessionID, signal) {
      const result = await requestJSON<TrendResponse>(
        `${API_BASE}/insights/sessions/${encodeURIComponent(sessionID)}/trend`,
        signal,
      );
      return {
        ...result,
        steps: (result.steps ?? []).map((step) => ({
          ...step,
          events: step.events ?? [],
          response_kinds: step.response_kinds ?? [],
        })),
      };
    },

    async getAgentTree(treeID, signal) {
      const result = await requestJSON<TreeResponse>(
        `${API_BASE}/insights/agent-trees/${encodeURIComponent(treeID)}`,
        signal,
      );
      return { ...result, nodes: result.nodes ?? [] };
    },

    async getComposition(auditID, signal) {
      const result = await requestJSON<CompositionResponse>(
        `${API_BASE}/audits/${encodeURIComponent(auditID)}/composition`,
        signal,
      );
      return {
        ...result,
        items: result.items ?? [],
        tools: result.tools ?? [],
        file_ops: result.file_ops ?? [],
        events: result.events ?? [],
      };
    },

    async getAnalysisOverview(range, signal, userID) {
      const params = new URLSearchParams({ from_ns: range.from_ns, to_ns: range.to_ns });
      if (userID) {
        params.set("user_id", String(userID));
      }
      const result = await requestJSON<AnalysisOverview>(`${API_BASE}/session-analysis/overview?${params}`, signal);
      if (result.last_run) {
        result.last_run.skip_reasons = result.last_run.skip_reasons ?? {};
      }
      return result;
    },

    async listAnalysisUsers(range, signal) {
      const params = new URLSearchParams({ from_ns: range.from_ns, to_ns: range.to_ns });
      const result = await requestJSON<AnalysisUsers>(`${API_BASE}/session-analysis/users?${params}`, signal);
      return { ...result, items: result.items ?? [] };
    },

    async listAnalysisSessions(query, signal) {
      const params = new URLSearchParams({ from_ns: query.from_ns, to_ns: query.to_ns, limit: String(query.limit ?? 50) });
      if (query.kind) {
        params.set("kind", query.kind);
      }
      if (query.flags && query.flags.length > 0) {
        params.set("flags", query.flags.join(","));
      }
      if (query.cursor) {
        params.set("cursor", query.cursor);
      }
      if (query.user_id) {
        params.set("user_id", String(query.user_id));
      }
      const result = await requestJSON<AnalysisSessionsPage>(`${API_BASE}/session-analysis/sessions?${params}`, signal);
      return {
        ...result,
        items: (result.items ?? []).map((item) => ({ ...item, danger: item.danger ?? {}, secrets: item.secrets ?? {} })),
      };
    },

    async getAnalysisPack(sessionID, signal) {
      const result = await requestJSON<AnalysisPack>(
        `${API_BASE}/session-analysis/sessions/${encodeURIComponent(sessionID)}/pack`,
        signal,
      );
      return { ...result, refs: result.refs ?? {} };
    },

    async getAnalysisFacet(sessionID, signal) {
      const result = await requestJSON<AnalysisFacet>(
        `${API_BASE}/session-analysis/sessions/${encodeURIComponent(sessionID)}/facet`,
        signal,
      );
      return {
        ...result,
        friction: result.friction ?? [],
        items: result.items ?? [],
        invalid_fields: result.invalid_fields ?? [],
        instructions: result.instructions ?? [],
        evidence: result.evidence ?? {},
        hidden_fields: result.hidden_fields ?? [],
      };
    },

    async calibrateAnalysis(labels, signal) {
      const result = await mutateJSON<AnalysisCalibration>(`${API_BASE}/session-analysis/calibration`, "POST", { labels }, signal);
      return { ...result, hidden_fields: result.hidden_fields ?? [], agreement: result.agreement ?? {}, compared: result.compared ?? {} };
    },

    async getAnalysisReport(week, signal, target) {
      const params = new URLSearchParams({ week });
      if (target?.project_id) {
        params.set("project_id", String(target.project_id));
      } else if (target?.group_id) {
        params.set("group_id", String(target.group_id));
      } else if (target?.user_id) {
        params.set("user_id", String(target.user_id));
      }
      const result = await requestJSON<AnalysisReport>(`${API_BASE}/session-analysis/report?${params}`, signal);
      return {
        ...result,
        projects: result.projects ?? [],
        groups: result.groups ?? [],
        users: result.users ?? [],
        suggestions: (result.suggestions ?? []).map((item) => ({ ...item, evidence: item.evidence ?? [] })),
        optimizations: (result.optimizations ?? []).map((item) => ({ ...item, danger: item.danger ?? {}, secrets: item.secrets ?? {} })),
      };
    },

    getAnalysisSettings(signal) {
      return requestJSON<AnalysisSettingsView>(`${API_BASE}/settings/session-analysis`, signal);
    },

    saveAnalysisSettings(update, signal) {
      return mutateJSON<AnalysisSettingsView>(`${API_BASE}/settings/session-analysis`, "PUT", update, signal);
    },

    async resetAnalysisSettings(signal) {
      const response = await sessionFetch(`${API_BASE}/settings/session-analysis`, { method: "DELETE", signal });
      if (!response.ok) {
        throw await responseError(response);
      }
      return (await response.json()) as AnalysisSettingsView;
    },

    testAnalysisSettings(update, signal) {
      return mutateJSON<AnalysisProbeResult>(`${API_BASE}/settings/session-analysis/test`, "POST", update, signal);
    },

    async getOrgReportSettings(signal) {
      return withClients(await requestJSON<OrgSettingsView>(`${API_BASE}/settings/org-reports`, signal));
    },

    async saveOrgReportSettings(update, signal) {
      return withClients(await mutateJSON<OrgSettingsView>(`${API_BASE}/settings/org-reports`, "PUT", update, signal));
    },

    async resetOrgReportSettings(signal) {
      const response = await sessionFetch(`${API_BASE}/settings/org-reports`, { method: "DELETE", signal });
      if (!response.ok) {
        throw await responseError(response);
      }
      return withClients((await response.json()) as OrgSettingsView);
    },

    async dismissAnalysisSuggestion(id, signal) {
      const response = await sessionFetch(`${API_BASE}/session-analysis/suggestions/${id}/dismiss`, { method: "POST", signal });
      if (!response.ok) {
        throw await responseError(response);
      }
    },

    async triggerAnalysisRun(signal) {
      const response = await sessionFetch(`${API_BASE}/session-analysis/run`, { method: "POST", signal });
      if (!response.ok) {
        throw await responseError(response);
      }
    },

    getStreamTimeline(auditID, side, signal) {
      return requestJSON<StreamTimeline>(
        `${API_BASE}/audits/${encodeURIComponent(auditID)}/timeline/${side}`,
        signal,
      );
    },
  };
}

async function responseError(response: Response): Promise<ApiError> {
  let message = `管理 API 返回 ${response.status}`;
  const contentType = response.headers.get("Content-Type") ?? "";

  try {
    if (contentType.includes("application/json")) {
      const body = (await response.json()) as {
        message?: unknown;
        error?: { message?: unknown } | unknown;
      };
      const nestedMessage =
        typeof body.error === "object" && body.error !== null && "message" in body.error
          ? body.error.message
          : undefined;
      if (typeof nestedMessage === "string" && nestedMessage.trim()) {
        message = nestedMessage;
      } else if (typeof body.message === "string" && body.message.trim()) {
        message = body.message;
      }
    }
  } catch {
    // Keep the stable status-only fallback. Server response bodies can be
    // truncated, and this UI must not surface arbitrary internal errors.
  }

  return new ApiError(response.status, message);
}

function filenameFromResponse(response: Response, fallback: string): string {
  const disposition = response.headers.get("Content-Disposition");
  const match = disposition?.match(/filename="?([^";]+)"?/i);
  return match?.[1] || fallback;
}
