import type {
  AuditCursor,
  AuditDetail,
  AuditFilters,
  AuditListPage,
  NewAPIUserList,
  RawBodyDownload,
  RawSide,
  ReconstructedBodyDownload,
  SessionInfo,
  StreamTimeline,
  UserAgentRule,
  UserAgentRuleInput,
  UserAgentRuleList,
} from "./types";

const API_BASE = "/api/v1";

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
