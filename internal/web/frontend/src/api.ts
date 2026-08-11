import type {
  AuditCursor,
  AuditDetail,
  AuditFilters,
  AuditListPage,
  NewAPITokenList,
  RawBodyDownload,
  RawSide,
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
  createSession: (token: string, signal?: AbortSignal) => Promise<void>;
  deleteSession: (signal?: AbortSignal) => Promise<void>;
  listNewAPITokens: (signal?: AbortSignal) => Promise<NewAPITokenList>;
  listAudits: (
    filters?: AuditFilters,
    cursor?: AuditCursor | null,
    signal?: AbortSignal,
  ) => Promise<AuditListPage>;
  getAudit: (auditID: string, signal?: AbortSignal) => Promise<AuditDetail>;
  getRawBody: (auditID: string, side: RawSide, signal?: AbortSignal) => Promise<RawBodyDownload>;
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

  return {
    async createSession(token, signal) {
      const response = await sessionFetch(
        `${API_BASE}/session`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
          signal,
        },
        false,
      );
      if (!response.ok) {
        throw await responseError(response);
      }
    },

    async deleteSession(signal) {
      const response = await sessionFetch(`${API_BASE}/session`, { method: "DELETE", signal }, false);
      if (!response.ok && response.status !== 401) {
        throw await responseError(response);
      }
    },

    listNewAPITokens(signal) {
      return requestJSON<NewAPITokenList>(`${API_BASE}/newapi/tokens`, signal);
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
