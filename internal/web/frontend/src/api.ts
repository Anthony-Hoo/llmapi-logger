import type {
  AuditCursor,
  AuditDetail,
  AuditFilters,
  AuditListPage,
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
  listAudits: (
    filters?: AuditFilters,
    cursor?: AuditCursor | null,
    signal?: AbortSignal,
  ) => Promise<AuditListPage>;
  getAudit: (auditID: string, signal?: AbortSignal) => Promise<AuditDetail>;
  getRawBody: (auditID: string, side: RawSide, signal?: AbortSignal) => Promise<RawBodyDownload>;
}

export function createApiClient(
  token: string,
  onUnauthorized: () => void,
  fetchImpl: FetchLike = fetch,
): ApiClient {
  async function authorizedFetch(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    const response = await fetchImpl(path, { ...init, headers });
    if (response.status === 401) {
      onUnauthorized();
      throw new ApiError(401, "管理令牌无效或已失效，请重新输入。");
    }
    return response;
  }

  async function requestJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
    const response = await authorizedFetch(path, { signal });
    if (!response.ok) {
      throw await responseError(response);
    }
    return (await response.json()) as T;
  }

  return {
    async listAudits(filters = {}, cursor = null, signal) {
      const query = new URLSearchParams({ limit: "50" });
      if (filters.path?.trim()) {
        query.set("path", filters.path.trim());
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
      const response = await authorizedFetch(
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
