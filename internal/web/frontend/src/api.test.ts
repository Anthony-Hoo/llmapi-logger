import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

describe("API client", () => {
  it("adds the bearer token and list limit without persisting it", async () => {
    let calledURL = "";
    let calledInit: RequestInit | undefined;
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calledURL = String(input);
      calledInit = init;
      return new Response(JSON.stringify({ items: [], next_cursor: null }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    const client = createApiClient("memory-only-token", vi.fn(), fetcher);

    await client.listAudits({ path: "/v1/messages", forward_status: "rejected" });

    expect(calledURL).toContain("limit=50");
    expect(calledURL).toContain("path=%2Fv1%2Fmessages");
    expect(calledURL).toContain("forward_status=rejected");
    expect(new Headers(calledInit?.headers).get("Authorization")).toBe("Bearer memory-only-token");
  });

  it("clears authentication through the shared 401 callback", async () => {
    const unauthorized = vi.fn();
    const fetcher = vi.fn(async () => new Response(null, { status: 401 }));
    const client = createApiClient("expired", unauthorized, fetcher as typeof fetch);

    try {
      await client.getAudit("apx_test");
      throw new Error("expected getAudit to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).status).toBe(401);
    }
    expect(unauthorized).toHaveBeenCalledOnce();
  });
});
