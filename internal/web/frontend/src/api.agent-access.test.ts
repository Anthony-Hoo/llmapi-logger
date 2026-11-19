import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("agent access API client", () => {
  it("sends the exact paths, methods and bodies", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_url, init) => (init?.method === "DELETE" ? new Response(null, { status: 204 }) : jsonResponse({ items: null })));
    const client = createApiClient(vi.fn(), fetcher);
    const authorization = {
      challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      mode: "loopback" as const,
      port: 53123,
      device_name: "laptop",
      cli_version: "0.1.0",
      tier: "read" as const,
      decision: "approve" as const,
    };
    await client.agentAccess.authorize(authorization);
    expect((await client.agentAccess.listTokens()).items).toEqual([]);
    await client.agentAccess.revokeToken(7);
    await client.agentAccess.createInstallLink({ agent: "other", platform: "linux-arm64", skills_dir: "/home/me/skills" });
    expect((await client.agentAccess.listChanges()).items).toEqual([]);
    await client.agentAccess.listChanges(200);

    const calls = fetcher.mock.calls.map(([url, init]) => [String(url), init?.method ?? "GET", init?.body]);
    expect(calls).toEqual([
      ["/api/v1/agent-access/authorizations", "POST", JSON.stringify(authorization)],
      ["/api/v1/agent-access/tokens", "GET", undefined],
      ["/api/v1/agent-access/tokens/7", "DELETE", undefined],
      ["/api/v1/agent-access/install-links", "POST", JSON.stringify({ agent: "other", platform: "linux-arm64", skills_dir: "/home/me/skills" })],
      ["/api/v1/agent-access/changes?limit=50", "GET", undefined],
      ["/api/v1/agent-access/changes?limit=200", "GET", undefined],
    ]);
    const headers = new Headers(fetcher.mock.calls[0][1]?.headers);
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(fetcher.mock.calls[0][1]?.credentials).toBe("same-origin");
  });

  it("surfaces the server's error message", async () => {
    const client = createApiClient(vi.fn(), vi.fn<typeof fetch>(async () => jsonResponse({ error: { code: "invalid_argument", message: "tier not allowed" } }, 400)));
    const failure = client.agentAccess.authorize({ challenge: "x", mode: "paste", device_name: "", cli_version: "", tier: "write", decision: "approve" });
    await expect(failure).rejects.toBeInstanceOf(ApiError);
    await expect(failure).rejects.toThrow("tier not allowed");
  });

  it("returns the user to the sign-in page on 401", async () => {
    const onUnauthorized = vi.fn();
    const client = createApiClient(onUnauthorized, vi.fn<typeof fetch>(async () => jsonResponse({ error: { code: "unauthorized", message: "no" } }, 401)));
    await expect(client.agentAccess.listTokens()).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });
});
