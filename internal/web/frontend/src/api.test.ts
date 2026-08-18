import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("API client", () => {
  it("uses the Cookie session and sends all supported list filters", async () => {
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
    const client = createApiClient(vi.fn(), fetcher);

    await client.listAudits({
      path: "/v1/messages",
      model: "gpt-test",
	  user_agent: "audit-client/1.0",
	  newapi_user_id: "7",
	  newapi_token_id: "42",
      forward_status: "rejected",
    });

    expect(calledURL).toContain("limit=50");
    expect(calledURL).toContain("path=%2Fv1%2Fmessages");
    expect(calledURL).toContain("model=gpt-test");
	expect(calledURL).toContain("user_agent=audit-client%2F1.0");
	expect(calledURL).toContain("newapi_user_id=7");
    expect(calledURL).toContain("newapi_token_id=42");
    expect(calledURL).toContain("forward_status=rejected");
    expect(calledInit?.credentials).toBe("same-origin");
    expect(new Headers(calledInit?.headers).has("Authorization")).toBe(false);
  });

  it("loads the safe NewAPI caller catalog through the Cookie session", async () => {
    let calledURL = "";
    const fetcher = (async (input: RequestInfo | URL) => {
      calledURL = String(input);
      return new Response(JSON.stringify({ items: [], refreshed_at: null }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);

	await expect(client.listNewAPICallers()).resolves.toEqual({ items: [], refreshed_at: null });
	expect(calledURL).toBe("/api/v1/newapi/callers");
  });

  it("downloads reconstructed JSON and reads a verified stream timeline", async () => {
    const calls: string[] = [];
    const fetcher = (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/timeline/response")) {
        return new Response(JSON.stringify({
          stage: "response_received_from_newapi",
          observed_length: 100,
          event_count: 2,
          first_event_at_ns: "10",
          last_event_at_ns: "20",
          complete: true,
          points: [{ offset: 40, at_ns: "10" }, { offset: 100, at_ns: "20" }],
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ model: "model-example" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);

    const reconstructed = await client.getReconstructedBody("audit-example", "request");
    const timeline = await client.getStreamTimeline("audit-example", "response");

    expect(calls).toEqual([
      "/api/v1/audits/audit-example/reconstructed/request",
      "/api/v1/audits/audit-example/timeline/response",
    ]);
    expect(reconstructed.filename).toBe("audit-example-reconstructed-request.json");
    expect(await reconstructed.blob.text()).toContain("model-example");
    expect(timeline.event_count).toBe(2);
    expect(timeline.points).toHaveLength(2);
  });

  it("manages authenticated User-Agent rules without Authorization headers", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (init?.method === "DELETE") {
        return new Response(null, { status: 204 });
      }
      if (!init?.method || init.method === "GET") {
        return new Response(JSON.stringify({ items: [] }), {
          status: 200, headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ id: 1, name: "rule" }), {
        status: init.method === "POST" ? 201 : 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);
    const input = { name: "rule", enabled: true, model_pattern: "^gpt", user_agent_pattern: "Desktop" };

    await client.listUserAgentRules();
    await client.createUserAgentRule(input);
    await client.updateUserAgentRule(1, { ...input, enabled: false });
    await client.deleteUserAgentRule(1);

    expect(calls.map((call) => [call.url, call.init?.method ?? "GET"])).toEqual([
      ["/api/v1/user-agent-rules", "GET"],
      ["/api/v1/user-agent-rules", "POST"],
      ["/api/v1/user-agent-rules/1", "PUT"],
      ["/api/v1/user-agent-rules/1", "DELETE"],
    ]);
    for (const call of calls) {
      expect(call.init?.credentials).toBe("same-origin");
      expect(new Headers(call.init?.headers).has("Authorization")).toBe(false);
    }
  });

  it("creates a session with a one-shot token POST and no Authorization Header", async () => {
    let calledURL = "";
    let calledInit: RequestInit | undefined;
    const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calledURL = String(input);
      calledInit = init;
      return jsonResponse({ status: "authenticated", role: "admin", expires_at: "2026-08-18T00:00:00Z" });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);

    const session = await client.createSession("one-shot-admin-token");

    expect(calledURL).toBe("/api/v1/session");
    expect(calledInit?.method).toBe("POST");
    expect(calledInit?.credentials).toBe("same-origin");
    expect(new Headers(calledInit?.headers).get("Content-Type")).toBe("application/json");
    expect(new Headers(calledInit?.headers).has("Authorization")).toBe(false);
    expect(JSON.parse(String(calledInit?.body))).toEqual({ token: "one-shot-admin-token" });
    expect(session.role).toBe("admin");
  });

  it("signs a developer in with their API key and never sends it as a Header", async () => {
    let calledInit: RequestInit | undefined;
    const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      calledInit = init;
      return jsonResponse({
        status: "authenticated",
        role: "developer",
        expires_at: "2026-08-18T00:00:00Z",
        identity: { user_id: 7, username: "developer", token_id: 42, token_name: "agent-token" },
      });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);

    const session = await client.createDeveloperSession("sk-test-developer-key");

    expect(calledInit?.method).toBe("POST");
    expect(new Headers(calledInit?.headers).has("Authorization")).toBe(false);
    expect(JSON.parse(String(calledInit?.body))).toEqual({ api_key: "sk-test-developer-key" });
    expect(session.role).toBe("developer");
    expect(session.identity?.token_name).toBe("agent-token");
  });

  it("reports an anonymous visitor as no session instead of an error", async () => {
    const anonymous = createApiClient(
      vi.fn(),
      (async () => new Response(null, { status: 401 })) as typeof fetch,
    );
    await expect(anonymous.getSession()).resolves.toBeNull();

    const unauthorized = vi.fn();
    const signedIn = createApiClient(
      unauthorized,
      (async () => jsonResponse({ status: "authenticated", role: "developer" })) as typeof fetch,
    );
    const session = await signedIn.getSession();
    expect(session?.role).toBe("developer");
    // Bootstrapping must not trip the shared 401 handler, which would bounce a
    // visitor who simply has not signed in yet.
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it("deletes the Cookie session", async () => {
    let calledInit: RequestInit | undefined;
    const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      calledInit = init;
      return new Response(null, { status: 204 });
    }) as typeof fetch;
    const client = createApiClient(vi.fn(), fetcher);

    await client.deleteSession();

    expect(calledInit?.method).toBe("DELETE");
    expect(calledInit?.credentials).toBe("same-origin");
  });

  it("clears authentication through the shared 401 callback", async () => {
    const unauthorized = vi.fn();
    const fetcher = vi.fn(async () => new Response(null, { status: 401 }));
    const client = createApiClient(unauthorized, fetcher as typeof fetch);

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
