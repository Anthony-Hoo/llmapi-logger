import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("org API client", () => {
  it("builds report URLs and only sends set parameters", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({}));
    const client = createApiClient(vi.fn(), fetcher);
    await client.org.weekly({});
    await client.org.weekly({ week: "2026-11-02", group_id: 0, metric: "cost" });
    await client.org.trend(8, 3);
    await client.org.projectWeekly(-1, "2026-11-02");
    await client.org.self();
    await client.org.unattributed(undefined, 20);
    const urls = fetcher.mock.calls.map(([url]) => String(url));
    expect(urls).toEqual([
      "/api/v1/org/weekly",
      "/api/v1/org/weekly?week=2026-11-02&group_id=0&metric=cost",
      "/api/v1/org/weekly/trend?weeks=8&group_id=3",
      "/api/v1/org/projects/-1/weekly?week=2026-11-02",
      "/api/v1/org/me/weekly",
      "/api/v1/org/unattributed?limit=20",
    ]);
  });

  it("sends catalog mutations as JSON and treats 204 deletes as success", async () => {
    const fetcher = vi.fn<typeof fetch>(async (_url, init) =>
      init?.method === "DELETE" || init?.method === "POST" && String(_url).includes("regenerate") ? new Response(null, { status: 204 }) : jsonResponse({ id: 1 }),
    );
    const client = createApiClient(vi.fn(), fetcher);
    await client.org.createProject({ name: "Core", group_id: null, enabled: true, rules: [{ kind: "repo_name", pattern: "core" }] });
    await client.org.setMember(7, 2);
    await client.org.setPrincipal("token", 70, "service");
    await client.org.deleteGroup(3);
    await client.org.regenerate("2026-11-02");
    const calls = fetcher.mock.calls.map(([url, init]) => [String(url), init?.method, init?.body]);
    expect(calls).toEqual([
      ["/api/v1/org/projects", "POST", JSON.stringify({ name: "Core", group_id: null, enabled: true, rules: [{ kind: "repo_name", pattern: "core" }] })],
      ["/api/v1/org/members/7", "PUT", JSON.stringify({ group_id: 2 })],
      ["/api/v1/org/principals/token/70", "PUT", JSON.stringify({ class: "service" })],
      ["/api/v1/org/groups/3", "DELETE", undefined],
      ["/api/v1/org/weekly/regenerate?week=2026-11-02", "POST", undefined],
    ]);
  });

  it("surfaces a disabled feature as ApiError(404)", async () => {
    const client = createApiClient(vi.fn(), vi.fn<typeof fetch>(async () => jsonResponse({ error: { code: "not_found", message: "organisation reports are not enabled" } }, 404)));
    await expect(client.org.settings()).rejects.toBeInstanceOf(ApiError);
  });
});
