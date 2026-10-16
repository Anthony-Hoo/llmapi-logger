import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "./api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("insights API client", () => {
  it("sends the overview range, timezone offset and grouping", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      jsonResponse({ totals: {}, daily: null, heatmap: null, groups: null, composition: {} }),
    );
    const client = createApiClient(vi.fn(), fetcher);

    const overview = await client.getInsightsOverview({
      from_ns: "1760000000000000000",
      to_ns: "1760086400000000000",
      tz_offset_min: 480,
      group_by: "client",
    });

    const [url, init] = fetcher.mock.calls[0];
    expect(String(url)).toBe(
      "/api/v1/insights/overview?from_ns=1760000000000000000&to_ns=1760086400000000000&tz_offset_min=480&group_by=client",
    );
    expect(init?.credentials).toBe("same-origin");
    // Go nil slices arrive as null; callers must be able to map them.
    expect(overview.daily).toEqual([]);
    expect(overview.heatmap).toEqual([]);
    expect(overview.groups).toEqual([]);
  });

  it("pages sessions with a keyset cursor", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ items: [{ session_id: "ses_a", models: null }], next_cursor: "c2" }));
    const client = createApiClient(vi.fn(), fetcher);

    const page = await client.listInsightsSessions({ from_ns: "1", to_ns: "2", sort: "context", limit: 10, cursor: "c1" });

    const url = String(fetcher.mock.calls[0][0]);
    expect(url).toContain("/api/v1/insights/sessions?");
    expect(url).toContain("sort=context");
    expect(url).toContain("limit=10");
    expect(url).toContain("cursor=c1");
    expect(page.next_cursor).toBe("c2");
    expect(page.items[0].models).toEqual([]);
  });

  it("encodes ids and normalizes trend, tree and composition payloads", async () => {
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.includes("/trend")) {
        return jsonResponse({ session_id: "ses_a/b", steps: [{ audit_id: "a", events: null, response_kinds: null }], truncated: false });
      }
      if (url.includes("/agent-trees/")) {
        return jsonResponse({ tree_id: "t", nodes: null, truncated: false });
      }
      return jsonResponse({ audit_id: "a", items: null, tools: null, file_ops: null, events: null });
    });
    const client = createApiClient(vi.fn(), fetcher);

    const trend = await client.getSessionTrend("ses_a/b");
    expect(String(fetcher.mock.calls[0][0])).toBe("/api/v1/insights/sessions/ses_a%2Fb/trend");
    expect(trend.steps[0].events).toEqual([]);
    expect(trend.steps[0].response_kinds).toEqual([]);

    expect((await client.getAgentTree("t")).nodes).toEqual([]);
    expect(String(fetcher.mock.calls[1][0])).toBe("/api/v1/insights/agent-trees/t");

    const composition = await client.getComposition("apx_1");
    expect(String(fetcher.mock.calls[2][0])).toBe("/api/v1/audits/apx_1/composition");
    expect(composition.items).toEqual([]);
    expect(composition.tools).toEqual([]);
    expect(composition.file_ops).toEqual([]);
  });

  it("reports an unanalyzed audit as a 404 ApiError", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ error: { message: "尚未分析" } }, 404));
    const client = createApiClient(vi.fn(), fetcher);
    await expect(client.getComposition("apx_1")).rejects.toMatchObject({ status: 404, message: "尚未分析" });
    await expect(client.getComposition("apx_1")).rejects.toBeInstanceOf(ApiError);
  });

  it("signals unauthorized on 401 like the other calls", async () => {
    const onUnauthorized = vi.fn();
    const client = createApiClient(onUnauthorized, vi.fn<typeof fetch>(async () => jsonResponse({}, 401)));
    await expect(client.getSessionTrend("ses_a")).rejects.toMatchObject({ status: 401 });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });
});
