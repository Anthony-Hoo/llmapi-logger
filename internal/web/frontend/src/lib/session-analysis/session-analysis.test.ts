import { describe, expect, it, vi } from "vitest";

import { ApiError, createApiClient } from "../../api";
import { analysisRange } from "../../components/session-analysis/analysis-view";
import { formatDuration, formatPointDelta, sessionBadges, share, signalRates, startOfLocalWeekMS } from "./format";
import type { AnalysisSessionItem, AnalysisSignalTotals } from "./types";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const baseItem: AnalysisSessionItem = {
  session_id: "a".repeat(64),
  kind: "agent",
  client: "codex",
  model: "codex-large",
  first_ns: "1",
  last_ns: "2",
  last_audit_id: "audit-1",
  requests: 10,
  subagents: 0,
  user_turns: 3,
  active_seconds: 600,
  input_tokens: 1000,
  output_tokens: 100,
  cost_usd: null,
  tool_calls: 8,
  tool_failures: 2,
  max_failure_streak: 1,
  loops: 0,
  max_loop_length: 0,
  thrash_files: 0,
  max_file_writes: 1,
  verified: "yes",
  error_pastes: 0,
  interrupts: 0,
  corrections: 0,
  compactions: 0,
  model_switches: 0,
  length_stops: 0,
  upstream_errors: 0,
  heavy_model: false,
  danger: {},
  secrets: {},
  eligible: true,
};

describe("session analysis formatting", () => {
  it("computes rates against the sessions they apply to", () => {
    const totals = { sessions: 10, agent_sessions: 4, sessions_with_writes: 2, loop_sessions: 1, thrash_sessions: 0, unverified_sessions: 1, correction_sessions: 5, error_paste_sessions: 0, heavy_model_sessions: 0 } as AnalysisSignalTotals;
    const rates = signalRates(totals);
    expect(rates.loop).toBe(0.25);
    expect(rates.unverified).toBe(0.5);
    expect(rates.corrections).toBe(0.5);
    expect(share(1, 0)).toBeNull();
  });

  it("formats point deltas and durations", () => {
    expect(formatPointDelta(0.3, 0.25)).toBe("+5.0pt");
    expect(formatPointDelta(0.2, 0.25)).toBe("-5.0pt");
    expect(formatPointDelta(0.2, 0.2)).toBe("持平");
    expect(formatPointDelta(null, 0.2)).toBeNull();
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(600)).toBe("10m");
    expect(formatDuration(3900)).toBe("1h5m");
  });

  it("orders badges by severity", () => {
    const badges = sessionBadges({ ...baseItem, secrets: { cloud_key: 1 }, danger: { force_push: 1 }, loops: 1, max_loop_length: 4, verified: "no" });
    expect(badges.map((badge) => badge.label)).toEqual(["疑似密钥", "强制推送", "死循环×4", "未验证", "失败 2/8"]);
    expect(badges[0].tone).toBe("danger");
  });

  it("starts weeks on Monday", () => {
    const wednesday = new Date(2026, 10, 4, 15, 30).getTime();
    const monday = new Date(startOfLocalWeekMS(wednesday));
    expect(monday.getDay()).toBe(1);
    expect(monday.getDate()).toBe(2);
    expect(monday.getHours()).toBe(0);
    const range = analysisRange("last-week", wednesday);
    expect(BigInt(range.to_ns) - BigInt(range.from_ns)).toBe(7n * 86_400_000n * 1_000_000n);
  });
});

describe("session analysis API client", () => {
  it("sends range, kind, flags and cursor and normalizes null maps", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ items: [{ ...baseItem, danger: null, secrets: null }], next_cursor: "n2" }));
    const client = createApiClient(vi.fn(), fetcher);
    const page = await client.listAnalysisSessions({ from_ns: "10", to_ns: "20", kind: "agent", flags: ["loop", "unverified"], cursor: "c1", limit: 25 });
    expect(String(fetcher.mock.calls[0][0])).toBe(
      "/api/v1/session-analysis/sessions?from_ns=10&to_ns=20&limit=25&kind=agent&flags=loop%2Cunverified&cursor=c1",
    );
    expect(page.items[0].danger).toEqual({});
    expect(page.items[0].secrets).toEqual({});
    expect(page.next_cursor).toBe("n2");
  });

  it("posts the run trigger and surfaces a conflict", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ error: { code: "run_in_progress", message: "busy" } }, 409));
    const client = createApiClient(vi.fn(), fetcher);
    await expect(client.triggerAnalysisRun()).rejects.toBeInstanceOf(ApiError);
    expect(fetcher.mock.calls[0][1]?.method).toBe("POST");
  });

  it("requests the overview for a range", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ from_ns: "1", to_ns: "2", current: {}, previous: {}, running: false, llm_enabled: false, last_run: { skip_reasons: null } }));
    const client = createApiClient(vi.fn(), fetcher);
    const overview = await client.getAnalysisOverview({ from_ns: "1", to_ns: "2" });
    expect(String(fetcher.mock.calls[0][0])).toBe("/api/v1/session-analysis/overview?from_ns=1&to_ns=2");
    expect(overview.last_run?.skip_reasons).toEqual({});
  });
});
