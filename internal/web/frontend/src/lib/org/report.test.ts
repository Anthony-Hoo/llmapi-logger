import { describe, expect, it } from "vitest";

import { buildMatrix, flagLabel, flagVariant, formatMetric, rankingRows, seriesKeys, trendRows, usedSeries } from "./report";
import type { OrgProjectCell, OrgRankedUser, OrgWeeklyReport } from "./types";

const tokens = (output: number) => ({ uncached: 0, cache_read: 0, cache_write: 0, output });
const hour = 3.6e12;

function cell(project: number, hours: number, output = 0, cost = 0): OrgProjectCell {
  return { project, active_ns: hours * hour, roots: 1, requests: 1, tokens: tokens(output), cost_usd: cost };
}

function user(id: number, cells: OrgProjectCell[], rank: number): OrgRankedUser {
  const active = cells.reduce((sum, item) => sum + item.active_ns, 0);
  return {
    user_id: id, group_id: 0, active_ns: active, other_active_ns: 0, inferred_ns: 0, roots: cells.length, single_request_roots: 0,
    requests: cells.length, identified_requests: cells.length, billed_requests: 0,
    tokens: tokens(cells.reduce((sum, item) => sum + item.tokens.output, 0)), cost_usd: cells.reduce((sum, item) => sum + item.cost_usd, 0),
    peak_concurrency: 1, avg_concurrency: 1, daily_active_ns: [active, 0, 0, 0, 0, 0, 0], projects: cells, flags: [], rank, coverage: 1,
  };
}

const report: OrgWeeklyReport = {
  week: "2026-11-02", start_ns: 0, end_ns: 1, timezone: "UTC", metric: "hours", frozen: false, complete: false,
  users: [user(1, [cell(10, 3, 100, 1), cell(-1, 1)], 1), user(2, [cell(11, 2, 900, 4)], 2)],
  service: [], projects: [{ id: 11, name: "Mobile" }, { id: 10, name: "Core" }],
  totals: { active_ns: 6 * hour, requests: 3, identified_requests: 3, tokens: tokens(1000), cost_usd: 5, users: 2 }, group_id: null,
};

describe("org report helpers", () => {
  it("orders series by project id and appends the buckets", () => {
    const keys = seriesKeys(report.projects, {});
    expect(keys.map((key) => key.key)).toEqual(["p10", "p11", "unattributed", "no_context"]);
    expect(keys[0].label).toBe("Core");
    expect(keys[2].label).toBe("未归属");
  });

  it("builds stacked ranking rows in the selected metric", () => {
    const hours = rankingRows(report, "hours", (id) => `user-${id}`);
    expect(hours[0]).toMatchObject({ user: "user-1", total: 4, p10: 3, unattributed: 1 });
    const cost = rankingRows(report, "cost", (id) => `user-${id}`);
    expect(cost[1]).toMatchObject({ p11: 4, total: 4 });
    const keys = usedSeries(seriesKeys(report.projects, {}), hours);
    expect(keys.map((key) => key.key)).toEqual(["p10", "p11", "unattributed"]);
  });

  it("levels the matrix relative to its maximum", () => {
    const keys = usedSeries(seriesKeys(report.projects, {}), rankingRows(report, "hours", String));
    const matrix = buildMatrix(report, "hours", keys);
    expect(matrix.max).toBe(3);
    expect(matrix.rows[0].cells.map((item) => item.level)).toEqual([4, 0, 2]);
    expect(matrix.rows[1].cells.map((item) => item.level)).toEqual([0, 3, 0]);
  });

  it("builds trend rows", () => {
    const rows = trendRows({ weeks: [{ week: "2026-11-02", frozen: true, active_ns: hour, tokens: 0, cost_usd: 0, users: 1, projects: [cell(10, 1)] }], projects: [] }, "hours");
    expect(rows[0]).toMatchObject({ week: "11-02", p10: 1 });
  });

  it("labels flags and formats metrics", () => {
    expect(flagLabel({ code: "concurrency", value: 12, threshold: 10 })).toBe("并行峰值 12（阈值 10）");
    expect(flagVariant({ code: "inferred_sessions", value: 1 })).toBe("info");
    expect(flagVariant({ code: "single_request_roots", value: 300, threshold: 200 })).toBe("warning");
    expect(formatMetric(12.4, "hours")).toBe("12 h");
    expect(formatMetric(1.25, "hours")).toBe("1.3 h");
    expect(formatMetric(2_500_000, "tokens")).toBe("2.5M");
    expect(formatMetric(3.456, "cost")).toBe("$3.46");
  });
});
