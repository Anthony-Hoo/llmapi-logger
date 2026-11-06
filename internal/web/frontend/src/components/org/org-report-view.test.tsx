import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { seriesKeys, usedSeries, rankingRows } from "../../lib/org/report";
import type { OrgRankedUser, OrgWeeklyReport } from "../../lib/org/types";
import { ProjectMatrix, RankingTable, SelfCard, ServiceTable } from "./org-report-view";

const tokens = { uncached: 0, cache_read: 0, cache_write: 0, output: 50 };
const hour = 3.6e12;

const ranked: OrgRankedUser = {
  user_id: 7, group_id: 1, active_ns: 2 * hour, other_active_ns: hour / 2, inferred_ns: hour, roots: 3, single_request_roots: 250,
  requests: 10, identified_requests: 9, billed_requests: 10, tokens, cost_usd: 1.5, peak_concurrency: 12, avg_concurrency: 2.5,
  daily_active_ns: [2 * hour, 0, 0, 0, 0, 0, 0],
  projects: [{ project: 10, active_ns: 1.5 * hour, roots: 2, requests: 8, tokens, cost_usd: 1 }, { project: -1, active_ns: hour / 2, roots: 1, requests: 2, tokens, cost_usd: 0.5 }],
  flags: [{ code: "concurrency", value: 12, threshold: 10 }, { code: "single_request_roots", value: 250, threshold: 200 }, { code: "inferred_sessions", value: hour }],
  rank: 1, coverage: 0.9,
};

const report: OrgWeeklyReport = {
  week: "2026-11-02", start_ns: 0, end_ns: 1, timezone: "UTC", metric: "hours", frozen: true, complete: true,
  users: [ranked], service: [{ user_id: 1, token_id: 0, active_ns: hour, roots: 1, requests: 4, tokens, cost_usd: 2 }],
  projects: [{ id: 10, name: "Core" }], totals: { active_ns: 2 * hour, requests: 10, identified_requests: 9, tokens, cost_usd: 1.5, users: 1 }, group_id: null,
};

const names = (id: number) => `user-${id}`;

describe("org report view", () => {
  it("renders the ranking with coverage, concurrency and anomaly badges", () => {
    const html = renderToStaticMarkup(<RankingTable report={report} metric="hours" userName={names} />);
    expect(html).toContain("user-7");
    expect(html).toContain("2.0 h");
    expect(html).toContain("其他客户端 30 min");
    expect(html).toContain("90%");
    expect(html).toContain("12 / 2.5");
    expect(html).toContain("并行峰值 12（阈值 10）");
    expect(html).toContain("单请求会话 250 个（阈值 200）");
    expect(html).toContain("含推断会话");
  });

  it("renders the user x project matrix with bucket columns", () => {
    const series = usedSeries(seriesKeys(report.projects, {}), rankingRows(report, "hours", names));
    const html = renderToStaticMarkup(<ProjectMatrix report={report} metric="hours" series={series} userName={names} />);
    expect(html).toContain("Core");
    expect(html).toContain("未归属");
    expect(html).toContain("1.5 h");
  });

  it("renders the service section and the developer card", () => {
    expect(renderToStaticMarkup(<ServiceTable rows={report.service} userName={names} />)).toContain("user-1");
    expect(renderToStaticMarkup(<ServiceTable rows={[]} userName={names} />)).toContain("没有服务");
    const self = renderToStaticMarkup(<SelfCard report={{ week: "2026-11-02", timezone: "UTC", row: ranked, projects: [{ id: 10, name: "Core" }] }} />);
    expect(self).toContain("我的本周 · 2026-11-02");
    expect(self).toContain("Core");
    expect(self).toContain("11-02 2.0 h");
    expect(renderToStaticMarkup(<SelfCard report={{ week: "2026-11-02", timezone: "UTC", row: null, projects: [] }} />)).toContain("还没有你的项目数据");
  });
});
