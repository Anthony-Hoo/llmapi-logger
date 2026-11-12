import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../../api";
import { settingsSections } from "../../app";
import type { AnalysisOverview } from "../../lib/session-analysis/types";
import { AnalysisModelCard, OrgSettingsCard, ReportSettingsPanel } from "./report-settings-panel";
import { SystemSettings, type SettingsSection } from "./system-settings";

describe("system settings menu", () => {
  it("lists every section and mounts only the selected one", () => {
    const first = vi.fn(() => <p>第一页内容</p>);
    const second = vi.fn(() => <p>第二页内容</p>);
    const sections: SettingsSection[] = [
      { id: "a", label: "甲配置", hint: "甲的说明", render: first },
      { id: "b", label: "乙配置", hint: "乙的说明", render: second },
    ];
    const html = renderToStaticMarkup(<SystemSettings sections={sections} />);
    expect(html).toContain('aria-label="系统配置"');
    expect(html).toContain("甲配置");
    expect(html).toContain("乙的说明");
    expect(html).toContain("第一页内容");
    expect(html).not.toContain("第二页内容");
    expect(second).not.toHaveBeenCalled();
    expect(html.match(/aria-current="page"/g)?.length).toBe(1);

    const other = renderToStaticMarkup(<SystemSettings sections={sections} initial="b" />);
    expect(other).toContain("第二页内容");
    expect(other).not.toContain("第一页内容");
    // An unknown or stale selection falls back to the first section.
    expect(renderToStaticMarkup(<SystemSettings sections={sections} initial="gone" />)).toContain("第一页内容");
    expect(renderToStaticMarkup(<SystemSettings sections={[]} />)).toContain("没有可配置的项目");
  });

  it("offers the sections the enabled features have", () => {
    const client = {} as ApiClient;
    const ids = (org: boolean, analysis: boolean) => settingsSections(client, org, analysis).map((section) => section.id);
    expect(ids(false, false)).toEqual(["ua-rules", "content-policy"]);
    expect(ids(false, true)).toEqual(["ua-rules", "content-policy", "reports"]);
    expect(ids(true, false)).toEqual(["ua-rules", "content-policy", "org", "reports"]);
    expect(ids(true, true)).toEqual(["ua-rules", "content-policy", "org", "reports"]);
    expect(settingsSections(client, true, true).map((section) => section.label)).toEqual(["UA 拦截规则", "关键词拦截", "项目组与项目", "周报与分析"]);
  });

  it("shows the report parameters read-only with their configuration keys", () => {
    const org = renderToStaticMarkup(
      <OrgSettingsCard settings={{ timezone: "Asia/Shanghai", week_start: "sunday", idle_gap_seconds: 180, ranked_clients: ["codex", "claude_code"], max_concurrent_roots: 10, max_single_request_roots: 200 }} />,
    );
    expect(org).toContain("Asia/Shanghai");
    expect(org).toContain("周日");
    expect(org).toContain("180 秒");
    expect(org).toContain("codex、claude_code");
    expect(org).toContain("org_reports.flags.max_single_request_roots");
    expect(org).not.toContain("<input");

    const overview = { from_ns: "1", to_ns: "2", running: false, llm_enabled: true, model: "local-small", prompt_version: "facet-v1" } as AnalysisOverview;
    const model = renderToStaticMarkup(<AnalysisModelCard overview={overview} />);
    expect(model).toContain("已启用");
    expect(model).toContain("local-small");
    expect(model).toContain("facet-v1");
    const off = renderToStaticMarkup(<AnalysisModelCard overview={{ ...overview, llm_enabled: false, model: undefined }} />);
    expect(off).toContain("未启用");
    expect(off).not.toContain("session_analysis.llm.model");

    const panel = renderToStaticMarkup(<ReportSettingsPanel client={{} as ApiClient} hasOrgReports hasSessionAnalysis />);
    expect(panel).toContain("周报与分析");
    expect(panel).toContain("这里只读");
  });
});
