import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../../api";
import { settingsSections } from "../../app";
import { contextBudget, draftChanged, draftFromSettings, keySourceLabel, probeSummary, updateFromDraft } from "../../lib/settings/analysis";
import { orgDraftChanged, orgDraftFromSettings, orgUpdateFromDraft, parseClients } from "../../lib/settings/org";
import type { AnalysisSettingsView, OrgSettingsView } from "../../lib/settings/types";
import { AnalysisFileOnly, AnalysisSettingsCard, AnalysisSettingsFields, AnalysisSettingsStatus, ProbeOutcome } from "./analysis-settings-form";
import { OrgSettingsCard, OrgSettingsFields } from "./org-settings-form";
import { ReportSettingsPanel } from "./report-settings-panel";
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

  it("edits the weekly report parameters and shows the calendar read-only", () => {
    const settings = { idle_gap_seconds: 180, ranked_clients: ["claude_code", "codex"], max_concurrent_roots: 10, max_single_request_roots: 200 };
    const view: OrgSettingsView = { source: "file", settings, file: settings, timezone: "Asia/Shanghai", week_start: "sunday" };
    const draft = orgDraftFromSettings(settings);
    expect(draft.ranked_clients).toBe("claude_code, codex");
    expect(orgUpdateFromDraft(draft)).toEqual(settings);
    expect(orgDraftChanged(draft, view)).toBe(false);
    // The order of clients does not count as a change; separators are forgiving.
    expect(orgDraftChanged({ ...draft, ranked_clients: "codex，claude_code" }, view)).toBe(false);
    expect(parseClients(" codex、 opencode,pi\nzcode ")).toEqual(["codex", "opencode", "pi", "zcode"]);
    expect(orgDraftChanged({ ...draft, idle_gap_seconds: "60" }, view)).toBe(true);
    expect(orgUpdateFromDraft({ ...draft, idle_gap_seconds: "3m" }).idle_gap_seconds).toBe(-1);

    const html = renderToStaticMarkup(<OrgSettingsFields view={view} draft={draft} busy={false} onChange={() => undefined} />);
    expect(html).toContain("来自配置文件");
    expect(html).toContain('id="org-idle_gap_seconds"');
    expect(html).toContain("已冻结的周保持原来的快照");
    // The time zone and the first weekday are shown, not edited.
    expect(html).toContain("Asia/Shanghai");
    expect(html).toContain("周日");
    expect(html).toContain("org_reports.week_start");
    expect(html).not.toContain('id="org-timezone"');
    const saved = renderToStaticMarkup(<OrgSettingsFields view={{ ...view, source: "saved", updated_ns: "1800000000000000000" }} draft={draft} busy={false} onChange={() => undefined} />);
    expect(saved).toContain("覆盖配置文件");
    expect(saved).toContain("保存于");

    const panel = renderToStaticMarkup(<ReportSettingsPanel client={{} as ApiClient} hasOrgReports hasSessionAnalysis />);
    expect(panel).toContain("周报与分析");
    expect(panel).toContain("会话分析与周度复盘");
    expect(panel).toContain(">项目周报<");
    expect(panel).toContain("覆盖配置文件");
    // Each card appears only with its feature.
    expect(renderToStaticMarkup(<ReportSettingsPanel client={{} as ApiClient} hasOrgReports={false} hasSessionAnalysis />)).not.toContain(">项目周报<");
    expect(renderToStaticMarkup(<ReportSettingsPanel client={{} as ApiClient} hasOrgReports hasSessionAnalysis={false} />)).not.toContain("会话分析与周度复盘");
    expect(renderToStaticMarkup(<OrgSettingsCard client={{} as ApiClient} />)).toContain(">项目周报<");
  });
});

function settingsView(overrides: Partial<AnalysisSettingsView> = {}): AnalysisSettingsView {
  const settings = {
    run_at: "02:00",
    l1_settle_hours: 24,
    llm: {
      enabled: true, base_url: "http://127.0.0.1:11434/v1", model: "local-small", structured_output: "json_schema" as const, context_tokens: 16384,
      disable_thinking: true, max_output_tokens: 1500, max_concurrency: 1, timeout_seconds: 120, max_sessions_per_run: 300,
    },
  };
  return {
    source: "file", settings, api_key: "file", file: settings, file_api_key: true, running: false,
    file_only: { allow_non_local: false, session_idle_minutes: 120, min_user_turns: 2, min_active_seconds: 60, pack_max_tokens: 6000, prompt_reserve_tokens: 2500 },
    ...overrides,
  };
}

describe("session analysis settings form", () => {
  it("builds the request from the draft and never sends a key that was not typed", () => {
    const view = settingsView();
    const draft = draftFromSettings(view.settings);
    expect(draft.api_key).toBe("");
    expect(draftChanged(draft, view)).toBe(false);
    // Unchanged: the same values go back and no api_key field at all.
    expect(updateFromDraft(draft)).toEqual(view.settings);
    expect("api_key" in updateFromDraft(draft)).toBe(false);

    const edited = { ...draft, max_concurrency: " 4 ", model: " other-model ", base_url: " http://10.0.0.5:8000/v1 " };
    expect(draftChanged(edited, view)).toBe(true);
    const update = updateFromDraft(edited);
    expect(update.llm.max_concurrency).toBe(4);
    expect(update.llm.model).toBe("other-model");
    expect(update.llm.base_url).toBe("http://10.0.0.5:8000/v1");

    expect(updateFromDraft({ ...draft, api_key: "new-key" }).api_key).toBe("new-key");
    expect(draftChanged({ ...draft, api_key: "new-key" }, view)).toBe(true);
    // "不使用 Key" wins over anything typed and sends an empty key.
    expect(updateFromDraft({ ...draft, api_key: "typed", clear_key: true }).api_key).toBe("");
    expect(draftChanged({ ...draft, clear_key: true }, view)).toBe(true);
    expect(draftChanged({ ...draft, clear_key: true }, settingsView({ api_key: "none" }))).toBe(false);
    // Not a whole number: sent as -1 so the server names the field.
    expect(updateFromDraft({ ...draft, max_output_tokens: "1.5k" }).llm.max_output_tokens).toBe(-1);
    expect(updateFromDraft({ ...draft, timeout_seconds: "" }).llm.timeout_seconds).toBe(-1);
  });

  it("checks the context budget and words the key source", () => {
    const view = settingsView();
    const draft = draftFromSettings(view.settings);
    expect(contextBudget(draft, view)).toEqual({ used: 10000, limit: 16384, fits: true });
    expect(contextBudget({ ...draft, max_output_tokens: "9000" }, view)).toEqual({ used: 17500, limit: 16384, fits: false });
    expect(contextBudget({ ...draft, context_tokens: "abc" }, view)).toBeNull();
    expect(keySourceLabel(view)).toContain("配置文件");
    expect(keySourceLabel(settingsView({ api_key: "saved" }))).toContain("已在页面上保存");
    expect(keySourceLabel(settingsView({ api_key: "none" }))).toContain("未设置");
  });

  it("renders the fields without the key in use, with the limits it will hit", () => {
    const view = settingsView();
    const draft = draftFromSettings(view.settings);
    const html = renderToStaticMarkup(<AnalysisSettingsFields view={view} draft={draft} busy={false} onChange={() => undefined} />);
    expect(html).toContain('type="password"');
    expect(html).toContain("new-password");
    expect(html).toMatch(/id="analysis-api_key"[^>]*value=""/);
    expect(html).toContain("这里不会显示已有的 Key");
    expect(html).toContain("只能是本机或内网地址");
    expect(html).toContain("网关之后转发到哪里不在检查范围内");
    expect(html).toContain("不超过上下文长度 16384");
    expect(html).not.toContain("换模型后");

    const changed = renderToStaticMarkup(
      <AnalysisSettingsFields view={view} draft={{ ...draft, model: "other", max_output_tokens: "9000", clear_key: true }} busy={false} onChange={() => undefined} />,
    );
    expect(changed).toContain("换模型后，已有的标注都不再算数");
    expect(changed).toContain("保存会被拒绝");
    expect(changed).toContain("保存后不发送 Key");
    const loose = renderToStaticMarkup(
      <AnalysisSettingsFields view={settingsView({ file_only: { ...view.file_only, allow_non_local: true } })} draft={draft} busy={false} onChange={() => undefined} />,
    );
    expect(loose).toContain("已放开非本地地址");

    const fileOnly = renderToStaticMarkup(<AnalysisFileOnly view={view} />);
    expect(fileOnly).toContain("session_analysis.llm.allow_non_local");
    expect(fileOnly).toContain("6000 Token");
    expect(fileOnly).not.toContain("<input");
  });

  it("says where the settings come from and when a change applies", () => {
    expect(renderToStaticMarkup(<AnalysisSettingsStatus view={settingsView()} />)).toContain("来自配置文件");
    const saved = renderToStaticMarkup(<AnalysisSettingsStatus view={settingsView({ source: "saved", updated_ns: "1800000000000000000", running: true })} />);
    expect(saved).toContain("覆盖配置文件");
    expect(saved).toContain("保存于");
    expect(saved).toContain("它仍按旧设置跑完");
    expect(renderToStaticMarkup(<AnalysisSettingsCard client={{} as ApiClient} />)).toContain("会话分析与周度复盘");
  });

  it("explains the outcome of a connection test without showing model output", () => {
    const ok = { ok: true, http_status: 200, latency_ms: 840, truncated: false, reasoned: false, valid_json: true, input_tokens: 20, output_tokens: 6 };
    expect(probeSummary(ok)).toEqual({ tone: "success", text: "连接成功，用时 840 毫秒（输入 20 / 输出 6 Token）。", notes: [] });
    const thinking = probeSummary({ ...ok, reasoned: true, truncated: true, valid_json: false });
    expect(thinking.tone).toBe("warning");
    expect(thinking.notes).toHaveLength(3);
    expect(thinking.notes[0]).toContain("没有生效");
    const unauthorized = probeSummary({ ...ok, ok: false, error: "http_status", http_status: 401 });
    expect(unauthorized.tone).toBe("danger");
    expect(unauthorized.text).toContain("HTTP 401");
    expect(unauthorized.text).toContain("Key 不对或没有填");
    expect(probeSummary({ ...ok, ok: false, error: "invalid_address", http_status: undefined }).text).toContain("只能是本机或内网地址");
    expect(probeSummary({ ...ok, ok: false, error: "timeout" }).text).toContain("超时");
    const html = renderToStaticMarkup(<ProbeOutcome result={{ ...ok, reasoned: true }} />);
    expect(html).toContain("连接成功");
    expect(html).toContain("思考会占用输出上限");
  });
});
