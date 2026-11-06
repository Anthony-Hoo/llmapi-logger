import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ApiClient } from "../../api";
import type { AnalysisOverview, AnalysisSessionItem, AnalysisSignalTotals } from "../../lib/session-analysis/types";
import { OverviewCards, SessionAnalysisView, SessionDetails } from "./analysis-view";
import { FacetView } from "./facet-panel";
import { PackView } from "./pack-panel";
import { ReportBody, weekDelta } from "./report-view";

function totals(overrides: Partial<AnalysisSignalTotals> = {}): AnalysisSignalTotals {
  return {
    sessions: 20,
    agent_sessions: 16,
    chat_sessions: 4,
    eligible: 10,
    cost_usd: 12.5,
    loop_sessions: 2,
    loop_cost_usd: 3,
    thrash_sessions: 1,
    unverified_sessions: 3,
    sessions_with_writes: 12,
    failure_sessions: 8,
    corrections: 5,
    correction_sessions: 4,
    error_paste_sessions: 2,
    interrupt_sessions: 1,
    heavy_model_sessions: 0,
    danger_sessions: 1,
    secret_sessions: 0,
    compaction_sessions: 3,
    cache_hit_rate: 0.9,
    ...overrides,
  };
}

describe("session analysis view", () => {
  it("renders headline tiles with deltas and the last run", () => {
    const overview: AnalysisOverview = {
      from_ns: "1",
      to_ns: "2",
      current: totals(),
      previous: totals({ loop_sessions: 0, cache_hit_rate: 0.85 }),
      running: false,
      llm_enabled: true,
      model: "local-small",
      prompt_version: "facet-v1",
      calibration: { prompt_version: "facet-v1", model: "local-small", samples: 30, compared: { outcome: 30 }, agreement: { outcome: 0.5 }, hidden_fields: ["outcome"], created_ns: "1" },
      last_run: { started_ns: "1700000000000000000", finished_ns: "1700000060000000000", trigger: "manual", candidates: 5, analyzed: 5, skipped: 0, skip_reasons: { single_turn_chat: 2 }, facets_due: 3, facets_ok: 2, facets_invalid: 1, facets_failed: 0, model_input_tokens: 4500, model_output_tokens: 600 },
    };
    const html = renderToStaticMarkup(<OverviewCards overview={overview} />);
    expect(html).toContain("死循环");
    expect(html).toContain("12.5%");
    expect(html).toContain("较上期 +12.5pt");
    expect(html).toContain("单轮聊天 2");
    expect(html).toContain("1 个会话出现危险命令");
    expect(html).toContain("本地模型 local-small（facet-v1）：本轮待分析 3、成功 2、输出无效 1");
    expect(html).toContain("结果 50%（30）；已隐藏 结果");
  });

  it("renders session details without identity fields", () => {
    const item = {
      session_id: "f".repeat(64),
      kind: "agent",
      client: "codex",
      model: "m",
      first_ns: "1700000000000000000",
      last_ns: "1700000000000000000",
      last_audit_id: "audit-9",
      requests: 3,
      subagents: 1,
      user_turns: 2,
      active_seconds: 30,
      input_tokens: 1500,
      output_tokens: 20,
      cost_usd: null,
      tool_calls: 2,
      tool_failures: 1,
      max_failure_streak: 1,
      loops: 0,
      max_loop_length: 0,
      thrash_files: 0,
      max_file_writes: 0,
      verified: "no_writes",
      error_pastes: 0,
      interrupts: 0,
      corrections: 0,
      compactions: 0,
      model_switches: 0,
      length_stops: 0,
      upstream_errors: 0,
      heavy_model: false,
      danger: { exfiltrate: 1 },
      secrets: {},
      eligible: false,
      skip_reason: "below_threshold",
    } satisfies AnalysisSessionItem;
    const html = renderToStaticMarkup(<SessionDetails item={item} />);
    expect(html).toContain("外传文件 1");
    expect(html).toContain("没有写文件");
    expect(html).not.toContain("username");
  });

  it("hides the run button from developers", () => {
    const client = {} as ApiClient;
    expect(renderToStaticMarkup(<SessionAnalysisView client={client} isDeveloper refreshKey={0} />)).not.toContain("立即运行");
    expect(renderToStaticMarkup(<SessionAnalysisView client={client} isDeveloper={false} refreshKey={0} />)).toContain("立即运行");
  });

  it("renders a pack with its evidence references", () => {
    const html = renderToStaticMarkup(
      <PackView
        pack={{ session_id: "s", pack_id: "p", kind: "chat_digest", text: "[会话] 类型=聊天汇总\n[U1 09:12] 问题", refs: { U10: "a10", U2: "a2" }, tokens: 42, truncated: true, members: 4, built_ns: "1" }}
      />,
    );
    expect(html).toContain("聊天汇总包（4 个单轮会话）");
    expect(html).toContain("已按预算截断");
    expect(html.indexOf("U2 → a2")).toBeLessThan(html.indexOf("U10 → a10"));
  });

  it("renders a facet and hides fields below the calibration bar", () => {
    const html = renderToStaticMarkup(
      <FacetView
        facet={{
          session_id: "s",
          pack_id: "p",
          kind: "session",
          status: "ok",
          model: "local-small",
          prompt_version: "facet-v1",
          created_ns: "1",
          task_type: "bug_fix",
          outcome: "achieved",
          collaboration: "task_iteration",
          friction: ["tool_failed"],
          items: [],
          invalid_fields: [],
          goal: "修复登录接口",
          instructions: ["参数校验错误一律返回 400"],
          evidence: { friction: [{ label: "C2", audit_id: "a2" }] },
          hidden_fields: ["outcome"],
        }}
      />,
    );
    expect(html).toContain("修缺陷");
    expect(html).toContain("工具失败");
    expect(html).toContain("参数校验错误一律返回 400");
    expect(html).toContain("C2 → a2");
    expect(html).not.toContain("达成");
    expect(html).toContain("隐藏：结果");
  });
  it("renders the weekly report with deltas and dismiss controls", () => {
    const stats = { week_start_ns: "1", totals: totals(), facets_ok: 7, task_types: { bug_fix: 4, feature: 2 }, outcomes: { achieved: 5 }, collaboration: {}, friction: { tool_failed: 3 } };
    const report = {
      week_start_ns: "1793548800000000000",
      scope: "all" as const,
      stats,
      previous: { ...stats, facets_ok: 5, totals: totals({ loop_sessions: 4 }) },
      narrative: "本周做了什么：共 20 个会话。\n卡在哪里：暂无。\n可以沉淀或改进的点：暂无。",
      narrative_source: "model" as const,
      computed_ns: "1",
      suggestions: [
        { id: 1, kind: "instruction" as const, text: "提交前先跑 go test", sessions: 3, strong: true, status: "open" as const, first_seen_ns: "1", last_seen_ns: "2", evidence: ["a1", "a2"] },
        { id: 2, kind: "skill" as const, text: "生成接口变更说明", sessions: 2, strong: false, status: "adopted_detected" as const, first_seen_ns: "1", last_seen_ns: "2", evidence: [] },
      ],
      optimizations: [],
    };
    const admin = renderToStaticMarkup(<ReportBody report={report} canDismiss onDismiss={() => undefined} />);
    expect(admin).toContain("本地模型撰写");
    expect(admin).toContain("本周做了什么：共 20 个会话。");
    expect(admin).toContain("修缺陷");
    expect(admin).toContain("(-2)");
    expect(admin).toContain("强候选");
    expect(admin).toContain("已沉淀");
    expect(admin).toContain("证据：a1，a2");
    expect(admin.match(/忽略/g)?.length).toBe(1);
    const developer = renderToStaticMarkup(<ReportBody report={report} canDismiss={false} onDismiss={() => undefined} />);
    expect(developer).not.toContain(">忽略<");
    expect(weekDelta(3, undefined)).toBeNull();
    expect(weekDelta(3, 3)).toBe("持平");
    expect(weekDelta(5, 3)).toBe("+2");
  });
});