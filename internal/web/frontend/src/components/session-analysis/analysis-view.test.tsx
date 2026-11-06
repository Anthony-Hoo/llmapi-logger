import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ApiClient } from "../../api";
import type { AnalysisOverview, AnalysisSessionItem, AnalysisSignalTotals } from "../../lib/session-analysis/types";
import { OverviewCards, SessionAnalysisView, SessionDetails } from "./analysis-view";

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
      llm_enabled: false,
      last_run: { started_ns: "1700000000000000000", finished_ns: "1700000060000000000", trigger: "manual", candidates: 5, analyzed: 5, skipped: 0, skip_reasons: { single_turn_chat: 2 } },
    };
    const html = renderToStaticMarkup(<OverviewCards overview={overview} />);
    expect(html).toContain("死循环");
    expect(html).toContain("12.5%");
    expect(html).toContain("较上期 +12.5pt");
    expect(html).toContain("单轮聊天 2");
    expect(html).toContain("1 个会话出现危险命令");
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
});
