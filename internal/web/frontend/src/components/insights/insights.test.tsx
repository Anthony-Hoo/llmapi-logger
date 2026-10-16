import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ApiClient } from "../../api";
import { AuditDetailBody } from "../../app";
import { emptyCategoryValues } from "../../lib/insights/categories";
import { buildChartRows, stepBars } from "../../lib/insights/trend";
import type {
  AuditDetail,
  CategoryValues,
  CompositionResponse,
  OverviewResponse,
  SessionCard,
  TreeNode,
  TrendStep,
  UsageTotals,
} from "../../types";
import { CategoryLegend, CompositionBar, OccupancyText } from "./composition-bar";
import { CompositionPanel, sortTools, toolSourceLabel } from "./composition-section";
import { dailyRows } from "./daily-chart";
import { ActivityHeatmap } from "./heatmap";
import { GroupTable, groupOptions, KpiBar } from "./overview-page";
import { SessionCardView } from "./session-card";
import { AgentTree, linkSourceLabel, placeNodes } from "./tree-page";
import { TrendTooltipBody } from "./trend-chart";

function values(partial: Partial<CategoryValues>): CategoryValues {
  return { ...emptyCategoryValues(), ...partial };
}

function usage(overrides: Partial<UsageTotals> = {}): UsageTotals {
  return {
    requests: 4,
    uncached_input: 100,
    cache_read: 800,
    cache_write: 100,
    output: 250,
    reasoning: 50,
    prompt_total: 1000,
    cache_hit_rate: 0.8,
    estimated_cost_usd: 0.1234,
    unpriced_requests: 0,
    ...overrides,
  };
}

const noop = () => undefined;

describe("audit detail integration", () => {
  const detail: AuditDetail = {
    audit: {
      audit_id: "apx_demo",
      started_at_ns: "1",
      route_id: "r",
      protocol: "anthropic",
      method: "POST",
      path: "/v1/messages",
      forward_status: "completed",
      capture_status: "complete",
      parse_status: "ok",
    },
    request_uri: "/v1/messages",
    stages: [],
    headers: [],
    bodies: [],
    conversation: null,
    parsed_result: { usage_input: 5 },
    turn: null,
    token_link: null,
  };

  function render(client?: ApiClient): string {
    return renderToStaticMarkup(
      <AuditDetailBody
        detail={detail}
        client={client}
        onExportConversation={noop}
        exportNote={null}
        reconstructedLoading={null}
        reconstructedNote={null}
        onDownloadReconstructed={noop}
        timelines={{}}
        timelineLoading={null}
        timelineNote={null}
        onLoadTimeline={noop}
        rawBodies={{}}
        rawLoading={null}
        rawNote={null}
        onLoadRaw={noop}
        onDownloadRaw={noop}
        onClearRaw={noop}
      />,
    );
  }

  it("adds the lazily loaded 上下文构成 section only when a client is supplied", () => {
    expect(render()).not.toContain("上下文构成");
    expect(render({} as ApiClient)).toContain("上下文构成");
  });

  it("keeps the parsed summary but collapses it by default", () => {
    const html = render();
    expect(html).toContain("解析摘要");
    expect(html).toContain("usage_input");
    const details = html.slice(html.indexOf("原始解析键值") - 400, html.indexOf("原始解析键值"));
    expect(details).toContain("<details");
    expect(details).not.toContain("open");
  });
});

describe("composition bar", () => {
  it("draws one segment per non-empty category with Chinese labels", () => {
    const html = renderToStaticMarkup(<CompositionBar values={values({ system: 100, tool_result: 300 })} contextWindow={1000} />);
    expect(html).toContain("系统提示 100");
    expect(html).toContain("工具结果 300");
    expect(html).not.toContain("用户");
    // Scaled to the window: 100 of 1000 is 10%.
    expect(html).toContain('width="10%"');
    expect(html).toContain('x="10%"');
  });

  it("lists all eight categories in the legend", () => {
    const html = renderToStaticMarkup(<CategoryLegend />);
    for (const label of ["系统提示", "工具定义", "用户", "注入上下文", "助手", "推理", "工具结果", "多媒体"]) {
      expect(html).toContain(label);
    }
  });

  it("colors occupancy red from 90% and amber from 70%", () => {
    expect(renderToStaticMarkup(<OccupancyText lastPrompt={92} contextWindow={100} />)).toContain('data-level="danger"');
    expect(renderToStaticMarkup(<OccupancyText lastPrompt={75} contextWindow={100} />)).toContain('data-level="warn"');
    expect(renderToStaticMarkup(<OccupancyText lastPrompt={10} contextWindow={100} />)).toContain('data-level="ok"');
    expect(renderToStaticMarkup(<OccupancyText lastPrompt={10} contextWindow={null} />)).toContain("窗口未知");
  });
});

describe("overview", () => {
  const overview: OverviewResponse = {
    from_ns: "1",
    to_ns: "2",
    totals: usage({ requests: 1234, unpriced_requests: 7 }),
    sessions: 12,
    trees: 3,
    daily: [{ day: "2026-10-16", usage: usage() }],
    heatmap: [],
    group_by: "model",
    groups: [{ key: "m", label: "gpt-test", usage: usage({ unpriced_requests: 1 }) }],
    composition: values({ user: 1 }),
  };

  it("labels cost as an estimate and flags unpriced models", () => {
    const html = renderToStaticMarkup(<KpiBar overview={overview} />);
    for (const label of ["请求数", "会话数", "Agent 树数", "prompt 总量", "输出", "缓存命中率", "估算成本"]) {
      expect(html).toContain(label);
    }
    expect(html).toContain("部分模型未知价格");
    expect(html).toContain("80.0%");
    expect(renderToStaticMarkup(<KpiBar overview={{ ...overview, totals: usage() }} />)).not.toContain("部分模型未知价格");
  });

  it("hides caller and token grouping for developers", () => {
    expect(groupOptions(false).map((option) => option.value)).toEqual(["model", "protocol", "client", "caller", "token"]);
    expect(groupOptions(true).map((option) => option.value)).toEqual(["model", "protocol", "client"]);
  });

  it("renders the group table and daily rows", () => {
    expect(renderToStaticMarkup(<GroupTable groups={overview.groups} />)).toContain("gpt-test");
    expect(renderToStaticMarkup(<GroupTable groups={[]} />)).toContain("没有可分组的数据");
    expect(dailyRows(overview.daily)[0]).toMatchObject({ label: "10-16", tokens: 1250, cost: 0.1234 });
  });

  it("renders an 8-week heatmap with clickable day cells", () => {
    const html = renderToStaticMarkup(
      <ActivityHeatmap days={[{ day: "2026-10-16", requests: 5, sessions: 2 }]} today="2026-10-16" selectedDay="2026-10-16" onSelectDay={noop} />,
    );
    expect(html).toContain("2026-10-16 · 5 次请求 · 2 个会话");
    expect(html).toContain('aria-pressed="true"');
    // 7 full weeks of 7 days plus Sunday..Friday of the current week.
    expect(html.match(/role="button"/g)?.length).toBe(7 * 7 + 6);
  });
});

describe("session card", () => {
  const card: SessionCard = {
    session_id: "ses_abc",
    session_link: "agent",
    protocol: "anthropic",
    client: "claude_code",
    role: "main",
    first_ns: "1",
    last_ns: "2",
    steps: 10,
    turns: 3,
    models: ["claude-test"],
    usage: usage({ unpriced_requests: 2 }),
    last_composition: values({ user: 10 }),
    last_prompt_total: 95,
    context_window: 100,
    subagents: 2,
    caller: null,
  };

  it("shows badges, subagent count and the tree button only for tree members", () => {
    const html = renderToStaticMarkup(<SessionCardView card={{ ...card, tree_id: "t1" }} onOpenSession={noop} onOpenTree={noop} />);
    expect(html).toContain("Claude Code");
    expect(html).toContain("主 Agent");
    expect(html).toContain("含 2 个子 Agent");
    expect(html).toContain("查看 Agent 树");
    expect(html).toContain("部分未知价格");
    expect(html).toContain('data-level="danger"');
    expect(html).not.toContain("调用者");
    expect(renderToStaticMarkup(<SessionCardView card={card} onOpenSession={noop} onOpenTree={noop} />)).not.toContain("查看 Agent 树");
  });

  it("shows the caller for administrators", () => {
    const html = renderToStaticMarkup(
      <SessionCardView card={{ ...card, caller: { username: "alice", token_name: "dev" } }} onOpenSession={noop} onOpenTree={noop} />,
    );
    expect(html).toContain("alice · dev");
  });
});

describe("trend tooltip", () => {
  function step(extra: Partial<TrendStep> = {}): TrendStep {
    return {
      audit_id: "a1",
      started_at_ns: "1",
      turn: 1,
      turn_start: true,
      model: "m1",
      role: "main",
      estimate: values({ system: 100, tool_result: 100 }),
      usage: { uncached_input: 50, cache_read: 900, cache_write: 50, output: 20, reasoning: 5 },
      prompt_total: 1000,
      events: ["compaction"],
      appended_items: 1,
      removed_items: 0,
      response_kinds: ["text"],
      first_event_ms: 640,
      generation_ms: 2500,
      client_gap_ms: 8000,
      cost_usd: 0.02,
      ...extra,
    };
  }

  it("shows anchored values, real usage, timing and cost", () => {
    const [row] = buildChartRows(stepBars([step()]), "total", "step");
    const html = renderToStaticMarkup(<TrendTooltipBody row={row} mode="total" granularity="step" />);
    expect(html).toContain("已锚定到 prompt 总量");
    expect(html).toContain("客户端侧时间（工具执行+等待）");
    expect(html).toContain("8.00 s");
    expect(html).toContain("首事件延迟");
    expect(html).toContain("压缩(推断)");
    expect(html).toContain("$0.02");
    expect(html).toContain("缓存读取");
  });

  it("shows the net change in delta mode and flags missing usage", () => {
    const rows = buildChartRows(stepBars([step(), step({ audit_id: "a2", estimate: values({ system: 100 }), prompt_total: null })]), "delta", "step");
    const html = renderToStaticMarkup(<TrendTooltipBody row={rows[1]} mode="delta" granularity="step" />);
    expect(html).toContain("净变化");
    expect(html).toContain("-900");
    const total = renderToStaticMarkup(<TrendTooltipBody row={buildChartRows(stepBars([step({ prompt_total: null })]), "total", "step")[0]} mode="total" granularity="step" />);
    expect(total).toContain("估算，无 usage");
  });
});

describe("agent tree", () => {
  function node(id: string, parent: string | undefined, extra: Partial<TreeNode> = {}): TreeNode {
    return {
      node_id: id,
      parent_node_id: parent,
      visible: true,
      session_id: `ses_${id}`,
      client: "codex",
      role: parent ? "subagent" : "main",
      first_ns: "1",
      last_ns: "2",
      steps: 5,
      aux_requests: 1,
      usage: usage(),
      last_composition: values({ user: 10 }),
      last_prompt_total: 50,
      context_window: 100,
      ...extra,
    };
  }

  it("labels the link source", () => {
    expect(linkSourceLabel({ link_source: "header" })).toBe("精确");
    expect(linkSourceLabel({ link_source: "body" })).toBe("回链");
    expect(linkSourceLabel({ link_source: "content", link_confidence: 82 })).toBe("推断 82%");
    expect(linkSourceLabel({})).toBeNull();
  });

  it("places children right of their parent without overlap", () => {
    const { placed } = placeNodes([node("r", undefined), node("a", "r"), node("b", "r"), node("c", "a")]);
    const at = (id: string) => placed.find((entry) => entry.node.node_id === id)!;
    expect(at("a").left).toBeGreaterThan(at("r").left);
    expect(at("c").left).toBeGreaterThan(at("a").left);
    expect(Math.abs(at("a").top - at("b").top)).toBeGreaterThan(100);
  });

  it("shares one lineage hue per branch of the root", () => {
    const { placed } = placeNodes([node("r", undefined), node("a", "r"), node("b", "r"), node("a1", "a"), node("a11", "a1")]);
    const lineage = (id: string) => placed.find((entry) => entry.node.node_id === id)!.lineage;
    expect(lineage("a1")).toBe(lineage("a"));
    expect(lineage("a11")).toBe(lineage("a"));
    expect(lineage("b")).not.toBe(lineage("a"));
  });

  it("renders cards, a greyed placeholder and an indented list fallback", () => {
    const html = renderToStaticMarkup(
      <AgentTree
        nodes={[
          node("p", undefined, { visible: false, session_id: undefined }),
          node("a", "p", { link_source: "header", last_prompt_total: 95 }),
          node("b", "p", { link_source: "content", link_confidence: 70, last_prompt_total: 75 }),
        ]}
        onOpenNode={noop}
      />,
    );
    expect(html).toContain("不可见的父 Agent");
    expect(html).toContain('data-placeholder="true"');
    expect(html).toContain("精确");
    expect(html).toContain("推断 70%");
    expect(html).toContain('data-occupancy="danger"');
    expect(html).toContain('data-occupancy="warn"');
    expect(html).toContain("附属请求 1");
    expect(html).toContain('data-testid="agent-tree-list"');
    expect(html).toContain("md:hidden");
  });

  it("explains an empty tree", () => {
    expect(renderToStaticMarkup(<AgentTree nodes={[]} onOpenNode={noop} />)).toContain("没有可展示的节点");
  });
});

describe("audit composition panel", () => {
  const item = (index: number, category: string, kind: string, tokens: number, extra: { label?: string; summary?: string; change?: string } = {}) => ({
    index,
    category,
    role: "user",
    kind,
    tokens,
    ...extra,
  });
  const data: CompositionResponse = {
    audit_id: "aud_1",
    analysis_version: 1,
    model: "claude-test",
    usage: { uncached_input: 10, cache_read: 80, cache_write: 10, output: 5, reasoning: null },
    prompt_total: 100,
    estimate: values({ system: 20, tool_result: 60 }),
    anchored: values({ system: 25, tool_result: 75 }),
    context_window: 1000,
    items: [
      item(0, "system", "system", 20, { summary: "You are <b>helpful</b>" }),
      item(1, "tool_result", "tool_result", 40, { label: "Read", summary: "file body", change: "added" }),
      item(2, "tool_result", "tool_result", 20, { label: "Read", change: "kept" }),
      item(3, "assistant", "thinking", 5, { label: "thinking" }),
      item(4, "assistant", "text", 7, { change: "added" }),
    ],
    tools: [
      { name: "small", tokens: 5, source: "custom" },
      { name: "mcp__gh__issue", tokens: 50, source: "mcp:gh" },
      { name: "Read", tokens: 20, source: "builtin" },
    ],
    file_ops: [{ tool: "Edit", op: "write", path: "src/a.ts", added_lines: 4, removed_lines: 1 }],
    agent: { client: "claude_code", role: "subagent", node_id: "n-1", parent_id: "p-1", root_id: "r-1", name: "researcher", link_source: "content", confidence: 80 },
    previous_audit_id: "aud_0",
    diff: { added_items: 2, removed_items: 1, by_category: values({ tool_result: 4500, assistant: -300 }) },
    events: ["system_changed"],
    truncated: true,
  };

  it("renders the stacked bar, per-category lists and diff badges", () => {
    const html = renderToStaticMarkup(<CompositionPanel data={data} />);
    expect(html).toContain("上下文窗口占用");
    expect(html).toContain("已按上游报告的 prompt 总量锚定");
    expect(html).toContain("+1 项"); // one added tool_result item
    expect(html).toContain("+4.5k");
    expect(html).toContain("-300");
    expect(html).toContain("新增");
    expect(html).toContain("条目清单已截断");
    expect(html).toContain("系统提示变化");
    expect(html).toContain("相对上一步：新增");
    for (const chip of ["Thinking", "Tools", "Answer"]) {
      expect(html).toContain(chip);
    }
  });

  it("escapes item summaries instead of rendering HTML", () => {
    const html = renderToStaticMarkup(<CompositionPanel data={data} />);
    expect(html).toContain("You are &lt;b&gt;helpful&lt;/b&gt;");
    expect(html).not.toContain("<b>helpful</b>");
  });

  it("sorts tools by tokens and labels their source", () => {
    expect(sortTools(data.tools).map((tool) => tool.name)).toEqual(["mcp__gh__issue", "Read", "small"]);
    expect(toolSourceLabel("mcp:gh").label).toBe("MCP · gh");
    expect(toolSourceLabel("builtin").label).toBe("内置");
    expect(toolSourceLabel("custom").label).toBe("自定义");
    const html = renderToStaticMarkup(<CompositionPanel data={data} />);
    expect(html.indexOf("mcp__gh__issue")).toBeLessThan(html.indexOf('title="Read"'));
    expect(html).toContain("MCP · gh");
  });

  it("shows file operations and the agent identity", () => {
    const html = renderToStaticMarkup(<CompositionPanel data={data} />);
    expect(html).toContain("src/a.ts");
    expect(html).toContain("+4");
    expect(html).toContain("−1");
    expect(html).toContain("researcher");
    expect(html).toContain("n-1");
    expect(html).toContain("内容匹配（推断 80%）");
    expect(html).toContain("子 Agent");
  });

  it("draws a treemap and a DNA strip that marks added items", () => {
    const html = renderToStaticMarkup(<CompositionPanel data={data} />);
    expect(html).toContain('aria-label="上下文构成 Treemap"');
    expect(html).toContain('aria-label="提示词 DNA 条带"');
    expect(html).toContain('data-added="true"');
  });

  it("falls back to raw estimates without usage", () => {
    const html = renderToStaticMarkup(
      <CompositionPanel data={{ ...data, anchored: null, prompt_total: null, previous_audit_id: undefined, diff: null }} />,
    );
    expect(html).toContain("没有 usage");
    expect(html).toContain("没有上一步可对比");
  });
});
