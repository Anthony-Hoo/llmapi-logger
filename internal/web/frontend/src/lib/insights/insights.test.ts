import { describe, expect, it } from "vitest";

import type { CategoryValues, CompositionItem, TrendStep } from "../../types";
import {
  anchorToPrompt,
  CATEGORIES,
  emptyCategoryValues,
  normalizeCategoryValues,
  sumCategories,
} from "./categories";
import { buildDnaBands } from "./dna";
import {
  formatMillis,
  formatRatio,
  formatSignedTokens,
  formatTokens,
  formatUSD,
  occupancy,
  occupancyLevel,
} from "./format";
import { buildHeatGrid, heatLevel } from "./heatmap";
import { dayRange, localDayString, rangeForDays, startOfLocalDayMS } from "./range";
import { aggregateByTurn, buildChartRows, computeDeltas, netDelta, stepBars, sumNullable } from "./trend";
import { buildTreemapData, layoutTreemap, squarify } from "./treemap";
import { lineageHue, tidyLayout } from "./tree-layout";

function values(partial: Partial<CategoryValues>): CategoryValues {
  return { ...emptyCategoryValues(), ...partial };
}

function step(id: string, turn: number, estimate: Partial<CategoryValues>, extra: Partial<TrendStep> = {}): TrendStep {
  return {
    audit_id: id,
    started_at_ns: "1",
    turn,
    turn_start: false,
    model: "m",
    role: "main",
    estimate: values(estimate),
    usage: { uncached_input: null, cache_read: null, cache_write: null, output: null, reasoning: null },
    prompt_total: null,
    events: [],
    appended_items: null,
    removed_items: null,
    response_kinds: [],
    first_event_ms: null,
    generation_ms: null,
    client_gap_ms: null,
    cost_usd: null,
    ...extra,
  };
}

describe("formatting", () => {
  it("abbreviates token counts", () => {
    expect(formatTokens(0)).toBe("0");
    expect(formatTokens(999)).toBe("999");
    expect(formatTokens(1000)).toBe("1k");
    expect(formatTokens(12_345)).toBe("12.3k");
    expect(formatTokens(99_949)).toBe("99.9k");
    expect(formatTokens(123_456)).toBe("123k");
    expect(formatTokens(1_250_000)).toBe("1.25M");
    expect(formatTokens(-4200)).toBe("-4.2k");
    expect(formatTokens(null)).toBe("—");
    expect(formatSignedTokens(1500)).toBe("+1.5k");
    expect(formatSignedTokens(-300)).toBe("-300");
  });

  it("formats cost, ratio, time and occupancy", () => {
    expect(formatUSD(null)).toBe("—");
    expect(formatUSD(0)).toBe("$0");
    expect(formatUSD(0.00421)).toBe("$0.0042");
    expect(formatUSD(12.345)).toBe("$12.35");
    expect(formatRatio(0.4237)).toBe("42.4%");
    expect(formatMillis(250)).toBe("250 ms");
    expect(formatMillis(2500)).toBe("2.50 s");
    expect(occupancy(90, 100)).toBe(0.9);
    expect(occupancy(null, 100)).toBeNull();
    expect(occupancyLevel(0.95)).toBe("danger");
    expect(occupancyLevel(0.7)).toBe("warn");
    expect(occupancyLevel(0.69)).toBe("ok");
  });
});

describe("categories", () => {
  it("defines eight unique colors and Chinese labels", () => {
    expect(CATEGORIES.map((category) => category.label)).toEqual([
      "系统提示",
      "工具定义",
      "用户",
      "注入上下文",
      "助手",
      "推理",
      "工具结果",
      "多媒体",
    ]);
    expect(new Set(CATEGORIES.map((category) => category.color)).size).toBe(8);
  });

  it("anchors estimates to the reported prompt total", () => {
    const anchored = anchorToPrompt(values({ system: 100, user: 300 }), 1000);
    expect(anchored.system).toBe(250);
    expect(anchored.user).toBe(750);
    expect(sumCategories(anchored)).toBe(1000);
    expect(anchorToPrompt(values({ user: 40 }), null).user).toBe(40);
    expect(anchorToPrompt(values({}), 500)).toEqual(emptyCategoryValues());
    expect(normalizeCategoryValues(null)).toEqual(emptyCategoryValues());
  });
});

describe("turn aggregation", () => {
  it("collapses consecutive equal turns to the last step and sums timings", () => {
    const steps = [
      step("a1", 1, { user: 10 }, { generation_ms: 100, client_gap_ms: null, cost_usd: 0.01, events: ["injected"] }),
      step("a2", 1, { user: 10, tool_result: 20 }, { generation_ms: 50, client_gap_ms: 400, cost_usd: 0.02, events: ["injected", "compaction"] }),
      step("a3", 1, { user: 10, tool_result: 40 }, { generation_ms: 25, client_gap_ms: 100, cost_usd: null }),
      step("b1", 2, { user: 50, tool_result: 40 }, { generation_ms: 10 }),
    ];
    const bars = aggregateByTurn(steps);
    expect(bars).toHaveLength(2);
    expect(bars[0].auditID).toBe("a3");
    expect(bars[0].steps).toBe(3);
    expect(bars[0].estimate.tool_result).toBe(40);
    expect(bars[0].generationMS).toBe(175);
    expect(bars[0].clientGapMS).toBe(500);
    expect(bars[0].costUSD).toBeCloseTo(0.03);
    expect(bars[0].events).toEqual(["injected", "compaction"]);
    expect(bars[1].steps).toBe(1);
    expect(bars[1].clientGapMS).toBeNull();
    // Folding must not lose requests.
    expect(bars.reduce((total, bar) => total + bar.steps, 0)).toBe(steps.length);
  });

  it("only folds runs, not repeated turn numbers elsewhere", () => {
    const bars = aggregateByTurn([step("a", 1, {}), step("b", 2, {}), step("c", 1, {})]);
    expect(bars.map((bar) => bar.auditID)).toEqual(["a", "b", "c"]);
    expect(aggregateByTurn([])).toEqual([]);
    expect(stepBars([step("a", 1, {}), step("b", 1, {})])).toHaveLength(2);
  });

  it("sums nullable values", () => {
    expect(sumNullable([null, null])).toBeNull();
    expect(sumNullable([1, null, 2])).toBe(3);
  });
});

describe("delta computation", () => {
  it("is the signed per-category difference from the previous bar", () => {
    const bars = stepBars([
      step("a", 1, { system: 100, user: 50 }),
      step("b", 1, { system: 100, user: 50, tool_result: 200 }),
      step("c", 2, { system: 100, user: 20, tool_result: 40 }),
    ]);
    const deltas = computeDeltas(bars);
    expect(deltas[0].system).toBe(100);
    expect(deltas[1]).toEqual(values({ tool_result: 200 }));
    expect(deltas[2].user).toBe(-30);
    expect(deltas[2].tool_result).toBe(-160);
    expect(netDelta(deltas[2])).toBe(-190);
  });

  it("feeds recharts rows with anchored totals or signed deltas", () => {
    const bars = stepBars([
      step("a", 1, { system: 1, user: 1 }, { prompt_total: 200 }),
      step("b", 1, { system: 1 }, { prompt_total: 100 }),
    ]);
    const total = buildChartRows(bars, "total", "step");
    expect(total[0].system).toBe(100);
    expect(total[1].system).toBe(100);
    expect(total[0].label).toBe("#1");
    const delta = buildChartRows(bars, "delta", "turn");
    expect(delta[1].user).toBe(-100);
    expect(delta[1].net).toBe(-100);
    expect(delta[1].label).toBe("轮 1");
  });
});

describe("heatmap", () => {
  it("assigns four levels by quartile of the maximum", () => {
    expect(heatLevel(0, 100)).toBe(0);
    expect(heatLevel(1, 100)).toBe(1);
    expect(heatLevel(25, 100)).toBe(1);
    expect(heatLevel(26, 100)).toBe(2);
    expect(heatLevel(50, 100)).toBe(2);
    expect(heatLevel(75, 100)).toBe(3);
    expect(heatLevel(76, 100)).toBe(4);
    expect(heatLevel(100, 100)).toBe(4);
    expect(heatLevel(5, 0)).toBe(0);
  });

  it("lays eight weeks out Sunday first and leaves future days empty", () => {
    // 2026-10-16 is a Friday.
    const grid = buildHeatGrid(
      [
        { day: "2026-10-16", requests: 8, sessions: 2 },
        { day: "2026-10-11", requests: 2, sessions: 1 },
        { day: "2026-08-23", requests: 4, sessions: 1 },
      ],
      "2026-10-16",
    );
    expect(grid.weeks).toBe(8);
    expect(grid.rows).toHaveLength(7);
    expect(grid.rows[0][0]?.day).toBe("2026-08-23"); // first Sunday, 7 weeks before the current one
    expect(grid.rows[0][7]?.day).toBe("2026-10-11");
    expect(grid.rows[5][7]?.day).toBe("2026-10-16");
    expect(grid.rows[6][7]).toBeNull();
    expect(grid.max).toBe(8);
    expect(grid.rows[5][7]?.level).toBe(4);
    expect(grid.rows[0][7]?.level).toBe(1);
    expect(grid.rows[0][0]?.level).toBe(2);
    expect(grid.rows[1][0]?.requests).toBe(0);
  });
});

describe("ranges", () => {
  it("aligns to local day boundaries and caps at 400 days", () => {
    const now = Date.UTC(2026, 9, 16, 20, 30); // 04:30 on the 17th at UTC+8
    const todayStart = startOfLocalDayMS(now, 480);
    expect(new Date(todayStart).toISOString()).toBe("2026-10-16T16:00:00.000Z");
    expect(localDayString(now, 480)).toBe("2026-10-17");
    const week = rangeForDays(7, now, 480);
    expect(BigInt(week.to_ns) - BigInt(week.from_ns)).toBe(7n * 86_400_000_000_000n);
    expect(BigInt(week.to_ns)).toBe(BigInt(todayStart + 86_400_000) * 1_000_000n);
    const all = rangeForDays(10_000, now, 0);
    expect(BigInt(all.to_ns) - BigInt(all.from_ns)).toBe(400n * 86_400_000_000_000n);
  });

  it("converts a heatmap day to a half-open range", () => {
    const range = dayRange("2026-10-17", 480);
    expect(range).not.toBeNull();
    expect(new Date(Number(BigInt(range!.from_ns) / 1_000_000n)).toISOString()).toBe("2026-10-16T16:00:00.000Z");
    expect(BigInt(range!.to_ns) - BigInt(range!.from_ns)).toBe(86_400_000_000_000n);
    expect(dayRange("nope", 0)).toBeNull();
  });
});

describe("treemap", () => {
  it("tiles the rectangle exactly with areas proportional to values", () => {
    const rect = { x: 0, y: 0, w: 600, h: 400 };
    const cells = squarify(
      [
        { id: "a", value: 6 },
        { id: "b", value: 6 },
        { id: "c", value: 4 },
        { id: "d", value: 3 },
        { id: "e", value: 2 },
        { id: "f", value: 2 },
        { id: "g", value: 1 },
      ],
      rect,
    );
    expect(cells).toHaveLength(7);
    const total = cells.reduce((sum, cell) => sum + cell.rect.w * cell.rect.h, 0);
    expect(total).toBeCloseTo(600 * 400, 3);
    for (const cell of cells) {
      expect(cell.rect.w * cell.rect.h).toBeCloseTo((cell.item.value / 24) * 600 * 400, 3);
      expect(cell.rect.x).toBeGreaterThanOrEqual(-1e-9);
      expect(cell.rect.y).toBeGreaterThanOrEqual(-1e-9);
      expect(cell.rect.x + cell.rect.w).toBeLessThanOrEqual(600 + 1e-6);
      expect(cell.rect.y + cell.rect.h).toBeLessThanOrEqual(400 + 1e-6);
    }
    // No overlaps.
    for (let i = 0; i < cells.length; i += 1) {
      for (let j = i + 1; j < cells.length; j += 1) {
        const a = cells[i].rect;
        const b = cells[j].rect;
        const overlapW = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
        const overlapH = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
        expect(overlapW > 1e-6 && overlapH > 1e-6).toBe(false);
      }
    }
    // Squarification keeps aspect ratios modest.
    for (const cell of cells) {
      expect(Math.max(cell.rect.w / cell.rect.h, cell.rect.h / cell.rect.w)).toBeLessThan(4);
    }
  });

  it("ignores empty input and non-positive values", () => {
    expect(squarify([], { x: 0, y: 0, w: 10, h: 10 })).toEqual([]);
    expect(squarify([{ id: "z", value: 0 }], { x: 0, y: 0, w: 10, h: 10 })).toEqual([]);
  });

  it("keeps the top 11 groups per category and sums the rest into 其他", () => {
    const items = Array.from({ length: 15 }, (_, index) => ({
      category: "tool_result",
      kind: "tool_result",
      label: `tool-${index}`,
      tokens: 100 - index,
    }));
    items.push({ category: "user", kind: "text", label: "", tokens: 10 });
    items.push({ category: "tool_result", kind: "tool_result", label: "tool-0", tokens: 5 });
    const data = buildTreemapData(items);
    expect(data.map((entry) => entry.category)).toEqual(["user", "tool_result"]);
    const results = data[1];
    expect(results.groups).toHaveLength(12);
    expect(results.groups[0]).toMatchObject({ name: "tool-0", tokens: 105, count: 2 });
    const other = results.groups[11];
    expect(other).toMatchObject({ name: "其他", other: true, count: 4 });
    expect(other.tokens).toBe(89 + 88 + 87 + 86);
    expect(results.groups.reduce((sum, group) => sum + group.tokens, 0)).toBe(results.tokens);
    expect(data[0].groups[0].name).toBe("文本");

    const laid = layoutTreemap(data, { x: 0, y: 0, w: 800, h: 360 });
    expect(laid).toHaveLength(2);
    for (const category of laid) {
      for (const group of category.groups) {
        expect(group.rect.x).toBeGreaterThanOrEqual(category.rect.x - 1e-6);
        expect(group.rect.x + group.rect.w).toBeLessThanOrEqual(category.rect.x + category.rect.w + 1e-6);
        expect(group.rect.y + group.rect.h).toBeLessThanOrEqual(category.rect.y + category.rect.h + 1e-6);
      }
    }
  });
});

describe("tidy tree layout", () => {
  it("centers parents over children and separates siblings", () => {
    const layout = tidyLayout([
      { id: "root" },
      { id: "a", parentId: "root" },
      { id: "b", parentId: "root" },
      { id: "a1", parentId: "a" },
      { id: "a2", parentId: "a" },
      { id: "a3", parentId: "a" },
    ]);
    const at = (id: string) => layout.nodes.find((node) => node.id === id)!;
    expect(at("root").depth).toBe(0);
    expect(at("a1").depth).toBe(2);
    expect(at("a2").x - at("a1").x).toBeCloseTo(1);
    expect(at("a").x).toBeCloseTo(at("a2").x);
    expect(at("root").x).toBeCloseTo((at("a").x + at("b").x) / 2);
    // b is a leaf: only its depth is compared with a, so it sits one unit away.
    expect(at("b").x - at("a").x).toBeCloseTo(1);
    expect(layout.levels).toBe(3);
    expect(Math.min(...layout.nodes.map((node) => node.x))).toBe(0);
  });

  it("never overlaps nodes on one depth and packs narrow subtrees tightly", () => {
    const inputs = [
      { id: "r" },
      { id: "l", parentId: "r" },
      { id: "m", parentId: "r" },
      { id: "l1", parentId: "l" },
      { id: "l2", parentId: "l" },
      { id: "l11", parentId: "l1" },
      { id: "m1", parentId: "m" },
    ];
    const layout = tidyLayout(inputs);
    const byDepth = new Map<number, number[]>();
    for (const node of layout.nodes) {
      byDepth.set(node.depth, [...(byDepth.get(node.depth) ?? []), node.x].sort((a, b) => a - b));
    }
    for (const xs of byDepth.values()) {
      for (let i = 1; i < xs.length; i += 1) {
        expect(xs[i] - xs[i - 1]).toBeGreaterThanOrEqual(1 - 1e-9);
      }
    }
    // l has two children (spread +-0.5) and m one child, so the contours at
    // depth 1 force a 1.5 gap; the deeper l11 level does not push m further.
    const x = (id: string) => layout.nodes.find((node) => node.id === id)!.x;
    expect(x("m") - x("l")).toBeCloseTo(1.5);
    expect(layout.nodes).toHaveLength(inputs.length);
  });

  it("handles forests, unknown parents and cycles", () => {
    const forest = tidyLayout([{ id: "x", parentId: "gone" }, { id: "y" }]);
    expect(forest.nodes.every((node) => node.depth === 0)).toBe(true);
    expect(Math.abs(forest.nodes[0].x - forest.nodes[1].x)).toBeGreaterThanOrEqual(1);
    const cyclic = tidyLayout([{ id: "p", parentId: "q" }, { id: "q", parentId: "p" }]);
    expect(cyclic.nodes).toHaveLength(2);
    expect(tidyLayout([]).nodes).toEqual([]);
  });

  it("uses the golden angle for lineage hues", () => {
    expect(lineageHue(0)).toBe(0);
    expect(lineageHue(1)).toBeCloseTo(137.508);
    expect(lineageHue(3)).toBeCloseTo((3 * 137.508) % 360);
  });
});

describe("dna strip", () => {
  const item = (index: number, category: string, tokens: number, change?: string): CompositionItem => ({
    index,
    category,
    role: "user",
    kind: "text",
    tokens,
    change,
  });

  it("orders bands by prompt position with widths proportional to tokens", () => {
    const bands = buildDnaBands([item(2, "user", 100, "added"), item(0, "system", 300), item(1, "tools", 100), item(3, "media", 0)], 1000, 0);
    expect(bands.map((band) => band.index)).toEqual([0, 1, 2]);
    expect(bands[0].width).toBeCloseTo(600);
    expect(bands[1].x).toBeCloseTo(600);
    expect(bands[2].added).toBe(true);
    expect(bands.reduce((sum, band) => sum + band.width, 0)).toBeCloseTo(1000);
    expect(buildDnaBands([], 1000)).toEqual([]);
  });

  it("keeps tiny items visible", () => {
    const bands = buildDnaBands([item(0, "system", 1_000_000), item(1, "user", 1)], 1000, 1.5);
    expect(bands[1].width).toBeGreaterThan(1.4);
    expect(bands.reduce((sum, band) => sum + band.width, 0)).toBeCloseTo(1000);
  });
});
