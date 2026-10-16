import type { CategoryValues, InsightsUsage, NanoTime, TrendStep } from "../../types";
import {
  anchorToPrompt,
  CATEGORY_KEYS,
  emptyCategoryValues,
  normalizeCategoryValues,
  sumCategories,
} from "./categories";

export type TrendGranularity = "step" | "turn";
export type TrendMode = "total" | "delta";

/** One bar of the trend chart: a single request, or the end of a turn. */
export interface TrendBar {
  /** Stable React key. */
  key: string;
  /** 1-based display position. */
  position: number;
  /** Audit opened when the bar is clicked (the last step of the bar). */
  auditID: string;
  startedAtNS: NanoTime;
  turn: number;
  /** Number of requests folded into the bar (1 in step mode). */
  steps: number;
  model: string;
  /** Raw per-category estimate of the last step (a snapshot, not a sum). */
  estimate: CategoryValues;
  /** Estimate scaled to the reported prompt total when usage is present. */
  anchored: CategoryValues;
  anchoredToUsage: boolean;
  usage: InsightsUsage;
  promptTotal: number | null;
  events: string[];
  firstEventMS: number | null;
  generationMS: number | null;
  clientGapMS: number | null;
  costUSD: number | null;
}

/**
 * Collapses runs of consecutive steps with an equal `turn` into one bar. The
 * composition is a snapshot, so the last step's values win; generation time,
 * client gap and cost are summed, events are unioned in first-seen order.
 */
export function aggregateByTurn(steps: readonly TrendStep[]): TrendBar[] {
  const bars: TrendBar[] = [];
  let run: TrendStep[] = [];
  const flush = () => {
    if (run.length > 0) {
      bars.push(barFromRun(run, bars.length + 1));
      run = [];
    }
  };
  for (const step of steps) {
    if (run.length > 0 && run[run.length - 1].turn !== step.turn) {
      flush();
    }
    run.push(step);
  }
  flush();
  return bars;
}

/** One bar per step, no folding. */
export function stepBars(steps: readonly TrendStep[]): TrendBar[] {
  return steps.map((step, index) => barFromRun([step], index + 1));
}

export function buildBars(steps: readonly TrendStep[], granularity: TrendGranularity): TrendBar[] {
  return granularity === "turn" ? aggregateByTurn(steps) : stepBars(steps);
}

function barFromRun(run: readonly TrendStep[], position: number): TrendBar {
  const last = run[run.length - 1];
  const events: string[] = [];
  for (const step of run) {
    for (const event of step.events ?? []) {
      if (!events.includes(event)) {
        events.push(event);
      }
    }
  }
  const estimate = normalizeCategoryValues(last.estimate);
  const anchoredToUsage = last.prompt_total !== null && last.prompt_total > 0 && sumCategories(estimate) > 0;
  return {
    key: `${last.audit_id}:${position}`,
    position,
    auditID: last.audit_id,
    startedAtNS: last.started_at_ns,
    turn: last.turn,
    steps: run.length,
    model: last.model,
    estimate,
    anchored: anchorToPrompt(estimate, last.prompt_total),
    anchoredToUsage,
    usage: last.usage,
    promptTotal: last.prompt_total,
    events,
    firstEventMS: last.first_event_ms,
    generationMS: sumNullable(run.map((step) => step.generation_ms)),
    clientGapMS: sumNullable(run.map((step) => step.client_gap_ms)),
    costUSD: sumNullable(run.map((step) => step.cost_usd)),
  };
}

/** Sum of the non-null values, or null when every value is null. */
export function sumNullable(values: ReadonlyArray<number | null | undefined>): number | null {
  let total = 0;
  let seen = false;
  for (const value of values) {
    if (value !== null && value !== undefined && Number.isFinite(value)) {
      total += value;
      seen = true;
    }
  }
  return seen ? total : null;
}

/**
 * Signed per-category difference between each bar and the one before it; the
 * first bar is compared against an empty context. Positive values stack up,
 * negative values stack down in the chart. When the trend is truncated the
 * first visible bar has a real predecessor that was cut off, so its delta is
 * unavailable and stays zero instead of a huge artificial increase.
 */
export function computeDeltas(bars: readonly TrendBar[], truncated = false): CategoryValues[] {
  const deltas: CategoryValues[] = [];
  let previous = emptyCategoryValues();
  for (const [index, bar] of bars.entries()) {
    const delta = emptyCategoryValues();
    if (!(truncated && index === 0)) {
      for (const key of CATEGORY_KEYS) {
        delta[key] = bar.anchored[key] - previous[key];
      }
    }
    deltas.push(delta);
    previous = bar.anchored;
  }
  return deltas;
}

/** Net change (sum of signed category deltas) shown in the tooltip. */
export function netDelta(delta: CategoryValues): number {
  return sumCategories(delta);
}

/** Bar height in delta mode: sum of absolute category changes. */
export function absoluteDelta(delta: CategoryValues): number {
  return CATEGORY_KEYS.reduce((total, key) => total + Math.abs(delta[key]), 0);
}

export interface ChartRow {
  key: string;
  label: string;
  bar: TrendBar;
  /** Signed delta of this bar; zero values in total mode. */
  delta: CategoryValues;
  net: number;
  /** True for the first bar of a truncated trend: its delta has no predecessor. */
  boundary: boolean;
  [category: string]: unknown;
}

/**
 * Flattens bars into recharts rows. Total mode feeds the anchored category
 * values; delta mode feeds signed differences (recharts stacks them with
 * stackOffset="sign").
 */
export function buildChartRows(
  bars: readonly TrendBar[],
  mode: TrendMode,
  granularity: TrendGranularity,
  truncated = false,
): ChartRow[] {
  const deltas = computeDeltas(bars, truncated);
  return bars.map((bar, index) => {
    const delta = deltas[index];
    const source = mode === "delta" ? delta : bar.anchored;
    const row: ChartRow = {
      key: bar.key,
      label: granularity === "turn" ? `轮 ${bar.turn}` : `#${bar.position}`,
      bar,
      delta,
      net: netDelta(delta),
      boundary: truncated && index === 0,
    };
    for (const key of CATEGORY_KEYS) {
      row[key] = source[key];
    }
    return row;
  });
}
