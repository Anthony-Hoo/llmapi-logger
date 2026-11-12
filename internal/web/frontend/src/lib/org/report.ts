import { colorVar } from "../tokens";
import { PROJECT_NO_CONTEXT, PROJECT_UNATTRIBUTED, projectLabel } from "./format";
import type { OrgFlag, OrgMetric, OrgProjectCell, OrgProjectRef, OrgTokens, OrgTrendReport, OrgUserRow, OrgWeeklyReport } from "./types";

/** Project series colors reuse the categorical chart tokens, cycling. */
const PROJECT_PALETTE = [
  "cat-user",
  "cat-assistant",
  "cat-tools",
  "cat-reasoning",
  "cat-system",
  "cat-tool-result",
  "cat-media",
  "cat-injected",
  "primary-400",
  // The dark blue of the light theme and its light counterpart in the dark one.
  "info-fg",
];

export function projectColor(projectID: number, order: number): string {
  if (projectID === PROJECT_UNATTRIBUTED) {
    return colorVar("neutral-400");
  }
  if (projectID === PROJECT_NO_CONTEXT) {
    return colorVar("neutral-300");
  }
  return colorVar(PROJECT_PALETTE[order % PROJECT_PALETTE.length]);
}

export function tokenTotal(tokens: OrgTokens): number {
  return tokens.uncached + tokens.cache_read + tokens.cache_write + tokens.output;
}

/** The value of one cell or row in the selected metric (hours as hours). */
export function cellValue(cell: Pick<OrgProjectCell, "active_ns" | "tokens" | "cost_usd">, metric: OrgMetric): number {
  switch (metric) {
    case "tokens":
      return tokenTotal(cell.tokens);
    case "cost":
      return cell.cost_usd;
    default:
      return cell.active_ns / 3.6e12;
  }
}

export interface SeriesKey {
  key: string;
  project: number;
  label: string;
  color: string;
}

/** Stack series in a stable order: projects by id, then the two buckets. */
export function seriesKeys(projects: OrgProjectRef[], names: Record<string, string>): SeriesKey[] {
  const ordered = [...projects].sort((left, right) => left.id - right.id);
  const keys = ordered.map((project, index) => ({
    key: `p${project.id}`,
    project: project.id,
    label: project.name || projectLabel(project.id, names),
    color: projectColor(project.id, index),
  }));
  for (const bucket of [PROJECT_UNATTRIBUTED, PROJECT_NO_CONTEXT]) {
    keys.push({ key: bucket === PROJECT_UNATTRIBUTED ? "unattributed" : "no_context", project: bucket, label: projectLabel(bucket, names), color: projectColor(bucket, 0) });
  }
  return keys;
}

export function seriesKeyFor(project: number): string {
  if (project === PROJECT_UNATTRIBUTED) {
    return "unattributed";
  }
  if (project === PROJECT_NO_CONTEXT) {
    return "no_context";
  }
  return `p${project}`;
}

export type RankingRow = Record<string, number | string> & { user: string; user_id: number; total: number };

/** One chart row per ranked user, a numeric field per project series. */
export function rankingRows(report: OrgWeeklyReport, metric: OrgMetric, userName: (id: number) => string): RankingRow[] {
  return report.users.map((user) => {
    const row: RankingRow = { user: userName(user.user_id), user_id: user.user_id, total: rowValue(user, metric) };
    for (const cell of user.projects) {
      const key = seriesKeyFor(cell.project);
      row[key] = (Number(row[key]) || 0) + cellValue(cell, metric);
    }
    return row;
  });
}

/** The ranked figure of a row: ranked-client hours, or all tokens / cost. */
export function rowValue(row: OrgUserRow, metric: OrgMetric): number {
  return cellValue(row, metric);
}

/** Only series that carry a value somewhere, so the legend stays short. */
export function usedSeries(keys: SeriesKey[], rows: Array<Record<string, unknown>>): SeriesKey[] {
  return keys.filter((series) => rows.some((row) => Number(row[series.key]) > 0));
}

export interface MatrixCell {
  value: number;
  level: 0 | 1 | 2 | 3 | 4;
}

/** User x project matrix with five intensity levels relative to the max. */
export function buildMatrix(report: OrgWeeklyReport, metric: OrgMetric, series: SeriesKey[]): { rows: Array<{ user_id: number; cells: MatrixCell[] }>; max: number } {
  let maxValue = 0;
  const raw = report.users.map((user) => {
    const values = series.map((entry) => {
      const cell = user.projects.find((candidate) => candidate.project === entry.project);
      const value = cell ? cellValue(cell, metric) : 0;
      maxValue = Math.max(maxValue, value);
      return value;
    });
    return { user_id: user.user_id, values };
  });
  const level = (value: number): MatrixCell["level"] => {
    if (value <= 0 || maxValue <= 0) {
      return 0;
    }
    return Math.min(4, Math.max(1, Math.ceil((value / maxValue) * 4))) as MatrixCell["level"];
  };
  return { rows: raw.map((row) => ({ user_id: row.user_id, cells: row.values.map((value) => ({ value, level: level(value) })) })), max: maxValue };
}

export const MATRIX_COLORS: Record<MatrixCell["level"], string> = {
  0: colorVar("surface-sunken"),
  1: colorVar("heat-1"),
  2: colorVar("heat-2"),
  3: colorVar("heat-3"),
  4: colorVar("heat-4"),
};

/** Weekly trend rows (hours), one numeric field per project series. */
export function trendRows(trend: OrgTrendReport, metric: OrgMetric): Array<Record<string, number | string>> {
  return trend.weeks.map((week) => {
    const row: Record<string, number | string> = { week: week.week.slice(5), label: week.week };
    for (const cell of week.projects) {
      row[seriesKeyFor(cell.project)] = cellValue(cell, metric);
    }
    return row;
  });
}

export function flagLabel(flag: OrgFlag): string {
  switch (flag.code) {
    case "concurrency":
      return `并行峰值 ${flag.value}（阈值 ${flag.threshold ?? "-"}）`;
    case "single_request_roots":
      return `单请求会话 ${flag.value} 个（阈值 ${flag.threshold ?? "-"}）`;
    case "inferred_sessions":
      return "含推断会话";
    default:
      return flag.code;
  }
}

/** Anomaly flags are warnings; the inferred note is informational. */
export function flagVariant(flag: OrgFlag): "warning" | "info" {
  return flag.code === "inferred_sessions" ? "info" : "warning";
}

export function formatMetric(value: number, metric: OrgMetric): string {
  switch (metric) {
    case "tokens":
      if (value >= 1e9) {
        return `${(value / 1e9).toFixed(1)}B`;
      }
      if (value >= 1e6) {
        return `${(value / 1e6).toFixed(1)}M`;
      }
      if (value >= 1e3) {
        return `${(value / 1e3).toFixed(1)}K`;
      }
      return String(Math.round(value));
    case "cost":
      return `$${value.toFixed(2)}`;
    default:
      return value >= 10 ? `${value.toFixed(0)} h` : `${value.toFixed(1)} h`;
  }
}
