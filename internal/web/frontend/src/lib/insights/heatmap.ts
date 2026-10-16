import type { HeatmapDay } from "../../types";

export const HEATMAP_WEEKS = 8;

/** Row labels, Sunday first. */
export const WEEKDAY_LABELS = ["日", "一", "二", "三", "四", "五", "六"] as const;

export type HeatLevel = 0 | 1 | 2 | 3 | 4;

/**
 * 0 for no activity, otherwise 1-4 by quartile of the busiest day: up to 25% of
 * the maximum is level 1, up to 50% level 2, up to 75% level 3, above that 4.
 */
export function heatLevel(value: number, max: number): HeatLevel {
  if (!(value > 0) || !(max > 0)) {
    return 0;
  }
  const ratio = value / max;
  if (ratio <= 0.25) {
    return 1;
  }
  if (ratio <= 0.5) {
    return 2;
  }
  if (ratio <= 0.75) {
    return 3;
  }
  return 4;
}

export interface HeatCell {
  day: string;
  requests: number;
  sessions: number;
  level: HeatLevel;
}

export interface HeatGrid {
  /** rows[0] is Sunday .. rows[6] is Saturday; each row has `weeks` columns. null: outside the window. */
  rows: Array<Array<HeatCell | null>>;
  weeks: number;
  max: number;
}

/**
 * Lays the last `weeks` calendar weeks (ending with the week of `today`) out as
 * seven Sunday-first rows. Days after `today` are null.
 */
export function buildHeatGrid(days: readonly HeatmapDay[], today: string, weeks = HEATMAP_WEEKS): HeatGrid {
  const byDay = new Map(days.map((entry) => [entry.day, entry]));
  const todayMS = parseDay(today);
  const rows: Array<Array<HeatCell | null>> = Array.from({ length: 7 }, () => Array<HeatCell | null>(weeks).fill(null));
  if (todayMS === null) {
    return { rows, weeks, max: 0 };
  }
  const todayWeekday = new Date(todayMS).getUTCDay();
  const firstSunday = todayMS - (todayWeekday + (weeks - 1) * 7) * 86_400_000;
  let max = 0;
  for (let week = 0; week < weeks; week += 1) {
    for (let weekday = 0; weekday < 7; weekday += 1) {
      const ms = firstSunday + (week * 7 + weekday) * 86_400_000;
      if (ms > todayMS) {
        continue;
      }
      const day = new Date(ms).toISOString().slice(0, 10);
      const entry = byDay.get(day);
      const requests = entry?.requests ?? 0;
      max = Math.max(max, requests);
      rows[weekday][week] = { day, requests, sessions: entry?.sessions ?? 0, level: 0 };
    }
  }
  for (const row of rows) {
    for (const cell of row) {
      if (cell) {
        cell.level = heatLevel(cell.requests, max);
      }
    }
  }
  return { rows, weeks, max };
}

function parseDay(day: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) {
    return null;
  }
  const ms = Date.parse(`${day}T00:00:00Z`);
  return Number.isNaN(ms) ? null : ms;
}
