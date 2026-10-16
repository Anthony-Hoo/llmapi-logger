/** Largest window the insights API accepts (doc 20 §7). */
export const MAX_RANGE_DAYS = 400;

export type RangeKey = "7d" | "30d" | "all";

export const RANGE_OPTIONS: ReadonlyArray<{ key: RangeKey; label: string; days: number }> = [
  { key: "7d", label: "7 天", days: 7 },
  { key: "30d", label: "30 天", days: 30 },
  { key: "all", label: "全部", days: MAX_RANGE_DAYS },
];

const DAY_MS = 86_400_000;

/** Minutes east of UTC (UTC+8 -> 480), the inverse of Date#getTimezoneOffset. */
export function localOffsetMinutes(date: Date = new Date()): number {
  const value = -date.getTimezoneOffset();
  return value === 0 ? 0 : value;
}

/** ms -> ns as a decimal string; nanosecond epochs do not fit a JS number. */
export function msToNSString(ms: number): string {
  return (BigInt(Math.trunc(ms)) * 1_000_000n).toString();
}

/** Start of the local calendar day containing `nowMS`, in epoch ms. */
export function startOfLocalDayMS(nowMS: number, offsetMin: number): number {
  const shifted = nowMS + offsetMin * 60_000;
  return Math.floor(shifted / DAY_MS) * DAY_MS - offsetMin * 60_000;
}

/**
 * Range covering the last `days` local calendar days including today, so the
 * daily chart starts and ends on day boundaries. `to` is exclusive.
 */
export function rangeForDays(
  days: number,
  nowMS: number,
  offsetMin: number,
): { from_ns: string; to_ns: string } {
  const bounded = Math.min(Math.max(Math.trunc(days), 1), MAX_RANGE_DAYS);
  const todayStart = startOfLocalDayMS(nowMS, offsetMin);
  return {
    from_ns: msToNSString(todayStart - (bounded - 1) * DAY_MS),
    to_ns: msToNSString(todayStart + DAY_MS),
  };
}

/** [start, end) of a `YYYY-MM-DD` local day as nanosecond strings, or null when malformed. */
export function dayRange(day: string, offsetMin: number): { from_ns: string; to_ns: string } | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) {
    return null;
  }
  const utc = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  if (Number.isNaN(utc)) {
    return null;
  }
  const start = utc - offsetMin * 60_000;
  return { from_ns: msToNSString(start), to_ns: msToNSString(start + DAY_MS) };
}

/** `YYYY-MM-DD` of the local day containing `nowMS`. */
export function localDayString(nowMS: number, offsetMin: number): string {
  return new Date(nowMS + offsetMin * 60_000).toISOString().slice(0, 10);
}
