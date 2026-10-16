/** 12345 -> "12.3k", 1_250_000 -> "1.25M", 999 -> "999". */
export function formatTokens(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "—";
  }
  const sign = value < 0 ? "-" : "";
  const abs = Math.abs(value);
  if (abs < 1000) {
    return `${sign}${Math.round(abs)}`;
  }
  if (abs < 999_500) {
    return `${sign}${trimZero(abs / 1000, abs < 100_000 ? 1 : 0)}k`;
  }
  return `${sign}${trimZero(abs / 1_000_000, 2)}M`;
}

/** Signed variant for deltas: "+1.2k", "-300", "0". */
export function formatSignedTokens(value: number): string {
  if (value > 0) {
    return `+${formatTokens(value)}`;
  }
  return formatTokens(value);
}

export function formatUSD(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "—";
  }
  if (value === 0) {
    return "$0";
  }
  if (Math.abs(value) < 0.01) {
    return `$${value.toFixed(4)}`;
  }
  return `$${value.toFixed(value < 100 ? 2 : 0)}`;
}

/** 0.4237 -> "42.4%". */
export function formatRatio(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "—";
  }
  return `${(value * 100).toFixed(1)}%`;
}

export function formatMillis(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "—";
  }
  if (value < 1000) {
    return `${Math.round(value)} ms`;
  }
  if (value < 60_000) {
    return `${(value / 1000).toFixed(value < 10_000 ? 2 : 1)} s`;
  }
  return `${(value / 60_000).toFixed(1)} min`;
}

export function occupancy(
  lastPrompt: number | null | undefined,
  contextWindow: number | null | undefined,
): number | null {
  if (!lastPrompt || !contextWindow || contextWindow <= 0) {
    return null;
  }
  return lastPrompt / contextWindow;
}

export type OccupancyLevel = "ok" | "warn" | "danger";

/** Red from 90%, amber from 70%. */
export function occupancyLevel(ratio: number): OccupancyLevel {
  if (ratio >= 0.9) {
    return "danger";
  }
  if (ratio >= 0.7) {
    return "warn";
  }
  return "ok";
}

function trimZero(value: number, digits: number): string {
  return value.toFixed(digits).replace(/\.0+$/, "").replace(/(\.\d*?)0+$/, "$1");
}
