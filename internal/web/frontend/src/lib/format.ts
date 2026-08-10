import type { BadgeVariant } from "../components/ui/badge";
import type { NanoTime } from "../types";

const stageLabels: Record<string, string> = {
  request_for_newapi_received_from_nginx: "接收入站请求",
  request_sent_to_newapi: "发送至 NewAPI",
  response_received_from_newapi: "接收 NewAPI 响应",
  response_from_newapi_sent_to_nginx: "返回响应",
};

export function formatNanoTime(value: NanoTime | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  try {
    const nanos = typeof value === "number" ? BigInt(Math.trunc(value)) : BigInt(value);
    const date = new Date(Number(nanos / 1_000_000n));
    if (Number.isNaN(date.getTime())) {
      return "—";
    }
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(date);
  } catch {
    return "—";
  }
}

export function formatBytes(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "—";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KiB", "MiB", "GiB"];
  let amount = bytes;
  let unit = -1;
  do {
    amount /= 1024;
    unit += 1;
  } while (amount >= 1024 && unit < units.length - 1);
  return `${amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${units[unit]}`;
}

export function humanizeStage(stage: string): string {
  return stageLabels[stage] ?? stage;
}

export function shortHash(hash: string | null | undefined): string {
  if (!hash) {
    return "—";
  }
  return hash.length > 18 ? `${hash.slice(0, 10)}…${hash.slice(-6)}` : hash;
}

export function statusVariant(status: string | null | undefined): BadgeVariant {
  switch (status) {
    case "completed":
    case "complete":
    case "ok":
      return "success";
    case "rejected":
    case "failed":
    case "error":
    case "proxy_error":
    case "newapi_error":
      return "destructive";
    case "partial":
    case "interrupted":
    case "client_cancelled":
      return "warning";
    case "pending":
    case "processing":
    case "in_progress":
      return "default";
    default:
      return "outline";
  }
}

export function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (typeof value === "boolean") {
    return value ? "是" : "否";
  }
  return String(value);
}
