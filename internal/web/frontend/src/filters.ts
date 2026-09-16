import type { AuditFilters } from "./types";

export function hasRowFilters(filters: AuditFilters): boolean {
  return Object.entries(filters).some(([key, value]) =>
    key !== "collapse" && key !== "conversation" && typeof value === "string" && value.trim() !== "",
  );
}

export function parseStatusCodeDraft(draft: string): { value?: string; error: string | null } {
  const value = draft.trim();
  if (value && (!/^[0-9]+$/.test(value) || Number(value) < 100 || Number(value) > 599)) {
    return { error: "状态码须为 100–599 的整数" };
  }
  return { value: value ? String(Number(value)) : undefined, error: null };
}

export function filtersForConversation(current: AuditFilters, conversation: string): AuditFilters {
  return { collapse: current.collapse, conversation };
}
