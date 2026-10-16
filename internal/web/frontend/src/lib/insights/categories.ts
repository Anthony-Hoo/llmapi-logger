import type { CategoryKey, CategoryValues } from "../../types";

export interface CategoryInfo {
  key: CategoryKey;
  label: string;
  color: string;
}

/**
 * The eight composition categories in display order. Labels and colors are
 * defined here once and reused by every chart, bar, treemap and legend.
 */
export const CATEGORIES: readonly CategoryInfo[] = [
  { key: "system", label: "系统提示", color: "#6366f1" },
  { key: "tools", label: "工具定义", color: "#0ea5e9" },
  { key: "user", label: "用户", color: "#10b981" },
  { key: "injected", label: "注入上下文", color: "#f59e0b" },
  { key: "assistant", label: "助手", color: "#8b5cf6" },
  { key: "reasoning", label: "推理", color: "#ec4899" },
  { key: "tool_result", label: "工具结果", color: "#14b8a6" },
  { key: "media", label: "多媒体", color: "#f97316" },
];

export const CATEGORY_KEYS: readonly CategoryKey[] = CATEGORIES.map((category) => category.key);

const byKey = new Map<string, CategoryInfo>(CATEGORIES.map((category) => [category.key, category]));

export const UNKNOWN_CATEGORY_COLOR = "#94a3b8";

export function categoryInfo(key: string): CategoryInfo {
  return byKey.get(key) ?? { key: key as CategoryKey, label: key, color: UNKNOWN_CATEGORY_COLOR };
}

export function emptyCategoryValues(): CategoryValues {
  return {
    system: 0,
    tools: 0,
    user: 0,
    injected: 0,
    assistant: 0,
    reasoning: 0,
    tool_result: 0,
    media: 0,
  };
}

/** Tolerates a missing or partial object (older rows, nil structs). */
export function normalizeCategoryValues(values: Partial<CategoryValues> | null | undefined): CategoryValues {
  const result = emptyCategoryValues();
  if (!values) {
    return result;
  }
  for (const key of CATEGORY_KEYS) {
    const value = values[key];
    result[key] = typeof value === "number" && Number.isFinite(value) ? value : 0;
  }
  return result;
}

export function sumCategories(values: Partial<CategoryValues> | null | undefined): number {
  const normalized = normalizeCategoryValues(values);
  return CATEGORY_KEYS.reduce((total, key) => total + normalized[key], 0);
}

/**
 * Scales per-category estimates so they add up to the upstream-reported prompt
 * total (the same anchoring as the backend's `anchored` field). Without usage,
 * or with an all-zero estimate, the raw estimate is returned unchanged.
 */
export function anchorToPrompt(
  estimate: Partial<CategoryValues> | null | undefined,
  promptTotal: number | null | undefined,
): CategoryValues {
  const normalized = normalizeCategoryValues(estimate);
  const sum = sumCategories(normalized);
  if (promptTotal === null || promptTotal === undefined || promptTotal <= 0 || sum <= 0) {
    return normalized;
  }
  const result = emptyCategoryValues();
  for (const key of CATEGORY_KEYS) {
    result[key] = Math.round((normalized[key] * promptTotal) / sum);
  }
  return result;
}
