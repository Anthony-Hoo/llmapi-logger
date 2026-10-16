import type { CategoryValues } from "../../types";
import { CATEGORIES, normalizeCategoryValues, sumCategories } from "../../lib/insights/categories";
import { formatRatio, formatTokens, occupancy, occupancyLevel } from "../../lib/insights/format";

/**
 * Stacked bar of the eight composition categories (custom SVG). When a context
 * window is known the bar is scaled to it, so the empty track shows headroom.
 */
export function CompositionBar({
  values,
  contextWindow,
  height = 10,
  className,
  label = "上下文构成",
}: {
  values: Partial<CategoryValues> | null | undefined;
  contextWindow?: number | null;
  height?: number;
  className?: string;
  label?: string;
}) {
  const normalized = normalizeCategoryValues(values);
  const sum = sumCategories(normalized);
  const denominator = Math.max(sum, contextWindow && contextWindow > 0 ? contextWindow : 0, 1);
  let offset = 0;
  const summary = CATEGORIES.filter((category) => normalized[category.key] > 0)
    .map((category) => `${category.label} ${formatTokens(normalized[category.key])}`)
    .join("，");
  return (
    <svg
      role="img"
      aria-label={`${label}：${summary || "无数据"}`}
      width="100%"
      height={height}
      className={className}
      style={{ display: "block" }}
    >
      <rect x="0" y="0" width="100%" height={height} rx={height / 2} fill="#e2e8f0" />
      <g>
        {CATEGORIES.map((category) => {
          const value = normalized[category.key];
          if (value <= 0) {
            return null;
          }
          const x = (offset / denominator) * 100;
          const width = (value / denominator) * 100;
          offset += value;
          return (
            <rect key={category.key} x={`${x}%`} y="0" width={`${width}%`} height={height} fill={category.color}>
              <title>{`${category.label} ${formatTokens(value)}（${formatRatio(value / Math.max(sum, 1))}）`}</title>
            </rect>
          );
        })}
      </g>
    </svg>
  );
}

export function CategoryLegend({
  values,
  className,
}: {
  values?: Partial<CategoryValues> | null;
  className?: string;
}) {
  const normalized = values ? normalizeCategoryValues(values) : null;
  return (
    <ul className={`flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground ${className ?? ""}`}>
      {CATEGORIES.map((category) => (
        <li key={category.key} className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: category.color }} />
          <span>{category.label}</span>
          {normalized ? <span className="tabular-nums">{formatTokens(normalized[category.key])}</span> : null}
        </li>
      ))}
    </ul>
  );
}

/** "已用 / 窗口" text colored by how full the window is: red from 90%, amber from 70%. */
export function OccupancyText({
  lastPrompt,
  contextWindow,
}: {
  lastPrompt: number | null | undefined;
  contextWindow: number | null | undefined;
}) {
  const ratio = occupancy(lastPrompt, contextWindow);
  if (ratio === null) {
    return <span className="text-muted-foreground">窗口未知</span>;
  }
  const level = occupancyLevel(ratio);
  const color = level === "danger" ? "text-red-600" : level === "warn" ? "text-amber-600" : "text-muted-foreground";
  return (
    <span className={`tabular-nums ${color}`} data-level={level}>
      {formatTokens(lastPrompt)} / {formatTokens(contextWindow)} · {formatRatio(ratio)}
    </span>
  );
}
