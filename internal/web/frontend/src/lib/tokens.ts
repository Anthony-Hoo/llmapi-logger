/**
 * TypeScript side of the design tokens. Every color here is a reference to a
 * CSS custom property defined once in `src/index.css` (`@theme`), so CSS
 * utilities and SVG/recharts code always render the same value. Never put a
 * literal hex color in component code; add a token instead.
 */

/** `var(--color-<name>)` for a color token from index.css. */
export function colorVar(name: string): string {
  return `var(--color-${name})`;
}

export const chartColors = {
  grid: colorVar("chart-grid"),
  axis: colorVar("chart-axis"),
  cursor: colorVar("chart-cursor"),
  track: colorVar("chart-track"),
  text: colorVar("foreground"),
  textSubtle: colorVar("subtle"),
  surface: colorVar("surface"),
  onColor: colorVar("white"),
  danger: colorVar("danger"),
  success: colorVar("success"),
  /** Primary series of a single-measure chart. */
  series1: colorVar("primary-500"),
  /** Second measure next to series1 (e.g. estimated cost). */
  series2: colorVar("cat-injected"),
} as const;

/** SVG font sizes in px; they mirror the caption (11px) and label (12px) type tokens. */
export const chartFont = {
  caption: 11,
  /** Glyphs inside 12px event marker circles. */
  glyph: 8,
} as const;

/**
 * Styles for recharts' built-in tooltip, whose own defaults are a white box
 * with black text whatever the theme. Charts with a custom tooltip component
 * style it with classes instead.
 */
export const chartTooltip = {
  contentStyle: {
    backgroundColor: chartColors.surface,
    borderColor: colorVar("border"),
    borderRadius: "var(--radius-md)",
    boxShadow: "var(--shadow-overlay)",
    color: chartColors.text,
  },
  labelStyle: { color: chartColors.text },
  itemStyle: { color: chartColors.text },
} as const;

/** Shared recharts axis tick style. */
export const axisTick = { fontSize: chartFont.caption, fill: chartColors.axis } as const;
