import type { CompositionItem } from "../../types";

export interface DnaBand {
  index: number;
  category: string;
  tokens: number;
  x: number;
  width: number;
  /** True when this item is new compared with the previous step. */
  added: boolean;
  label: string;
}

/**
 * One band per item in prompt order, width proportional to tokens (with a
 * visible minimum), laid out across `width` units.
 */
export function buildDnaBands(
  items: ReadonlyArray<CompositionItem>,
  width = 1000,
  minBand = 1.5,
): DnaBand[] {
  const ordered = items.filter((item) => item.tokens > 0).sort((a, b) => a.index - b.index);
  const total = ordered.reduce((sum, item) => sum + item.tokens, 0);
  if (ordered.length === 0 || total <= 0) {
    return [];
  }
  const raw = ordered.map((item) => Math.max((item.tokens / total) * width, minBand));
  const scale = width / raw.reduce((sum, value) => sum + value, 0);
  let x = 0;
  return ordered.map((item, position) => {
    const bandWidth = raw[position] * scale;
    const band: DnaBand = {
      index: item.index,
      category: item.category,
      tokens: item.tokens,
      x,
      width: bandWidth,
      added: item.change === "added",
      label: item.label?.trim() || item.kind,
    };
    x += bandWidth;
    return band;
  });
}
