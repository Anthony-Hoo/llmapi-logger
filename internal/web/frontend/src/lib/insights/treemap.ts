import type { CompositionItem } from "../../types";
import { CATEGORY_KEYS } from "./categories";

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface TreemapInput<T = undefined> {
  id: string;
  value: number;
  data?: T;
}

export interface TreemapCell<T = undefined> {
  item: TreemapInput<T>;
  rect: Rect;
}

/**
 * Squarified treemap (Bruls, Huizing, van Wijk). Items with a non-positive
 * value are dropped; the remaining ones tile `rect` exactly, largest first.
 */
export function squarify<T = undefined>(items: ReadonlyArray<TreemapInput<T>>, rect: Rect): TreemapCell<T>[] {
  const sorted = items.filter((item) => item.value > 0).sort((a, b) => b.value - a.value);
  const total = sorted.reduce((sum, item) => sum + item.value, 0);
  if (sorted.length === 0 || total <= 0 || rect.w <= 0 || rect.h <= 0) {
    return [];
  }
  const scale = (rect.w * rect.h) / total;
  const nodes = sorted.map((item) => ({ item, area: item.value * scale }));
  const remaining: Rect = { ...rect };
  const cells: TreemapCell<T>[] = [];

  let index = 0;
  while (index < nodes.length) {
    const side = Math.min(remaining.w, remaining.h);
    const row = [nodes[index]];
    index += 1;
    while (index < nodes.length && worstRatio([...row, nodes[index]], side) <= worstRatio(row, side)) {
      row.push(nodes[index]);
      index += 1;
    }
    placeRow(row, remaining, cells, index >= nodes.length);
  }
  return cells;
}

function worstRatio(row: ReadonlyArray<{ area: number }>, side: number): number {
  const sum = row.reduce((total, node) => total + node.area, 0);
  const max = Math.max(...row.map((node) => node.area));
  const min = Math.min(...row.map((node) => node.area));
  if (sum <= 0 || min <= 0 || side <= 0) {
    return Number.POSITIVE_INFINITY;
  }
  return Math.max((side * side * max) / (sum * sum), (sum * sum) / (side * side * min));
}

function placeRow<T>(
  row: ReadonlyArray<{ item: TreemapInput<T>; area: number }>,
  remaining: Rect,
  cells: TreemapCell<T>[],
  last: boolean,
): void {
  const sum = row.reduce((total, node) => total + node.area, 0);
  if (remaining.w >= remaining.h) {
    // A column on the left, items stacked top to bottom.
    const width = last ? remaining.w : sum / remaining.h;
    let y = remaining.y;
    row.forEach((node, position) => {
      const height = position === row.length - 1 ? remaining.y + remaining.h - y : node.area / width;
      cells.push({ item: node.item, rect: { x: remaining.x, y, w: width, h: height } });
      y += height;
    });
    remaining.x += width;
    remaining.w -= width;
  } else {
    // A strip on top, items side by side.
    const height = last ? remaining.h : sum / remaining.w;
    let x = remaining.x;
    row.forEach((node, position) => {
      const width = position === row.length - 1 ? remaining.x + remaining.w - x : node.area / height;
      cells.push({ item: node.item, rect: { x, y: remaining.y, w: width, h: height } });
      x += width;
    });
    remaining.y += height;
    remaining.h -= height;
  }
}

export const OTHER_LABEL = "其他";
export const TREEMAP_TOP_N = 11;

export interface TreemapGroup {
  name: string;
  tokens: number;
  count: number;
  /** True for the aggregated 其他 remainder. */
  other: boolean;
}

export interface TreemapCategory {
  category: string;
  tokens: number;
  groups: TreemapGroup[];
}

const KIND_LABELS: Record<string, string> = {
  text: "文本",
  thinking: "推理",
  tool_call: "工具调用",
  tool_result: "工具结果",
  image: "图片",
  file: "文件",
  tool_def: "工具定义",
  system: "系统提示",
};

/**
 * Groups items by category, then by label (falling back to the kind) and keeps
 * the largest `topN` groups per category; the rest are summed into 其他.
 * Categories are returned in display order, empty ones omitted.
 */
export function buildTreemapData(
  items: ReadonlyArray<Pick<CompositionItem, "category" | "kind" | "label" | "tokens">>,
  topN: number = TREEMAP_TOP_N,
): TreemapCategory[] {
  const perCategory = new Map<string, Map<string, TreemapGroup>>();
  for (const item of items) {
    if (!(item.tokens > 0)) {
      continue;
    }
    const groups = perCategory.get(item.category) ?? new Map<string, TreemapGroup>();
    perCategory.set(item.category, groups);
    const name = item.label?.trim() || KIND_LABELS[item.kind] || item.kind || "未命名";
    const group = groups.get(name) ?? { name, tokens: 0, count: 0, other: false };
    group.tokens += item.tokens;
    group.count += 1;
    groups.set(name, group);
  }

  const order = [...CATEGORY_KEYS.filter((key) => perCategory.has(key)), ...[...perCategory.keys()].filter((key) => !CATEGORY_KEYS.includes(key as never))];
  return order.map((category) => {
    const sorted = [...(perCategory.get(category)?.values() ?? [])].sort((a, b) => b.tokens - a.tokens);
    const head = sorted.slice(0, topN);
    const tail = sorted.slice(topN);
    if (tail.length > 0) {
      head.push({
        name: OTHER_LABEL,
        tokens: tail.reduce((sum, group) => sum + group.tokens, 0),
        count: tail.reduce((sum, group) => sum + group.count, 0),
        other: true,
      });
    }
    return { category, tokens: sorted.reduce((sum, group) => sum + group.tokens, 0), groups: head };
  });
}

export interface LaidOutGroup extends TreemapGroup {
  rect: Rect;
}

export interface LaidOutCategory {
  category: string;
  tokens: number;
  rect: Rect;
  /** Rect left for the inner groups after the category header and padding. */
  inner: Rect;
  groups: LaidOutGroup[];
}

const HEADER_HEIGHT = 16;
const PADDING = 2;

/** Two-level layout: categories fill `bounds`, their groups fill the inner rect. */
export function layoutTreemap(data: readonly TreemapCategory[], bounds: Rect): LaidOutCategory[] {
  const outer = squarify(
    data.map((category) => ({ id: category.category, value: category.tokens, data: category })),
    bounds,
  );
  return outer.map(({ item, rect }) => {
    const category = item.data as TreemapCategory;
    const header = rect.h > HEADER_HEIGHT * 2 && rect.w > 40 ? HEADER_HEIGHT : 0;
    const inner: Rect = {
      x: rect.x + PADDING,
      y: rect.y + header + PADDING,
      w: Math.max(rect.w - PADDING * 2, 0),
      h: Math.max(rect.h - header - PADDING * 2, 0),
    };
    const groups = squarify(
      category.groups.map((group) => ({ id: group.name, value: group.tokens, data: group })),
      inner,
    ).map(({ item: groupItem, rect: groupRect }) => ({ ...(groupItem.data as TreemapGroup), rect: groupRect }));
    return { category: category.category, tokens: category.tokens, rect, inner, groups };
  });
}
