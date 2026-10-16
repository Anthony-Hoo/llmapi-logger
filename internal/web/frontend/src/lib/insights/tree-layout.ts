export interface LayoutInput {
  id: string;
  parentId?: string | null;
}

export interface LayoutNode {
  id: string;
  parentId: string | null;
  /** Distance from a root, 0 for roots. */
  depth: number;
  /** Position across the tree's breadth, in node units; the minimum is 0. */
  x: number;
  /** Pre-order index (input order among siblings); used for lineage colors. */
  order: number;
  childIDs: string[];
}

export interface TreeLayout {
  nodes: LayoutNode[];
  /** Breadth span in node units (max x). */
  breadth: number;
  /** Number of depth levels. */
  levels: number;
}

interface Contour {
  lo: number[];
  hi: number[];
}

const VIRTUAL_ROOT = "\u0000root";

/**
 * Tidy tree layout in the Reingold-Tilford style: subtrees are placed left to
 * right as close as their contours allow (siblings one unit apart at every
 * level) and each parent is centered over its children. Forests are laid out
 * under a virtual root. Unknown parents make a node a root; cycles are broken
 * at the first node reached.
 */
export function tidyLayout(inputs: readonly LayoutInput[]): TreeLayout {
  const ids = new Set(inputs.map((input) => input.id));
  const parentOf = new Map<string, string | null>();
  for (const input of inputs) {
    const parent = input.parentId && ids.has(input.parentId) && input.parentId !== input.id ? input.parentId : null;
    parentOf.set(input.id, parent);
  }

  const children = new Map<string, string[]>();
  children.set(VIRTUAL_ROOT, []);
  for (const input of inputs) {
    children.set(input.id, []);
  }
  for (const input of inputs) {
    const parent = parentOf.get(input.id) ?? null;
    children.get(parent ?? VIRTUAL_ROOT)?.push(input.id);
  }

  // Break cycles: nodes unreachable from the virtual root become roots.
  const reachable = new Set<string>();
  const mark = (id: string) => {
    if (reachable.has(id)) {
      return;
    }
    reachable.add(id);
    for (const child of children.get(id) ?? []) {
      mark(child);
    }
  };
  mark(VIRTUAL_ROOT);
  for (const input of inputs) {
    if (!reachable.has(input.id)) {
      const parent = parentOf.get(input.id) ?? null;
      if (parent) {
        const siblings = children.get(parent);
        if (siblings) {
          children.set(parent, siblings.filter((id) => id !== input.id));
        }
      }
      parentOf.set(input.id, null);
      children.get(VIRTUAL_ROOT)?.push(input.id);
      mark(input.id);
    }
  }

  const offset = new Map<string, number>(); // x relative to the parent
  const place = (id: string): Contour => {
    const kids = children.get(id) ?? [];
    if (kids.length === 0) {
      return { lo: [0], hi: [0] };
    }
    const contours = kids.map(place);
    const xs: number[] = [0];
    const merged: Contour = { lo: [...contours[0].lo], hi: [...contours[0].hi] };
    for (let index = 1; index < kids.length; index += 1) {
      const contour = contours[index];
      let shift = Number.NEGATIVE_INFINITY;
      const shared = Math.min(merged.hi.length, contour.lo.length);
      for (let depth = 0; depth < shared; depth += 1) {
        shift = Math.max(shift, merged.hi[depth] + 1 - contour.lo[depth]);
      }
      xs.push(shift);
      for (let depth = 0; depth < contour.lo.length; depth += 1) {
        if (depth < merged.hi.length) {
          merged.lo[depth] = Math.min(merged.lo[depth], contour.lo[depth] + shift);
          merged.hi[depth] = Math.max(merged.hi[depth], contour.hi[depth] + shift);
        } else {
          merged.lo.push(contour.lo[depth] + shift);
          merged.hi.push(contour.hi[depth] + shift);
        }
      }
    }
    const center = (xs[0] + xs[xs.length - 1]) / 2;
    kids.forEach((kid, index) => offset.set(kid, xs[index] - center));
    return {
      lo: [0, ...merged.lo.map((value) => value - center)],
      hi: [0, ...merged.hi.map((value) => value - center)],
    };
  };
  const rootContour = place(VIRTUAL_ROOT);

  const nodes: LayoutNode[] = [];
  const absolute = new Map<string, number>();
  absolute.set(VIRTUAL_ROOT, 0);
  const walk = (id: string, depth: number) => {
    for (const kid of children.get(id) ?? []) {
      const x = (absolute.get(id) ?? 0) + (offset.get(kid) ?? 0);
      absolute.set(kid, x);
      nodes.push({
        id: kid,
        parentId: parentOf.get(kid) ?? null,
        depth,
        x,
        order: nodes.length,
        childIDs: [...(children.get(kid) ?? [])],
      });
      walk(kid, depth + 1);
    }
  };
  walk(VIRTUAL_ROOT, 0);

  const minX = Math.min(...nodes.map((node) => node.x), 0);
  for (const node of nodes) {
    node.x -= minX;
  }
  return {
    nodes,
    breadth: nodes.length === 0 ? 0 : Math.max(...nodes.map((node) => node.x)),
    levels: Math.max(rootContour.lo.length - 1, 0),
  };
}

/** Golden-angle hue for lineage `index` (degrees, 0-360). */
export function lineageHue(index: number): number {
  return (index * 137.508) % 360;
}

export function lineageColor(index: number): string {
  return `hsl(${lineageHue(index).toFixed(1)} 62% 46%)`;
}
