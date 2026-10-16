import { describe, expect, it } from "vitest";

import { createGeneration } from "./generation";

describe("generation counter", () => {
  it("treats only the latest generation as current", () => {
    const generation = createGeneration();
    const first = generation.advance();
    expect(generation.isCurrent(first)).toBe(true);
    const second = generation.advance();
    expect(generation.isCurrent(first)).toBe(false);
    expect(generation.isCurrent(second)).toBe(true);
    expect(generation.current()).toBe(second);
  });

  it("discards a pagination response that outlives a filter change", async () => {
    const generation = createGeneration();
    let cards = ["first-page"];
    let cursor: string | null = "cursor-1";
    generation.advance(); // initial load

    let resolveMore: (items: string[]) => void = () => undefined;
    const pending = new Promise<string[]>((resolve) => {
      resolveMore = resolve;
    });
    const requested = generation.current();
    const loadMore = pending.then((items) => {
      if (!generation.isCurrent(requested)) {
        return;
      }
      cards = [...cards, ...items];
      cursor = "cursor-stale";
    });

    // The day filter or sort changes while "加载更多" is in flight.
    generation.advance();
    cards = ["filtered-page"];
    cursor = "cursor-2";
    resolveMore(["stale-card"]);
    await loadMore;

    expect(cards).toEqual(["filtered-page"]);
    expect(cursor).toBe("cursor-2");
  });
});
