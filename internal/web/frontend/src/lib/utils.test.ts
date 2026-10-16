import { describe, expect, it } from "vitest";

import { cn } from "./utils";

const tokens = (value: string) => value.split(" ");

describe("cn", () => {
  it("keeps the signature: skips falsy values", () => {
    expect(cn("a", false, null, undefined, "b")).toBe("a b");
  });

  it("lets later height override the default", () => {
    const out = tokens(cn("h-10 px-3", "h-9"));
    expect(out).toContain("h-9");
    expect(out).not.toContain("h-10");
    expect(out).toContain("px-3");
  });

  it("resolves padding, rounded and shadow conflicts", () => {
    const out = tokens(cn("px-4 py-2 rounded-md shadow-xs", "px-8 rounded-lg shadow-soft"));
    expect(out).toEqual(expect.arrayContaining(["px-8", "py-2", "rounded-lg", "shadow-soft"]));
    for (const dropped of ["px-4", "rounded-md", "shadow-xs"]) {
      expect(out).not.toContain(dropped);
    }
  });

  it("keeps project theme tokens and does not drop unrelated classes", () => {
    const out = tokens(cn("bg-primary/90 text-primary-foreground border-border shadow-xs shadow-soft rounded-[0.25rem] outline-hidden", "ring-2 ring-ring"));
    expect(out).toEqual(expect.arrayContaining(["bg-primary/90", "text-primary-foreground", "border-border", "shadow-soft", "rounded-[0.25rem]", "outline-hidden", "ring-2", "ring-ring"]));
    expect(out).not.toContain("shadow-xs");
  });

  it("treats custom color tokens as colors, not as sizes", () => {
    expect(cn("text-sm text-muted-foreground", "text-xs")).toBe("text-muted-foreground text-xs");
    expect(cn("bg-white/90", "bg-primary")).toBe("bg-primary");
  });
});