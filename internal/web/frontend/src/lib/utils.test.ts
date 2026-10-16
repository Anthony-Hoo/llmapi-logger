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
    const out = tokens(cn("px-4 py-2 rounded-md shadow-xs", "px-8 rounded-lg shadow-card"));
    expect(out).toEqual(expect.arrayContaining(["px-8", "py-2", "rounded-lg", "shadow-card"]));
    for (const dropped of ["px-4", "rounded-md", "shadow-xs"]) {
      expect(out).not.toContain(dropped);
    }
  });

  it("keeps project theme tokens and does not drop unrelated classes", () => {
    const out = tokens(cn("bg-primary/90 text-primary-foreground border-border shadow-xs shadow-overlay rounded-xs outline-hidden", "ring-2 ring-ring"));
    expect(out).toEqual(expect.arrayContaining(["bg-primary/90", "text-primary-foreground", "border-border", "shadow-overlay", "rounded-xs", "outline-hidden", "ring-2", "ring-ring"]));
    expect(out).not.toContain("shadow-xs");
  });

  it("treats type-scale tokens as sizes and color tokens as colors", () => {
    expect(cn("text-body text-muted", "text-label")).toBe("text-muted text-label");
    expect(cn("text-body-sm text-foreground", "text-subtle")).toBe("text-body-sm text-subtle");
    expect(cn("text-caption", "text-success-fg")).toBe("text-caption text-success-fg");
    expect(cn("bg-surface", "bg-primary")).toBe("bg-primary");
    expect(cn("border-border", "border-border-strong")).toBe("border-border-strong");
  });

  it("knows the semantic spacing, shadow and container tokens", () => {
    expect(cn("p-card", "pt-0")).toBe("p-card pt-0");
    expect(cn("p-4", "p-card")).toBe("p-card");
    expect(cn("space-y-3", "space-y-stack")).toBe("space-y-stack");
    expect(cn("gap-4", "gap-section")).toBe("gap-section");
    expect(cn("shadow-card", "shadow-overlay")).toBe("shadow-overlay");
    expect(cn("max-w-md", "max-w-page")).toBe("max-w-page");
  });
});
