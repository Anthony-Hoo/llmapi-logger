import { describe, expect, it } from "vitest";

// Guards the token system (doc/design/tokens.md): component code may only use
// the semantic/brand tokens defined in index.css. Raw Tailwind palette
// classes, default type-scale sizes, arbitrary pixel font sizes and literal
// colors are rejected.

const modules = import.meta.glob<string>(["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}", "!./vite-env.d.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});

/** The brand mark artwork is fixed (same as public/favicon.svg). */
function withoutBrandMark(path: string, source: string): string {
  if (!path.endsWith("/app.tsx")) {
    return source;
  }
  return source.replace(/function BrandMark[\s\S]*?\r?\n}\r?\n/, "");
}

const palette =
  "slate|gray|zinc|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose";
const rules: Array<[string, RegExp]> = [
  ["raw Tailwind palette class", new RegExp(`\\b(?:bg|text|border|ring|from|via|to|fill|stroke|accent|outline|divide)-(?:${palette})-\\d{2,3}\\b`)],
  ["arbitrary font size", /\btext-\[\d+(?:\.\d+)?(?:px|rem|em)\]/],
  ["Tailwind default type scale", /\btext-(?:xs|sm|base|lg|xl|[2-9]xl)\b/],
  ["literal hex color", /["'`]#[0-9a-fA-F]{3,8}\b/],
  // tree-layout.ts derives lineage hues algorithmically (documented exception).
  ["literal rgb()/hsl() color", /["'`](?:rgba?|hsla?)\((?!\$\{lineageHue)/],
  ["gradient", /\bbg-(?:gradient|linear|radial)-/],
  ["one-off shadow", /\bshadow-(?:sm|md|lg|xl|2xl|soft|\[)/],
  ["legacy shadcn token", /\b(?:muted-foreground|bg-muted|bg-secondary|bg-accent|destructive|bg-card|border-input)\b/],
];

describe("design tokens", () => {
  const files = Object.entries(modules);

  it("scans the component sources", () => {
    expect(files.length).toBeGreaterThan(20);
    expect(files.some(([path]) => path.endsWith("/app.tsx"))).toBe(true);
  });

  for (const [name, pattern] of rules) {
    it(`has no ${name}`, () => {
      const hits: string[] = [];
      for (const [path, raw] of files) {
        withoutBrandMark(path, raw)
          .split(/\r?\n/)
          .forEach((line, index) => {
            if (pattern.test(line)) {
              hits.push(`${path}:${index + 1}: ${line.trim()}`);
            }
          });
      }
      expect(hits).toEqual([]);
    });
  }
});
