import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ThemeSwitch } from "../components/ui/theme-switch";
import indexHTML from "../../index.html?raw";
import { applyThemePreference, parseThemePreference, readThemePreference, THEME_OPTIONS, THEME_STORAGE_KEY, writeThemePreference } from "./theme";

// The test runner blanks stylesheet imports (also with ?raw), so the token
// file is read from disk. The project has no Node typings; this is the one
// call needed.
declare const process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: URL, encoding: "utf8"): string } };
const indexCSS = process.getBuiltinModule("node:fs").readFileSync(new URL("../index.css", import.meta.url), "utf8");

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
}

describe("theme preference", () => {
  it("defaults to the system and accepts only the two pinned themes", () => {
    expect(parseThemePreference(null)).toBe("system");
    expect(parseThemePreference("")).toBe("system");
    expect(parseThemePreference("sepia")).toBe("system");
    expect(parseThemePreference("light")).toBe("light");
    expect(parseThemePreference("dark")).toBe("dark");
    expect(THEME_OPTIONS.map((option) => option.value)).toEqual(["system", "light", "dark"]);
  });

  it("remembers a pinned theme and forgets it for the system", () => {
    const storage = memoryStorage();
    expect(readThemePreference(storage)).toBe("system");
    writeThemePreference(storage, "dark");
    expect(storage.values.get(THEME_STORAGE_KEY)).toBe("dark");
    expect(readThemePreference(storage)).toBe("dark");
    writeThemePreference(storage, "system");
    expect(storage.values.has(THEME_STORAGE_KEY)).toBe(false);
    expect(readThemePreference(memoryStorage({ [THEME_STORAGE_KEY]: "neon" }))).toBe("system");
  });

  it("works without usable storage", () => {
    const blocked = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    };
    expect(readThemePreference(blocked)).toBe("system");
    expect(() => writeThemePreference(blocked, "dark")).not.toThrow();
    expect(readThemePreference(null)).toBe("system");
    expect(() => writeThemePreference(undefined, "light")).not.toThrow();
  });

  it("pins a theme with data-theme and leaves the system to CSS", () => {
    const root = { dataset: {} as Record<string, string | undefined> };
    applyThemePreference(root, "dark");
    expect(root.dataset.theme).toBe("dark");
    applyThemePreference(root, "light");
    expect(root.dataset.theme).toBe("light");
    applyThemePreference(root, "system");
    expect("theme" in root.dataset).toBe(false);
    expect(() => applyThemePreference(null, "dark")).not.toThrow();
  });

  it("renders the three-way switch with the system selected by default", () => {
    const html = renderToStaticMarkup(<ThemeSwitch />);
    expect(html).toContain('aria-label="主题"');
    expect(html).toContain("自动");
    expect(html).toContain("亮色");
    expect(html).toContain("暗色");
    expect(html.match(/aria-pressed="true"/g)?.length).toBe(1);
    expect(html).toMatch(/aria-pressed="true"[^>]*>自动</);
  });
});

describe("theme styles", () => {
  it("follows the system by default and lets data-theme pin one side", () => {
    const compact = indexCSS.replace(/\s+/g, " ");
    expect(compact).toContain(":root { color-scheme: light dark; }");
    expect(compact).toContain(':root[data-theme="light"] { color-scheme: light; }');
    expect(compact).toContain(':root[data-theme="dark"] { color-scheme: dark; }');
    expect(indexHTML).toContain('<meta name="color-scheme" content="light dark" />');
  });

  it("gives every surface, text and status role a value for both themes", () => {
    const roles = [
      "background", "surface", "surface-muted", "surface-sunken", "surface-sunken-hover", "selected", "border", "border-strong",
      "foreground", "muted", "subtle", "ring", "link", "link-hover", "code",
      "success", "success-bg", "success-border", "success-fg", "warning", "warning-bg", "warning-border", "warning-fg",
      "danger", "danger-hover", "danger-bg", "danger-border", "danger-fg", "info", "info-bg", "info-border", "info-fg",
      "chart-grid", "chart-track", "heat-1", "heat-2", "heat-3", "heat-4",
    ];
    for (const role of roles) {
      expect(indexCSS, role).toMatch(new RegExp(`--color-${role}: light-dark\\(#[0-9a-f]{6}, #[0-9a-f]{6}\\);`));
    }
  });

  it("applies a pinned theme before the first paint with the same storage key", () => {
    expect(indexHTML).toContain(`localStorage.getItem("${THEME_STORAGE_KEY}")`);
    expect(indexHTML).toContain("document.documentElement.dataset.theme = theme");
    // The inline script must come before the module that renders the page.
    expect(indexHTML.indexOf("localStorage.getItem")).toBeLessThan(indexHTML.indexOf('src="/src/main.tsx"'));
  });
});
