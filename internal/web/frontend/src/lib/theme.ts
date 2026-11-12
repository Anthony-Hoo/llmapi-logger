import { useCallback, useEffect, useState } from "react";

/**
 * Theme preference. "system" follows the operating system through CSS alone
 * (color-scheme: light dark in index.css); "light" and "dark" pin one side by
 * setting data-theme on <html>. The choice is kept per browser.
 */
export type ThemePreference = "system" | "light" | "dark";

/** Also read by the inline script in index.html, before the first paint. */
export const THEME_STORAGE_KEY = "llmapi-logger:theme";

export const THEME_OPTIONS: ReadonlyArray<{ value: ThemePreference; label: string; title: string }> = [
  { value: "system", label: "自动", title: "跟随系统的亮色或暗色设置" },
  { value: "light", label: "亮色", title: "始终使用亮色主题" },
  { value: "dark", label: "暗色", title: "始终使用暗色主题" },
];

export function parseThemePreference(value: string | null | undefined): ThemePreference {
  return value === "light" || value === "dark" ? value : "system";
}

/** The stored preference; "system" when nothing usable is stored. */
export function readThemePreference(storage: Pick<Storage, "getItem"> | null | undefined): ThemePreference {
  try {
    return parseThemePreference(storage?.getItem(THEME_STORAGE_KEY));
  } catch {
    return "system"; // storage blocked (private mode, policy)
  }
}

/** Stores a pinned theme, or removes the entry for "system". */
export function writeThemePreference(storage: Pick<Storage, "setItem" | "removeItem"> | null | undefined, preference: ThemePreference): void {
  try {
    if (preference === "system") {
      storage?.removeItem(THEME_STORAGE_KEY);
    } else {
      storage?.setItem(THEME_STORAGE_KEY, preference);
    }
  } catch {
    // The choice still applies to this page; it just is not remembered.
  }
}

/** Reflects a preference on the root element: data-theme for a pinned theme, none for "system". */
export function applyThemePreference(root: { dataset: Record<string, string | undefined> } | null | undefined, preference: ThemePreference): void {
  if (!root) {
    return;
  }
  if (preference === "system") {
    delete root.dataset.theme;
  } else {
    root.dataset.theme = preference;
  }
}

function browserStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

/**
 * The theme preference and its setter. Changing it applies at once, is
 * remembered in this browser, and follows a change made in another tab.
 */
export function useThemePreference(): [ThemePreference, (preference: ThemePreference) => void] {
  const [preference, setPreference] = useState<ThemePreference>(() => readThemePreference(browserStorage()));

  useEffect(() => {
    applyThemePreference(typeof document === "undefined" ? null : document.documentElement, preference);
  }, [preference]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const onStorage = (event: StorageEvent) => {
      if (event.key === THEME_STORAGE_KEY || event.key === null) {
        setPreference(readThemePreference(browserStorage()));
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const choose = useCallback((next: ThemePreference) => {
    writeThemePreference(browserStorage(), next);
    setPreference(next);
  }, []);
  return [preference, choose];
}
