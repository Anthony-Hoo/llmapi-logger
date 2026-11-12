import type { OrgClientOption, OrgEditableSettings, OrgSettingsView } from "./types";

/** The form's working copy: numbers stay text until sent; clients are the ticked keys. */
export interface OrgSettingsDraft {
  idle_gap_seconds: string;
  ranked_clients: string[];
  max_concurrent_roots: string;
  max_single_request_roots: string;
}

/**
 * The clients that can be ranked: the ones the vocabulary recognises. A
 * server that does not say (an empty list) leaves only the keys in use.
 */
export function clientOptions(view: OrgSettingsView): OrgClientOption[] {
  if (view.clients.length > 0) {
    return view.clients;
  }
  return view.settings.ranked_clients.map((key) => ({ key, label: "" }));
}

/**
 * Keys in use that the vocabulary does not know. No request is ever
 * attributed to such a client, so they rank nothing; a save drops them.
 */
export function unknownRankedClients(view: OrgSettingsView): string[] {
  const known = new Set(clientOptions(view).map((option) => option.key));
  return view.settings.ranked_clients.filter((key) => !known.has(key));
}

export function orgDraftFromView(view: OrgSettingsView): OrgSettingsDraft {
  const known = new Set(clientOptions(view).map((option) => option.key));
  return {
    idle_gap_seconds: String(view.settings.idle_gap_seconds),
    ranked_clients: view.settings.ranked_clients.filter((key) => known.has(key)),
    max_concurrent_roots: String(view.settings.max_concurrent_roots),
    max_single_request_roots: String(view.settings.max_single_request_roots),
  };
}

function integer(text: string): number {
  const trimmed = text.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : -1;
}

/** Ticks or unticks one client, keeping the keys sorted. */
export function toggleClient(selected: readonly string[], key: string, on: boolean): string[] {
  const next = new Set(selected);
  if (on) {
    next.add(key);
  } else {
    next.delete(key);
  }
  return [...next].sort();
}

export function orgUpdateFromDraft(draft: OrgSettingsDraft): OrgEditableSettings {
  return {
    idle_gap_seconds: integer(draft.idle_gap_seconds),
    ranked_clients: [...draft.ranked_clients].sort(),
    max_concurrent_roots: integer(draft.max_concurrent_roots),
    max_single_request_roots: integer(draft.max_single_request_roots),
  };
}

/**
 * Whether the draft differs from the settings in use. The order of clients
 * does not count; an unknown key in use does, because saving removes it.
 */
export function orgDraftChanged(draft: OrgSettingsDraft, view: OrgSettingsView): boolean {
  const edited = orgUpdateFromDraft(draft);
  const sorted = (clients: readonly string[]) => [...clients].sort().join("\n");
  return (
    edited.idle_gap_seconds !== view.settings.idle_gap_seconds ||
    edited.max_concurrent_roots !== view.settings.max_concurrent_roots ||
    edited.max_single_request_roots !== view.settings.max_single_request_roots ||
    sorted(edited.ranked_clients) !== sorted(view.settings.ranked_clients)
  );
}
