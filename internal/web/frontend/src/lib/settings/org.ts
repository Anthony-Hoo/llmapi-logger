import type { OrgEditableSettings, OrgSettingsView } from "./types";

/** The form's working copy: numbers and the client list stay text until sent. */
export interface OrgSettingsDraft {
  idle_gap_seconds: string;
  ranked_clients: string;
  max_concurrent_roots: string;
  max_single_request_roots: string;
}

export function orgDraftFromSettings(settings: OrgEditableSettings): OrgSettingsDraft {
  return {
    idle_gap_seconds: String(settings.idle_gap_seconds),
    ranked_clients: settings.ranked_clients.join(", "),
    max_concurrent_roots: String(settings.max_concurrent_roots),
    max_single_request_roots: String(settings.max_single_request_roots),
  };
}

function integer(text: string): number {
  const trimmed = text.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : -1;
}

/** Client keys separated by commas (ASCII or full-width), 、 or whitespace. */
export function parseClients(text: string): string[] {
  return text
    .split(/[\s,，、]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

export function orgUpdateFromDraft(draft: OrgSettingsDraft): OrgEditableSettings {
  return {
    idle_gap_seconds: integer(draft.idle_gap_seconds),
    ranked_clients: parseClients(draft.ranked_clients),
    max_concurrent_roots: integer(draft.max_concurrent_roots),
    max_single_request_roots: integer(draft.max_single_request_roots),
  };
}

/** Whether the draft differs from the settings in use; the order of clients does not count. */
export function orgDraftChanged(draft: OrgSettingsDraft, view: OrgSettingsView): boolean {
  const edited = orgUpdateFromDraft(draft);
  const sorted = (clients: string[]) => [...clients].sort().join("\n");
  return (
    edited.idle_gap_seconds !== view.settings.idle_gap_seconds ||
    edited.max_concurrent_roots !== view.settings.max_concurrent_roots ||
    edited.max_single_request_roots !== view.settings.max_single_request_roots ||
    sorted(edited.ranked_clients) !== sorted(view.settings.ranked_clients)
  );
}
