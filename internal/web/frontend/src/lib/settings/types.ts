// Settings an administrator saves from the "系统配置" menu. The server keeps
// the configuration file as the base; a saved section overrides the fields
// below (doc 24 section 4).

export interface AnalysisEditableLLM {
  enabled: boolean;
  base_url: string;
  model: string;
  structured_output: "json_schema" | "json_object" | "prompt";
  context_tokens: number;
  disable_thinking: boolean;
  max_output_tokens: number;
  max_concurrency: number;
  timeout_seconds: number;
  max_sessions_per_run: number;
}

export interface AnalysisEditableSettings {
  run_at: string;
  l1_settle_hours: number;
  llm: AnalysisEditableLLM;
}

/** Where the model API key in use comes from. The key itself is never returned. */
export type AnalysisKeySource = "none" | "file" | "saved";

export interface AnalysisSettingsView {
  /** "saved": a saved section overrides the configuration file. */
  source: "file" | "saved";
  updated_ns?: string;
  settings: AnalysisEditableSettings;
  api_key: AnalysisKeySource;
  /** What the configuration file says, i.e. what a reset returns to. */
  file: AnalysisEditableSettings;
  file_api_key: boolean;
  /** Read from the configuration file only; the page cannot change them. */
  file_only: {
    allow_non_local: boolean;
    session_idle_minutes: number;
    min_user_turns: number;
    min_active_seconds: number;
    pack_max_tokens: number;
    prompt_reserve_tokens: number;
  };
  /** A run is in progress: a change is picked up by the run after it. */
  running: boolean;
}

/** api_key: absent keeps the key in use, "" sends none, anything else is saved. */
export interface AnalysisSettingsUpdate extends AnalysisEditableSettings {
  api_key?: string;
}

/** The weekly report fields an administrator can change from the page. */
export interface OrgEditableSettings {
  idle_gap_seconds: number;
  ranked_clients: string[];
  max_concurrent_roots: number;
  max_single_request_roots: number;
}

export interface OrgSettingsView {
  /** "saved": a saved section overrides the configuration file. */
  source: "file" | "saved";
  updated_ns?: string;
  settings: OrgEditableSettings;
  /** What the configuration file says, i.e. what a reset returns to. */
  file: OrgEditableSettings;
  /** Read from the configuration file only: they place the week boundaries. */
  timezone: string;
  week_start: "monday" | "sunday";
  /** The clients ranked_clients is chosen from: the ones the vocabulary recognises. */
  clients: OrgClientOption[];
}

/** One client of the vocabulary; label is empty when the vocabulary sets none. */
export interface OrgClientOption {
  key: string;
  label: string;
}

/** Outcome of the connection test; it carries no model output. */
export interface AnalysisProbeResult {
  ok: boolean;
  error?: "invalid_address" | "unreachable" | "timeout" | "http_status" | "bad_response";
  http_status?: number;
  latency_ms: number;
  truncated: boolean;
  reasoned: boolean;
  valid_json: boolean;
  input_tokens: number;
  output_tokens: number;
}
