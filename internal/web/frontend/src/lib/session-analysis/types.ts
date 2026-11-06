// Session analysis (doc/features/24-session-analysis.md). Mirrors the JSON
// tags of internal/sessionanalysis/api.go. Nanosecond times are decimal strings.

export interface AnalysisSignalTotals {
  sessions: number;
  agent_sessions: number;
  chat_sessions: number;
  eligible: number;
  cost_usd: number | null;
  loop_sessions: number;
  loop_cost_usd: number | null;
  thrash_sessions: number;
  unverified_sessions: number;
  sessions_with_writes: number;
  failure_sessions: number;
  corrections: number;
  correction_sessions: number;
  error_paste_sessions: number;
  interrupt_sessions: number;
  heavy_model_sessions: number;
  danger_sessions: number;
  secret_sessions: number;
  compaction_sessions: number;
  cache_hit_rate: number | null;
}

export interface AnalysisRunSummary {
  started_ns: string;
  finished_ns: string;
  trigger: "schedule" | "manual";
  candidates: number;
  analyzed: number;
  skipped: number;
  skip_reasons: Record<string, number>;
  error?: string;
}

export interface AnalysisOverview {
  from_ns: string;
  to_ns: string;
  current: AnalysisSignalTotals;
  previous: AnalysisSignalTotals;
  last_run?: AnalysisRunSummary;
  running: boolean;
  llm_enabled: boolean;
}

export type AnalysisFlag =
  | "loop"
  | "thrash"
  | "unverified"
  | "failures"
  | "corrections"
  | "error_paste"
  | "interrupt"
  | "heavy_model"
  | "danger"
  | "secret"
  | "compaction";

export interface AnalysisSessionItem {
  session_id: string;
  tree_id?: string;
  trend_session_id?: string;
  kind: "agent" | "chat";
  client: string;
  model: string;
  first_ns: string;
  last_ns: string;
  last_audit_id: string;
  requests: number;
  subagents: number;
  user_turns: number;
  active_seconds: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number | null;
  tool_calls: number;
  tool_failures: number;
  max_failure_streak: number;
  loops: number;
  max_loop_length: number;
  thrash_files: number;
  max_file_writes: number;
  verified: "yes" | "no" | "no_writes";
  error_pastes: number;
  interrupts: number;
  corrections: number;
  compactions: number;
  model_switches: number;
  length_stops: number;
  upstream_errors: number;
  heavy_model: boolean;
  danger: Record<string, number>;
  secrets: Record<string, number>;
  eligible: boolean;
  skip_reason?: string;
}

export interface AnalysisSessionsPage {
  items: AnalysisSessionItem[];
  next_cursor?: string;
}

export interface AnalysisSessionsQuery {
  from_ns: string;
  to_ns: string;
  kind?: "agent" | "chat";
  flags?: AnalysisFlag[];
  cursor?: string;
  limit?: number;
}
