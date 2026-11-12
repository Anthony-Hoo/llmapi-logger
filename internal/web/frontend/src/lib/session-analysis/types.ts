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
  facets_due: number;
  facets_ok: number;
  facets_invalid: number;
  facets_failed: number;
  model_input_tokens: number;
  model_output_tokens: number;
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
  model?: string;
  prompt_version: string;
  calibration?: AnalysisCalibration;
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
  facet_status?: "ok" | "invalid" | "failed";
  task_type?: string;
  outcome?: string;
  /** Organisation reports only: where the session is booked. */
  bucket?: "attributed" | "unattributed" | "no_context" | "service";
  project_id?: number;
  /** Current project name; absent when the project was deleted. */
  project?: string;
  /** Administrators only: the session's NewAPI user; absent when the caller was not resolved. */
  user_id?: number;
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
  /** Administrators only: keeps one NewAPI user's sessions. */
  user_id?: number;
}

/** Session totals of one NewAPI user; user_id is null for unresolved callers. */
export interface AnalysisUserTotals {
  user_id: number | null;
  last_ns: string;
  totals: AnalysisSignalTotals;
}

export interface AnalysisUsers {
  from_ns: string;
  to_ns: string;
  items: AnalysisUserTotals[];
}

export interface AnalysisPack {
  session_id: string;
  pack_id: string;
  kind: "session" | "chat_digest";
  /** Redacted text the local model sees; sensitive, never cached. */
  text: string;
  refs: Record<string, string>;
  tokens: number;
  truncated: boolean;
  members: number;
  built_ns: string;
}

export interface AnalysisCalibration {
  prompt_version: string;
  model: string;
  labels?: number;
  samples: number;
  compared: Record<string, number>;
  agreement: Record<string, number>;
  hidden_fields: string[];
  created_ns: string;
}

export interface AnalysisCalibrationLabel {
  session_id: string;
  task_type?: string;
  outcome?: string;
  collaboration?: string;
  work_relevance?: string;
  friction?: string[];
}

export interface AnalysisFacet {
  session_id: string;
  pack_id: string;
  kind: "session" | "chat_digest";
  status: "ok" | "invalid" | "failed";
  model: string;
  prompt_version: string;
  created_ns: string;
  task_type?: string;
  outcome?: string;
  collaboration?: string;
  work_relevance?: string;
  friction: string[];
  items: Array<{ ref: string; task_type?: string; work_relevance?: string }>;
  invalid_fields: string[];
  goal?: string;
  instructions: string[];
  skill_candidate?: string;
  evidence: Record<string, Array<{ label: string; audit_id?: string }>>;
  hidden_fields: string[];
}
export interface AnalysisWeeklyStats {
  week_start_ns: string;
  totals: AnalysisSignalTotals;
  facets_ok: number;
  task_types: Record<string, number>;
  outcomes: Record<string, number>;
  collaboration: Record<string, number>;
  friction: Record<string, number>;
  /** Project and group scopes only: distinct callers of the week. */
  contributors?: number;
  /** Too few callers: counts only, no goals or suggestion texts. */
  limited?: boolean;
}

export interface AnalysisSuggestion {
  id: number;
  kind: "instruction" | "skill";
  text: string;
  sessions: number;
  strong: boolean;
  status: "open" | "adopted_detected" | "dismissed";
  first_seen_ns: string;
  last_seen_ns: string;
  evidence: string[];
}

export interface AnalysisScopeOption {
  id: number;
  name: string;
}

/** Selects a user, project or group report (administrators; projects and groups need organisation reports). */
export interface AnalysisReportTarget {
  project_id?: number;
  group_id?: number;
  user_id?: number;
}

export interface AnalysisReport {
  week_start_ns: string;
  scope: "person" | "all" | "project" | "group" | "user";
  scope_id?: number;
  scope_name?: string;
  /** Scopes an administrator can open for this week; projects and groups are empty without organisation reports. */
  projects: AnalysisScopeOption[];
  groups: AnalysisScopeOption[];
  /** Users with statistics this week; their names come from the caller catalog. */
  users: AnalysisScopeOption[];
  stats: AnalysisWeeklyStats | null;
  previous: AnalysisWeeklyStats | null;
  narrative: string;
  narrative_source?: "model" | "template";
  computed_ns: string;
  suggestions: AnalysisSuggestion[];
  optimizations: AnalysisSessionItem[];
}
