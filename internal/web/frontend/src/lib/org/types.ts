/** Wire types of /api/v1/org (doc/features/23-org-project-reports.md). */

export type RuleKind = "repo_url" | "repo_name" | "path_glob" | "agent_project";

export interface OrgRule {
  kind: RuleKind;
  pattern: string;
}

export interface OrgGroup {
  id: number;
  name: string;
  enabled: boolean;
  created_at_ns: number;
  updated_at_ns: number;
}

export interface OrgProject {
  id: number;
  name: string;
  /** null is a global project shared by every group. */
  group_id: number | null;
  enabled: boolean;
  rules: OrgRule[];
  created_at_ns: number;
  updated_at_ns: number;
}

export interface OrgMember {
  user_id: number;
  group_id: number;
  updated_at_ns: number;
}

export type PrincipalKind = "user" | "token";
export type PrincipalClass = "human" | "service";

export interface OrgPrincipal {
  kind: PrincipalKind;
  id: number;
  class: PrincipalClass;
  updated_at_ns: number;
}

export interface OrgCatalog {
  groups: OrgGroup[];
  projects: OrgProject[];
  members: OrgMember[];
  principals: OrgPrincipal[];
  /** NewAPI administrator ids proposed as service principals. */
  service_candidates: number[];
}

export interface OrgSettings {
  timezone: string;
  week_start: "monday" | "sunday";
  idle_gap_seconds: number;
  ranked_clients: string[];
  max_concurrent_roots: number;
  max_single_request_roots: number;
}

export interface OrgGroupInput {
  name: string;
  enabled: boolean;
}

export interface OrgProjectInput {
  name: string;
  group_id: number | null;
  enabled: boolean;
  rules: OrgRule[];
}

export interface OrgPreviewInput {
  week?: string;
  group_id: number | null;
  rules: OrgRule[];
  project_id?: number;
}

export interface OrgPreviewResult {
  requests: number;
  identities: number;
  users: number;
  from_unattributed: number;
  from_other_projects: number;
}

export interface OrgUnattributedEntry {
  kind: string;
  value: string;
  requests: number;
  users: number;
  draft_rule: OrgRule;
}

export interface OrgTokens {
  uncached: number;
  cache_read: number;
  cache_write: number;
  output: number;
}

export interface OrgFlag {
  code: "concurrency" | "single_request_roots" | "inferred_sessions" | string;
  value: number;
  threshold?: number;
}

export interface OrgProjectCell {
  /** A project id, or -1 (unattributed) / -2 (no project context). */
  project: number;
  active_ns: number;
  roots: number;
  requests: number;
  tokens: OrgTokens;
  cost_usd: number;
}

export interface OrgUserRow {
  user_id: number;
  group_id: number;
  active_ns: number;
  other_active_ns: number;
  inferred_ns: number;
  roots: number;
  single_request_roots: number;
  requests: number;
  identified_requests: number;
  billed_requests: number;
  tokens: OrgTokens;
  cost_usd: number;
  peak_concurrency: number;
  avg_concurrency: number;
  daily_active_ns: number[];
  projects: OrgProjectCell[];
  flags: OrgFlag[];
}

export interface OrgRankedUser extends OrgUserRow {
  rank: number;
  coverage: number;
}

export interface OrgServiceRow {
  user_id: number;
  token_id: number;
  active_ns: number;
  roots: number;
  requests: number;
  tokens: OrgTokens;
  cost_usd: number;
}

export interface OrgProjectRef {
  id: number;
  name: string;
}

export type OrgMetric = "hours" | "tokens" | "cost";

export interface OrgWeeklyReport {
  week: string;
  start_ns: number;
  end_ns: number;
  timezone: string;
  metric: OrgMetric;
  frozen: boolean;
  frozen_at_ns?: number;
  complete: boolean;
  users: OrgRankedUser[];
  unresolved?: OrgUserRow;
  service: OrgServiceRow[];
  projects: OrgProjectRef[];
  totals: { active_ns: number; requests: number; identified_requests: number; tokens: OrgTokens; cost_usd: number; users: number };
  group_id: number | null;
}

export interface OrgTrendWeek {
  week: string;
  frozen: boolean;
  active_ns: number;
  tokens: number;
  cost_usd: number;
  users: number;
  projects: OrgProjectCell[];
}

export interface OrgTrendReport {
  weeks: OrgTrendWeek[];
  projects: OrgProjectRef[];
}

export interface OrgProjectReport {
  week: string;
  project: OrgProjectRef;
  frozen: boolean;
  contributors: Array<OrgProjectCell & { user_id: number; group_id: number }>;
  total: OrgProjectCell;
}

export interface OrgSelfReport {
  week: string;
  timezone: string;
  row: OrgUserRow | null;
  projects: OrgProjectRef[];
}

export interface OrgWeeklyQuery {
  week?: string;
  group_id?: number;
  metric?: OrgMetric;
}