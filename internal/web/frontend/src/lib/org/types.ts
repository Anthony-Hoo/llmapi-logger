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
