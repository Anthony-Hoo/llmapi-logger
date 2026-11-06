import type { OrgGroup, OrgProject, OrgRule, OrgUnattributedEntry, RuleKind } from "./types";

/** Mirrors orgreport rule kinds and limits in Go. */
export const RULE_KINDS: Array<{ value: RuleKind; label: string; placeholder: string }> = [
  { value: "repo_url", label: "仓库地址（通配）", placeholder: "git.example.com/team/*" },
  { value: "repo_name", label: "仓库名 / 路径段", placeholder: "billing" },
  { value: "path_glob", label: "路径通配", placeholder: "/home/*/work/billing/**" },
  { value: "agent_project", label: "X-Agent-Project 声明", placeholder: "billing-service" },
];
export const MAX_RULES_PER_PROJECT = 32;
export const MAX_ORG_NAME_CHARS = 128;

/** The two buckets that are not a project (orgreport.ProjectUnattributed / ProjectNoContext). */
export const PROJECT_UNATTRIBUTED = -1;
export const PROJECT_NO_CONTEXT = -2;

export function ruleKindLabel(kind: string): string {
  return RULE_KINDS.find((option) => option.value === kind)?.label ?? kind;
}

export function ruleSummary(rules: OrgRule[]): string {
  if (rules.length === 0) {
    return "无规则（不会命中）";
  }
  const head = rules.slice(0, 2).map((rule) => `${ruleKindLabel(rule.kind)}：${rule.pattern}`);
  return rules.length > 2 ? `${head.join("；")} 等 ${rules.length} 条` : head.join("；");
}

export function scopeLabel(project: Pick<OrgProject, "group_id">, groups: OrgGroup[]): string {
  if (project.group_id === null) {
    return "全员统一项目";
  }
  return groups.find((group) => group.id === project.group_id)?.name ?? `组 #${project.group_id}`;
}

/** Validates a rule draft list the way the Go service does, before sending. */
export function validateRules(rules: OrgRule[]): string | null {
  if (rules.length > MAX_RULES_PER_PROJECT) {
    return `每个项目最多 ${MAX_RULES_PER_PROJECT} 条规则`;
  }
  for (const rule of rules) {
    const pattern = rule.pattern.trim();
    if (pattern === "") {
      return "规则内容不能为空";
    }
    if (rule.kind === "repo_name" && /[\\/]/.test(pattern)) {
      return "仓库名规则只能是单个名称，不能包含路径分隔符";
    }
  }
  return null;
}

/** Project label for a report cell: a project name or one of the buckets. */
export function projectLabel(projectID: number, names: Record<string, string>): string {
  if (projectID === PROJECT_UNATTRIBUTED) {
    return "未归属";
  }
  if (projectID === PROJECT_NO_CONTEXT) {
    return "无项目上下文";
  }
  return names[String(projectID)] ?? `项目 #${projectID}`;
}

/** A project draft pre-filled from an unattributed entry ("一键生成规则草稿"). */
export function draftFromUnattributed(entry: OrgUnattributedEntry): { name: string; rules: OrgRule[] } {
  const segments = entry.value.split("/").filter((segment) => segment !== "");
  const name = (segments.at(-1) ?? entry.value).slice(0, MAX_ORG_NAME_CHARS);
  return { name, rules: [{ ...entry.draft_rule }] };
}

/** Monday (or Sunday) of the current week as YYYY-MM-DD in the browser zone. */
export function isoDay(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

export function shiftWeek(week: string, weeks: number): string {
  const [year, month, day] = week.split("-").map(Number);
  const date = new Date(year, month - 1, day + weeks * 7);
  return isoDay(date);
}

export function formatHours(ns: number): string {
  const hours = ns / 3.6e12;
  if (hours >= 10) {
    return `${hours.toFixed(0)} h`;
  }
  if (hours >= 1) {
    return `${hours.toFixed(1)} h`;
  }
  return `${Math.round(ns / 6e10)} min`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}
