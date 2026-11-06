import { describe, expect, it } from "vitest";

import {
  draftFromUnattributed,
  formatHours,
  formatPercent,
  projectLabel,
  PROJECT_NO_CONTEXT,
  PROJECT_UNATTRIBUTED,
  ruleSummary,
  scopeLabel,
  shiftWeek,
  validateRules,
} from "./format";

describe("org format helpers", () => {
  it("summarises rules and scopes", () => {
    expect(ruleSummary([])).toContain("无规则");
    expect(ruleSummary([{ kind: "repo_name", pattern: "billing" }])).toBe("仓库名 / 路径段：billing");
    expect(
      ruleSummary([
        { kind: "repo_name", pattern: "a" },
        { kind: "repo_name", pattern: "b" },
        { kind: "path_glob", pattern: "/c/**" },
      ]),
    ).toContain("等 3 条");
    const groups = [{ id: 2, name: "Platform", enabled: true, created_at_ns: 1, updated_at_ns: 1 }];
    expect(scopeLabel({ group_id: null }, groups)).toBe("全员统一项目");
    expect(scopeLabel({ group_id: 2 }, groups)).toBe("Platform");
    expect(scopeLabel({ group_id: 9 }, groups)).toBe("组 #9");
  });

  it("validates rules like the service", () => {
    expect(validateRules([{ kind: "repo_url", pattern: "git.example.com/*" }])).toBeNull();
    expect(validateRules([{ kind: "repo_name", pattern: "  " }])).toContain("不能为空");
    expect(validateRules([{ kind: "repo_name", pattern: "a/b" }])).toContain("单个名称");
    expect(validateRules(Array.from({ length: 33 }, () => ({ kind: "repo_name" as const, pattern: "x" })))).toContain("32");
  });

  it("labels the two non-project buckets", () => {
    expect(projectLabel(PROJECT_UNATTRIBUTED, {})).toBe("未归属");
    expect(projectLabel(PROJECT_NO_CONTEXT, {})).toBe("无项目上下文");
    expect(projectLabel(4, { "4": "Core" })).toBe("Core");
    expect(projectLabel(5, {})).toBe("项目 #5");
  });

  it("drafts a project from an unattributed entry", () => {
    const draft = draftFromUnattributed({
      kind: "path_glob", value: "/home/dev/tool", requests: 3, users: 1, draft_rule: { kind: "repo_name", pattern: "tool" },
    });
    expect(draft).toEqual({ name: "tool", rules: [{ kind: "repo_name", pattern: "tool" }] });
  });

  it("formats weeks, hours and percentages", () => {
    expect(shiftWeek("2026-11-02", -1)).toBe("2026-10-26");
    expect(shiftWeek("2026-12-28", 1)).toBe("2027-01-04");
    expect(formatHours(3.6e12 * 12)).toBe("12 h");
    expect(formatHours(3.6e12 * 1.25)).toBe("1.3 h");
    expect(formatHours(6e10 * 25)).toBe("25 min");
    expect(formatPercent(0.876)).toBe("88%");
  });
});
