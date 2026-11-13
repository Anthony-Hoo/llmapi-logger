import { describe, expect, it } from "vitest";

import type { ConversationMessage } from "../types";
import { buildUserInputOutline, isInjectedUserText } from "./user-input-outline";

// The Go vocabulary tests read the same file (internal/insights), so the UI
// classifier and IsInjectedUserText are pinned to the same cases.
declare const process: { getBuiltinModule(id: "node:fs"): { readFileSync(path: URL, encoding: "utf8"): string } };
const fixture = JSON.parse(
  process
    .getBuiltinModule("node:fs")
    .readFileSync(new URL("../../../../insights/testdata/user_input_prefixes.json", import.meta.url), "utf8"),
) as { prefixes: string[]; cases: { text: string; injected: boolean }[] };

function userText(index: number, ...texts: string[]): ConversationMessage {
  return {
    index,
    role: "user",
    phase: "request",
    direction: "client_to_upstream",
    content: texts.map((text, part) => ({ index: part, type: "text", text })),
  };
}

describe("isInjectedUserText", () => {
  it("classifies the shared Go fixture cases like the vocabulary does", () => {
    expect(fixture.cases.length).toBeGreaterThan(0);
    for (const testCase of fixture.cases) {
      expect(isInjectedUserText(testCase.text, fixture.prefixes), JSON.stringify(testCase.text)).toBe(testCase.injected);
    }
  });

  it("compares only the first 64 characters after leading whitespace", () => {
    const prefixes = ["<late"];
    expect(isInjectedUserText(`${" ".repeat(100)}<LATE>`, prefixes)).toBe(true);
    expect(isInjectedUserText(`${"x".repeat(60)}<late`, ["x".repeat(60) + "<late"])).toBe(false);
    // Code points, not UTF-16 units: 60 astral characters still leave room for the prefix.
    expect(isInjectedUserText(`${"😀".repeat(60)}<la`, ["😀".repeat(60) + "<la"])).toBe(true);
  });

  it("treats nothing as injected without a prefix list", () => {
    expect(isInjectedUserText("<system-reminder>x", [])).toBe(false);
  });
});

describe("buildUserInputOutline", () => {
  it("keeps typed user text and skips injected context, tool results and other roles", () => {
    const messages: ConversationMessage[] = [
      userText(0, "# AGENTS.md instructions for /work\n\nbe concise"),
      userText(1, "<environment_context>\n  <cwd>/work</cwd>\n</environment_context>"),
      userText(2, "  Fix the\nflaky   login test  "),
      { index: 3, role: "assistant", phase: "request", direction: "client_to_upstream", content: [{ index: 0, type: "text", text: "Done." }] },
      {
        index: 4,
        role: "user",
        phase: "request",
        direction: "client_to_upstream",
        content: [{ index: 0, type: "tool_result", tool_call_id: "call_1", result: "ok" }],
      },
      userText(5, "<system-reminder>plan mode</system-reminder>", "x".repeat(100)),
      userText(6, "   "),
    ];

    expect(buildUserInputOutline(messages, fixture.prefixes)).toEqual([
      { position: 2, displayIndex: 3, preview: "Fix the flaky login test" },
      { position: 5, displayIndex: 6, preview: `${"x".repeat(80)}…` },
    ]);
  });

  it("follows the server list, so an operator override changes the outline", () => {
    const messages = [userText(0, "<company-context>secret</company-context>"), userText(1, "deploy it")];
    expect(buildUserInputOutline(messages, ["<company-context"]).map((entry) => entry.position)).toEqual([1]);
    expect(buildUserInputOutline(messages, []).map((entry) => entry.position)).toEqual([0, 1]);
  });

  it("does not split surrogate pairs when truncating the preview", () => {
    const [entry] = buildUserInputOutline([userText(0, "😀".repeat(90))], []);
    expect(entry.preview).toBe(`${"😀".repeat(80)}…`);
  });
});
