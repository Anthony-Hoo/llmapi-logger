import { describe, expect, it } from "vitest";
import { filtersForConversation, hasRowFilters, parseStatusCodeDraft } from "./filters";

describe("audit filter transitions", () => {
  it.each(["99", "600", "503.0", "5e2", "-100", "+503", "abc", "５０３"])("rejects invalid status %s", (draft) => {
    expect(parseStatusCodeDraft(draft).error).toBe("状态码须为 100–599 的整数");
  });

  it.each([["", undefined], [" \t ", undefined], ["100", "100"], ["599", "599"], [" 00503 ", "503"]])(
    "normalizes status %s", (draft, value) => {
      expect(parseStatusCodeDraft(draft!)).toEqual({ value, error: null });
    },
  );

  it("opens the complete conversation and preserves the collapse preference", () => {
    for (const collapse of [true, false]) {
      expect(filtersForConversation({
        collapse, conversation: "conv_old", path: "/v1/responses", model: "model-example",
        user_agent: "client", newapi_user_id: "1", newapi_token_id: "2",
        forward_status: "completed", status_class: "5xx", status_code: "503",
      }, "conv_new")).toEqual({ collapse, conversation: "conv_new" });
    }
  });

  it("keeps scope-independent conversation preferences out of row filters", () => {
    expect(hasRowFilters({ collapse: true, conversation: "conv_example", status_code: " \t " })).toBe(false);
  });
});
