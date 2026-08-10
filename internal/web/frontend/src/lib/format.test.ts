import { describe, expect, it } from "vitest";

import { formatBytes, humanizeStage, statusVariant } from "./format";

describe("display formatters", () => {
  it("makes capture sizes and stage names readable", () => {
    expect(formatBytes(1536)).toBe("1.50 KiB");
    expect(humanizeStage("request_sent_to_newapi")).toBe("发送至 NewAPI");
  });

  it("makes rejected records visually destructive", () => {
    expect(statusVariant("rejected")).toBe("destructive");
    expect(statusVariant("completed")).toBe("success");
  });
});
