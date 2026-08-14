import { describe, expect, it } from "vitest";

import { formatBytes, formatDurationNS, humanizeStage, statusVariant } from "./format";

describe("display formatters", () => {
  it("makes capture sizes and stage names readable", () => {
    expect(formatBytes(1536)).toBe("1.50 KiB");
    expect(humanizeStage("request_sent_to_newapi")).toBe("发送至 NewAPI");
  });

  it("makes rejected records visually destructive", () => {
    expect(statusVariant("rejected")).toBe("destructive");
    expect(statusVariant("completed")).toBe("success");
  });

  it("formats TTFT without losing the useful unit", () => {
    expect(formatDurationNS(null)).toBe("—");
    expect(formatDurationNS(999)).toBe("999 ns");
    expect(formatDurationNS(12_500)).toBe("12.5 µs");
    expect(formatDurationNS(125_000_000)).toBe("125 ms");
    expect(formatDurationNS("1500000000")).toBe("1.50 s");
  });
});
