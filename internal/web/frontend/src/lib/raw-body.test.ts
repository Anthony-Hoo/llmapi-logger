import { describe, expect, it } from "vitest";

import type { AuditBody, AuditHeader, RawBodyDownload } from "../types";
import type { AuditDetail } from "../types";
import { bodyForSide, buildEvidenceEnvelope, capturedContentType, createRawBodyPreview, evidenceStage } from "./raw-body";

function download(bytes: BlobPart, contentType = "application/octet-stream"): RawBodyDownload {
  return {
    blob: new Blob([bytes], { type: contentType }),
    filename: "evidence.bin",
    contentType,
    observedLength: null,
    storedLength: null,
    sha256: null,
    complete: true,
  };
}

describe("raw Body preview", () => {
  it.each([
    ["request", "request_sent_to_newapi", "request_for_newapi_received_from_nginx"],
    ["response", "response_received_from_newapi", "response_from_newapi_sent_to_nginx"],
  ] as const)("selects the %s fallback and keeps its metadata together", (side, preferred, fallback) => {
    const detail = {
      bodies: [{ stage: fallback, retention_state: "full", error_code: "capture_chunk_missing" } as AuditBody],
      // A preferred stage without a body must not hide a retained fallback body.
      stages: [{ stage: preferred, state: "complete" }, { stage: fallback, state: "partial" }],
      headers: [preferred, fallback].map((stage) => ({ stage, kind: "header", name: "Content-Type", value_index: 0, value_length: 10,
        value: stage === fallback ? "text/plain" : "application/json" })),
      audit: { method: "POST", path: "/v1/responses", status_code: 503 },
    } as AuditDetail;
    expect(bodyForSide(detail, side)?.stage).toBe(fallback);
    expect(evidenceStage(side, detail)).toBe(fallback);
    expect(capturedContentType(detail.headers, side, detail)).toBe("text/plain");
    expect(buildEvidenceEnvelope(detail, side).headerLines).toEqual(["Content-Type: text/plain"]);
    detail.bodies.push({ stage: preferred, retention_state: "metadata" } as AuditBody);
    expect(bodyForSide(detail, side)?.stage).toBe(preferred);
    expect(capturedContentType(detail.headers, side, detail)).toBe("application/json");
  });
  it("renders valid UTF-8 evidence without rewriting it", async () => {
    const raw = "{\"message\":\"你好\"}\n";

    await expect(createRawBodyPreview(download(raw), "application/json; charset=utf-8")).resolves.toEqual({
      kind: "text",
      text: raw,
      contentType: "application/json; charset=utf-8",
    });
  });

  it("falls back safely for undecodable or binary bytes", async () => {
    const preview = await createRawBodyPreview(download(new Uint8Array([0xff, 0x00, 0x80])));

    expect(preview.kind).toBe("binary");
  });

  it("uses the Content-Type captured at the selected audit boundary", () => {
    const headers: AuditHeader[] = [
      {
        stage: "request_sent_to_newapi",
        kind: "header",
        name: "Content-Type",
        value_index: 0,
        value_length: 16,
        value: "application/json",
      },
      {
        stage: "response_received_from_newapi",
        kind: "header",
        name: "Content-Type",
        value_index: 0,
        value_length: 17,
        value: "text/event-stream",
      },
    ];

    expect(capturedContentType(headers, "request")).toBe("application/json");
    expect(capturedContentType(headers, "response")).toBe("text/event-stream");
  });

  it("rebuilds the request target and actual Header values from detail evidence", () => {
    const detail = {
      audit: {
        audit_id: "apx_test",
        started_at_ns: "1",
        route_id: "openai-chat-completions",
        protocol: "openai",
        method: "POST",
        path: "/v1/chat/completions",
        status_code: 200,
        forward_status: "completed",
        capture_status: "complete",
        parse_status: "ok",
      },
      request_uri: "/v1/chat/completions?trace=full",
      stages: [
        {
          stage: "request_sent_to_newapi",
          state: "complete",
          proto: "HTTP/1.1",
          method: "POST",
          host: "ai.example.test",
          content_length: 18,
        },
      ],
      headers: [
        {
          stage: "request_sent_to_newapi",
          kind: "header",
          name: "X-Trace",
          value_index: 0,
          value_length: 12,
          value: "actual-value",
        },
        {
          stage: "request_sent_to_newapi",
          kind: "trailer",
          name: "X-Checksum",
          value_index: 0,
          value_length: 4,
          value: "done",
        },
      ],
      bodies: [],
      conversation: null,
      parsed_result: null,
      turn: null,
      token_link: null,
    } satisfies AuditDetail;

    expect(buildEvidenceEnvelope(detail, "request")).toEqual({
      startLine: "POST /v1/chat/completions?trace=full HTTP/1.1",
      headerLines: ["Host: ai.example.test", "X-Trace: actual-value", "Content-Length: 18"],
      trailerLines: ["X-Checksum: done"],
    });
  });

  it("uses the outbound origin-form target when the inbound request used absolute-form", () => {
    const detail = {
      audit: {
        audit_id: "apx_absolute",
        started_at_ns: "1",
        route_id: "openai-chat-completions",
        protocol: "openai",
        method: "POST",
        path: "/v1/chat/completions",
        status_code: 200,
        forward_status: "completed",
        capture_status: "complete",
        parse_status: "ok",
      },
      request_uri: "http://logger.example/v1/chat/completions?trace=absolute",
      stages: [
        {
          stage: "request_sent_to_newapi",
          state: "complete",
          proto: "HTTP/1.1",
          method: "POST",
          host: "ai.example.test",
          content_length: 0,
        },
      ],
      headers: [],
      bodies: [],
      conversation: null,
      parsed_result: null,
      turn: null,
      token_link: null,
    } satisfies AuditDetail;

    expect(buildEvidenceEnvelope(detail, "request").startLine).toBe(
      "POST /v1/chat/completions?trace=absolute HTTP/1.1",
    );
  });
});
