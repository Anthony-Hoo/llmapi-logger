import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AuditDetail, AuditSummary } from "./types";
import { AuditList, HTTPAuditEvidence } from "./app";

const detail: AuditDetail = {
  audit: {
    audit_id: "apx_evidence",
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
  request_uri: "/v1/chat/completions",
  stages: [],
  headers: [
    {
      stage: "request_sent_to_newapi",
      kind: "header",
      name: "Content-Type",
      value_index: 0,
      value_length: 16,
      value: "application/json",
    },
  ],
  bodies: [],
  conversation: null,
  parsed_result: null,
  token_link: null,
};

describe("HTTP audit evidence", () => {
  it("keeps raw HTTP and Header values in a secondary disclosure collapsed by default", () => {
    const html = renderToStaticMarkup(
      <HTTPAuditEvidence
        detail={detail}
        rawBodies={{}}
        rawLoading={null}
        rawNote={null}
        onLoad={() => undefined}
        onDownload={() => undefined}
        onClear={() => undefined}
      />,
    );

    expect(html).toContain("原始 HTTP 证据与完整性");
    expect(html).toContain("辅助证据 · 默认折叠");
    expect(html).toContain("Header / Trailer 值（1）");
    expect(html).toContain("Content-Type");
    expect(html).toContain("<details");
    expect(html).not.toContain("<details open");
  });
});

describe("audit list", () => {
  it("uses compact native list buttons instead of a horizontally scrolling Table", () => {
    const audit: AuditSummary = {
      audit_id: "apx_selected",
      started_at_ns: "1",
      route_id: "openai-chat-completions",
      protocol: "openai",
      method: "POST",
      path: "/v1/chat/completions",
      status_code: 200,
      forward_status: "completed",
      capture_status: "complete",
      parse_status: "ok",
      response_model: "gpt-4o",
      newapi_token_id: 42,
      token_name: "personal",
      masked_key: "abcd**********wxyz",
    };

    const html = renderToStaticMarkup(
      <AuditList items={[audit]} loading={false} selectedID={audit.audit_id} onSelect={() => undefined} />,
    );

    expect(html).toContain("<ul");
    expect(html).toContain("<li");
    expect(html).toContain('<button type="button" aria-current="true"');
    expect(html).toContain("gpt-4o");
    expect(html).toContain("API #42 personal");
    expect(html).toContain("abcd**********wxyz");
    expect(html).not.toContain("<table");
  });
});
