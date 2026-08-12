import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AuditDetail, AuditSummary, NewAPIUser } from "./types";
import { AuditFiltersPanel, AuditList, HTTPAuditEvidence } from "./app";

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
  it("shows only time, caller, model, and User-Agent in compact native list buttons", () => {
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
	  caller_status: "resolved",
	  newapi_user_id: 7,
	  username: "alice",
	  newapi_token_id: 42,
	  token_name: "personal",
      user_agent: "codex-cli/1.0",
    };

    const html = renderToStaticMarkup(
      <AuditList items={[audit]} loading={false} selectedID={audit.audit_id} onSelect={() => undefined} />,
    );

    expect(html).toContain("<ul");
    expect(html).toContain("<li");
    expect(html).toContain('<button type="button" aria-current="true"');
    expect(html).toContain("调用者");
	expect(html).toContain("personal");
	expect(html).toContain("@alice");
    expect(html).toContain("模型");
    expect(html).toContain("gpt-4o");
    expect(html).toContain("User-Agent");
    expect(html).toContain("codex-cli/1.0");
    expect(html).not.toContain("apx_selected");
    expect(html).not.toContain("/v1/chat/completions");
    expect(html).not.toContain("openai-chat-completions");
	expect(html).not.toContain("masked_key");
    expect(html).not.toContain("completed");
    expect(html).not.toContain("capture");
    expect(html).not.toContain("parse");
    expect(html).not.toContain("<table");
  });

  it("uses fallbacks and renders one short anomaly hint", () => {
    const audit: AuditSummary = {
      audit_id: "apx_rejected",
      started_at_ns: "1",
      route_id: "anthropic-messages",
      protocol: "anthropic",
      method: "POST",
      path: "/v1/messages",
      status_code: 403,
      forward_status: "rejected",
      capture_status: "complete",
      parse_status: "skipped",
      request_model: "claude-test",
    };

    const html = renderToStaticMarkup(
      <AuditList items={[audit]} loading={false} selectedID={null} onSelect={() => undefined} />,
    );

    expect(html).toContain("未关联");
    expect(html).toContain("claude-test");
    expect(html).toContain("User-Agent");
    expect(html).toContain("未记录");
    expect(html.match(/已拦截/g)).toHaveLength(1);
    expect(html.match(/HTTP 403/g)).toHaveLength(1);
    expect(html).not.toContain("skipped");
  });
});

describe("audit filters", () => {
  it("puts caller, model, and User-Agent first while keeping diagnostics in collapsed advanced filters", () => {
	const users: NewAPIUser[] = [
	  {
		id: 7,
		username: "alice",
		display_name: "Alice",
		status: 1,
		group: "default",
	  },
    ];
    const html = renderToStaticMarkup(
      <AuditFiltersPanel
        path=""
        model=""
		userAgent=""
		newAPIUserID=""
		newAPITokenID=""
		forwardStatus=""
		users={users}
        onPathChange={() => undefined}
        onModelChange={() => undefined}
		onUserAgentChange={() => undefined}
		onNewAPIUserIDChange={() => undefined}
        onNewAPITokenIDChange={() => undefined}
        onForwardStatusChange={() => undefined}
        onSubmit={() => undefined}
      />,
    );

    expect(html.indexOf("调用者")).toBeLessThan(html.indexOf("模型"));
    expect(html.indexOf("模型")).toBeLessThan(html.indexOf("User-Agent"));
    expect(html.indexOf("User-Agent")).toBeLessThan(html.indexOf("高级筛选"));
    expect(html.indexOf("高级筛选")).toBeLessThan(html.lastIndexOf("转发状态"));
	expect(html).toContain("Alice · @alice");
	expect(html).toContain("NewAPI Token ID");
    expect(html).toContain("应用筛选");
    expect(html).toContain("高级筛选");
    expect(html).toContain("路径");
    expect(html).toContain("<details");
    expect(html).not.toContain("<details open");
  });
});
