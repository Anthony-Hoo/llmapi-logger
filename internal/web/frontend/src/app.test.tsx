import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AuditDetail, AuditSummary, NewAPIUser } from "./types";
import type { ApiClient } from "./api";
import {
  AuditDetailBody,
  AuditFiltersPanel,
  AuditList,
  DeveloperBadge,
  HTTPAuditEvidence,
  StreamTimingPanel,
  TurnStoragePanel,
  UserAgentRulesPanel,
} from "./app";

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
  turn: null,
  token_link: null,
};

function renderDetailBody(value: AuditDetail): string {
  return renderToStaticMarkup(
    <AuditDetailBody
      detail={value}
      onFilterConversation={() => undefined}
      onExportConversation={() => undefined}
      exportNote={null}
      reconstructedLoading={null}
      reconstructedNote={null}
      onDownloadReconstructed={() => undefined}
      timelines={{}}
      timelineLoading={null}
      timelineNote={null}
      onLoadTimeline={() => undefined}
      rawBodies={{}}
      rawLoading={null}
      rawNote={null}
      onLoadRaw={() => undefined}
      onDownloadRaw={() => undefined}
      onClearRaw={() => undefined}
    />,
  );
}

describe("audit detail layout", () => {
  const conversationDetail: AuditDetail = {
    ...detail,
    audit: {
      ...detail.audit,
      response_model: "gpt-4o",
      user_agent: "codex-cli/1.0",
      conversation_id: "conv_demo",
    },
    conversation: {
      schema_version: 1,
      messages: [
        {
          index: 0,
          role: "user",
          phase: "request",
          direction: "client_to_upstream",
          content: [{ index: 0, type: "text", text: "What is the weather?" }],
        },
        {
          index: 1,
          role: "assistant",
          phase: "response",
          direction: "upstream_to_client",
          content: [{ index: 0, type: "text", text: "Sunny." }],
        },
      ],
    },
  };

  it("shows the conversation first and every HTTP / storage detail below it", () => {
    const html = renderDetailBody(conversationDetail);

    expect(html.indexOf("对话审计")).toBeGreaterThan(-1);
    expect(html.indexOf("对话审计")).toBeLessThan(html.indexOf("HTTP 请求概览"));
    expect(html.indexOf("HTTP 请求概览")).toBeLessThan(html.indexOf("解析摘要"));
    expect(html.indexOf("解析摘要")).toBeLessThan(html.indexOf("流式响应时序"));
    expect(html.indexOf("流式响应时序")).toBeLessThan(html.indexOf("轮次与内容存储"));
    expect(html.indexOf("轮次与内容存储")).toBeLessThan(html.indexOf("原始 HTTP 证据与完整性"));
    // Key facts appear above the conversation for orientation.
    expect(html.indexOf("gpt-4o")).toBeLessThan(html.indexOf("对话审计"));
    expect(html).toContain("codex-cli/1.0");
    expect(html).toContain("查看同会话");
  });

  it("keeps turn storage and raw HTTP evidence in collapsed disclosures", () => {
    const html = renderDetailBody(conversationDetail);

    expect(html).toContain("<details");
    expect(html).not.toContain("<details open");
    expect(html).toContain("轮次与内容存储");
    expect(html).toContain("原始 HTTP 证据与完整性");
  });

  it("offers a conversation JSON export exactly when a parsed conversation exists", () => {
    const withConversation = renderDetailBody(conversationDetail);
    expect(withConversation).toContain("导出会话 JSON");
    expect(withConversation).not.toContain('disabled=""');

    const withoutConversation = renderDetailBody({ ...conversationDetail, conversation: null });
    expect(withoutConversation).toContain("导出会话 JSON");
    expect(withoutConversation).toContain('disabled=""');
  });
});

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

  it("explains metadata-only retention without offering a raw download that would return 410", () => {
    const metadataDetail: AuditDetail = {
      ...detail,
      bodies: [{
        stage: "request_sent_to_newapi",
        source_stage: "request_for_newapi_received_from_nginx",
        observed_length: 4096,
        stored_length: 0,
        sha256: "a".repeat(64),
        hash_complete: true,
        eof_seen: true,
        state: "complete",
        retention_state: "metadata",
        first_observed_at_ns: "10",
        last_observed_at_ns: "20",
        chunk_count: 0,
        stream_event_count: 0,
        stream_timeline_complete: true,
      }],
    };
    const html = renderToStaticMarkup(
      <HTTPAuditEvidence
        detail={metadataDetail}
        rawBodies={{}}
        rawLoading={null}
        rawNote={null}
        onLoad={() => undefined}
        onDownload={() => undefined}
        onClear={() => undefined}
      />,
    );

    expect(html).toContain("原始 Body 已完成校验并释放");
    expect(html).toContain("仅元数据 + 可重建对象");
    expect(html).not.toContain("下载原始 Body");
    expect(html).not.toContain("加载并查看 Body");
  });
});

describe("content-addressed turn evidence", () => {
  const turnDetail: AuditDetail = {
    ...detail,
    audit: { ...detail.audit, ttft_ns: "125000000" },
    turn: {
      turn_id: "turn-example",
      conversation_id: "conversation-example",
      parent_turn_id: "turn-parent",
      parent_base: "post_turn",
      link_reason: "branch",
      link_confidence: 85,
      request_layout: "responses",
      response_layout: "responses",
      request_item_count: 12,
      response_item_count: 3,
      request_sequence_sha256: "1".repeat(64),
      response_sequence_sha256: "2".repeat(64),
      request_reconstruction_sha256: "3".repeat(64),
      response_reconstruction_sha256: "4".repeat(64),
      reconstruction_status: "verified",
      previous_response_id: "resp-parent",
      response_id: "resp-current",
      created_at_ns: "30",
    },
    bodies: [{
      stage: "response_received_from_newapi",
      source_stage: "response_received_from_newapi",
      observed_length: 100,
      stored_length: 0,
      sha256: "5".repeat(64),
      hash_complete: true,
      eof_seen: true,
      state: "complete",
      retention_state: "metadata",
      first_observed_at_ns: "10",
      last_observed_at_ns: "20",
      chunk_count: 0,
      stream_event_count: 2,
      stream_timeline_complete: true,
    }],
  };

  it("shows graph linkage and reconstructed JSON download actions", () => {
    const html = renderToStaticMarkup(
      <TurnStoragePanel detail={turnDetail} loading={null} note={null} onDownload={() => undefined} />,
    );

    expect(html).toContain("轮次已通过精确重建校验");
    expect(html).toContain("conversation-example");
    expect(html).toContain("分支");
    expect(html).toContain("下载重建请求 JSON");
    expect(html).toContain("下载重建响应 JSON");
  });

  it("shows TTFT and verifies first/last logical SSE event times", () => {
    const html = renderToStaticMarkup(
      <StreamTimingPanel
        detail={turnDetail}
        timelines={{ response: {
          stage: "response_received_from_newapi",
          observed_length: 100,
          event_count: 2,
          first_event_at_ns: "10",
          last_event_at_ns: "20",
          complete: true,
          points: [{ offset: 40, at_ns: "10" }, { offset: 100, at_ns: "20" }],
        } }}
        loading={null}
        note={null}
        onLoad={() => undefined}
      />,
    );

    expect(html).toContain("125 ms");
    expect(html).toContain("逻辑事件");
    expect(html).toContain("已保存时间点");
    expect(html).toContain("首事件");
    expect(html).toContain("末事件");
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
	  username: "alice-long-username",
	  display_name: "Alice",
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
	expect(html).toContain("Alice");
	expect(html).toContain("ID: 42");
	expect(html).not.toContain("alice-long-username");
    expect(html).toContain("模型");
    expect(html).toContain("gpt-4o");
    expect(html).toContain("User-Agent");
    expect(html).toContain("codex-cli/1.0");
    expect(html).toContain("whitespace-normal break-words");
    expect(html).not.toContain("apx_selected");
    expect(html).not.toContain("/v1/chat/completions");
    expect(html).not.toContain("openai-chat-completions");
	expect(html).not.toContain("api_key");
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
		statusClass=""
		statusCode=""
		users={users}
        onPathChange={() => undefined}
        onModelChange={() => undefined}
		onUserAgentChange={() => undefined}
		onNewAPIUserIDChange={() => undefined}
        onNewAPITokenIDChange={() => undefined}
        onForwardStatusChange={() => undefined}
		onStatusClassChange={() => undefined}
		onStatusCodeChange={() => undefined}
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

  it("hides the caller filters from a scoped developer session", () => {
    const html = renderToStaticMarkup(
      <AuditFiltersPanel
        path=""
        model=""
        userAgent=""
        newAPIUserID=""
        newAPITokenID=""
        forwardStatus=""
		statusClass=""
		statusCode=""
        users={[]}
        showCallerFilters={false}
        onPathChange={() => undefined}
        onModelChange={() => undefined}
        onUserAgentChange={() => undefined}
        onNewAPIUserIDChange={() => undefined}
        onNewAPITokenIDChange={() => undefined}
        onForwardStatusChange={() => undefined}
		onStatusClassChange={() => undefined}
		onStatusCodeChange={() => undefined}
        onSubmit={() => undefined}
      />,
    );

    // A scoped session is pinned to one caller, and the API rejects these
    // filters outright, so offering them would only mislead.
    expect(html).not.toContain("全部调用者");
    expect(html).not.toContain("NewAPI Token ID");
    // Everything not tied to caller identity stays available.
    expect(html).toContain("模型");
    expect(html).toContain("User-Agent");
    expect(html).toContain("路径");
    expect(html).toContain("转发状态");
  });

  it("renders the HTTP status filters with the selected values", () => {
    const html = renderToStaticMarkup(
      <AuditFiltersPanel
        path=""
        model=""
        userAgent=""
        newAPIUserID=""
        newAPITokenID=""
        forwardStatus=""
        statusClass="5xx"
        statusCode="503"
        users={[]}
        onPathChange={() => undefined}
        onModelChange={() => undefined}
        onUserAgentChange={() => undefined}
        onNewAPIUserIDChange={() => undefined}
        onNewAPITokenIDChange={() => undefined}
        onForwardStatusChange={() => undefined}
        onStatusClassChange={() => undefined}
        onStatusCodeChange={() => undefined}
        onSubmit={() => undefined}
      />,
    );

    expect(html).toContain('id="filter-status-class"');
    expect(html).toContain('id="filter-status-code"');
    expect(html).toContain("≥400（4xx+5xx）");
    expect(html).toContain(">4xx<");
    expect(html).toContain(">5xx<");
    expect(html).toContain('value="5xx" selected=""');
    expect(html).toContain('value="503"');
  });
});

describe("developer session badge", () => {
  it("names the token whose traffic is being shown", () => {
    const html = renderToStaticMarkup(
      <DeveloperBadge identity={{ user_id: 7, username: "developer", token_id: 42, token_name: "agent-token" }} />,
    );
    expect(html).toContain("开发者");
    expect(html).toContain("agent-token");
  });

  it("stays meaningful for a key NewAPI could not identify yet", () => {
    const html = renderToStaticMarkup(<DeveloperBadge identity={null} />);
    expect(html).toContain("开发者");
    expect(html).toContain("本 API Key 的调用记录");
  });
});

describe("User-Agent rule configuration", () => {
  it("renders regex semantics and the default active rule", () => {
    const client = {
      listUserAgentRules: async () => ({
        items: [{
          id: 1,
          name: "GPT models require Codex clients",
          enabled: true,
          model_pattern: "^gpt",
          user_agent_pattern: "^(codex-tui|Codex Desktop)",
          created_at_ns: "1",
          updated_at_ns: "1",
        }],
      }),
    } as ApiClient;
    const html = renderToStaticMarkup(<UserAgentRulesPanel client={client} />);

    expect(html).toContain("UA 拦截规则");
    expect(html).toContain("Go RE2");
    expect(html).toContain("模型正则");
    expect(html).toContain("User-Agent 正则");
    expect(html).toContain("多条命中规则全部需要通过");
  });
});
