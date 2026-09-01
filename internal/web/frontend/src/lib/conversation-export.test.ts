import { describe, expect, it } from "vitest";

import type { AuditDetail } from "../types";
import { buildConversationExport } from "./conversation-export";

const detail: AuditDetail = {
  audit: {
    audit_id: "apx_export",
    started_at_ns: "1725000000000000000",
    route_id: "openai-chat-completions",
    protocol: "openai",
    method: "POST",
    path: "/v1/chat/completions",
    status_code: 200,
    forward_status: "completed",
    capture_status: "complete",
    parse_status: "ok",
    response_model: "gpt-4o",
    display_name: "Alice",
    username: "alice",
    token_name: "personal",
    newapi_token_id: 42,
    user_agent: "codex-cli/1.0",
    conversation_id: "conv_demo",
  },
  request_uri: "/v1/chat/completions",
  stages: [],
  headers: [],
  bodies: [],
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
        content: [
          { index: 0, type: "tool_call", id: "call_1", name: "get_weather", arguments: '{"city":"Shanghai"}' },
        ],
      },
      {
        index: 2,
        role: "tool",
        phase: "request",
        direction: "client_to_upstream",
        tool_call_id: "call_1",
        content: [
          { index: 0, type: "tool_result", tool_call_id: "call_1", name: "get_weather", result: '{"temperature":30}' },
        ],
      },
    ],
  },
  parsed_result: null,
  turn: null,
  token_link: null,
};

describe("buildConversationExport", () => {
  it("serializes the parsed conversation with audit metadata for humans", () => {
    const file = buildConversationExport(detail);

    expect(file).not.toBeNull();
    expect(file!.filename).toBe("conversation-apx_export.json");

    const payload = JSON.parse(file!.json) as Record<string, unknown>;
    expect(payload.kind).toBe("llmapi-logger.conversation");
    expect(payload.audit_id).toBe("apx_export");
    expect(payload.conversation_id).toBe("conv_demo");
    expect(payload.model).toBe("gpt-4o");
    expect(payload.started_at).toBe(new Date(1725000000000).toISOString());
    expect(payload.user_agent).toBe("codex-cli/1.0");
    expect(payload.caller).toEqual({
      display_name: "Alice",
      username: "alice",
      token_name: "personal",
      newapi_token_id: 42,
    });

    const messages = payload.messages as Array<Record<string, unknown>>;
    expect(messages).toHaveLength(3);
    expect(messages[0]).toEqual({
      role: "user",
      phase: "request",
      content: [{ type: "text", text: "What is the weather?" }],
    });
    expect(messages[1].content).toEqual([
      { type: "tool_call", id: "call_1", name: "get_weather", arguments: '{"city":"Shanghai"}' },
    ]);
    expect(messages[2]).toMatchObject({
      role: "tool",
      tool_call_id: "call_1",
      content: [{ type: "tool_result", tool_call_id: "call_1", name: "get_weather", result: '{"temperature":30}' }],
    });
  });

  it("returns null when the record has no parsed conversation", () => {
    expect(buildConversationExport({ ...detail, conversation: null })).toBeNull();
    expect(
      buildConversationExport({ ...detail, conversation: { schema_version: 1, messages: [] } }),
    ).toBeNull();
  });
});
