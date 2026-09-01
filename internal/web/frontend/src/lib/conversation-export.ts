import type { AuditDetail, ConversationMessage, NanoTime } from "../types";

export interface ConversationExportFile {
  json: string;
  filename: string;
}

/**
 * Serializes the parsed conversation of one audit into a reader-facing JSON
 * file: messages in display order plus the metadata a person needs to place
 * the transcript (time, model, caller). This intentionally differs from the
 * provider-exact reconstruction download, which targets byte-level replay.
 */
export function buildConversationExport(detail: AuditDetail): ConversationExportFile | null {
  const messages = detail.conversation?.messages ?? [];
  if (messages.length === 0) {
    return null;
  }

  const audit = detail.audit;
  const payload = {
    kind: "llmapi-logger.conversation",
    schema_version: detail.conversation?.schema_version ?? null,
    audit_id: audit.audit_id,
    conversation_id: audit.conversation_id ?? detail.turn?.conversation_id ?? null,
    turn_id: detail.turn?.turn_id ?? null,
    started_at: isoFromNanoTime(audit.started_at_ns),
    model: audit.response_model?.trim() || audit.request_model?.trim() || null,
    caller: {
      display_name: audit.display_name ?? null,
      username: audit.username ?? null,
      token_name: audit.token_name ?? null,
      newapi_token_id: audit.newapi_token_id ?? null,
    },
    user_agent: audit.user_agent ?? null,
    messages: messages.map(exportMessage),
  };

  return {
    json: JSON.stringify(payload, null, 2),
    filename: `conversation-${audit.audit_id}.json`,
  };
}

function exportMessage(message: ConversationMessage) {
  return {
    role: message.role,
    phase: message.phase,
    ...(message.name ? { name: message.name } : {}),
    ...(message.tool_call_id ? { tool_call_id: message.tool_call_id } : {}),
    content: message.content.map((part) => {
      switch (part.type) {
        case "text":
        case "reasoning":
          return { type: part.type, text: part.text ?? "" };
        case "tool_call":
          return {
            type: part.type,
            ...(part.id ? { id: part.id } : {}),
            ...(part.name ? { name: part.name } : {}),
            arguments: part.arguments ?? "",
          };
        case "tool_result":
          return {
            type: part.type,
            ...(part.tool_call_id ? { tool_call_id: part.tool_call_id } : {}),
            ...(part.name ? { name: part.name } : {}),
            result: part.result ?? "",
          };
        case "unknown":
          return { type: part.type, data: part.data ?? "" };
      }
    }),
  };
}

function isoFromNanoTime(value: NanoTime | null | undefined): string | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  try {
    const nanos = typeof value === "number" ? BigInt(Math.trunc(value)) : BigInt(value);
    const date = new Date(Number(nanos / 1_000_000n));
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  } catch {
    return null;
  }
}
