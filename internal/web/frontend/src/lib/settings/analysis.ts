import type { AnalysisEditableSettings, AnalysisProbeResult, AnalysisSettingsUpdate, AnalysisSettingsView } from "./types";

/** The form's working copy: numbers stay text until they are sent. */
export interface AnalysisSettingsDraft {
  run_at: string;
  l1_settle_hours: string;
  enabled: boolean;
  base_url: string;
  model: string;
  structured_output: AnalysisEditableSettings["llm"]["structured_output"];
  disable_thinking: boolean;
  context_tokens: string;
  max_output_tokens: string;
  max_concurrency: string;
  timeout_seconds: string;
  max_sessions_per_run: string;
  /** A new key to save; never prefilled with the key in use. */
  api_key: string;
  /** Send no key at all, whatever the file or an earlier save says. */
  clear_key: boolean;
}

export function draftFromSettings(settings: AnalysisEditableSettings): AnalysisSettingsDraft {
  const llm = settings.llm;
  return {
    run_at: settings.run_at,
    l1_settle_hours: String(settings.l1_settle_hours),
    enabled: llm.enabled,
    base_url: llm.base_url,
    model: llm.model,
    structured_output: llm.structured_output,
    disable_thinking: llm.disable_thinking,
    context_tokens: String(llm.context_tokens),
    max_output_tokens: String(llm.max_output_tokens),
    max_concurrency: String(llm.max_concurrency),
    timeout_seconds: String(llm.timeout_seconds),
    max_sessions_per_run: String(llm.max_sessions_per_run),
    api_key: "",
    clear_key: false,
  };
}

/** Whole numbers only; anything else becomes -1, which the server rejects by field. */
function integer(text: string): number {
  const trimmed = text.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : -1;
}

/**
 * The request body of a draft. api_key is left out to keep the key in use,
 * empty to send none, and the typed value to save a new one.
 */
export function updateFromDraft(draft: AnalysisSettingsDraft): AnalysisSettingsUpdate {
  const update: AnalysisSettingsUpdate = {
    run_at: draft.run_at.trim(),
    l1_settle_hours: integer(draft.l1_settle_hours),
    llm: {
      enabled: draft.enabled,
      base_url: draft.base_url.trim(),
      model: draft.model.trim(),
      structured_output: draft.structured_output,
      context_tokens: integer(draft.context_tokens),
      disable_thinking: draft.disable_thinking,
      max_output_tokens: integer(draft.max_output_tokens),
      max_concurrency: integer(draft.max_concurrency),
      timeout_seconds: integer(draft.timeout_seconds),
      max_sessions_per_run: integer(draft.max_sessions_per_run),
    },
  };
  if (draft.clear_key) {
    update.api_key = "";
  } else if (draft.api_key !== "") {
    update.api_key = draft.api_key;
  }
  return update;
}

/** Whether the draft differs from the settings in use (a typed key counts). */
export function draftChanged(draft: AnalysisSettingsDraft, view: AnalysisSettingsView): boolean {
  const { api_key: _key, ...edited } = updateFromDraft(draft);
  return draft.api_key !== "" || (draft.clear_key && view.api_key !== "none") || JSON.stringify(edited) !== JSON.stringify(view.settings);
}

/** pack + fixed prefix + output must fit the context; null when the numbers are not usable yet. */
export function contextBudget(draft: AnalysisSettingsDraft, view: AnalysisSettingsView): { used: number; limit: number; fits: boolean } | null {
  const output = integer(draft.max_output_tokens);
  const limit = integer(draft.context_tokens);
  if (output < 0 || limit < 0) {
    return null;
  }
  const used = view.file_only.pack_max_tokens + view.file_only.prompt_reserve_tokens + output;
  return { used, limit, fits: used <= limit };
}

export function keySourceLabel(view: AnalysisSettingsView): string {
  switch (view.api_key) {
    case "saved":
      return "已在页面上保存";
    case "file":
      return "使用配置文件里的 Key";
    default:
      return "未设置，不发送 Key";
  }
}

const PROBE_ERRORS: Record<NonNullable<AnalysisProbeResult["error"]>, string> = {
  invalid_address: "地址不被允许：只能是本机或内网地址",
  unreachable: "连不上这个地址",
  timeout: "请求超时",
  http_status: "模型服务返回了错误状态",
  bad_response: "返回的内容不是预期的格式",
};

/** One line for the result of a connection test, plus what to look at. */
export function probeSummary(result: AnalysisProbeResult): { tone: "success" | "warning" | "danger"; text: string; notes: string[] } {
  if (!result.ok) {
    const status = result.error === "http_status" && result.http_status ? `（HTTP ${result.http_status}${result.http_status === 401 || result.http_status === 403 ? "，多半是 Key 不对或没有填" : ""}）` : "";
    return { tone: "danger", text: `连接失败：${PROBE_ERRORS[result.error ?? "unreachable"]}${status}。`, notes: [] };
  }
  const notes: string[] = [];
  if (result.reasoned) {
    notes.push("模型返回了思考内容：“关闭思考”对它没有生效，思考会占用输出上限。");
  }
  if (result.truncated) {
    notes.push("回答被输出上限截断了。");
  }
  if (!result.valid_json) {
    notes.push("回答不是 JSON 对象：可以换一种结构化输出方式再试。");
  }
  return {
    tone: notes.length > 0 ? "warning" : "success",
    text: `连接成功，用时 ${result.latency_ms} 毫秒（输入 ${result.input_tokens} / 输出 ${result.output_tokens} Token）。`,
    notes,
  };
}
