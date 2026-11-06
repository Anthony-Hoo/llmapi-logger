import type { AnalysisFlag, AnalysisSessionItem, AnalysisSignalTotals } from "./types";

/** Filter chips, in display order. */
export const FLAG_OPTIONS: ReadonlyArray<{ value: AnalysisFlag; label: string; hint: string }> = [
  { value: "loop", label: "死循环", hint: "同一工具调用连续重复 3 次以上" },
  { value: "thrash", label: "反复编辑", hint: "同一文件写入 4 次以上且中间有失败" },
  { value: "unverified", label: "结束前未验证", hint: "最后一次写文件后没有跑测试、构建或 lint" },
  { value: "failures", label: "工具失败", hint: "至少一次工具调用失败" },
  { value: "corrections", label: "用户纠正", hint: "用户轮次以纠正语句开头" },
  { value: "error_paste", label: "报错回贴", hint: "用户把报错或堆栈贴回给 Agent" },
  { value: "interrupt", label: "用户中断", hint: "用户中途打断了 Agent" },
  { value: "heavy_model", label: "重模型候选", hint: "用了重模型但输出和工具调用都很少" },
  { value: "compaction", label: "上下文压缩", hint: "会话发生过上下文压缩" },
  { value: "danger", label: "危险命令", hint: "破坏性删除、强制推送、远程脚本、读凭据或外传文件" },
  { value: "secret", label: "疑似密钥", hint: "用户输入或工具结果里出现疑似密钥" },
];

export const SKIP_REASON_LABELS: Record<string, string> = {
  below_threshold: "未达门槛",
  single_turn_chat: "单轮聊天",
  content_unavailable: "正文不可得",
  no_agent_identity: "无会话标识",
  error: "处理失败",
};

export const DANGER_LABELS: Record<string, string> = {
  destructive_delete: "破坏性删除",
  force_push: "强制推送",
  remote_script: "远程脚本",
  credential_read: "读取凭据",
  exfiltrate: "外传文件",
};

/** Ratio of part to whole, or null when the whole is empty. */
export function share(part: number, whole: number): number | null {
  return whole > 0 ? part / whole : null;
}

/** "+3.2pt" / "-1.0pt" / "持平" for a change between two ratios; null when either side is unknown. */
export function formatPointDelta(current: number | null, previous: number | null): string | null {
  if (current === null || previous === null) {
    return null;
  }
  const delta = (current - previous) * 100;
  if (Math.abs(delta) < 0.05) {
    return "持平";
  }
  return `${delta > 0 ? "+" : ""}${delta.toFixed(1)}pt`;
}

/** Headline rates of one period; each is a share of the sessions it applies to. */
export function signalRates(totals: AnalysisSignalTotals) {
  return {
    loop: share(totals.loop_sessions, totals.agent_sessions),
    thrash: share(totals.thrash_sessions, totals.agent_sessions),
    unverified: share(totals.unverified_sessions, totals.sessions_with_writes),
    corrections: share(totals.correction_sessions, totals.sessions),
    errorPaste: share(totals.error_paste_sessions, totals.sessions),
    heavyModel: share(totals.heavy_model_sessions, totals.sessions),
  };
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "0s";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)}m`;
  }
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.round((seconds % 3600) / 60);
  return minutes ? `${hours}h${minutes}m` : `${hours}h`;
}

/** Signal badges of one session, most actionable first. */
export function sessionBadges(item: AnalysisSessionItem): Array<{ label: string; tone: "danger" | "warning" | "info" }> {
  const badges: Array<{ label: string; tone: "danger" | "warning" | "info" }> = [];
  if (Object.keys(item.secrets).length > 0) {
    badges.push({ label: "疑似密钥", tone: "danger" });
  }
  for (const category of Object.keys(item.danger).sort()) {
    badges.push({ label: DANGER_LABELS[category] ?? category, tone: "danger" });
  }
  if (item.loops > 0) {
    badges.push({ label: `死循环×${item.max_loop_length}`, tone: "warning" });
  }
  if (item.thrash_files > 0) {
    badges.push({ label: `反复编辑 ${item.max_file_writes} 次`, tone: "warning" });
  }
  if (item.verified === "no") {
    badges.push({ label: "未验证", tone: "warning" });
  }
  if (item.tool_failures > 0) {
    badges.push({ label: `失败 ${item.tool_failures}/${item.tool_calls}`, tone: "info" });
  }
  if (item.corrections > 0) {
    badges.push({ label: `纠正 ${item.corrections}`, tone: "info" });
  }
  if (item.error_pastes > 0) {
    badges.push({ label: `报错回贴 ${item.error_pastes}`, tone: "info" });
  }
  if (item.interrupts > 0) {
    badges.push({ label: `中断 ${item.interrupts}`, tone: "info" });
  }
  if (item.heavy_model) {
    badges.push({ label: "重模型候选", tone: "info" });
  }
  if (item.compactions > 0) {
    badges.push({ label: `压缩 ${item.compactions}`, tone: "info" });
  }
  return badges;
}

/** Monday 00:00 local of the week containing nowMS, in epoch ms. */
export function startOfLocalWeekMS(nowMS: number): number {
  const date = new Date(nowMS);
  date.setHours(0, 0, 0, 0);
  const weekday = (date.getDay() + 6) % 7; // Monday = 0
  date.setDate(date.getDate() - weekday);
  return date.getTime();
}
