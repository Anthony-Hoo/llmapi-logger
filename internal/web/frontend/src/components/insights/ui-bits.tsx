import type { ReactNode } from "react";

import { colorVar } from "../../lib/tokens";
import { cn } from "../../lib/utils";
import type { ClientLabels } from "../../types";
import { PageHeader } from "../ui/page-header";
import { emptyStateClassName } from "../ui/styles";

export { Segmented } from "../ui/segmented";

export function EmptyNote({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn(emptyStateClassName, className)}>{children}</div>;
}

/** Title row of a panel inside a card: the shared header pattern at panel level. */
export function PanelTitle({ title, hint, actions }: { title: string; hint?: ReactNode; actions?: ReactNode }) {
  return <PageHeader level="panel" title={title} description={hint} actions={actions} />;
}

const BUILTIN_CLIENT_LABELS: Record<string, string> = {
  codex: "Codex",
  claude_code: "Claude Code",
  opencode: "OpenCode",
  dsh: "DSH",
  custom: "自定义",
  unknown: "未知客户端",
};

/**
 * Display name of a client key: the built-in name, else the vocabulary label the
 * server attached to the response (`client_labels`), else the key itself.
 */
export function clientLabel(client: string, labels?: ClientLabels | null): string {
  return BUILTIN_CLIENT_LABELS[client] ?? labels?.[client] ?? client;
}

export function roleLabel(role: string): string {
  return (
    ({
      main: "主 Agent",
      subagent: "子 Agent",
      compaction: "压缩",
      title: "标题",
      review: "评审",
      auxiliary: "附属",
    } as Record<string, string>)[role] ?? role
  );
}

export function protocolLabel(protocol: string): string {
  return ({ openai: "OpenAI", anthropic: "Anthropic", gemini: "Gemini" } as Record<string, string>)[protocol] ?? protocol;
}

/** Context events; colors reuse the status and composition-category tokens. */
export const EVENT_INFO: Record<string, { label: string; glyph: string; color: string }> = {
  model_switch: { label: "模型切换", glyph: "模", color: colorVar("primary") },
  compaction: { label: "压缩(推断)", glyph: "压", color: colorVar("danger") },
  prune: { label: "清理(推断)", glyph: "清", color: colorVar("warning") },
  system_changed: { label: "系统提示变化", glyph: "系", color: colorVar("cat-system") },
  tools_changed: { label: "工具集变化", glyph: "工", color: colorVar("cat-tools") },
  injected: { label: "注入上下文(推断)", glyph: "注", color: colorVar("cat-injected") },
};

export function eventLabel(event: string): string {
  return EVENT_INFO[event]?.label ?? event;
}


/** Muted "含 N 条未计费" note shown next to a cost when some requests have no billing result. */
export function UnbilledNote({ count, className }: { count: number; className?: string }) {
  if (count <= 0) {
    return null;
  }
  return <span className={cn("text-label text-subtle", className)}>含 {count.toLocaleString("zh-CN")} 条未计费</span>;
}