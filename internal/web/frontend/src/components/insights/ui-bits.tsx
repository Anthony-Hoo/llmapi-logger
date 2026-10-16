import type { ReactNode } from "react";

import { Button } from "../ui/button";
import { cn } from "../../lib/utils";

export const selectClassName =
  "h-9 rounded-md border border-input bg-white px-3 text-sm shadow-xs outline-hidden focus:ring-2 focus:ring-ring";

export function EmptyNote({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "rounded-md border border-dashed bg-slate-50/60 px-4 py-5 text-center text-sm text-muted-foreground",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** A row of mutually exclusive buttons. */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string; title?: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex items-center gap-1 rounded-lg border bg-white/70 p-0.5">
      {options.map((option) => (
        <Button
          key={option.value}
          variant={option.value === value ? "secondary" : "ghost"}
          size="sm"

          aria-pressed={option.value === value}
          title={option.title}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </Button>
      ))}
    </div>
  );
}

export function PanelTitle({ title, hint, actions }: { title: string; hint?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="min-w-0">
        <h3 className="text-sm font-semibold">{title}</h3>
        {hint ? <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p> : null}
      </div>
      {actions}
    </div>
  );
}

export function clientLabel(client: string): string {
  return (
    ({
      codex: "Codex",
      claude_code: "Claude Code",
      opencode: "OpenCode",
      dsh: "DSH",
      custom: "自定义",
      unknown: "未知客户端",
    } as Record<string, string>)[client] ?? client
  );
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

export const EVENT_INFO: Record<string, { label: string; glyph: string; color: string }> = {
  model_switch: { label: "模型切换", glyph: "模", color: "#2563eb" },
  compaction: { label: "压缩(推断)", glyph: "压", color: "#dc2626" },
  prune: { label: "清理(推断)", glyph: "清", color: "#ea580c" },
  system_changed: { label: "系统提示变化", glyph: "系", color: "#7c3aed" },
  tools_changed: { label: "工具集变化", glyph: "工", color: "#0891b2" },
  injected: { label: "注入上下文(推断)", glyph: "注", color: "#ca8a04" },
};

export function eventLabel(event: string): string {
  return EVENT_INFO[event]?.label ?? event;
}
