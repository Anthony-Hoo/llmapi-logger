import ReactMarkdown, { defaultUrlTransform, type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { Badge } from "./ui/badge";

import type {
  Conversation,
  ConversationMessage,
  ConversationPart,
  ConversationToolCallPart,
  ConversationToolResultPart,
} from "../types";

const rolePresentation: Record<string, { label: string; classes: string; dot: string }> = {
  system: {
    label: "系统指令",
    classes: "border-slate-200 bg-slate-50/90",
    dot: "bg-slate-500",
  },
  developer: {
    label: "开发者指令",
    classes: "border-violet-200 bg-violet-50/80",
    dot: "bg-violet-500",
  },
  user: {
    label: "用户",
    classes: "border-blue-200 bg-blue-50/80",
    dot: "bg-blue-500",
  },
  assistant: {
    label: "助手",
    classes: "border-emerald-200 bg-emerald-50/70",
    dot: "bg-emerald-500",
  },
  tool: {
    label: "工具结果",
    classes: "border-amber-200 bg-amber-50/80",
    dot: "bg-amber-500",
  },
  unknown: {
    label: "未知角色",
    classes: "border-slate-200 bg-white",
    dot: "bg-slate-400",
  },
};

const markdownPlugins = [remarkGfm];
const allowedMarkdownProtocols = new Set(["http", "https", "mailto"]);

function safeMarkdownUrl(url: string): string {
  const transformed = defaultUrlTransform(url);
  if (!transformed) {
    return "";
  }

  const protocol = /^([a-z][a-z\d+.-]*):/i.exec(transformed)?.[1]?.toLowerCase();
  return !protocol || allowedMarkdownProtocols.has(protocol) ? transformed : "";
}

const markdownComponents: Components = {
  h1: ({ children }) => <h1 className="mb-3 mt-4 text-xl font-semibold first:mt-0">{children}</h1>,
  h2: ({ children }) => <h2 className="mb-2 mt-4 text-lg font-semibold first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mb-2 mt-3 text-base font-semibold first:mt-0">{children}</h3>,
  p: ({ children }) => <p className="mb-3 whitespace-pre-wrap break-words leading-6 last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="mb-3 list-disc space-y-1 pl-5 last:mb-0">{children}</ul>,
  ol: ({ children }) => <ol className="mb-3 list-decimal space-y-1 pl-5 last:mb-0">{children}</ol>,
  li: ({ children }) => <li className="break-words pl-0.5">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="mb-3 border-l-4 border-slate-300 pl-3 text-muted-foreground last:mb-0">
      {children}
    </blockquote>
  ),
  table: ({ children }) => (
    <div className="mb-3 max-w-full overflow-x-auto rounded-md border last:mb-0">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  th: ({ children }) => <th className="border-b bg-slate-100 px-2 py-1.5 font-semibold">{children}</th>,
  td: ({ children }) => <td className="border-b px-2 py-1.5 align-top last:border-b-0">{children}</td>,
  pre: ({ children }) => (
    <pre className="mb-3 max-h-96 overflow-auto whitespace-pre rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100 last:mb-0 [&>code]:bg-transparent [&>code]:p-0">
      {children}
    </pre>
  ),
  code: ({ className, children, node: _node, ...props }) => (
    <code
      className={className ? `${className} font-mono` : "rounded bg-slate-200/80 px-1 py-0.5 font-mono text-[0.9em]"}
      {...props}
    >
      {children}
    </code>
  ),
  a: ({ children, href, node: _node, ...props }) =>
    href ? (
      <a
        {...props}
        href={href}
        className="break-all text-blue-700 underline underline-offset-2"
        target="_blank"
        rel="noreferrer noopener"
        referrerPolicy="no-referrer"
      >
        {children}
      </a>
    ) : (
      <span className="break-all">{children}</span>
    ),
  img: ({ alt, src }) => (
    <span className="inline-flex max-w-full flex-wrap items-baseline gap-1 rounded bg-slate-200/70 px-1.5 py-0.5 text-xs text-muted-foreground">
      <span>图片：{alt || "未命名"}</span>
      {src ? <code className="break-all font-mono">{src}</code> : null}
    </span>
  ),
  hr: () => <hr className="my-4 border-slate-300" />,
};

export function ConversationView({ conversation }: { conversation: Conversation | null | undefined }) {
  const messages = conversation?.messages ?? [];

  if (messages.length === 0) {
    return (
      <div className="rounded-md border border-dashed bg-slate-50/60 px-4 py-6 text-center text-sm text-muted-foreground">
        当前记录没有可展示的对话解析结果。原始 HTTP 证据仍可在下方查看。
      </div>
    );
  }

  const partCounts = countParts(messages);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="outline" className="font-mono">
          schema v{conversation?.schema_version}
        </Badge>
        <Badge variant="outline">{messages.length} 条消息</Badge>
        {partCounts.toolCalls > 0 ? <Badge variant="outline">{partCounts.toolCalls} 次工具调用</Badge> : null}
        {partCounts.toolResults > 0 ? <Badge variant="outline">{partCounts.toolResults} 条工具结果</Badge> : null}
        <span>按代理解析出的原始顺序展示</span>
      </div>

      <ol className="ml-2 space-y-4 border-l-2 border-slate-200 pl-5">
        {messages.map((message, position) => (
          <ConversationMessageView
            key={`${message.index}-${position}`}
            message={message}
            displayIndex={position + 1}
          />
        ))}
      </ol>
    </div>
  );
}

function ConversationMessageView({ message, displayIndex }: { message: ConversationMessage; displayIndex: number }) {
  const presentation = rolePresentation[message.role] ?? rolePresentation.unknown;
  const isResponse = message.phase === "response";

  return (
    <li className="relative">
      <span
        aria-hidden="true"
        className={`absolute -left-[1.77rem] top-5 h-3 w-3 rounded-full ring-4 ring-white ${presentation.dot}`}
      />
      <article
        aria-label={`第 ${displayIndex} 条：${presentation.label}`}
        className={`min-w-0 rounded-lg border p-3 shadow-sm ${presentation.classes}`}
      >
        <header className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold">{presentation.label}</span>
          <Badge variant="outline" className="font-mono font-normal">
            {message.role}
          </Badge>
          <span className="text-xs tabular-nums text-muted-foreground">#{displayIndex}</span>
          <Badge variant={isResponse ? "success" : "secondary"} className="font-normal">
            {isResponse ? "上游响应" : "请求上下文"}
          </Badge>
          {message.name ? (
            <Badge variant="secondary" className="font-mono font-normal">
              name: {message.name}
            </Badge>
          ) : null}
          {message.tool_call_id ? (
            <span className="break-all font-mono text-[11px] text-muted-foreground">
              call id: {message.tool_call_id}
            </span>
          ) : null}
          <span className="break-all font-mono text-[10px] text-muted-foreground" title="数据方向">
            {message.direction}
          </span>
        </header>

        <div className="mt-3 space-y-3">
          {message.content.length > 0 ? (
            message.content.map((part, partIndex) => (
              <ConversationPartView
                key={`${part.type}-${partIndex}`}
                part={part}
                renderMarkdown={message.role === "assistant"}
              />
            ))
          ) : (
            <p className="text-sm italic text-muted-foreground">（空消息）</p>
          )}
        </div>
      </article>
    </li>
  );
}

function ConversationPartView({ part, renderMarkdown }: { part: ConversationPart; renderMarkdown: boolean }) {
  switch (part.type) {
    case "text":
      return part.text ? (
        renderMarkdown ? (
          <div className="min-w-0 text-sm">
            <ReactMarkdown
              remarkPlugins={markdownPlugins}
              skipHtml
              urlTransform={safeMarkdownUrl}
              components={markdownComponents}
            >
              {part.text}
            </ReactMarkdown>
          </div>
        ) : (
          <div className="whitespace-pre-wrap break-words text-sm leading-6">{part.text}</div>
        )
      ) : (
        <p className="text-sm italic text-muted-foreground">（空文本块）</p>
      );
    case "reasoning":
      return (
        <details className="rounded-md border border-slate-200 bg-slate-50/70 px-3 py-2 text-muted-foreground">
          <summary className="cursor-pointer text-xs font-medium">推理内容（默认折叠）</summary>
          <div className="mt-2 whitespace-pre-wrap break-words border-l-2 border-slate-300 pl-3 text-xs leading-5">
            {part.text || "（空推理内容）"}
          </div>
        </details>
      );
    case "tool_call":
      return <ToolCallView call={part} />;
    case "tool_result":
      return <ToolResultView result={part} />;
    case "unknown":
      return (
        <details className="rounded-md border border-slate-200 bg-white/70 px-3 py-2">
          <summary className="cursor-pointer text-xs font-medium text-muted-foreground">未识别内容块</summary>
          <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100">
            {part.data || "（空）"}
          </pre>
        </details>
      );
  }
}

function ToolCallView({ call }: { call: ConversationToolCallPart }) {
  const argumentsView = formatStructuredText(call.arguments ?? "");

  return (
    <div className="overflow-hidden rounded-md border border-violet-200 bg-white/85">
      <div className="flex flex-wrap items-center gap-2 border-b border-violet-100 bg-violet-50/80 px-3 py-2">
        <Badge className="border-violet-200 bg-violet-100 text-violet-800">工具调用</Badge>
        <span className="break-all font-mono text-sm font-semibold text-violet-950">{call.name || "（未命名）"}</span>
        {call.id ? <span className="break-all font-mono text-[11px] text-violet-700">call id: {call.id}</span> : null}
      </div>
      <div className="p-3">
        <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          Arguments{argumentsView.formatted ? "（JSON 格式化）" : ""}
        </p>
        {argumentsView.text ? (
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100">
            {argumentsView.text}
          </pre>
        ) : (
          <p className="text-xs italic text-muted-foreground">（空参数）</p>
        )}
      </div>
    </div>
  );
}

function ToolResultView({ result }: { result: ConversationToolResultPart }) {
  const contentView = formatStructuredText(result.result ?? "");

  return (
    <div className="overflow-hidden rounded-md border border-amber-200 bg-white/85">
      <div className="flex flex-wrap items-center gap-2 border-b border-amber-100 bg-amber-50/80 px-3 py-2">
        <Badge variant="warning">工具结果</Badge>
        {result.name ? <span className="break-all font-mono text-sm font-semibold">{result.name}</span> : null}
        {result.tool_call_id ? (
          <span className="break-all font-mono text-[11px] text-amber-800">call id: {result.tool_call_id}</span>
        ) : null}
      </div>
      <div className="p-3">
        <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          Result{contentView.formatted ? "（JSON 格式化）" : ""}
        </p>
        {contentView.text ? (
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100">
            {contentView.text}
          </pre>
        ) : (
          <p className="text-xs italic text-muted-foreground">（空结果）</p>
        )}
      </div>
    </div>
  );
}

export function formatStructuredText(value: string): { text: string; formatted: boolean } {
  if (!value.trim()) {
    return { text: value, formatted: false };
  }

  try {
    return { text: JSON.stringify(JSON.parse(value), null, 2), formatted: true };
  } catch {
    return { text: value, formatted: false };
  }
}

function countParts(messages: ConversationMessage[]): { toolCalls: number; toolResults: number } {
  let toolCalls = 0;
  let toolResults = 0;
  for (const message of messages) {
    for (const part of message.content) {
      if (part.type === "tool_call") {
        toolCalls += 1;
      } else if (part.type === "tool_result") {
        toolResults += 1;
      }
    }
  }
  return { toolCalls, toolResults };
}
