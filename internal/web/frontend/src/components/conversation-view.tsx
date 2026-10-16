import ReactMarkdown, { defaultUrlTransform, type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { extractStructuredContent } from "../lib/images";
import { Badge } from "./ui/badge";
import { blockLabelClassName, codeBlockClassName, emptyStateClassName } from "./ui/styles";
import { ImageAttachments } from "./image-attachments";

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
    classes: "border-cat-system/25 bg-cat-system/5",
    dot: "bg-cat-system",
  },
  developer: {
    label: "开发者指令",
    classes: "border-cat-system/25 bg-surface-muted",
    dot: "bg-cat-system",
  },
  user: {
    label: "用户",
    classes: "border-cat-user/25 bg-cat-user/5",
    dot: "bg-cat-user",
  },
  assistant: {
    label: "助手",
    classes: "border-cat-assistant/25 bg-cat-assistant/5",
    dot: "bg-cat-assistant",
  },
  tool: {
    label: "工具结果",
    classes: "border-cat-tool-result/25 bg-cat-tool-result/5",
    dot: "bg-cat-tool-result",
  },
  unknown: {
    label: "未知角色",
    classes: "border-border bg-surface",
    dot: "bg-cat-unknown",
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
  h1: ({ children }) => <h1 className="mb-3 mt-4 text-heading font-semibold first:mt-0">{children}</h1>,
  h2: ({ children }) => <h2 className="mb-2 mt-4 text-title font-semibold first:mt-0">{children}</h2>,
  h3: ({ children }) => <h3 className="mb-2 mt-3 text-body font-semibold first:mt-0">{children}</h3>,
  p: ({ children }) => <p className="mb-3 whitespace-pre-wrap break-words last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="mb-3 list-disc space-y-1 pl-5 last:mb-0">{children}</ul>,
  ol: ({ children }) => <ol className="mb-3 list-decimal space-y-1 pl-5 last:mb-0">{children}</ol>,
  li: ({ children }) => <li className="break-words pl-0.5">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="mb-3 border-l-4 border-border-strong pl-3 text-muted last:mb-0">
      {children}
    </blockquote>
  ),
  table: ({ children }) => (
    <div className="mb-3 max-w-full overflow-x-auto rounded-md border last:mb-0">
      <table className="w-full border-collapse text-left text-label">{children}</table>
    </div>
  ),
  th: ({ children }) => <th className="border-b bg-surface-muted px-2 py-1.5 font-semibold">{children}</th>,
  td: ({ children }) => <td className="border-b px-2 py-1.5 align-top last:border-b-0">{children}</td>,
  pre: ({ children }) => (
    <pre className={`${codeBlockClassName} mb-3 max-h-96 whitespace-pre last:mb-0 [&>code]:bg-transparent [&>code]:p-0`}>
      {children}
    </pre>
  ),
  code: ({ className, children, node: _node, ...props }) => (
    <code
      className={className ? `${className} font-mono` : "rounded-xs bg-surface-sunken px-1 py-0.5 font-mono text-body-sm"}
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
        className="break-all text-primary underline underline-offset-2 hover:text-primary-hover"
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
    <span className="inline-flex max-w-full flex-wrap items-baseline gap-1 rounded-xs bg-surface-sunken px-1.5 py-0.5 text-label text-muted">
      <span>图片：{alt || "未命名"}</span>
      {src ? <code className="break-all font-mono">{src}</code> : null}
    </span>
  ),
  hr: () => <hr className="my-4 border-border-strong" />,
};

export function ConversationView({ conversation }: { conversation: Conversation | null | undefined }) {
  const messages = conversation?.messages ?? [];

  if (messages.length === 0) {
    return (
      <div className={emptyStateClassName}>
        当前记录没有可展示的对话解析结果。原始 HTTP 证据仍可在下方查看。
      </div>
    );
  }

  const partCounts = countParts(messages);

  return (
    <div className="space-y-stack">
      <div className="flex flex-wrap items-center gap-2 text-label text-subtle">
        <Badge variant="outline">{messages.length} 条消息</Badge>
        {partCounts.toolCalls > 0 ? <Badge variant="outline">{partCounts.toolCalls} 次工具调用</Badge> : null}
        {partCounts.toolResults > 0 ? <Badge variant="outline">{partCounts.toolResults} 条工具结果</Badge> : null}
        <span>按代理解析出的原始顺序展示</span>
      </div>

      <ol className="ml-2 space-y-3 border-l-2 border-border pl-5">
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
        className={`absolute -left-[1.77rem] top-4 h-3 w-3 rounded-full ring-4 ring-surface ${presentation.dot}`}
      />
      <article
        aria-label={`第 ${displayIndex} 条：${presentation.label}`}
        className={`min-w-0 rounded-md border p-3 ${presentation.classes}`}
      >
        <header className="flex flex-wrap items-center gap-2">
          <span className="text-body font-semibold">{presentation.label}</span>
          <span className="text-label tabular-nums text-subtle">#{displayIndex}</span>
          <Badge variant={isResponse ? "info" : "outline"}>
            {isResponse ? "上游响应" : "请求上下文"}
          </Badge>
          {message.name ? (
            <Badge variant="neutral" className="font-mono">
              name: {message.name}
            </Badge>
          ) : null}
          {message.tool_call_id ? (
            <span className="break-all font-mono text-caption text-subtle">
              call id: {message.tool_call_id}
            </span>
          ) : null}
        </header>

        <div className="mt-2 space-y-3">
          {message.content.length > 0 ? (
            message.content.map((part, partIndex) => (
              <ConversationPartView
                key={`${part.type}-${partIndex}`}
                part={part}
                renderMarkdown={message.role === "assistant"}
              />
            ))
          ) : (
            <p className="text-body italic text-subtle">（空消息）</p>
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
          <div className="min-w-0 text-body">
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
          <div className="whitespace-pre-wrap break-words text-body">{part.text}</div>
        )
      ) : (
        <p className="text-body italic text-subtle">（空文本块）</p>
      );
    case "reasoning":
      return (
        <details className="rounded-md border border-cat-reasoning/25 bg-surface px-3 py-2 text-muted">
          <summary className="cursor-pointer text-label font-medium">推理内容（默认折叠）</summary>
          <div className="mt-2 whitespace-pre-wrap break-words border-l-2 border-cat-reasoning/40 pl-3 text-body-sm">
            {part.text || "（空推理内容）"}
          </div>
        </details>
      );
    case "tool_call":
      return <ToolCallView call={part} />;
    case "tool_result":
      return <ToolResultView result={part} />;
    case "unknown":
      return <UnknownPartView data={part.data ?? ""} />;
  }
}

function ToolCallView({ call }: { call: ConversationToolCallPart }) {
  const argumentsView = extractStructuredContent(call.arguments ?? "");

  return (
    <div className="overflow-hidden rounded-md border bg-surface">
      <div className="flex flex-wrap items-center gap-2 border-b bg-surface-muted px-3 py-2">
        <Badge variant="info">工具调用</Badge>
        <span className="break-all font-mono text-body-sm font-semibold text-foreground">{call.name || "（未命名）"}</span>
        {call.id ? <span className="break-all font-mono text-caption text-subtle">call id: {call.id}</span> : null}
      </div>
      <div className="p-3">
        <ImageAttachments images={argumentsView.images} omitted={argumentsView.omittedImages} ownerLabel="工具调用参数" />
        <p className={`${blockLabelClassName} mb-1.5`}>
          Arguments{argumentsView.formatted ? "（JSON 格式化）" : ""}
        </p>
        {argumentsView.text ? (
          <pre className={`${codeBlockClassName} max-h-80 whitespace-pre-wrap break-all`}>
            {argumentsView.text}
          </pre>
        ) : (
          <p className="text-label italic text-subtle">（空参数）</p>
        )}
      </div>
    </div>
  );
}

function ToolResultView({ result }: { result: ConversationToolResultPart }) {
  const contentView = extractStructuredContent(result.result ?? "");

  return (
    <div className="overflow-hidden rounded-md border bg-surface">
      <div className="flex flex-wrap items-center gap-2 border-b bg-surface-muted px-3 py-2">
        <Badge variant="success">工具结果</Badge>
        {result.name ? <span className="break-all font-mono text-body-sm font-semibold">{result.name}</span> : null}
        {result.tool_call_id ? (
          <span className="break-all font-mono text-caption text-subtle">call id: {result.tool_call_id}</span>
        ) : null}
      </div>
      <div className="p-3">
        <ImageAttachments images={contentView.images} omitted={contentView.omittedImages} ownerLabel="工具结果" />
        <p className={`${blockLabelClassName} mb-1.5`}>
          Result{contentView.formatted ? "（JSON 格式化）" : ""}
        </p>
        {contentView.text ? (
          <pre className={`${codeBlockClassName} max-h-80 whitespace-pre-wrap break-all`}>
            {contentView.text}
          </pre>
        ) : (
          <p className="text-label italic text-subtle">（空结果）</p>
        )}
      </div>
    </div>
  );
}

// Unknown blocks carry unparsed provider JSON (for example image blocks in
// user messages); image extraction still applies so complete payloads render
// while anything else stays inspectable as raw text.
function UnknownPartView({ data }: { data: string }) {
  const contentView = extractStructuredContent(data);

  return (
    <details className="rounded-md border bg-surface px-3 py-2" open={contentView.images.length > 0}>
      <summary className="cursor-pointer text-label font-medium text-muted">未识别内容块</summary>
      <div className="mt-2">
        <ImageAttachments images={contentView.images} omitted={contentView.omittedImages} ownerLabel="未识别内容块" />
        <pre className={`${codeBlockClassName} max-h-72 whitespace-pre-wrap break-all`}>
          {contentView.text || "（空）"}
        </pre>
      </div>
    </details>
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
