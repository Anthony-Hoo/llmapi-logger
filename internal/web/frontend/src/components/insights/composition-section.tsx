import { useEffect, useMemo, useState, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { categoryInfo, CATEGORIES, normalizeCategoryValues } from "../../lib/insights/categories";
import { buildDnaBands } from "../../lib/insights/dna";
import { formatSignedTokens, formatTokens } from "../../lib/insights/format";
import { buildTreemapData, layoutTreemap } from "../../lib/insights/treemap";
import type { AgentIdentity, CategoryKey, CompositionItem, CompositionResponse, FileOp, ToolDef } from "../../types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Skeleton } from "../ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { CategoryLegend, CompositionBar, OccupancyText } from "./composition-bar";
import { clientLabel, EmptyNote, eventLabel, roleLabel } from "./ui-bits";

const ITEM_RENDER_LIMIT = 200;

type CompositionState =
  | { status: "loading" }
  | { status: "missing" }
  | { status: "error"; message: string }
  | { status: "ready"; data: CompositionResponse };

/** Lazily fetched "上下文构成" section of the audit detail. */
export function CompositionSection({ client, auditID }: { client: ApiClient; auditID: string }) {
  const [state, setState] = useState<CompositionState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    client
      .getComposition(auditID, controller.signal)
      .then((data) => setState({ status: "ready", data }))
      .catch((cause: unknown) => {
        if (isAbortError(cause) || (cause instanceof ApiError && cause.status === 401)) {
          return;
        }
        if (cause instanceof ApiError && cause.status === 404) {
          setState({ status: "missing" });
          return;
        }
        setState({ status: "error", message: errorMessage(cause) });
      });
    return () => controller.abort();
  }, [client, auditID]);

  if (state.status === "loading") {
    return <Skeleton className="h-28 w-full" />;
  }
  if (state.status === "missing") {
    return <EmptyNote>尚未分析。请求解析完成后会生成上下文构成；较早的记录可能不会被回填。</EmptyNote>;
  }
  if (state.status === "error") {
    return (
      <Alert className="border-red-200 bg-red-50">
        <AlertDescription className="text-red-800">无法读取上下文构成：{state.message}</AlertDescription>
      </Alert>
    );
  }
  return <CompositionPanel data={state.data} />;
}

const KIND_CHIPS = [
  { kind: "thinking", label: "Thinking" },
  { kind: "tool_call", label: "Tools" },
  { kind: "text", label: "Answer" },
] as const;

const FILTERED_CATEGORIES = new Set(["assistant", "reasoning"]);

export function CompositionPanel({ data }: { data: CompositionResponse }) {
  const [hiddenKinds, setHiddenKinds] = useState<ReadonlySet<string>>(new Set());
  const values = data.anchored ?? data.estimate;
  const items = data.items ?? [];
  const grouped = useMemo(() => {
    const map = new Map<string, CompositionItem[]>();
    for (const item of items) {
      const list = map.get(item.category) ?? [];
      list.push(item);
      map.set(item.category, list);
    }
    return map;
  }, [items]);
  const categoryOrder = [
    ...CATEGORIES.map((category) => category.key as string).filter((key) => grouped.has(key)),
    ...[...grouped.keys()].filter((key) => !CATEGORIES.some((category) => category.key === key)),
  ];
  const diff = data.diff;
  const diffByCategory = diff ? normalizeCategoryValues(diff.by_category) : null;
  const events = data.events ?? [];

  function toggleKind(kind: string) {
    setHiddenKinds((current) => {
      const next = new Set(current);
      if (next.has(kind)) {
        next.delete(kind);
      } else {
        next.add(kind);
      }
      return next;
    });
  }

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>模型：<span className="font-mono">{data.model || "未记录"}</span></span>
          <span>
            prompt 总量：
            <span className="tabular-nums text-foreground">{data.prompt_total === null ? "无 usage（显示估算）" : formatTokens(data.prompt_total)}</span>
          </span>
          <span>
            上下文窗口占用：
            <OccupancyText lastPrompt={data.prompt_total ?? sumOf(values)} contextWindow={data.context_window} />
          </span>
          <span>分析版本 v{data.analysis_version}</span>
        </div>
        <CompositionBar values={values} contextWindow={data.context_window} height={16} label="上下文构成" />
        <CategoryLegend values={values} />
        <p className="text-[11px] text-muted-foreground">
          {data.anchored
            ? "各类别为估算值，已按上游报告的 prompt 总量锚定；条目 Token 为未锚定的估算。"
            : "该请求没有 usage，显示原始估算（约 4 字符 / Token）。"}
        </p>
        {events.length > 0 ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-muted-foreground">事件</span>
            {events.map((event) => (
              <Badge key={event} variant="outline">{eventLabel(event)}</Badge>
            ))}
          </div>
        ) : null}
        {diff ? (
          <p className="text-xs text-muted-foreground">
            相对上一步：新增 <span className="font-medium text-foreground">{diff.added_items}</span> 项，移除{" "}
            <span className="font-medium text-foreground">{diff.removed_items}</span> 项。
          </p>
        ) : null}
        {data.truncated ? (
          <Alert className="border-amber-200 bg-amber-50/80">
            <AlertDescription className="text-amber-900">条目清单已截断，部分条目未列出；类别合计仍为完整估算。</AlertDescription>
          </Alert>
        ) : null}
      </div>

      <SubBlock title="构成分布（Treemap）" hint="外层为类别，内层按标签聚合，每类最多 11 项，其余归入“其他”">
        <TreemapView items={items} />
      </SubBlock>

      <SubBlock title="提示词 DNA 条带" hint="每个条目一段，按在提示词中的顺序排列，宽度正比于 Token">
        <DnaStrip items={items} compared={Boolean(data.previous_audit_id)} />
      </SubBlock>

      <SubBlock title="条目清单">
        {items.length === 0 ? (
          <EmptyNote>没有逐条目清单。</EmptyNote>
        ) : (
          <div className="space-y-2">
            {categoryOrder.some((key) => FILTERED_CATEGORIES.has(key)) ? (
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="助手内容筛选">
                <span className="text-xs text-muted-foreground">助手 / 推理内容</span>
                {KIND_CHIPS.map((chip) => {
                  const on = !hiddenKinds.has(chip.kind);
                  return (
                    <button
                      key={chip.kind}
                      type="button"
                      aria-pressed={on}
                      onClick={() => toggleKind(chip.kind)}
                      className={`rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors ${
                        on ? "border-primary bg-primary/10 text-primary" : "border-border bg-white text-muted-foreground"
                      }`}
                    >
                      {chip.label}
                    </button>
                  );
                })}
              </div>
            ) : null}
            {categoryOrder.map((key) => (
              <CategoryList
                key={key}
                category={key}
                items={grouped.get(key) ?? []}
                hiddenKinds={FILTERED_CATEGORIES.has(key) ? hiddenKinds : EMPTY_SET}
                deltaTokens={diffByCategory ? (diffByCategory[key as CategoryKey] ?? 0) : null}
              />
            ))}
          </div>
        )}
      </SubBlock>

      <SubBlock title={`工具定义（${data.tools?.length ?? 0}）`} hint="按 Token 从大到小">
        <ToolList tools={data.tools ?? []} />
      </SubBlock>

      <SubBlock title="文件操作" hint="来自本次响应中的工具调用">
        <FileOps ops={data.file_ops ?? []} />
      </SubBlock>

      <SubBlock title="Agent 身份">
        <AgentBlock agent={data.agent} />
      </SubBlock>
    </div>
  );
}

const EMPTY_SET: ReadonlySet<string> = new Set();

function sumOf(values: Record<string, number>): number {
  return Object.values(values).reduce((total, value) => total + value, 0);
}

function SubBlock({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <div className="space-y-2">
      <div>
        <h4 className="text-xs font-semibold text-foreground">{title}</h4>
        {hint ? <p className="text-[11px] text-muted-foreground">{hint}</p> : null}
      </div>
      {children}
    </div>
  );
}

export function itemKindLabel(kind: string): string {
  return (
    ({
      text: "文本",
      thinking: "Thinking",
      tool_call: "工具调用",
      tool_result: "工具结果",
      image: "图片",
      file: "文件",
      tool_def: "工具定义",
      system: "系统",
    } as Record<string, string>)[kind] ?? kind
  );
}

function CategoryList({
  category,
  items,
  hiddenKinds,
  deltaTokens,
}: {
  category: string;
  items: readonly CompositionItem[];
  hiddenKinds: ReadonlySet<string>;
  deltaTokens: number | null;
}) {
  const info = categoryInfo(category);
  const total = items.reduce((sum, item) => sum + item.tokens, 0);
  const added = items.filter((item) => item.change === "added").length;
  const visible = items.filter((item) => !hiddenKinds.has(item.kind));
  const shown = visible.slice(0, ITEM_RENDER_LIMIT);
  return (
    <details className="overflow-hidden rounded-lg border bg-white/80">
      <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 text-sm hover:bg-slate-50">
        <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: info.color }} />
        <span className="font-medium">{info.label}</span>
        <span className="text-xs tabular-nums text-muted-foreground">
          {formatTokens(total)} · {items.length} 项
        </span>
        {added > 0 ? <Badge variant="success" className="px-2 py-0 text-[11px]">+{added} 项</Badge> : null}
        {deltaTokens !== null && deltaTokens !== 0 ? (
          <Badge variant={deltaTokens > 0 ? "warning" : "outline"} className="px-2 py-0 text-[11px] tabular-nums">
            {formatSignedTokens(deltaTokens)}
          </Badge>
        ) : null}
      </summary>
      <ul className="divide-y border-t text-xs">
        {shown.map((item) => (
          <li key={item.index} className="flex items-start gap-3 px-3 py-1.5">
            <span className="w-14 shrink-0 text-right tabular-nums text-muted-foreground">{formatTokens(item.tokens)}</span>
            <span className="min-w-0 flex-1">
              <span className="inline-flex flex-wrap items-center gap-1.5">
                <span className="font-medium">{item.label?.trim() || itemKindLabel(item.kind)}</span>
                <span className="text-muted-foreground">{itemKindLabel(item.kind)}</span>
                {item.change === "added" ? <Badge variant="success" className="px-1.5 py-0 text-[10px]">新增</Badge> : null}
              </span>
              {item.summary ? <span className="mt-0.5 block break-words text-muted-foreground">{item.summary}</span> : null}
            </span>
          </li>
        ))}
        {visible.length === 0 ? <li className="px-3 py-2 text-muted-foreground">筛选后没有条目。</li> : null}
        {visible.length > shown.length ? (
          <li className="px-3 py-2 text-muted-foreground">仅显示前 {ITEM_RENDER_LIMIT} 项，共 {visible.length} 项。</li>
        ) : null}
      </ul>
    </details>
  );
}

export function toolSourceLabel(source: string): { label: string; variant: "secondary" | "outline" | "default" } {
  if (source === "builtin") {
    return { label: "内置", variant: "secondary" };
  }
  if (source.startsWith("mcp:")) {
    return { label: `MCP · ${source.slice(4) || "未知服务"}`, variant: "default" };
  }
  if (source === "custom") {
    return { label: "自定义", variant: "outline" };
  }
  return { label: source || "未知", variant: "outline" };
}

export function sortTools(tools: readonly ToolDef[]): ToolDef[] {
  return [...tools].sort((a, b) => b.tokens - a.tokens || a.name.localeCompare(b.name));
}

function ToolList({ tools }: { tools: readonly ToolDef[] }) {
  if (tools.length === 0) {
    return <EmptyNote>本次请求没有工具定义。</EmptyNote>;
  }
  const sorted = sortTools(tools);
  const max = Math.max(...sorted.map((tool) => tool.tokens), 1);
  return (
    <details className="overflow-hidden rounded-lg border bg-white/80">
      <summary className="cursor-pointer px-3 py-2 text-sm hover:bg-slate-50">
        展开 {sorted.length} 个工具 · 共 {formatTokens(sorted.reduce((sum, tool) => sum + tool.tokens, 0))}
      </summary>
      <ul className="divide-y border-t text-xs">
        {sorted.map((tool) => {
          const source = toolSourceLabel(tool.source);
          return (
            <li key={`${tool.source}:${tool.name}`} className="flex items-center gap-3 px-3 py-1.5">
              <span className="w-14 shrink-0 text-right tabular-nums text-muted-foreground">{formatTokens(tool.tokens)}</span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono" title={tool.name}>{tool.name}</span>
                <span className="mt-1 block h-1 rounded-full bg-slate-100">
                  <span className="block h-1 rounded-full bg-sky-400" style={{ width: `${(tool.tokens / max) * 100}%` }} />
                </span>
              </span>
              <Badge variant={source.variant} className="shrink-0 px-2 py-0 text-[11px]">{source.label}</Badge>
            </li>
          );
        })}
      </ul>
    </details>
  );
}

function FileOps({ ops }: { ops: readonly FileOp[] }) {
  if (ops.length === 0) {
    return <EmptyNote>本次响应没有文件相关的工具调用。</EmptyNote>;
  }
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>操作</TableHead>
            <TableHead>工具</TableHead>
            <TableHead>路径</TableHead>
            <TableHead className="text-right">+ 行</TableHead>
            <TableHead className="text-right">− 行</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ops.map((op, index) => (
            <TableRow key={`${index}:${op.tool}:${op.path ?? ""}`}>
              <TableCell>
                <Badge variant="outline">{fileOpLabel(op.op)}</Badge>
              </TableCell>
              <TableCell className="font-mono text-xs">{op.tool}</TableCell>
              <TableCell className="max-w-[24rem] break-all font-mono text-xs">{op.path || "—"}</TableCell>
              <TableCell className="text-right tabular-nums text-emerald-700">{op.added_lines ? `+${op.added_lines}` : "—"}</TableCell>
              <TableCell className="text-right tabular-nums text-red-700">{op.removed_lines ? `−${op.removed_lines}` : "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function fileOpLabel(op: string): string {
  return ({ read: "读取", write: "写入", search: "搜索", shell: "命令" } as Record<string, string>)[op] ?? op;
}

export function linkSourceText(agent: Pick<AgentIdentity, "link_source" | "confidence">): string {
  switch (agent.link_source) {
    case "header":
      return "Header 显式标识（精确）";
    case "body":
      return "Body 回链（精确）";
    case "content":
      return `内容匹配（推断${agent.confidence ? ` ${agent.confidence}%` : ""}）`;
    default:
      return "—";
  }
}

function AgentBlock({ agent }: { agent: AgentIdentity }) {
  const rows: Array<[string, string, boolean]> = [
    ["客户端", clientLabel(agent.client), false],
    ["角色", roleLabel(agent.role), false],
    ["名称", agent.name || "—", false],
    ["关联方式", linkSourceText(agent), false],
    ["Node ID", agent.node_id || "—", true],
    ["Parent ID", agent.parent_id || "—", true],
    ["Root ID", agent.root_id || "—", true],
  ];
  return (
    <dl className="grid gap-x-5 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
      {rows.map(([label, value, mono]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className={`mt-0.5 break-all font-medium ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

const TREEMAP_W = 800;
const TREEMAP_H = 320;

export function TreemapView({ items }: { items: readonly CompositionItem[] }) {
  const laidOut = useMemo(() => layoutTreemap(buildTreemapData(items), { x: 0, y: 0, w: TREEMAP_W, h: TREEMAP_H }), [items]);
  if (laidOut.length === 0) {
    return <EmptyNote>没有可绘制的条目。</EmptyNote>;
  }
  return (
    <svg
      role="img"
      aria-label="上下文构成 Treemap"
      viewBox={`0 0 ${TREEMAP_W} ${TREEMAP_H}`}
      width="100%"
      style={{ display: "block", maxHeight: 360 }}
    >
      {laidOut.map((category) => {
        const info = categoryInfo(category.category);
        const showHeader = category.inner.y - category.rect.y > 4;
        return (
          <g key={category.category}>
            <rect
              x={category.rect.x}
              y={category.rect.y}
              width={category.rect.w}
              height={category.rect.h}
              fill={info.color}
              fillOpacity={0.16}
              stroke={info.color}
              strokeWidth={1}
            >
              <title>{`${info.label} ${formatTokens(category.tokens)}`}</title>
            </rect>
            {showHeader ? (
              <text x={category.rect.x + 4} y={category.rect.y + 12} fontSize="11" fontWeight="600" fill="#0f172a">
                {truncateText(`${info.label} ${formatTokens(category.tokens)}`, Math.floor(category.rect.w / 6.5))}
              </text>
            ) : null}
            {category.groups.map((group) => (
              <g key={group.name}>
                <rect
                  x={group.rect.x}
                  y={group.rect.y}
                  width={Math.max(group.rect.w - 1, 0)}
                  height={Math.max(group.rect.h - 1, 0)}
                  fill={info.color}
                  fillOpacity={group.other ? 0.4 : 0.78}
                  stroke="#ffffff"
                  strokeWidth={1}
                >
                  <title>{`${info.label} · ${group.name}：${formatTokens(group.tokens)}（${group.count} 项）`}</title>
                </rect>
                {group.rect.w > 46 && group.rect.h > 18 ? (
                  <text x={group.rect.x + 4} y={group.rect.y + 13} fontSize="10" fill="#ffffff">
                    {truncateText(`${group.name} ${formatTokens(group.tokens)}`, Math.floor((group.rect.w - 6) / 5.6))}
                  </text>
                ) : null}
              </g>
            ))}
          </g>
        );
      })}
    </svg>
  );
}

function truncateText(text: string, maxChars: number): string {
  if (maxChars <= 1) {
    return "";
  }
  return text.length > maxChars ? `${text.slice(0, maxChars - 1)}…` : text;
}

const DNA_W = 1000;
const DNA_H = 36;

export function DnaStrip({ items, compared }: { items: readonly CompositionItem[]; compared: boolean }) {
  const bands = useMemo(() => buildDnaBands(items, DNA_W), [items]);
  if (bands.length === 0) {
    return <EmptyNote>没有可绘制的条目。</EmptyNote>;
  }
  const addedCount = bands.filter((band) => band.added).length;
  return (
    <div className="space-y-1">
      <svg
        role="img"
        aria-label="提示词 DNA 条带"
        viewBox={`0 0 ${DNA_W} ${DNA_H + 8}`}
        width="100%"
        height={DNA_H + 8}
        preserveAspectRatio="none"
        style={{ display: "block" }}
      >
        {bands.map((band) => {
          const info = categoryInfo(band.category);
          return (
            <g key={band.index}>
              <rect x={band.x} y={8} width={band.width} height={DNA_H} fill={info.color}>
                <title>{`#${band.index} ${info.label} · ${band.label}：${formatTokens(band.tokens)}${band.added ? "（新增）" : ""}`}</title>
              </rect>
              {band.added ? <rect x={band.x} y={0} width={band.width} height={6} fill="#16a34a" data-added="true" /> : null}
            </g>
          );
        })}
      </svg>
      <p className="text-[11px] text-muted-foreground">
        {compared
          ? `绿色标记表示相对上一步新增的条目（${addedCount} 段）。`
          : "没有上一步可对比，未标记新增条目。"}
      </p>
    </div>
  );
}
