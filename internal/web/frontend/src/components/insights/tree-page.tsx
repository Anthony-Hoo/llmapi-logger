import { useEffect, useMemo, useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatTokens, formatUSD, occupancy, occupancyLevel } from "../../lib/insights/format";
import { lineageColor, tidyLayout, type TreeLayout } from "../../lib/insights/tree-layout";
import type { TreeNode, TreeResponse } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { CategoryLegend, CompositionBar, OccupancyText } from "./composition-bar";
import { clientLabel, EmptyNote, PanelTitle, roleLabel } from "./ui-bits";

export const CARD_WIDTH = 264;
export const CARD_HEIGHT = 148;
const GAP_X = 56;
const GAP_Y = 14;

export function linkSourceLabel(node: Pick<TreeNode, "link_source" | "link_confidence">): string | null {
  switch (node.link_source) {
    case "header":
      return "精确";
    case "body":
      return "回链";
    case "content":
      return node.link_confidence ? `推断 ${node.link_confidence}%` : "推断";
    default:
      return null;
  }
}

export interface PlacedNode {
  node: TreeNode;
  depth: number;
  order: number;
  /** Pre-order index of the depth-1 ancestor (own index for roots); descendants share its hue. */
  lineage: number;
  left: number;
  top: number;
}

export function placeNodes(nodes: readonly TreeNode[]): { placed: PlacedNode[]; layout: TreeLayout; width: number; height: number } {
  const layout = tidyLayout(nodes.map((node) => ({ id: node.node_id, parentId: node.parent_node_id })));
  const byID = new Map(nodes.map((node) => [node.node_id, node]));
  const placed: PlacedNode[] = [];
  for (const entry of layout.nodes) {
    const node = byID.get(entry.id);
    if (node) {
      placed.push({
        node,
        depth: entry.depth,
        order: entry.order,
        lineage: entry.order,
        left: entry.depth * (CARD_WIDTH + GAP_X),
        top: entry.x * (CARD_HEIGHT + GAP_Y),
      });
    }
  }
  const placedByID = new Map(placed.map((entry) => [entry.node.node_id, entry]));
  for (const entry of placed) {
    let cursor = entry;
    while (cursor.depth > 1) {
      const parent = placedByID.get(cursor.node.parent_node_id ?? "");
      if (!parent) {
        break;
      }
      cursor = parent;
    }
    entry.lineage = cursor.order;
  }
  const width = layout.levels * (CARD_WIDTH + GAP_X) - GAP_X;
  const height = layout.breadth * (CARD_HEIGHT + GAP_Y) + CARD_HEIGHT;
  return { placed, layout, width: Math.max(width, CARD_WIDTH), height };
}

export function TreePage({
  client,
  treeID,
  refreshKey,
  onBack,
  onOpenSession,
}: {
  client: ApiClient;
  treeID: string;
  refreshKey: number;
  onBack: () => void;
  onOpenSession: (node: TreeNode) => void;
}) {
  const [tree, setTree] = useState<TreeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    client
      .getAgentTree(treeID, controller.signal)
      .then(setTree)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setTree(null);
          setError(
            cause instanceof ApiError && cause.status === 404 ? "找不到该 Agent 树，或其节点不在当前身份的可见范围内。" : errorMessage(cause),
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, treeID, refreshKey]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" size="sm" onClick={onBack}>
          ← 返回
        </Button>
        <div className="min-w-0">
          <h2 className="text-base font-semibold">Agent 树</h2>
          <p className="truncate font-mono text-xs text-muted-foreground" title={treeID}>
            {treeID}
          </p>
        </div>
      </div>

      {error ? (
        <Alert className="border-red-200">
          <AlertTitle className="text-red-900">无法读取 Agent 树</AlertTitle>
          <AlertDescription className="text-red-800">{error}</AlertDescription>
        </Alert>
      ) : null}
      {loading ? <Skeleton className="h-64 w-full" /> : null}

      {tree && !loading ? (
        <Card className="bg-white/90">
          <CardContent className="space-y-4 pt-4">
            <PanelTitle
              title={`共 ${tree.nodes.length} 个节点`}
              hint="点击节点查看该 Agent 的会话趋势；附属请求（压缩、标题等）计在发起它的节点上"
            />
            {tree.truncated ? (
              <Alert className="border-amber-200">
                <AlertDescription>节点过多，仅显示最多 40 个。</AlertDescription>
              </Alert>
            ) : null}
            <AgentTree nodes={tree.nodes} onOpenNode={onOpenSession} />
            <CategoryLegend />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

/**
 * Wide screens: tidy tree (cards positioned over an SVG edge layer) that may
 * scroll inside its own box. Narrow screens: an indented list, so the page
 * itself never scrolls horizontally.
 */
export function AgentTree({ nodes, onOpenNode }: { nodes: readonly TreeNode[]; onOpenNode: (node: TreeNode) => void }) {
  const { placed, width, height } = useMemo(() => placeNodes(nodes), [nodes]);
  const byID = useMemo(() => new Map(placed.map((entry) => [entry.node.node_id, entry])), [placed]);
  if (placed.length === 0) {
    return <EmptyNote>这棵树没有可展示的节点。</EmptyNote>;
  }
  return (
    <>
      <div className="hidden overflow-x-auto md:block" data-testid="agent-tree-canvas">
        <div className="relative" style={{ width, height }}>
          <svg width={width} height={height} className="absolute inset-0" aria-hidden="true">
            {placed.map((entry) => {
              const parent = entry.node.parent_node_id ? byID.get(entry.node.parent_node_id) : undefined;
              if (!parent) {
                return null;
              }
              const x1 = parent.left + CARD_WIDTH;
              const y1 = parent.top + CARD_HEIGHT / 2;
              const x2 = entry.left;
              const y2 = entry.top + CARD_HEIGHT / 2;
              const mid = (x1 + x2) / 2;
              return (
                <path
                  key={entry.node.node_id}
                  d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
                  fill="none"
                  stroke={lineageColor(entry.lineage)}
                  strokeWidth={2}
                  opacity={entry.node.visible ? 0.9 : 0.4}
                />
              );
            })}
          </svg>
          {placed.map((entry) => (
            <div key={entry.node.node_id} className="absolute" style={{ left: entry.left, top: entry.top, width: CARD_WIDTH, height: CARD_HEIGHT }}>
              <NodeCard node={entry.node} color={lineageColor(entry.lineage)} onOpen={onOpenNode} />
            </div>
          ))}
        </div>
      </div>

      <ul className="space-y-2 md:hidden" aria-label="Agent 树（列表）" data-testid="agent-tree-list">
        {placed.map((entry) => (
          <li key={entry.node.node_id} style={{ marginLeft: Math.min(entry.depth, 4) * 14 }}>
            <NodeCard node={entry.node} color={lineageColor(entry.lineage)} onOpen={onOpenNode} />
          </li>
        ))}
      </ul>
    </>
  );
}

export function NodeCard({ node, color, onOpen }: { node: TreeNode; color: string; onOpen: (node: TreeNode) => void }) {
  if (!node.visible) {
    return (
      <div
        className="h-full rounded-lg border border-dashed bg-slate-100/70 p-3 text-slate-500"
        style={{ borderLeft: `4px solid ${color}` }}
        data-placeholder="true"
      >
        <p className="text-sm font-medium">不可见的父 Agent</p>
        <p className="mt-1 text-xs">该节点不在当前身份的可见范围内，仅用于保持树结构。</p>
        <p className="mt-2 truncate font-mono text-[11px]" title={node.node_id}>
          {node.node_id}
        </p>
      </div>
    );
  }

  const ratio = occupancy(node.last_prompt_total, node.context_window);
  const level = ratio === null ? "ok" : occupancyLevel(ratio);
  const borderClass = level === "danger" ? "border-red-400" : level === "warn" ? "border-amber-400" : "border-border";
  const link = linkSourceLabel(node);
  const clickable = Boolean(node.session_id);
  const usage = node.usage;

  return (
    <div
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      aria-label={clickable ? `查看 ${clientLabel(node.client)} ${roleLabel(node.role)} 的会话趋势` : undefined}
      className={`h-full space-y-1.5 overflow-hidden rounded-lg border bg-white p-3 shadow-xs ${borderClass} ${
        clickable ? "cursor-pointer outline-hidden transition-colors hover:border-primary/60 focus-visible:ring-2 focus-visible:ring-ring" : ""
      }`}
      style={{ borderLeft: `4px solid ${color}` }}
      data-occupancy={level}
      onClick={clickable ? () => onOpen(node) : undefined}
      onKeyDown={
        clickable
          ? (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onOpen(node);
              }
            }
          : undefined
      }
    >
      <div className="flex flex-wrap items-center gap-1">
        <Badge variant="secondary">
          {clientLabel(node.client)}
        </Badge>
        <Badge variant={node.role === "main" ? "default" : "outline"}>
          {roleLabel(node.role)}
        </Badge>
        {link ? (
          <Badge variant={node.link_source === "content" ? "warning" : "success"} title="父子关系来源">
            {link}
          </Badge>
        ) : null}
      </div>
      <p className="text-xs text-muted-foreground">
        {node.steps} 步
        {node.aux_requests > 0 ? ` · 附属请求 ${node.aux_requests}` : ""}
      </p>
      <p className="truncate text-xs tabular-nums">
        prompt {formatTokens(usage.prompt_total)} · 输出 {formatTokens(usage.output)} · {formatUSD(usage.estimated_cost_usd)}
      </p>
      <CompositionBar values={node.last_composition} contextWindow={node.context_window} height={8} label="末步上下文构成" />
      <p className="text-[11px]">
        <OccupancyText lastPrompt={node.last_prompt_total} contextWindow={node.context_window} />
      </p>
    </div>
  );
}
