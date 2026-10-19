import { useEffect, useMemo, useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatTokens, formatUSD, occupancy, occupancyLevel } from "../../lib/insights/format";
import { lineageColor, tidyLayout, type TreeLayout } from "../../lib/insights/tree-layout";
import type { ClientLabels, TreeNode, TreeResponse } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { PageHeader } from "../ui/page-header";
import { Skeleton } from "../ui/skeleton";
import { CategoryLegend, CompositionBar, OccupancyText } from "./composition-bar";
import { clientLabel, EmptyNote, PanelTitle, roleLabel } from "./ui-bits";

export const CARD_WIDTH = 264;
// Tall enough for the optional name row above the badges.
export const CARD_HEIGHT = 176;
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
  onOpenSession: (node: TreeNode, clientLabels?: ClientLabels) => void;
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
    <div className="space-y-section">
      <PageHeader
        leading={
          <Button variant="outline" size="sm" onClick={onBack}>
            ← 返回
          </Button>
        }
        title="Agent 树"
        description={treeID}
        descriptionTitle={treeID}
        descriptionClassName="truncate font-mono text-label text-subtle"
      />

      {error ? (
        <Alert variant="danger">
          <AlertTitle>无法读取 Agent 树</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {loading ? <Skeleton className="h-64 w-full" /> : null}

      {tree && !loading ? (
        <Card>
          <CardContent className="space-y-stack pt-card">
            <PanelTitle
              title={`共 ${tree.nodes.length} 个节点`}
              hint="点击节点查看该 Agent 的会话趋势；附属请求（压缩、标题等）计在发起它的节点上"
            />
            {tree.truncated ? (
              <Alert variant="warning">
                <AlertDescription>节点过多，仅显示最多 40 个。</AlertDescription>
              </Alert>
            ) : null}
            <AgentTree nodes={tree.nodes} clientLabels={tree.client_labels} onOpenNode={(node) => onOpenSession(node, tree.client_labels)} />
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
export function AgentTree({
  nodes,
  clientLabels,
  onOpenNode,
}: {
  nodes: readonly TreeNode[];
  /** `client_labels` of the tree response. */
  clientLabels?: ClientLabels;
  onOpenNode: (node: TreeNode) => void;
}) {
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
              <NodeCard node={entry.node} color={lineageColor(entry.lineage)} clientLabels={clientLabels} onOpen={onOpenNode} />
            </div>
          ))}
        </div>
      </div>

      <ul className="space-y-2 md:hidden" aria-label="Agent 树（列表）" data-testid="agent-tree-list">
        {placed.map((entry) => (
          <li key={entry.node.node_id} style={{ marginLeft: Math.min(entry.depth, 4) * 14 }}>
            <NodeCard node={entry.node} color={lineageColor(entry.lineage)} clientLabels={clientLabels} onOpen={onOpenNode} />
          </li>
        ))}
      </ul>
    </>
  );
}

/** Short form of a node id for secondary display next to a name. */
export function shortNodeID(nodeID: string): string {
  return nodeID.length > 8 ? nodeID.slice(0, 8) : nodeID;
}

export function NodeCard({
  node,
  color,
  clientLabels,
  onOpen,
}: {
  node: TreeNode;
  color: string;
  clientLabels?: ClientLabels;
  onOpen: (node: TreeNode) => void;
}) {
  if (!node.visible) {
    return (
      <div
        className="h-full rounded-md border border-dashed bg-surface-sunken p-3 text-subtle"
        style={{ borderLeft: `4px solid ${color}` }}
        data-placeholder="true"
      >
        <p className="text-body font-medium">父 Agent 不在范围内或尚未分析</p>
        <p className="mt-1 text-label">没有可见的分析记录描述该父节点：它可能不在当前身份的可见范围内、已过期，或其请求尚未分析。占位仅用于保持树结构。</p>
        <p className="mt-2 truncate font-mono text-caption" title={node.node_id}>
          {node.node_id}
        </p>
      </div>
    );
  }

  const ratio = occupancy(node.last_prompt_total, node.context_window);
  const level = ratio === null ? "ok" : occupancyLevel(ratio);
  const borderClass = level === "danger" ? "border-danger" : level === "warn" ? "border-warning" : "border-border";
  const link = linkSourceLabel(node);
  const clickable = Boolean(node.session_id);
  const usage = node.usage;
  const client = clientLabel(node.client, clientLabels);
  const who = node.name ? `${node.name}（${client} ${roleLabel(node.role)}）` : `${client} ${roleLabel(node.role)}`;

  return (
    <div
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      aria-label={clickable ? `查看 ${who} 的会话趋势` : undefined}
      className={`h-full space-y-1.5 overflow-hidden rounded-md border bg-surface p-3 shadow-xs ${borderClass} ${
        clickable ? "cursor-pointer outline-hidden transition-colors hover:border-primary-400 focus-visible:ring-2 focus-visible:ring-ring" : ""
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
      {node.name ? (
        <p className="flex min-w-0 items-baseline gap-2" data-testid="node-name">
          <span className="truncate text-body font-medium" title={node.name}>
            {node.name}
          </span>
          <span className="shrink-0 font-mono text-caption text-subtle" title={node.node_id}>
            {shortNodeID(node.node_id)}
          </span>
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-1">
        <Badge variant="neutral">
          {client}
        </Badge>
        <Badge variant={node.role === "main" ? "info" : "outline"}>
          {roleLabel(node.role)}
        </Badge>
        {link ? (
          <Badge variant={node.link_source === "content" ? "warning" : "success"} title="父子关系来源">
            {link}
          </Badge>
        ) : null}
      </div>
      <p className="text-label text-muted">
        {node.steps} 步
        {node.aux_requests > 0 ? ` · 附属请求 ${node.aux_requests}` : ""}
      </p>
      <p className="truncate text-label tabular-nums">
        prompt {formatTokens(usage.prompt_total)} · 输出 {formatTokens(usage.output)} · 实际计费 {formatUSD(usage.cost_usd)}
      </p>
      <CompositionBar values={node.last_composition} contextWindow={node.context_window} height={8} label="末步上下文构成" />
      <p className="text-caption">
        <OccupancyText lastPrompt={node.last_prompt_total} contextWindow={node.context_window} />
      </p>
    </div>
  );
}
