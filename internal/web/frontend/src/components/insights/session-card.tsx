import type { ReactNode } from "react";
import type { SessionCard as SessionCardData } from "../../types";
import { formatNanoTime } from "../../lib/format";
import { formatRatio, formatTokens, formatUSD } from "../../lib/insights/format";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { CompositionBar, OccupancyText } from "./composition-bar";
import { clientLabel, protocolLabel, roleLabel, UnbilledNote } from "./ui-bits";

export function SessionCardView({
  card,
  billingEnabled = true,
  onOpenSession,
  onOpenTree,
}: {
  card: SessionCardData;
  /** False when the server has no NewAPI credentials: cost is unavailable, not unbilled. */
  billingEnabled?: boolean;
  onOpenSession: (card: SessionCardData) => void;
  onOpenTree: (treeID: string) => void;
}) {
  const usage = card.usage;
  const callerText = card.caller
    ? [card.caller.username, card.caller.token_name].filter(Boolean).join(" · ")
    : "";
  return (
    <article className="min-w-0 rounded-lg border bg-surface p-card shadow-card transition-colors hover:border-primary-300">
      <div
        role="button"
        tabIndex={0}
        className="cursor-pointer space-y-3 outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        aria-label={`查看会话趋势 ${card.session_id}`}
        onClick={() => onOpenSession(card)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onOpenSession(card);
          }
        }}
      >
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant="neutral">{clientLabel(card.client)}</Badge>
          <Badge variant={card.role === "main" ? "info" : "outline"}>{roleLabel(card.role)}</Badge>
          <Badge variant="outline">{protocolLabel(card.protocol)}</Badge>
          {card.subagents > 0 ? <Badge variant="warning">含 {card.subagents} 个子 Agent</Badge> : null}
          <span className="ml-auto text-caption text-subtle">{formatNanoTime(card.last_ns)}</span>
        </div>

        <p className="break-words text-body font-medium" title={card.models.join(", ")}>
          {card.models.length > 0 ? card.models.join(" · ") : "未记录模型"}
        </p>

        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-label sm:grid-cols-4">
          <Stat label="步 / 轮" value={`${card.steps} / ${card.turns}`} />
          <Stat label="prompt" value={formatTokens(usage.prompt_total)} />
          <Stat label="输出" value={formatTokens(usage.output)} />
          <Stat label="缓存命中" value={formatRatio(usage.cache_hit_rate)} />
          <Stat
            label="实际计费"
            value={
              billingEnabled ? (
                <>
                  {formatUSD(usage.cost_usd)}
                  {usage.unbilled_requests > 0 ? <UnbilledNote count={usage.unbilled_requests} className="ml-1" /> : null}
                </>
              ) : (
                "—"
              )
            }
          />
          {callerText ? <Stat label="调用者" value={callerText} /> : null}
        </dl>

        <div className="space-y-1">
          <CompositionBar values={card.last_composition} contextWindow={card.context_window} height={8} label="末步上下文构成" />
          <p className="text-caption">
            <span className="text-subtle">末步上下文：</span>
            <OccupancyText lastPrompt={card.last_prompt_total} contextWindow={card.context_window} />
          </p>
        </div>
      </div>

      {card.tree_id ? (
        <div className="mt-3 flex justify-end">
          <Button variant="outline" size="sm" onClick={() => onOpenTree(card.tree_id!)}>
            查看 Agent 树
          </Button>
        </div>
      ) : null}
    </article>
  );
}

function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-subtle">{label}</dt>
      <dd className="truncate font-medium tabular-nums">{value}</dd>
    </div>
  );
}
