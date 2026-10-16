import type { ReactNode } from "react";
import type { SessionCard as SessionCardData } from "../../types";
import { formatNanoTime } from "../../lib/format";
import { formatRatio, formatTokens, formatUSD } from "../../lib/insights/format";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { CompositionBar, OccupancyText } from "./composition-bar";
import { clientLabel, protocolLabel, roleLabel } from "./ui-bits";

export function SessionCardView({
  card,
  onOpenSession,
  onOpenTree,
}: {
  card: SessionCardData;
  onOpenSession: (card: SessionCardData) => void;
  onOpenTree: (treeID: string) => void;
}) {
  const usage = card.usage;
  const callerText = card.caller
    ? [card.caller.username, card.caller.token_name].filter(Boolean).join(" · ")
    : "";
  return (
    <article className="min-w-0 rounded-lg border bg-white/90 p-4 shadow-sm transition-colors hover:border-primary/40">
      <div
        role="button"
        tabIndex={0}
        className="cursor-pointer space-y-3 outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
          <Badge variant="secondary">{clientLabel(card.client)}</Badge>
          <Badge variant={card.role === "main" ? "default" : "outline"}>{roleLabel(card.role)}</Badge>
          <Badge variant="outline">{protocolLabel(card.protocol)}</Badge>
          {card.subagents > 0 ? <Badge variant="warning">含 {card.subagents} 个子 Agent</Badge> : null}
          <span className="ml-auto text-xs text-muted-foreground">{formatNanoTime(card.last_ns)}</span>
        </div>

        <p className="break-words text-sm font-medium" title={card.models.join(", ")}>
          {card.models.length > 0 ? card.models.join(" · ") : "未记录模型"}
        </p>

        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
          <Stat label="步 / 轮" value={`${card.steps} / ${card.turns}`} />
          <Stat label="prompt" value={formatTokens(usage.prompt_total)} />
          <Stat label="输出" value={formatTokens(usage.output)} />
          <Stat label="缓存命中" value={formatRatio(usage.cache_hit_rate)} />
          <Stat
            label="估算成本"
            value={
              <>
                {formatUSD(usage.estimated_cost_usd)}
                {usage.unpriced_requests > 0 ? <span className="text-amber-700">（部分未知价格）</span> : null}
              </>
            }
          />
          {callerText ? <Stat label="调用者" value={callerText} /> : null}
        </dl>

        <div className="space-y-1">
          <CompositionBar values={card.last_composition} contextWindow={card.context_window} height={8} label="末步上下文构成" />
          <p className="text-[11px]">
            <span className="text-muted-foreground">末步上下文：</span>
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
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate font-medium tabular-nums">{value}</dd>
    </div>
  );
}
