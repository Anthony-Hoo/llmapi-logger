import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { DailyUsage } from "../../types";
import { formatRatio, formatTokens, formatUSD } from "../../lib/insights/format";
import { EmptyNote } from "./ui-bits";

const TOKEN_COLOR = "#3b82f6";
const COST_COLOR = "#f59e0b";

interface DailyRow {
  day: string;
  label: string;
  tokens: number;
  cost: number | null;
  usage: DailyUsage["usage"];
}

export function dailyRows(daily: readonly DailyUsage[]): DailyRow[] {
  return daily.map((entry) => ({
    day: entry.day,
    label: entry.day.slice(5),
    tokens: entry.usage.prompt_total + entry.usage.output,
    cost: entry.usage.estimated_cost_usd,
    usage: entry.usage,
  }));
}

/** Paired bars per day: tokens (left axis) next to estimated cost (right axis). */
export function DailyChart({ daily }: { daily: readonly DailyUsage[] }) {
  const rows = dailyRows(daily);
  if (rows.length === 0) {
    return <EmptyNote>所选范围内没有用量数据。</EmptyNote>;
  }
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-4 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: TOKEN_COLOR }} />
          Token（prompt + 输出，左轴）
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: COST_COLOR }} />
          估算成本（右轴）
        </span>
      </div>
      <div className="h-64 w-full" data-testid="daily-chart">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barGap={2}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
            <XAxis dataKey="label" tick={{ fontSize: 11 }} interval="preserveStartEnd" minTickGap={16} />
            <YAxis yAxisId="tokens" tick={{ fontSize: 11 }} tickFormatter={(value: number) => formatTokens(value)} width={48} />
            <YAxis
              yAxisId="cost"
              orientation="right"
              tick={{ fontSize: 11 }}
              tickFormatter={(value: number) => formatUSD(value)}
              width={56}
            />
            <Tooltip content={<DailyTooltip />} cursor={{ fill: "rgba(148,163,184,0.15)" }} />
            <Bar yAxisId="tokens" dataKey="tokens" name="Token" fill={TOKEN_COLOR} radius={[2, 2, 0, 0]} isAnimationActive={false} />
            <Bar yAxisId="cost" dataKey="cost" name="估算成本" fill={COST_COLOR} radius={[2, 2, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function DailyTooltip({ active, payload }: { active?: boolean; payload?: ReadonlyArray<{ payload?: DailyRow }> }) {
  const row = payload?.[0]?.payload;
  if (!active || !row) {
    return null;
  }
  const usage = row.usage;
  return (
    <div className="rounded-md border bg-white p-3 text-xs shadow-md">
      <p className="mb-1 font-semibold">{row.day}</p>
      <dl className="grid grid-cols-[auto_auto] gap-x-4 gap-y-0.5">
        <dt className="text-muted-foreground">请求数</dt>
        <dd className="text-right tabular-nums">{usage.requests}</dd>
        <dt className="text-muted-foreground">prompt</dt>
        <dd className="text-right tabular-nums">{formatTokens(usage.prompt_total)}</dd>
        <dt className="text-muted-foreground">输出</dt>
        <dd className="text-right tabular-nums">{formatTokens(usage.output)}</dd>
        <dt className="text-muted-foreground">缓存命中率</dt>
        <dd className="text-right tabular-nums">{formatRatio(usage.cache_hit_rate)}</dd>
        <dt className="text-muted-foreground">估算成本</dt>
        <dd className="text-right tabular-nums">
          {formatUSD(usage.estimated_cost_usd)}
          {usage.unpriced_requests > 0 ? "（部分未知价格）" : ""}
        </dd>
      </dl>
    </div>
  );
}
