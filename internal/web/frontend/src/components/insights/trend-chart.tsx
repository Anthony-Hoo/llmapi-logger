import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, usePlotArea, useXAxisScale, XAxis, YAxis } from "recharts";

import { formatNanoTime } from "../../lib/format";
import { CATEGORIES } from "../../lib/insights/categories";
import {
  formatMillis,
  formatRatio,
  formatSignedTokens,
  formatTokens,
  formatUSD,
} from "../../lib/insights/format";
import {
  absoluteDelta,
  buildChartRows,
  type ChartRow,
  type TrendBar,
  type TrendGranularity,
  type TrendMode,
} from "../../lib/insights/trend";
import { EVENT_INFO, eventLabel } from "./ui-bits";

const MARKER_ROOM = 26;

export function TrendChart({
  bars,
  mode,
  granularity,
  contextWindow,
  selectedAuditID,
  onSelectBar,
}: {
  bars: readonly TrendBar[];
  mode: TrendMode;
  granularity: TrendGranularity;
  contextWindow: number | null;
  selectedAuditID: string | null;
  onSelectBar: (auditID: string) => void;
}) {
  const rows = buildChartRows(bars, mode, granularity);
  const tickEvery = Math.max(1, Math.ceil(rows.length / 24));
  const maxTotal = Math.max(0, ...bars.map((bar) => bar.promptTotal ?? Object.values(bar.anchored).reduce((a, b) => a + b, 0)));
  const showWindow = mode === "total" && contextWindow !== null && contextWindow > 0 && maxTotal >= contextWindow * 0.5;

  return (
    <div
      className="h-80 w-full [&_.recharts-bar-rectangle]:cursor-pointer"
      data-testid="trend-chart"
      data-mode={mode}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={rows}
          stackOffset={mode === "delta" ? "sign" : "none"}
          margin={{ top: MARKER_ROOM, right: 8, bottom: 0, left: 0 }}
          barCategoryGap="12%"
        >
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
          <XAxis
            dataKey="key"
            tick={{ fontSize: 11 }}
            interval={tickEvery - 1}
            tickFormatter={(value: string) => rows.find((row) => row.key === value)?.label ?? ""}
          />
          <YAxis
            tick={{ fontSize: 11 }}
            width={52}
            tickFormatter={(value: number) => (mode === "delta" ? formatSignedTokens(value) : formatTokens(value))}
          />
          {mode === "delta" ? <ReferenceLine y={0} stroke="#64748b" /> : null}
          {showWindow ? (
            <ReferenceLine
              y={contextWindow ?? undefined}
              stroke="#dc2626"
              strokeDasharray="4 4"
              label={{ value: "上下文窗口", position: "insideTopRight", fontSize: 11, fill: "#dc2626" }}
            />
          ) : null}
          <Tooltip content={<TrendTooltip mode={mode} granularity={granularity} />} cursor={{ fill: "rgba(148,163,184,0.15)" }} />
          {CATEGORIES.map((category) => (
            <Bar
              key={category.key}
              dataKey={category.key}
              name={category.label}
              stackId="context"
              fill={category.color}
              isAnimationActive={false}
              onClick={(entry: { payload?: ChartRow }) => {
                const row = entry?.payload;
                if (row) {
                  onSelectBar(row.bar.auditID);
                }
              }}
            />
          ))}
          <EventMarkers rows={rows} selectedAuditID={selectedAuditID} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Glyphs above the plot area for steps that carry context events. */
function EventMarkers({ rows, selectedAuditID }: { rows: readonly ChartRow[]; selectedAuditID: string | null }) {
  const scale = useXAxisScale() as unknown as
    | (((value: unknown) => number | undefined) & { bandwidth?: () => number })
    | undefined;
  const area = usePlotArea();
  if (!scale || !area) {
    return null;
  }
  const band = typeof scale.bandwidth === "function" ? scale.bandwidth() : 0;
  return (
    <g data-testid="event-markers">
      {rows.map((row) => {
        const events = row.bar.events.filter((event) => EVENT_INFO[event]);
        const start = scale(row.key);
        if (events.length === 0 || start === undefined) {
          return null;
        }
        const center = start + band / 2;
        return (
          <g key={row.key} opacity={selectedAuditID && selectedAuditID !== row.bar.auditID ? 0.7 : 1}>
            <title>{events.map(eventLabel).join("、")}</title>
            {events.map((event, index) => {
              const info = EVENT_INFO[event];
              const x = center + (index - (events.length - 1) / 2) * 13;
              return (
                <g key={event}>
                  <circle cx={x} cy={area.y - 12} r={6} fill={info.color} />
                  <text x={x} y={area.y - 12} fontSize="8" fill="#ffffff" textAnchor="middle" dominantBaseline="central">
                    {info.glyph}
                  </text>
                </g>
              );
            })}
          </g>
        );
      })}
    </g>
  );
}

export function TrendTooltip({
  active,
  payload,
  mode,
  granularity,
}: {
  active?: boolean;
  payload?: ReadonlyArray<{ payload?: ChartRow }>;
  mode: TrendMode;
  granularity: TrendGranularity;
}) {
  const row = payload?.[0]?.payload;
  if (!active || !row) {
    return null;
  }
  return <TrendTooltipBody row={row} mode={mode} granularity={granularity} />;
}

export function TrendTooltipBody({ row, mode, granularity }: { row: ChartRow; mode: TrendMode; granularity: TrendGranularity }) {
  const bar = row.bar;
  const source = mode === "delta" ? row.delta : bar.anchored;
  const usage = bar.usage;
  return (
    <div className="max-w-[20rem] space-y-2 rounded-md border bg-white p-3 text-xs shadow-md">
      <div>
        <p className="font-semibold">
          {granularity === "turn" ? `第 ${bar.turn} 轮（${bar.steps} 步）` : `第 ${bar.position} 步`}
          <span className="ml-2 font-normal text-muted-foreground">{bar.model || "未记录模型"}</span>
        </p>
        <p className="text-muted-foreground">{formatNanoTime(bar.startedAtNS)}</p>
      </div>

      <div>
        <p className="mb-1 text-muted-foreground">
          {mode === "delta"
            ? "相对上一柱的变化（估算）"
            : bar.anchoredToUsage
              ? "构成（已锚定到 prompt 总量）"
              : "构成（估算，无 usage）"}
        </p>
        <ul className="space-y-0.5">
          {CATEGORIES.filter((category) => source[category.key] !== 0).map((category) => (
            <li key={category.key} className="flex items-center justify-between gap-4">
              <span className="inline-flex items-center gap-1.5">
                <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: category.color }} />
                {category.label}
              </span>
              <span className="tabular-nums">
                {mode === "delta" ? formatSignedTokens(source[category.key]) : formatTokens(source[category.key])}
              </span>
            </li>
          ))}
        </ul>
        {mode === "delta" ? (
          <p className="mt-1 flex justify-between border-t pt-1 font-medium">
            <span>净变化</span>
            <span className="tabular-nums">
              {formatSignedTokens(row.net)}
              <span className="ml-1 font-normal text-muted-foreground">（幅度 {formatTokens(absoluteDelta(row.delta))}）</span>
            </span>
          </p>
        ) : null}
      </div>

      <div>
        <p className="mb-1 text-muted-foreground">实际 usage</p>
        <dl className="grid grid-cols-[auto_auto] gap-x-4 gap-y-0.5">
          <dt>未缓存输入</dt>
          <dd className="text-right tabular-nums">{formatTokens(usage.uncached_input)}</dd>
          <dt>缓存读取</dt>
          <dd className="text-right tabular-nums">{formatTokens(usage.cache_read)}</dd>
          <dt>缓存写入</dt>
          <dd className="text-right tabular-nums">{formatTokens(usage.cache_write)}</dd>
          <dt>输出</dt>
          <dd className="text-right tabular-nums">{formatTokens(usage.output)}</dd>
          <dt>推理</dt>
          <dd className="text-right tabular-nums">{formatTokens(usage.reasoning)}</dd>
          <dt className="font-medium">prompt 总量</dt>
          <dd className="text-right font-medium tabular-nums">
            {formatTokens(bar.promptTotal)}
            {bar.promptTotal ? (
              <span className="ml-1 font-normal text-muted-foreground">
                缓存 {formatRatio((usage.cache_read ?? 0) / bar.promptTotal)}
              </span>
            ) : null}
          </dd>
        </dl>
      </div>

      <div>
        <p className="mb-1 text-muted-foreground">耗时</p>
        <dl className="grid grid-cols-[auto_auto] gap-x-4 gap-y-0.5">
          <dt>首事件延迟</dt>
          <dd className="text-right tabular-nums">{formatMillis(bar.firstEventMS)}</dd>
          <dt>生成时长{granularity === "turn" && bar.steps > 1 ? "（合计）" : ""}</dt>
          <dd className="text-right tabular-nums">{formatMillis(bar.generationMS)}</dd>
          <dt>客户端侧时间（工具执行+等待）{granularity === "turn" && bar.steps > 1 ? "（合计）" : ""}</dt>
          <dd className="text-right tabular-nums">{formatMillis(bar.clientGapMS)}</dd>
        </dl>
      </div>

      <p className="flex justify-between">
        <span className="text-muted-foreground">估算成本{granularity === "turn" && bar.steps > 1 ? "（合计）" : ""}</span>
        <span className="tabular-nums">{formatUSD(bar.costUSD)}</span>
      </p>
      {bar.events.length > 0 ? (
        <p className="text-muted-foreground">事件：{bar.events.map(eventLabel).join("、")}</p>
      ) : null}
      <p className="text-[11px] text-muted-foreground">点击柱子查看该请求的审计详情</p>
    </div>
  );
}
