import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatRatio, formatTokens, formatUSD } from "../../lib/insights/format";
import { createGeneration } from "../../lib/insights/generation";
import {
  dayRange,
  localDayString,
  localOffsetMinutes,
  RANGE_OPTIONS,
  rangeForDays,
  type RangeKey,
} from "../../lib/insights/range";
import type {
  GroupUsage,
  InsightsGroupBy,
  InsightsSessionSort,
  OverviewResponse,
  SessionCard,
  UsageTotals,
} from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { PageHeader } from "../ui/page-header";
import { Select } from "../ui/select";
import { Skeleton } from "../ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { CategoryLegend, CompositionBar } from "./composition-bar";
import { DailyChart } from "./daily-chart";
import { ActivityHeatmap } from "./heatmap";
import { SessionCardView } from "./session-card";
import { EmptyNote, PanelTitle, Segmented } from "./ui-bits";

const ALL_GROUPS: ReadonlyArray<{ value: InsightsGroupBy; label: string; adminOnly: boolean }> = [
  { value: "model", label: "按模型", adminOnly: false },
  { value: "protocol", label: "按协议", adminOnly: false },
  { value: "client", label: "按客户端", adminOnly: false },
  { value: "caller", label: "按调用者", adminOnly: true },
  { value: "token", label: "按 Token", adminOnly: true },
];

const SESSION_SORTS: ReadonlyArray<{ value: InsightsSessionSort; label: string }> = [
  { value: "recent", label: "最近活动" },
  { value: "tokens", label: "Token 用量" },
  { value: "context", label: "上下文占用" },
];

export function groupOptions(isDeveloper: boolean) {
  return ALL_GROUPS.filter((option) => !(isDeveloper && option.adminOnly));
}

export function OverviewPage({
  client,
  isDeveloper,
  refreshKey,
  onOpenSession,
  onOpenTree,
}: {
  client: ApiClient;
  isDeveloper: boolean;
  refreshKey: number;
  onOpenSession: (card: SessionCard) => void;
  onOpenTree: (treeID: string) => void;
}) {
  const [rangeKey, setRangeKey] = useState<RangeKey>("7d");
  const [groupBy, setGroupBy] = useState<InsightsGroupBy>("model");
  const [sort, setSort] = useState<InsightsSessionSort>("recent");
  const [selectedDay, setSelectedDay] = useState<string | null>(null);

  const offsetMin = useMemo(() => localOffsetMinutes(), []);
  const days = RANGE_OPTIONS.find((option) => option.key === rangeKey)?.days ?? 7;
  // `refreshKey` is part of the dependencies so a manual refresh moves "now".
  const range = useMemo(() => rangeForDays(days, Date.now(), offsetMin), [days, offsetMin, refreshKey]);
  const today = useMemo(() => localDayString(Date.now(), offsetMin), [offsetMin, refreshKey]);

  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewError, setOverviewError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setOverviewLoading(true);
    setOverviewError(null);
    client
      .getInsightsOverview({ ...range, tz_offset_min: offsetMin, group_by: groupBy }, controller.signal)
      .then(setOverview)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setOverview(null);
          setOverviewError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setOverviewLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, range, offsetMin, groupBy]);

  const sessionRange = useMemo(
    () => (selectedDay ? dayRange(selectedDay, offsetMin) ?? range : range),
    [selectedDay, offsetMin, range],
  );
  const [cards, setCards] = useState<SessionCard[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [cardsLoading, setCardsLoading] = useState(true);
  const [moreLoading, setMoreLoading] = useState(false);
  const [cardsError, setCardsError] = useState<string | null>(null);

  // Advanced whenever the first page is reloaded (day filter, sort or range
  // change), so a "加载更多" response of an older list is discarded.
  const listGeneration = useRef(createGeneration());

  useEffect(() => {
    const controller = new AbortController();
    listGeneration.current.advance();
    setMoreLoading(false);
    setCardsLoading(true);
    setCardsError(null);
    client
      .listInsightsSessions({ ...sessionRange, sort, limit: 20 }, controller.signal)
      .then((page) => {
        setCards(page.items);
        setNextCursor(page.next_cursor || null);
      })
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setCards([]);
          setNextCursor(null);
          setCardsError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setCardsLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, sessionRange, sort]);

  async function loadMore() {
    if (!nextCursor || moreLoading) {
      return;
    }
    const generation = listGeneration.current.current();
    setMoreLoading(true);
    try {
      const page = await client.listInsightsSessions({ ...sessionRange, sort, limit: 20, cursor: nextCursor });
      if (!listGeneration.current.isCurrent(generation)) {
        return;
      }
      setCards((current) => [...current, ...page.items]);
      setNextCursor(page.next_cursor || null);
    } catch (cause: unknown) {
      if (listGeneration.current.isCurrent(generation) && !(cause instanceof ApiError && cause.status === 401)) {
        setCardsError(errorMessage(cause));
      }
    } finally {
      if (listGeneration.current.isCurrent(generation)) {
        setMoreLoading(false);
      }
    }
  }

  const groups = groupOptions(isDeveloper);

  return (
    <div className="space-y-section">
      <PageHeader
        title="用量洞察"
        description="成本为按内置价格快照的估算，不含 NewAPI 的实际计费倍率。"
        actions={
          <>
            <Segmented
              label="时间范围"
              value={rangeKey}
              options={RANGE_OPTIONS.map((option) => ({
                value: option.key,
                label: option.label,
                title: option.key === "all" ? "最多 400 天" : undefined,
              }))}
              onChange={(value) => {
                setRangeKey(value);
                setSelectedDay(null);
              }}
            />
            <label className="flex items-center gap-2 text-label text-muted">
              分组
              <Select
                aria-label="分组方式"
                className="w-auto"
                value={groupBy}
                onChange={(event) => setGroupBy(event.target.value as InsightsGroupBy)}
              >
                {groups.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </Select>
            </label>
          </>
        }
      />

      {overviewError ? (
        <Alert variant="danger">
          <AlertTitle>无法读取用量洞察</AlertTitle>
          <AlertDescription>{overviewError}</AlertDescription>
        </Alert>
      ) : null}

      {overviewLoading && !overview ? <OverviewSkeleton /> : null}

      {overview ? (
        <>
          <KpiBar overview={overview} />

          <Card>
            <CardContent className="space-y-stack pt-card">
              <PanelTitle title="每日用量" hint="每天一对柱：Token 与估算成本" />
              <DailyChart daily={overview.daily} />
            </CardContent>
          </Card>

          <div className="grid gap-section lg:grid-cols-2">
            <Card>
              <CardContent className="space-y-stack pt-card">
                <PanelTitle title="近 8 周活动" hint="颜色按当前最忙一天的四分位分级" />
                <ActivityHeatmap days={overview.heatmap} today={today} selectedDay={selectedDay} onSelectDay={setSelectedDay} />
              </CardContent>
            </Card>
            <Card>
              <CardContent className="space-y-stack pt-card">
                <PanelTitle title="上下文构成" hint="范围内各请求的估算，已按 prompt 总量锚定" />
                <MixPanel mix={overview.composition} />
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardContent className="space-y-stack pt-card">
              <PanelTitle title="分组统计" />
              <GroupTable groups={overview.groups} />
            </CardContent>
          </Card>
        </>
      ) : null}

      <section className="space-y-stack" aria-label="会话">
        <PanelTitle
          title="会话"
          hint={selectedDay ? undefined : "每个 Agent 一张卡片，点击查看逐步趋势"}
          actions={
            <div className="flex flex-wrap items-center gap-2">
              {selectedDay ? (
                <Button variant="outline" size="sm" onClick={() => setSelectedDay(null)}>
                  仅 {selectedDay} · 清除
                </Button>
              ) : null}
              <label className="flex items-center gap-2 text-label text-muted">
                排序
                <Select
                  aria-label="会话排序"
                  className="w-auto"
                  value={sort}
                  onChange={(event) => setSort(event.target.value as InsightsSessionSort)}
                >
                  {SESSION_SORTS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
          }
        />
        {cardsError ? (
          <Alert variant="danger">
            <AlertDescription>{cardsError}</AlertDescription>
          </Alert>
        ) : null}
        {cardsLoading ? (
          <div className="grid gap-section md:grid-cols-2 2xl:grid-cols-3">
            {Array.from({ length: 3 }, (_, index) => (
              <Skeleton key={index} className="h-40 w-full" />
            ))}
          </div>
        ) : cards.length === 0 && !cardsError ? (
          <EmptyNote>所选范围内没有已分析的会话。新请求解析完成后会出现在这里。</EmptyNote>
        ) : (
          <div className="grid gap-section md:grid-cols-2 2xl:grid-cols-3">
            {cards.map((card) => (
              <SessionCardView key={card.session_id} card={card} onOpenSession={onOpenSession} onOpenTree={onOpenTree} />
            ))}
          </div>
        )}
        {nextCursor && !cardsLoading ? (
          <div className="flex justify-center">
            <Button variant="outline" size="sm" disabled={moreLoading} onClick={() => void loadMore()}>
              {moreLoading ? "加载中…" : "加载更多"}
            </Button>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-section">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        {Array.from({ length: 7 }, (_, index) => (
          <Skeleton key={index} className="h-20 w-full" />
        ))}
      </div>
      <Skeleton className="h-64 w-full" />
    </div>
  );
}

export function KpiBar({ overview }: { overview: OverviewResponse }) {
  const totals = overview.totals;
  const partial = totals.unpriced_requests > 0;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7" aria-label="关键指标">
      <Kpi label="请求数" value={totals.requests.toLocaleString("zh-CN")} />
      <Kpi label="会话数" value={overview.sessions.toLocaleString("zh-CN")} />
      <Kpi label="Agent 树数" value={overview.trees.toLocaleString("zh-CN")} />
      <Kpi label="prompt 总量" value={formatTokens(totals.prompt_total)} hint={`缓存读 ${formatTokens(totals.cache_read)}`} />
      <Kpi label="输出" value={formatTokens(totals.output)} hint={`含推理 ${formatTokens(totals.reasoning)}`} />
      <Kpi label="缓存命中率" value={formatRatio(totals.cache_hit_rate)} />
      <Kpi
        label="估算成本"
        value={formatUSD(totals.estimated_cost_usd)}
        hint={partial ? `部分模型未知价格（${totals.unpriced_requests} 次请求未计价）` : "估算，非实际账单"}
        warn={partial}
      />
    </div>
  );
}

function Kpi({ label, value, hint, warn }: { label: string; value: string; hint?: string; warn?: boolean }) {
  return (
    <div className="min-w-0 rounded-lg border bg-surface p-3 shadow-card">
      <p className="text-label text-muted">{label}</p>
      <p className="mt-1 truncate text-heading font-semibold tabular-nums">{value}</p>
      {hint ? <p className={`mt-0.5 text-caption ${warn ? "text-warning-fg" : "text-subtle"}`}>{hint}</p> : null}
    </div>
  );
}

function MixPanel({ mix }: { mix: OverviewResponse["composition"] }) {
  const sum = Object.values(mix ?? {}).reduce((total, value) => total + (typeof value === "number" ? value : 0), 0);
  if (sum <= 0) {
    return <EmptyNote>所选范围内没有构成估算。</EmptyNote>;
  }
  return (
    <div className="space-y-3">
      <CompositionBar values={mix} height={18} label="范围内上下文构成" />
      <CategoryLegend values={mix} />
    </div>
  );
}

export function GroupTable({ groups }: { groups: readonly GroupUsage[] }) {
  if (groups.length === 0) {
    return <EmptyNote>没有可分组的数据。</EmptyNote>;
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>名称</TableHead>
            <TableHead className="text-right">请求数</TableHead>
            <TableHead className="text-right">prompt</TableHead>
            <TableHead className="text-right">输出</TableHead>
            <TableHead className="text-right">缓存命中率</TableHead>
            <TableHead className="text-right">估算成本</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {groups.map((group) => (
            <TableRow key={group.key}>
              <TableCell className="max-w-72 truncate font-medium" title={group.label || group.key}>
                {group.label || group.key || "（空）"}
              </TableCell>
              <GroupNumbers usage={group.usage} />
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function GroupNumbers({ usage }: { usage: UsageTotals }): ReactNode {
  return (
    <>
      <TableCell className="text-right tabular-nums">{usage.requests.toLocaleString("zh-CN")}</TableCell>
      <TableCell className="text-right tabular-nums">{formatTokens(usage.prompt_total)}</TableCell>
      <TableCell className="text-right tabular-nums">{formatTokens(usage.output)}</TableCell>
      <TableCell className="text-right tabular-nums">{formatRatio(usage.cache_hit_rate)}</TableCell>
      <TableCell className="text-right tabular-nums">
        {formatUSD(usage.estimated_cost_usd)}
        {usage.unpriced_requests > 0 ? <span className="ml-1 text-label text-warning-fg">部分未知价格</span> : null}
      </TableCell>
    </>
  );
}
