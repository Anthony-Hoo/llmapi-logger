import { Fragment, useEffect, useMemo, useState, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatRatio, formatTokens, formatUSD } from "../../lib/insights/format";
import { msToNSString } from "../../lib/insights/range";
import {
  DANGER_LABELS,
  FLAG_OPTIONS,
  formatDuration,
  formatPointDelta,
  labelOf,
  sessionBadges,
  signalRates,
  SKIP_REASON_LABELS,
  projectLabel,
  startOfLocalWeekMS,
  TASK_TYPE_LABELS,
} from "../../lib/session-analysis/format";
import type {
  AnalysisFlag,
  AnalysisOverview,
  AnalysisSessionItem,
} from "../../lib/session-analysis/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { PageHeader } from "../ui/page-header";
import { Segmented } from "../ui/segmented";
import { Skeleton } from "../ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { clientLabel } from "../insights/ui-bits";
import { CalibrationPanel, CalibrationSummary, FacetPanel } from "./facet-panel";
import { PackPanel } from "./pack-panel";
import { ReportView } from "./report-view";

type RangeKey = "week" | "last-week" | "30d";

const RANGES: ReadonlyArray<{ value: RangeKey; label: string }> = [
  { value: "week", label: "本周" },
  { value: "last-week", label: "上周" },
  { value: "30d", label: "近 30 天" },
];

const DAY_MS = 86_400_000;

export function analysisRange(key: RangeKey, nowMS: number): { from_ns: string; to_ns: string } {
  const weekStart = startOfLocalWeekMS(nowMS);
  switch (key) {
    case "last-week":
      return { from_ns: msToNSString(weekStart - 7 * DAY_MS), to_ns: msToNSString(weekStart) };
    case "30d":
      return { from_ns: msToNSString(nowMS - 30 * DAY_MS), to_ns: msToNSString(nowMS + 60_000) };
    default:
      return { from_ns: msToNSString(weekStart), to_ns: msToNSString(Math.max(nowMS + 60_000, weekStart + 7 * DAY_MS)) };
  }
}

const DESCRIPTION =
  "每天按计划从已审计的会话中计算确定性信号；启用本地模型后再生成会话摘要和周度复盘。管理端只显示匿名会话；开发者只看到自己 Key 的会话。结论只是线索，不用于个人评价。";

function formatNS(value: string): string {
  const ms = Number(BigInt(value) / 1_000_000n);
  return new Date(ms).toLocaleString("zh-CN", { hour12: false });
}

export function SessionAnalysisView({
  client,
  isDeveloper,
  refreshKey,
  renderSessionDetail,
}: {
  client: ApiClient;
  isDeveloper: boolean;
  refreshKey: number;
  /** Extra detail below an expanded session row (input pack, facet). */
  renderSessionDetail?: (item: AnalysisSessionItem) => ReactNode;
}) {
  const [page, setPage] = useState<"signals" | "report">("signals");
  const [rangeKey, setRangeKey] = useState<RangeKey>("week");
  const [kind, setKind] = useState<"all" | "agent" | "chat">("all");
  const [flags, setFlags] = useState<AnalysisFlag[]>([]);
  const [runNonce, setRunNonce] = useState(0);
  const range = useMemo(() => analysisRange(rangeKey, Date.now()), [rangeKey, refreshKey, runNonce]);

  const [overview, setOverview] = useState<AnalysisOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [items, setItems] = useState<AnalysisSessionItem[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [runMessage, setRunMessage] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setOverviewError(null);
    client
      .getAnalysisOverview(range, controller.signal)
      .then(setOverview)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setOverview(null);
          setOverviewError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [client, range]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setListError(null);
    client
      .listAnalysisSessions({ ...range, kind: kind === "all" ? undefined : kind, flags, limit: 50 }, controller.signal)
      .then((page) => {
        setItems(page.items);
        setNextCursor(page.next_cursor || null);
      })
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setItems([]);
          setNextCursor(null);
          setListError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, range, kind, flags]);

  async function loadMore() {
    if (!nextCursor) {
      return;
    }
    try {
      const page = await client.listAnalysisSessions({ ...range, kind: kind === "all" ? undefined : kind, flags, limit: 50, cursor: nextCursor });
      setItems((current) => [...current, ...page.items]);
      setNextCursor(page.next_cursor || null);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setListError(errorMessage(cause));
      }
    }
  }

  async function runNow() {
    setRunMessage(null);
    try {
      await client.triggerAnalysisRun();
      setRunMessage("已开始运行，完成后刷新即可看到新结果。");
    } catch (cause: unknown) {
      if (cause instanceof ApiError && cause.status === 409) {
        setRunMessage("已有一轮分析正在运行。");
      } else if (!(cause instanceof ApiError && cause.status === 401)) {
        setRunMessage(errorMessage(cause));
      }
    }
    setRunNonce((value) => value + 1);
  }

  function toggleFlag(flag: AnalysisFlag) {
    setFlags((current) => (current.includes(flag) ? current.filter((value) => value !== flag) : [...current, flag]));
  }

  return (
    <div className="space-y-section">
      <PageHeader
        title="会话分析"
        description={DESCRIPTION}
        actions={
          <>
            <Segmented
              label="视图"
              value={page}
              options={[
                { value: "signals", label: "会话信号" },
                { value: "report", label: "周度复盘" },
              ]}
              onChange={setPage}
            />
            {page === "signals" ? <Segmented label="时间范围" value={rangeKey} options={RANGES} onChange={setRangeKey} /> : null}
            {isDeveloper ? null : (
              <Button variant="outline" size="sm" onClick={() => void runNow()} disabled={overview?.running}>
                {overview?.running ? "运行中…" : "立即运行"}
              </Button>
            )}
          </>
        }
      />
      {page === "report" ? <ReportView client={client} isDeveloper={isDeveloper} refreshKey={refreshKey + runNonce} /> : null}
      <div className={page === "report" ? "hidden" : "space-y-section"}>
      {runMessage ? (
        <Alert variant="info">
          <AlertDescription>{runMessage}</AlertDescription>
        </Alert>
      ) : null}
      {overviewError ? (
        <Alert variant="danger">
          <AlertDescription>{overviewError}</AlertDescription>
        </Alert>
      ) : null}
      {overview ? <OverviewCards overview={overview} /> : overviewError ? null : <Skeleton className="h-32 w-full" />}
      {overview?.llm_enabled && !isDeveloper ? (
        <Card>
          <CardContent className="pt-card">
            <CalibrationPanel client={client} onDone={() => setRunNonce((value) => value + 1)} />
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardContent className="space-y-3 pt-card">
          <div className="flex flex-wrap items-center gap-2">
            <Segmented
              label="会话类型"
              value={kind}
              options={[
                { value: "all", label: "全部" },
                { value: "agent", label: "Agent" },
                { value: "chat", label: "聊天" },
              ]}
              onChange={setKind}
            />
            {FLAG_OPTIONS.map((option) => (
              <button
                key={option.value}
                type="button"
                title={option.hint}
                aria-pressed={flags.includes(option.value)}
                onClick={() => toggleFlag(option.value)}
                className={
                  "rounded-sm border px-2 py-0.5 text-label transition-colors " +
                  (flags.includes(option.value) ? "border-primary bg-primary text-primary-foreground" : "border-border text-muted hover:text-foreground")
                }
              >
                {option.label}
              </button>
            ))}
          </div>
          {listError ? (
            <Alert variant="danger">
              <AlertDescription>{listError}</AlertDescription>
            </Alert>
          ) : null}
          {loading ? (
            <Skeleton className="h-40 w-full" />
          ) : items.length === 0 ? (
            <p className="py-6 text-center text-body-sm text-muted">这个时间范围内没有符合条件的会话。</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>最后活动</TableHead>
                  <TableHead>客户端 / 模型</TableHead>
                  <TableHead className="text-right">轮次</TableHead>
                  <TableHead className="text-right">活跃</TableHead>
                  <TableHead className="text-right">工具调用</TableHead>
                  <TableHead className="text-right">费用</TableHead>
                  <TableHead>信号</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <Fragment key={item.session_id}>
                    <TableRow
                      className="cursor-pointer"
                      aria-expanded={expanded === item.session_id}
                      onClick={() => setExpanded((current) => (current === item.session_id ? null : item.session_id))}
                    >
                      <TableCell className="whitespace-nowrap">{formatNS(item.last_ns)}</TableCell>
                      <TableCell>
                        <div>{clientLabel(item.client || "unknown")}</div>
                        <div className="text-label text-subtle">{item.model || "—"}</div>
                        {projectLabel(item) ? <div className="text-label text-subtle">{projectLabel(item)}</div> : null}
                      </TableCell>
                      <TableCell className="text-right">{item.user_turns}</TableCell>
                      <TableCell className="text-right">{formatDuration(item.active_seconds)}</TableCell>
                      <TableCell className="text-right">{item.tool_calls}</TableCell>
                      <TableCell className="text-right">{formatUSD(item.cost_usd)}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {item.facet_status === "ok" && item.task_type ? <Badge variant="outline">{labelOf(TASK_TYPE_LABELS, item.task_type)}</Badge> : null}
                          {sessionBadges(item).map((badge) => (
                            <Badge key={badge.label} variant={badge.tone}>
                              {badge.label}
                            </Badge>
                          ))}
                          {!item.eligible && item.skip_reason ? <Badge variant="outline">{SKIP_REASON_LABELS[item.skip_reason] ?? item.skip_reason}</Badge> : null}
                        </div>
                      </TableCell>
                    </TableRow>
                    {expanded === item.session_id ? (
                      <TableRow>
                        <TableCell colSpan={7} className="bg-surface-sunken">
                          <SessionDetails item={item} />
                          {item.eligible || item.skip_reason === "single_turn_chat" ? (
                            <PackPanel client={client} sessionID={item.session_id} isDeveloper={isDeveloper} />
                          ) : null}
                          {overview?.llm_enabled && (item.eligible || item.skip_reason === "single_turn_chat") ? (
                            <FacetPanel client={client} sessionID={item.session_id} />
                          ) : null}
                          {renderSessionDetail ? renderSessionDetail(item) : null}
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          )}
          {nextCursor ? (
            <div className="flex justify-center">
              <Button variant="outline" size="sm" onClick={() => void loadMore()}>
                加载更多
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>
      </div>
    </div>
  );
}

export function Tile({ label, value, delta, hint }: { label: string; value: string; delta?: string | null; hint?: string }) {
  return (
    <div className="rounded-md border bg-surface p-3" title={hint}>
      <div className="text-label text-muted">{label}</div>
      <div className="text-title font-semibold">{value}</div>
      {delta ? <div className="text-label text-subtle">较上期 {delta}</div> : null}
    </div>
  );
}

export function OverviewCards({ overview }: { overview: AnalysisOverview }) {
  const current = signalRates(overview.current);
  const previous = signalRates(overview.previous);
  const run = overview.last_run;
  return (
    <Card>
      <CardContent className="space-y-3 pt-card">
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-8">
          <Tile label="会话" value={`${overview.current.sessions}`} hint={`Agent ${overview.current.agent_sessions} · 聊天 ${overview.current.chat_sessions}`} />
          <Tile label="费用" value={formatUSD(overview.current.cost_usd)} />
          <Tile label="死循环" value={formatRatio(current.loop)} delta={formatPointDelta(current.loop, previous.loop)} hint="占 Agent 会话" />
          <Tile label="反复编辑" value={formatRatio(current.thrash)} delta={formatPointDelta(current.thrash, previous.thrash)} hint="占 Agent 会话" />
          <Tile label="结束前未验证" value={formatRatio(current.unverified)} delta={formatPointDelta(current.unverified, previous.unverified)} hint="占有写文件的会话" />
          <Tile label="有纠正的会话" value={formatRatio(current.corrections)} delta={formatPointDelta(current.corrections, previous.corrections)} />
          <Tile label="报错回贴" value={formatRatio(current.errorPaste)} delta={formatPointDelta(current.errorPaste, previous.errorPaste)} />
          <Tile label="缓存命中" value={formatRatio(overview.current.cache_hit_rate)} delta={formatPointDelta(overview.current.cache_hit_rate, overview.previous.cache_hit_rate)} />
        </div>
        <p className="text-label text-subtle">
          {run
            ? `最近一次运行：${formatNS(run.finished_ns)}（${run.trigger === "manual" ? "手动" : "计划"}），候选 ${run.candidates}、完成 ${run.analyzed}、失败 ${run.skipped}` +
              (Object.keys(run.skip_reasons).length > 0
                ? `；未打包：${Object.entries(run.skip_reasons)
                    .map(([reason, count]) => `${SKIP_REASON_LABELS[reason] ?? reason} ${count}`)
                    .join("、")}`
                : "") +
              "。"
            : "还没有运行记录。"}
          {overview.llm_enabled
            ? ` 本地模型 ${overview.model ?? ""}（${overview.prompt_version}）` +
              (run ? `：本轮待分析 ${run.facets_due}、成功 ${run.facets_ok}、输出无效 ${run.facets_invalid}、失败 ${run.facets_failed}，输入 ${formatTokens(run.model_input_tokens)} / 输出 ${formatTokens(run.model_output_tokens)} Token。` : "。")
            : " 未启用本地模型，只计算确定性信号和输入包。"}
          {overview.current.danger_sessions + overview.current.secret_sessions > 0
            ? ` 本期有 ${overview.current.danger_sessions} 个会话出现危险命令、${overview.current.secret_sessions} 个出现疑似密钥。`
            : ""}
        </p>
        {overview.calibration ? <CalibrationSummary calibration={overview.calibration} /> : null}
      </CardContent>
    </Card>
  );
}

export function SessionDetails({ item }: { item: AnalysisSessionItem }) {
  const rows: Array<[string, string]> = [
    ["类型", item.kind === "agent" ? "Agent 会话" : "聊天"],
    ["开始", formatNS(item.first_ns)],
    ["请求 / 子 Agent", `${item.requests} / ${item.subagents}`],
    ["Token（输入 / 输出）", `${formatTokens(item.input_tokens)} / ${formatTokens(item.output_tokens)}`],
    ["工具失败（最长连续）", `${item.tool_failures}（${item.max_failure_streak}）`],
    ["结束前验证", item.verified === "yes" ? "是" : item.verified === "no" ? "否" : "没有写文件"],
    ["上下文压缩 / 模型切换", `${item.compactions} / ${item.model_switches}`],
    ["长度截断 / 上游错误", `${item.length_stops} / ${item.upstream_errors}`],
    ["危险命令", Object.entries(item.danger).map(([key, count]) => `${DANGER_LABELS[key] ?? key} ${count}`).join("、") || "无"],
    ["疑似密钥（类别）", Object.entries(item.secrets).map(([key, count]) => `${key} ${count}`).join("、") || "无"],
    ["最后一条审计", item.last_audit_id],
  ];
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-body-sm sm:grid-cols-2">
      {rows.map(([label, value]) => (
        <div key={label} className="flex gap-2">
          <dt className="w-40 shrink-0 text-muted">{label}</dt>
          <dd className="break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
