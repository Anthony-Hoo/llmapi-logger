import { useEffect, useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatUSD } from "../../lib/insights/format";
import { FRICTION_LABELS, labelOf, OUTCOME_LABELS, TASK_TYPE_LABELS } from "../../lib/session-analysis/format";
import type { AnalysisReport, AnalysisSuggestion, AnalysisWeeklyStats } from "../../lib/session-analysis/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Segmented } from "../ui/segmented";
import { Skeleton } from "../ui/skeleton";
import { clientLabel } from "../insights/ui-bits";

const STATUS_LABELS: Record<AnalysisSuggestion["status"], string> = {
  open: "待处理",
  adopted_detected: "已沉淀",
  dismissed: "已忽略",
};

function weekLabel(ns: string): string {
  const start = new Date(Number(BigInt(ns) / 1_000_000n));
  const end = new Date(start.getTime() + 6 * 86_400_000);
  const day = (date: Date) => `${date.getMonth() + 1}/${date.getDate()}`;
  return `${day(start)}–${day(end)}`;
}

/** Signed difference against the previous week, or null without one. */
export function weekDelta(current: number, previous: number | undefined): string | null {
  if (previous === undefined) {
    return null;
  }
  const difference = current - previous;
  if (difference === 0) {
    return "持平";
  }
  return difference > 0 ? `+${difference}` : `${difference}`;
}

function CountList({ title, counts, labels }: { title: string; counts: Record<string, number>; labels: Record<string, string> }) {
  const entries = Object.entries(counts).sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
  return (
    <div>
      <div className="text-label text-muted">{title}</div>
      {entries.length === 0 ? (
        <div className="text-body-sm text-subtle">暂无</div>
      ) : (
        <ul className="text-body-sm">
          {entries.slice(0, 6).map(([key, count]) => (
            <li key={key} className="flex justify-between gap-4">
              <span>{labelOf(labels, key)}</span>
              <span className="tabular-nums">{count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function WeeklyStatsView({ stats, previous }: { stats: AnalysisWeeklyStats; previous: AnalysisWeeklyStats | null }) {
  const rows: Array<[string, number, number | undefined]> = [
    ["会话", stats.totals.sessions, previous?.totals.sessions],
    ["已分析（facet）", stats.facets_ok, previous?.facets_ok],
    ["死循环会话", stats.totals.loop_sessions, previous?.totals.loop_sessions],
    ["反复编辑会话", stats.totals.thrash_sessions, previous?.totals.thrash_sessions],
    ["结束前未验证", stats.totals.unverified_sessions, previous?.totals.unverified_sessions],
    ["有纠正的会话", stats.totals.correction_sessions, previous?.totals.correction_sessions],
    ["报错回贴会话", stats.totals.error_paste_sessions, previous?.totals.error_paste_sessions],
  ];
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
      <div>
        <div className="text-label text-muted">确定性信号（较上周）</div>
        <ul className="text-body-sm">
          {rows.map(([label, value, prior]) => {
            const delta = weekDelta(value, prior);
            return (
              <li key={label} className="flex justify-between gap-4">
                <span>{label}</span>
                <span className="tabular-nums">
                  {value}
                  {delta ? <span className="ml-1 text-subtle">({delta})</span> : null}
                </span>
              </li>
            );
          })}
          <li className="flex justify-between gap-4">
            <span>费用</span>
            <span className="tabular-nums">{formatUSD(stats.totals.cost_usd)}</span>
          </li>
        </ul>
      </div>
      <CountList title="任务类型" counts={stats.task_types} labels={TASK_TYPE_LABELS} />
      <CountList title="结果" counts={stats.outcomes} labels={OUTCOME_LABELS} />
      <CountList title="摩擦" counts={stats.friction} labels={FRICTION_LABELS} />
    </div>
  );
}

export function SuggestionList({
  suggestions,
  canDismiss,
  onDismiss,
}: {
  suggestions: AnalysisSuggestion[];
  canDismiss: boolean;
  onDismiss: (id: number) => void;
}) {
  if (suggestions.length === 0) {
    return <p className="text-body-sm text-subtle">还没有在两个以上会话里重复出现的指令或请求。</p>;
  }
  return (
    <ul className="space-y-2">
      {suggestions.map((item) => (
        <li key={item.id} className="flex flex-wrap items-start justify-between gap-2 rounded-md border p-2">
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-1">
              <Badge variant={item.strong ? "warning" : "outline"}>{item.strong ? "强候选" : "候选"}</Badge>
              <Badge variant="neutral">{item.kind === "skill" ? "skill" : "AGENTS.md 指令"}</Badge>
              <Badge variant={item.status === "open" ? "info" : "neutral"}>{STATUS_LABELS[item.status]}</Badge>
              <span className="text-label text-subtle">{item.sessions} 个会话</span>
            </div>
            <p className="break-words text-body-sm">{item.text}</p>
            {item.evidence.length > 0 ? <p className="font-mono text-label text-subtle">证据：{item.evidence.join("，")}</p> : null}
          </div>
          {canDismiss && item.status === "open" ? (
            <Button variant="ghost" size="sm" onClick={() => onDismiss(item.id)}>
              忽略
            </Button>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

export function ReportView({ client, isDeveloper, refreshKey }: { client: ApiClient; isDeveloper: boolean; refreshKey: number }) {
  const [week, setWeek] = useState<"current" | "previous">("current");
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    client
      .getAnalysisReport(week, controller.signal)
      .then(setReport)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setReport(null);
          setError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [client, week, refreshKey, nonce]);

  async function dismiss(id: number) {
    try {
      await client.dismissAnalysisSuggestion(id);
      setNonce((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  return (
    <div className="space-y-section">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-body-sm text-muted">
          {isDeveloper ? "只包含你这把 Key 的会话，仅你本人可见。" : "全体 Key 的汇总，不按人拆分。"}
          {report ? ` 周期 ${weekLabel(report.week_start_ns)}。` : ""}
        </p>
        <Segmented
          label="周期"
          value={week}
          options={[
            { value: "current", label: "本周" },
            { value: "previous", label: "上周" },
          ]}
          onChange={setWeek}
        />
      </div>
      {error ? (
        <Alert variant="danger">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {!report && !error ? <Skeleton className="h-48 w-full" /> : null}
      {report ? <ReportBody report={report} canDismiss={!isDeveloper && report.scope === "all"} onDismiss={(id) => void dismiss(id)} /> : null}
    </div>
  );
}

export function ReportBody({ report, canDismiss, onDismiss }: { report: AnalysisReport; canDismiss: boolean; onDismiss: (id: number) => void }) {
  return (
    <>
      <Card>
        <CardContent className="space-y-2 pt-card">
          <div className="flex items-center gap-2">
            <h3 className="text-body font-semibold">周度复盘</h3>
            {report.narrative_source ? <Badge variant="neutral">{report.narrative_source === "model" ? "本地模型撰写" : "模板生成"}</Badge> : null}
          </div>
          {report.narrative ? (
            <div className="space-y-1 whitespace-pre-wrap text-body-sm">{report.narrative}</div>
          ) : (
            <p className="text-body-sm text-subtle">本周还没有生成复盘，下一次批处理后出现。</p>
          )}
        </CardContent>
      </Card>
      {report.stats ? (
        <Card>
          <CardContent className="pt-card">
            <WeeklyStatsView stats={report.stats} previous={report.previous} />
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardContent className="space-y-2 pt-card">
          <h3 className="text-body font-semibold">可沉淀的指令与 skill</h3>
          <p className="text-label text-subtle">同一句话在 2 个会话出现为候选，3 个以上为强候选；之后的会话注入的 AGENTS.md / CLAUDE.md 里出现了同一句，会自动标为已沉淀。</p>
          <SuggestionList suggestions={report.suggestions} canDismiss={canDismiss} onDismiss={onDismiss} />
        </CardContent>
      </Card>
      {report.optimizations.length > 0 ? (
        <Card>
          <CardContent className="space-y-2 pt-card">
            <h3 className="text-body font-semibold">成本最高的问题会话</h3>
            <ul className="text-body-sm">
              {report.optimizations.map((item) => (
                <li key={item.session_id} className="flex flex-wrap justify-between gap-2">
                  <span>
                    {clientLabel(item.client || "unknown")} · {item.model || "—"} · {item.user_turns} 轮
                    {item.loops > 0 ? " · 死循环" : ""}
                    {item.thrash_files > 0 ? " · 反复编辑" : ""}
                    {item.verified === "no" ? " · 未验证" : ""}
                  </span>
                  <span className="tabular-nums">{formatUSD(item.cost_usd)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </>
  );
}
