import { useEffect, useMemo, useState, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatTokens } from "../../lib/insights/format";
import { buildBars, type TrendGranularity, type TrendMode } from "../../lib/insights/trend";
import type { TrendResponse } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Button } from "../ui/button";
import { Card, CardContent } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import { CategoryLegend } from "./composition-bar";
import { TrendChart } from "./trend-chart";
import { EmptyNote, EVENT_INFO, PanelTitle, Segmented } from "./ui-bits";

export function TrendPage({
  client,
  sessionID,
  title,
  refreshKey,
  onBack,
  onOpenTree,
  renderAuditDetail,
}: {
  client: ApiClient;
  sessionID: string;
  title: string;
  refreshKey: number;
  onBack: () => void;
  onOpenTree: (treeID: string) => void;
  /** Renders the app's existing audit detail panel for the clicked bar. */
  renderAuditDetail: (auditID: string) => ReactNode;
}) {
  const [trend, setTrend] = useState<TrendResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [granularity, setGranularity] = useState<TrendGranularity>("step");
  const [mode, setMode] = useState<TrendMode>("total");
  const [selectedAuditID, setSelectedAuditID] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    client
      .getSessionTrend(sessionID, controller.signal)
      .then(setTrend)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setTrend(null);
          setError(
            cause instanceof ApiError && cause.status === 404 ? "找不到该会话，或其步骤不在当前身份的可见范围内。" : errorMessage(cause),
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, sessionID, refreshKey]);

  const bars = useMemo(() => buildBars(trend?.steps ?? [], granularity), [trend, granularity]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <Button variant="outline" size="sm" onClick={onBack}>
            ← 返回洞察
          </Button>
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold">会话趋势</h2>
            <p className="truncate font-mono text-xs text-muted-foreground" title={sessionID}>
              {title || sessionID}
            </p>
          </div>
        </div>
        {trend?.tree_id ? (
          <Button variant="outline" size="sm" onClick={() => onOpenTree(trend.tree_id!)}>
            查看 Agent 树
          </Button>
        ) : null}
      </div>

      {error ? (
        <Alert className="border-red-200 bg-red-50/90">
          <AlertTitle className="text-red-900">无法读取会话趋势</AlertTitle>
          <AlertDescription className="text-red-800">{error}</AlertDescription>
        </Alert>
      ) : null}

      {loading ? <Skeleton className="h-80 w-full" /> : null}

      {trend && !loading ? (
        <Card className="bg-white/90 shadow-xs">
          <CardContent className="space-y-4 p-4 pt-4">
            <PanelTitle
              title="上下文构成趋势"
              hint={
                trend.context_window
                  ? `共 ${trend.steps.length} 步 · 上下文窗口 ${formatTokens(trend.context_window)}`
                  : `共 ${trend.steps.length} 步 · 窗口未知`
              }
              actions={
                <div className="flex flex-wrap items-center gap-2">
                  <Segmented
                    label="粒度"
                    value={granularity}
                    options={[
                      { value: "step", label: "步骤" },
                      { value: "turn", label: "轮次" },
                    ]}
                    onChange={setGranularity}
                  />
                  <Segmented
                    label="数值"
                    value={mode}
                    options={[
                      { value: "total", label: "总量" },
                      { value: "delta", label: "增量" },
                    ]}
                    onChange={setMode}
                  />
                </div>
              }
            />
            {trend.truncated ? (
              <Alert className="border-amber-200 bg-amber-50/80">
                <AlertDescription className="text-amber-900">更早步骤已截断，仅显示最近的步骤。</AlertDescription>
              </Alert>
            ) : null}
            {bars.length === 0 ? (
              <EmptyNote>该会话还没有可展示的步骤。</EmptyNote>
            ) : (
              <>
                <TrendChart
                  bars={bars}
                  mode={mode}
                  granularity={granularity}
                  contextWindow={trend.context_window}
                  selectedAuditID={selectedAuditID}
                  truncated={trend.truncated}
                  onSelectBar={setSelectedAuditID}
                />
                <CategoryLegend />
                <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-label="事件图例">
                  {Object.entries(EVENT_INFO).map(([key, info]) => (
                    <li key={key} className="inline-flex items-center gap-1.5">
                      <span
                        className="grid h-4 w-4 place-items-center rounded-full text-[9px] text-white"
                        style={{ backgroundColor: info.color }}
                        aria-hidden="true"
                      >
                        {info.glyph}
                      </span>
                      {info.label}
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-muted-foreground">
                  {mode === "delta"
                    ? "增量：每类相对上一柱的有符号变化，增加向上堆叠、减少向下堆叠；提示中给出净变化。"
                    : "总量：估算值按该请求上游报告的 prompt 总量锚定；没有 usage 时显示原始估算。"}
                  {granularity === "turn" ? " 轮次视图取每轮最后一步的快照，耗时与成本为合计。" : ""}
                </p>
              </>
            )}
          </CardContent>
        </Card>
      ) : null}

      {selectedAuditID ? (
        <section className="space-y-2" aria-label="审计详情">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">所选请求的审计详情</h3>
            <Button variant="ghost" size="sm" onClick={() => setSelectedAuditID(null)}>
              关闭
            </Button>
          </div>
          {renderAuditDetail(selectedAuditID)}
        </section>
      ) : null}
    </div>
  );
}
