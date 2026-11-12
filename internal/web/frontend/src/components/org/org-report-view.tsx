import { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { formatHours, formatPercent, isoDay, projectLabel, shiftWeek } from "../../lib/org/format";
import {
  buildMatrix,
  flagLabel,
  flagVariant,
  formatMetric,
  MATRIX_COLORS,
  rankingRows,
  rowValue,
  seriesKeys,
  tokenTotal,
  trendRows,
  usedSeries,
  type SeriesKey,
} from "../../lib/org/report";
import type { OrgGroup, OrgMetric, OrgProjectReport, OrgSelfReport, OrgServiceRow, OrgTrendReport, OrgWeeklyReport } from "../../lib/org/types";
import { axisTick, chartColors, chartTooltip } from "../../lib/tokens";
import type { NewAPIUser } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { PageHeader } from "../ui/page-header";
import { segmentedItemClassName, segmentedTrackClassName } from "../ui/segmented";
import { Select } from "../ui/select";
import { Skeleton } from "../ui/skeleton";
import { emptyStateClassName } from "../ui/styles";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";

const METRICS: Array<{ value: OrgMetric; label: string }> = [
  { value: "hours", label: "AI 活跃时长" },
  { value: "tokens", label: "Token" },
  { value: "cost", label: "实际计费" },
];

function nameOf(users: NewAPIUser[]) {
  return (id: number) => {
    if (id === 0) {
      return "未识别调用者";
    }
    const user = users.find((candidate) => candidate.id === id);
    return user ? user.display_name || user.username : `用户 #${id}`;
  };
}

function projectNames(report: OrgWeeklyReport | null): Record<string, string> {
  const names: Record<string, string> = {};
  for (const project of report?.projects ?? []) {
    names[String(project.id)] = project.name;
  }
  return names;
}

/** "项目周报" view: the administrator report, or a developer's own week. */
export function OrgReportView({ client, isDeveloper, refreshKey }: { client: ApiClient; isDeveloper: boolean; refreshKey: number }) {
  if (isDeveloper) {
    return <SelfWeek client={client} refreshKey={refreshKey} />;
  }
  return <AdminReport client={client} refreshKey={refreshKey} />;
}

function AdminReport({ client, refreshKey }: { client: ApiClient; refreshKey: number }) {
  const [week, setWeek] = useState<string | undefined>(undefined);
  const [groupID, setGroupID] = useState<string>("");
  const [metric, setMetric] = useState<OrgMetric>("hours");
  const [report, setReport] = useState<OrgWeeklyReport | null>(null);
  const [trend, setTrend] = useState<OrgTrendReport | null>(null);
  const [groups, setGroups] = useState<OrgGroup[]>([]);
  const [users, setUsers] = useState<NewAPIUser[]>([]);
  const [project, setProject] = useState<OrgProjectReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    client.org.catalog(controller.signal).then((catalog) => setGroups(catalog.groups)).catch(() => setGroups([]));
    client.listNewAPICallers(controller.signal).then((result) => setUsers(result.items)).catch(() => setUsers([]));
    return () => controller.abort();
  }, [client, refreshKey]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    const group = groupID === "" ? undefined : Number(groupID);
    Promise.all([client.org.weekly({ week, group_id: group, metric }, controller.signal), client.org.trend(8, group, controller.signal)])
      .then(([weekly, weeks]) => {
        setReport(weekly);
        setTrend(weeks);
      })
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, week, groupID, metric, refreshKey, reloadKey]);

  const names = useMemo(() => projectNames(report), [report]);
  const userName = useMemo(() => nameOf(users), [users]);
  const rows = useMemo(() => (report ? rankingRows(report, metric, userName) : []), [report, metric, userName]);
  const series = useMemo(() => usedSeries(seriesKeys(report?.projects ?? [], names), rows), [report, names, rows]);

  async function openProject(projectID: number) {
    setError(null);
    try {
      setProject(await client.org.projectWeekly(projectID, report?.week));
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  async function regenerate() {
    if (!report) {
      return;
    }
    setNotice(null);
    setError(null);
    try {
      await client.org.regenerate(report.week);
      setNotice(`已按当前规则重新生成 ${report.week} 周快照。`);
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  const coverage = report && report.totals.requests > 0 ? report.totals.identified_requests / report.totals.requests : 0;

  return (
    <div className="space-y-section">
      <PageHeader
        title="项目周报"
        description="排名口径为 AI 活跃时长（同一根会话内间隔不超过阈值的请求合并，不同根会话相加），不是工作时长。"
        badges={
          report ? (
            <>
              <Badge variant={report.frozen ? "success" : "info"}>{report.frozen ? "已冻结" : report.complete ? "未冻结" : "本周至今"}</Badge>
              <Badge variant="outline">{report.timezone}</Badge>
            </>
          ) : null
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => report && setWeek(shiftWeek(report.week, -1))} disabled={!report}>
              上一周
            </Button>
            <span className="font-mono text-body-sm">{report?.week ?? "…"}</span>
            <Button size="sm" variant="outline" onClick={() => report && setWeek(shiftWeek(report.week, 1))} disabled={!report || !report.complete}>
              下一周
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setWeek(undefined)}>
              本周
            </Button>
            <Select aria-label="项目组" value={groupID} onChange={(event) => setGroupID(event.target.value)}>
              <option value="">全部项目组</option>
              <option value="0">未分组</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </Select>
            <div className={segmentedTrackClassName} role="group" aria-label="指标">
              {METRICS.map((item) => (
                <button key={item.value} type="button" className={segmentedItemClassName(metric === item.value)} aria-pressed={metric === item.value} onClick={() => setMetric(item.value)}>
                  {item.label}
                </button>
              ))}
            </div>
            {report?.complete ? (
              <Button size="sm" variant="outline" onClick={() => void regenerate()}>
                重新生成
              </Button>
            ) : null}
          </div>
        }
      />
      {error ? (
        <Alert variant="danger">
          <AlertTitle>无法读取项目周报</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert variant="info">
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {loading && !report ? <Skeleton className="h-64 w-full" /> : null}
      {report ? (
        <>
          <div className="grid gap-3 sm:grid-cols-4">
            <Kpi label="AI 活跃时长（排名口径）" value={formatHours(report.totals.active_ns)} />
            <Kpi label="Token" value={formatMetric(tokenTotal(report.totals.tokens), "tokens")} />
            <Kpi label="实际计费" value={formatMetric(report.totals.cost_usd, "cost")} />
            <Kpi label="身份覆盖率" value={formatPercent(coverage)} hint={`${report.totals.identified_requests} / ${report.totals.requests} 次请求带项目标识`} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>排名（按项目分段）</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {rows.length === 0 ? (
                <p className={emptyStateClassName}>本周没有排名数据。</p>
              ) : (
                <div className="w-full" style={{ height: Math.max(160, rows.length * 32 + 60) }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke={chartColors.grid} />
                      <XAxis type="number" tick={axisTick} stroke={chartColors.grid} tickFormatter={(value: number) => formatMetric(value, metric)} />
                      <YAxis type="category" dataKey="user" tick={axisTick} stroke={chartColors.grid} width={120} />
                      <Tooltip formatter={(value) => formatMetric(Number(value), metric)} cursor={{ fill: chartColors.cursor }} {...chartTooltip} />
                      <Legend wrapperStyle={{ fontSize: axisTick.fontSize }} />
                      {series.map((entry) => (
                        <Bar key={entry.key} dataKey={entry.key} name={entry.label} stackId="projects" fill={entry.color} isAnimationActive={false} />
                      ))}
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
              <RankingTable report={report} metric={metric} userName={userName} />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>人 × 项目</CardTitle>
            </CardHeader>
            <CardContent>
              <ProjectMatrix report={report} metric={metric} series={series} userName={userName} onOpenProject={(id) => void openProject(id)} />
            </CardContent>
          </Card>
          {project ? <ProjectPanel report={project} userName={userName} onClose={() => setProject(null)} /> : null}
          <Card>
            <CardHeader>
              <CardTitle>近 8 周趋势</CardTitle>
            </CardHeader>
            <CardContent>{trend ? <TrendChart trend={trend} metric={metric} names={names} /> : null}</CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>服务 / 系统</CardTitle>
            </CardHeader>
            <CardContent>
              <ServiceTable rows={report.service} userName={userName} />
              {report.unresolved ? (
                <p className="mt-3 text-body-sm text-subtle">
                  另有 {report.unresolved.requests} 次请求无法识别调用者（未进入排名），Token {formatMetric(tokenTotal(report.unresolved.tokens), "tokens")}。
                </p>
              ) : null}
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}

function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card>
      <CardContent className="space-y-1 pt-4">
        <p className="text-label text-muted">{label}</p>
        <p className="text-title font-semibold">{value}</p>
        {hint ? <p className="text-caption text-subtle">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

export function RankingTable({ report, metric, userName }: { report: OrgWeeklyReport; metric: OrgMetric; userName: (id: number) => string }) {
  if (report.users.length === 0) {
    return null;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>#</TableHead>
          <TableHead>用户</TableHead>
          <TableHead>{METRICS.find((item) => item.value === metric)?.label}</TableHead>
          <TableHead>根会话</TableHead>
          <TableHead>并行（峰值 / 平均）</TableHead>
          <TableHead>覆盖率</TableHead>
          <TableHead>标记</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {report.users.map((user) => (
          <TableRow key={user.user_id}>
            <TableCell>{user.rank}</TableCell>
            <TableCell>{userName(user.user_id)}</TableCell>
            <TableCell className="font-mono">
              {formatMetric(rowValue(user, metric), metric)}
              {metric === "hours" && user.other_active_ns > 0 ? <span className="ml-2 text-caption text-subtle">其他客户端 {formatHours(user.other_active_ns)}</span> : null}
            </TableCell>
            <TableCell>{user.roots}</TableCell>
            <TableCell>
              {user.peak_concurrency} / {user.avg_concurrency.toFixed(1)}
            </TableCell>
            <TableCell>{formatPercent(user.coverage)}</TableCell>
            <TableCell className="space-x-1">
              {user.flags.map((flag) => (
                <Badge key={flag.code} variant={flagVariant(flag)} title={flagLabel(flag)}>
                  {flagLabel(flag)}
                </Badge>
              ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ProjectMatrix({
  report,
  metric,
  series,
  userName,
  onOpenProject,
}: {
  report: OrgWeeklyReport;
  metric: OrgMetric;
  series: SeriesKey[];
  userName: (id: number) => string;
  onOpenProject?: (projectID: number) => void;
}) {
  const matrix = buildMatrix(report, metric, series);
  if (matrix.rows.length === 0 || series.length === 0) {
    return <p className={emptyStateClassName}>没有可展示的项目数据。</p>;
  }
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>用户</TableHead>
            {series.map((entry) => (
              <TableHead key={entry.key}>
                <button type="button" className="inline-flex items-center gap-1.5 hover:underline" onClick={() => onOpenProject?.(entry.project)}>
                  <span className="inline-block h-2.5 w-2.5 rounded-xs" style={{ backgroundColor: entry.color }} />
                  {entry.label}
                </button>
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {matrix.rows.map((row) => (
            <TableRow key={row.user_id}>
              <TableCell>{userName(row.user_id)}</TableCell>
              {row.cells.map((cell, index) => (
                <TableCell key={series[index].key} className="font-mono text-label">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="inline-block h-3 w-3 rounded-xs" style={{ backgroundColor: MATRIX_COLORS[cell.level] }} />
                    {cell.value > 0 ? formatMetric(cell.value, metric) : "–"}
                  </span>
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ProjectPanel({ report, userName, onClose }: { report: OrgProjectReport; userName: (id: number) => string; onClose: () => void }) {
  return (
    <Card>
      <CardHeader>
        <PageHeader
          level="panel"
          title={`${report.project.name || projectLabel(report.project.id, {})} · ${report.week}`}
          description={`合计 ${formatHours(report.total.active_ns)}，${report.total.requests} 次请求，${formatMetric(report.total.cost_usd, "cost")}`}
          actions={
            <Button size="sm" variant="ghost" onClick={onClose}>
              关闭
            </Button>
          }
        />
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>贡献者</TableHead>
              <TableHead>时长</TableHead>
              <TableHead>根会话</TableHead>
              <TableHead>Token</TableHead>
              <TableHead>计费</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {report.contributors.map((row) => (
              <TableRow key={row.user_id}>
                <TableCell>{userName(row.user_id)}</TableCell>
                <TableCell>{formatHours(row.active_ns)}</TableCell>
                <TableCell>{row.roots}</TableCell>
                <TableCell>{formatMetric(tokenTotal(row.tokens), "tokens")}</TableCell>
                <TableCell>{formatMetric(row.cost_usd, "cost")}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function TrendChart({ trend, metric, names }: { trend: OrgTrendReport; metric: OrgMetric; names: Record<string, string> }) {
  const rows = trendRows(trend, metric);
  const series = usedSeries(seriesKeys(trend.projects, names), rows);
  if (rows.length === 0 || series.length === 0) {
    return <p className={emptyStateClassName}>近几周没有数据。</p>;
  }
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={chartColors.grid} />
          <XAxis dataKey="week" tick={axisTick} stroke={chartColors.grid} />
          <YAxis tick={axisTick} stroke={chartColors.grid} tickFormatter={(value: number) => formatMetric(value, metric)} width={56} />
          <Tooltip formatter={(value) => formatMetric(Number(value), metric)} cursor={{ fill: chartColors.cursor }} {...chartTooltip} />
          {series.map((entry) => (
            <Bar key={entry.key} dataKey={entry.key} name={entry.label} stackId="trend" fill={entry.color} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ServiceTable({ rows, userName }: { rows: OrgServiceRow[]; userName: (id: number) => string }) {
  if (rows.length === 0) {
    return <p className={emptyStateClassName}>没有服务/系统主体的流量。</p>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>主体</TableHead>
          <TableHead>时长</TableHead>
          <TableHead>请求</TableHead>
          <TableHead>Token</TableHead>
          <TableHead>计费</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={`${row.user_id}-${row.token_id}`}>
            <TableCell>
              {userName(row.user_id)}
              {row.token_id > 0 ? <span className="ml-1 text-caption text-subtle">Token #{row.token_id}</span> : null}
            </TableCell>
            <TableCell>{formatHours(row.active_ns)}</TableCell>
            <TableCell>{row.requests}</TableCell>
            <TableCell>{formatMetric(tokenTotal(row.tokens), "tokens")}</TableCell>
            <TableCell>{formatMetric(row.cost_usd, "cost")}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function SelfWeek({ client, refreshKey }: { client: ApiClient; refreshKey: number }) {
  const [report, setReport] = useState<OrgSelfReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    client.org
      .self(controller.signal)
      .then(setReport)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [client, refreshKey]);
  if (error) {
    return (
      <Alert variant="danger">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (!report) {
    return <Skeleton className="h-40 w-full" />;
  }
  return <SelfCard report={report} />;
}

function dayLabel(week: string, offset: number): string {
  const [year, month, day] = week.split("-").map(Number);
  return isoDay(new Date(year, month - 1, day + offset)).slice(5);
}

export function SelfCard({ report }: { report: OrgSelfReport }) {
  const names: Record<string, string> = {};
  for (const project of report.projects) {
    names[String(project.id)] = project.name;
  }
  const row = report.row;
  return (
    <Card>
      <CardHeader>
        <PageHeader level="panel" title={`我的本周 · ${report.week}`} description={`AI 活跃时长按 ${report.timezone} 计算，只包含你自己的请求。`} />
      </CardHeader>
      <CardContent className="space-y-3">
        {!row ? (
          <p className={emptyStateClassName}>本周还没有你的项目数据。</p>
        ) : (
          <>
            <p className="text-title font-semibold">{formatHours(row.active_ns)}</p>
            <ul className="space-y-1 text-body-sm">
              {row.projects.map((cell) => (
                <li key={cell.project} className="flex justify-between gap-2">
                  <span>{projectLabel(cell.project, names)}</span>
                  <span className="font-mono">{formatHours(cell.active_ns)}</span>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap gap-2 text-caption text-subtle">
              {row.daily_active_ns.map((value, index) => (
                <span key={index}>
                  {dayLabel(report.week, index)} {formatHours(value)}
                </span>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
