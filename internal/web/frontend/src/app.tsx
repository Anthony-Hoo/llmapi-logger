import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";

import { ApiError, createApiClient, type ApiClient } from "./api";
import { Alert, AlertDescription, AlertTitle } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import { Input } from "./components/ui/input";
import { Separator } from "./components/ui/separator";
import { Skeleton } from "./components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./components/ui/table";
import { ConversationView } from "./components/conversation-view";
import {
  displayValue,
  formatBytes,
  formatNanoTime,
  humanizeStage,
  shortHash,
  statusVariant,
} from "./lib/format";
import {
  buildEvidenceEnvelope,
  capturedContentType,
  createRawBodyPreview,
  evidenceStage,
  type RawBodyPreview,
} from "./lib/raw-body";
import type {
  AuditBody,
  AuditCursor,
  AuditDetail,
  AuditFilters,
  AuditHeader,
  AuditStage,
  AuditSummary,
  RawBodyDownload,
  RawSide,
} from "./types";

interface LoadedRawBody {
  download: RawBodyDownload;
  preview: RawBodyPreview;
}

export function App() {
  const [token, setToken] = useState<string | null>(null);
  const [authMessage, setAuthMessage] = useState<string | null>(null);

  const logOut = useCallback((message?: string) => {
    setToken(null);
    setAuthMessage(message ?? null);
  }, []);

  if (!token) {
    return (
      <TokenGate
        message={authMessage}
        onSubmit={(nextToken) => {
          setAuthMessage(null);
          setToken(nextToken);
        }}
      />
    );
  }

  return (
    <Dashboard
      token={token}
      onUnauthorized={() => logOut("认证失败，令牌已从页面内存中清除。")}
      onLogOut={() => logOut()}
    />
  );
}

function TokenGate({ message, onSubmit }: { message: string | null; onSubmit: (token: string) => void }) {
  const [draft, setDraft] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const token = draft.trim();
    if (token) {
      onSubmit(token);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-5 py-12">
      <Card className="w-full max-w-md overflow-hidden bg-white/90 backdrop-blur">
        <div className="h-1.5 bg-gradient-to-r from-blue-600 via-indigo-500 to-cyan-400" />
        <CardHeader className="space-y-4 pb-5">
          <BrandMark />
          <div className="space-y-2">
            <CardTitle className="text-2xl">LLM API Audit</CardTitle>
            <CardDescription>
              输入本机管理令牌以查看审计记录。令牌只保存在当前页面内存中，刷新页面后需要重新输入。
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {message ? (
            <Alert className="mb-5 border-amber-200 bg-amber-50/90">
              <AlertTitle className="text-amber-900">需要重新认证</AlertTitle>
              <AlertDescription className="text-amber-800">{message}</AlertDescription>
            </Alert>
          ) : null}
          <form className="space-y-4" onSubmit={submit}>
            <div className="space-y-2">
              <label htmlFor="admin-token" className="text-sm font-medium">
                Admin token
              </label>
              <Input
                id="admin-token"
                autoFocus
                autoComplete="off"
                name="admin-token"
                type="password"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder="输入 configs 中配置的 admin_token"
              />
            </div>
            <Button className="w-full" type="submit" disabled={!draft.trim()}>
              进入审计页面
            </Button>
          </form>
          <p className="mt-5 text-center text-xs leading-relaxed text-muted-foreground">
            页面不会使用 Cookie、localStorage 或 sessionStorage 保存令牌。
          </p>
        </CardContent>
      </Card>
    </main>
  );
}

function Dashboard({
  token,
  onUnauthorized,
  onLogOut,
}: {
  token: string;
  onUnauthorized: () => void;
  onLogOut: () => void;
}) {
  const client = useMemo(() => createApiClient(token, onUnauthorized), [onUnauthorized, token]);
  const [page, setPage] = useState<{ items: AuditSummary[]; next_cursor: AuditCursor | null }>({
    items: [],
    next_cursor: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [draftPath, setDraftPath] = useState("");
  const [draftForwardStatus, setDraftForwardStatus] = useState("");
  const [filters, setFilters] = useState<AuditFilters>({});
  const [cursor, setCursor] = useState<AuditCursor | null>(null);
  const [cursorHistory, setCursorHistory] = useState<Array<AuditCursor | null>>([]);
  const [selectedID, setSelectedID] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);

    client
      .listAudits(filters, cursor, controller.signal)
      .then((result) => {
        setPage(result);
        setSelectedID((current) => {
          if (current && result.items.some((item) => item.audit_id === current)) {
            return current;
          }
          return null;
        });
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
  }, [client, cursor, filters, refreshKey]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCursor(null);
    setCursorHistory([]);
    setFilters({
      path: draftPath.trim() || undefined,
      forward_status: draftForwardStatus || undefined,
    });
  }

  function nextPage() {
    if (!page.next_cursor) {
      return;
    }
    setCursorHistory((history) => [...history, cursor]);
    setCursor(page.next_cursor);
  }

  function previousPage() {
    const previous = cursorHistory.at(-1);
    if (previous === undefined) {
      return;
    }
    setCursorHistory((history) => history.slice(0, -1));
    setCursor(previous);
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b bg-white/85 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-8">
          <div className="flex items-center gap-3">
            <BrandMark compact />
            <div>
              <h1 className="text-sm font-semibold sm:text-base">LLM API Audit</h1>
              <p className="hidden text-xs text-muted-foreground sm:block">本地 LLM 请求与响应证据</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setRefreshKey((value) => value + 1)} disabled={loading}>
              <RefreshIcon />
              <span className="ml-2 hidden sm:inline">刷新</span>
            </Button>
            <Button variant="ghost" size="sm" onClick={onLogOut}>
              清除令牌
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] space-y-5 px-4 py-5 sm:px-6 lg:px-8">
        <Card className="bg-white/85 shadow-sm">
          <CardContent className="p-4">
            <form className="grid gap-3 md:grid-cols-[minmax(240px,1fr)_220px_auto]" onSubmit={applyFilters}>
              <Input
                aria-label="按路径筛选"
                value={draftPath}
                onChange={(event) => setDraftPath(event.target.value)}
                placeholder="按 LLM API 路径筛选"
              />
              <select
                aria-label="按转发状态筛选"
                className="h-10 rounded-md border border-input bg-white px-3 text-sm shadow-sm outline-none focus:ring-2 focus:ring-ring"
                value={draftForwardStatus}
                onChange={(event) => setDraftForwardStatus(event.target.value)}
              >
                <option value="">全部转发状态</option>
                <option value="completed">completed</option>
                <option value="rejected">rejected</option>
                <option value="client_cancelled">client_cancelled</option>
                <option value="newapi_error">newapi_error</option>
                <option value="proxy_error">proxy_error</option>
                <option value="interrupted">interrupted</option>
              </select>
              <Button type="submit">应用筛选</Button>
            </form>
          </CardContent>
        </Card>

        {error ? (
          <Alert className="border-red-200 bg-red-50/90">
            <AlertTitle className="text-red-900">无法读取审计列表</AlertTitle>
            <AlertDescription className="flex flex-wrap items-center justify-between gap-3 text-red-800">
              <span>{error}</span>
              <Button variant="outline" size="sm" onClick={() => setRefreshKey((value) => value + 1)}>
                重试
              </Button>
            </AlertDescription>
          </Alert>
        ) : null}

        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.15fr)_minmax(440px,0.85fr)]">
          <AuditList
            items={page.items}
            loading={loading}
            selectedID={selectedID}
            onSelect={setSelectedID}
          />
          <AuditDetailPanel key={selectedID ?? "none"} client={client} auditID={selectedID} />
        </div>

        <div className="flex items-center justify-between pb-5">
          <p className="text-xs text-muted-foreground">
            当前页 {page.items.length} 条 · 每页最多 50 条
          </p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={loading || cursorHistory.length === 0} onClick={previousPage}>
              上一页
            </Button>
            <Button variant="outline" size="sm" disabled={loading || !page.next_cursor} onClick={nextPage}>
              下一页
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}

function AuditList({
  items,
  loading,
  selectedID,
  onSelect,
}: {
  items: AuditSummary[];
  loading: boolean;
  selectedID: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <Card className="min-w-0 overflow-hidden bg-white/90 shadow-sm">
      <CardHeader className="flex-row items-center justify-between space-y-0 border-b px-5 py-4">
        <div>
          <CardTitle className="text-base">审计记录</CardTitle>
          <CardDescription className="mt-1">只包含代理白名单内的 LLM API 请求</CardDescription>
        </div>
        {loading ? <Badge variant="secondary">加载中</Badge> : <Badge variant="outline">{items.length} 条</Badge>}
      </CardHeader>
      <CardContent className="p-0">
        {loading ? (
          <div className="space-y-3 p-5">
            {Array.from({ length: 7 }, (_, index) => (
              <Skeleton key={index} className="h-12 w-full" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
            <div className="mb-3 rounded-full bg-muted p-3 text-muted-foreground">
              <DocumentIcon />
            </div>
            <p className="font-medium">没有符合条件的审计记录</p>
            <p className="mt-1 text-sm text-muted-foreground">发送一条白名单内的 LLM API 请求后再刷新。</p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>时间 / ID</TableHead>
                <TableHead>请求</TableHead>
                <TableHead>结果</TableHead>
                <TableHead>捕获 / 解析</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((audit) => (
                <TableRow
                  key={audit.audit_id}
                  tabIndex={0}
                  aria-selected={audit.audit_id === selectedID}
                  className={
                    audit.audit_id === selectedID
                      ? "cursor-pointer bg-blue-50/80 hover:bg-blue-50"
                      : "cursor-pointer"
                  }
                  onClick={() => onSelect(audit.audit_id)}
                  onKeyDown={(event) => selectOnKeyboard(event, () => onSelect(audit.audit_id))}
                >
                  <TableCell className="min-w-48">
                    <div className="text-xs text-muted-foreground">{formatNanoTime(audit.started_at_ns)}</div>
                    <div className="mt-1 max-w-48 truncate font-mono text-xs" title={audit.audit_id}>
                      {audit.audit_id}
                    </div>
                  </TableCell>
                  <TableCell className="min-w-64">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono">
                        {audit.method}
                      </Badge>
                      <span className="truncate font-medium" title={audit.path}>
                        {audit.path}
                      </span>
                    </div>
                    <div className="mt-1 flex gap-2 text-xs text-muted-foreground">
                      <span>{audit.protocol}</span>
                      <span>·</span>
                      <span>{audit.route_id}</span>
                    </div>
                    {audit.response_model || audit.request_model ? (
                      <div
                        className="mt-1 max-w-64 truncate font-mono text-xs text-muted-foreground"
                        title={audit.response_model ?? audit.request_model ?? undefined}
                      >
                        {audit.response_model ?? audit.request_model}
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell className="min-w-40">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <StatusBadge value={audit.forward_status} />
                      {audit.status_code ? <Badge variant="outline">HTTP {audit.status_code}</Badge> : null}
                    </div>
                    {audit.block_code ? (
                      <div className="mt-1.5 truncate text-xs font-medium text-red-700" title={audit.block_code}>
                        {audit.block_code}
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell className="min-w-40">
                    <div className="flex flex-wrap gap-1.5">
                      <StatusBadge labelPrefix="capture" value={audit.capture_status} />
                      <StatusBadge labelPrefix="parse" value={audit.parse_status} />
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function AuditDetailPanel({ client, auditID }: { client: ApiClient; auditID: string | null }) {
  const [detail, setDetail] = useState<AuditDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rawBodies, setRawBodies] = useState<Partial<Record<RawSide, LoadedRawBody>>>({});
  const [rawLoading, setRawLoading] = useState<RawSide | null>(null);
  const [rawNote, setRawNote] = useState<string | null>(null);
  const rawController = useRef<AbortController | null>(null);

  useEffect(() => {
    setRawNote(null);
    setRawBodies({});
    if (!auditID) {
      setDetail(null);
      setError(null);
      return;
    }

    const controller = new AbortController();
    setDetail(null);
    setLoading(true);
    setError(null);
    client
      .getAudit(auditID, controller.signal)
      .then(setDetail)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setDetail(null);
          setError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });

    return () => controller.abort();
  }, [auditID, client]);

  useEffect(() => {
    return () => {
      rawController.current?.abort();
      rawController.current = null;
    };
  }, [auditID, client]);

  async function loadRawBody(side: RawSide) {
    if (rawBodies[side]) {
      return;
    }
    await fetchRawBody(side, async (result) => {
      const preview = await createRawBodyPreview(result, capturedContentType(detail?.headers ?? [], side));
      setRawBodies((current) => ({ ...current, [side]: { download: result, preview } }));
    });
  }

  async function downloadRawBody(side: RawSide) {
    const loaded = rawBodies[side];
    if (loaded) {
      saveDownload(loaded.download);
      setRawNote(downloadMessage(side, loaded.download));
      return;
    }
    await fetchRawBody(side, async (result) => {
      saveDownload(result);
      setRawNote(downloadMessage(side, result));
    });
  }

  async function fetchRawBody(side: RawSide, consume: (result: RawBodyDownload) => Promise<void>) {
    if (!auditID) {
      return;
    }
    rawController.current?.abort();
    const controller = new AbortController();
    rawController.current = controller;
    setRawLoading(side);
    setRawNote(null);
    try {
      const result = await client.getRawBody(auditID, side, controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      await consume(result);
    } catch (cause: unknown) {
      if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
        setRawNote(errorMessage(cause));
      }
    } finally {
      if (rawController.current === controller) {
        rawController.current = null;
        setRawLoading(null);
      }
    }
  }

  function clearRawBody(side: RawSide) {
    setRawBodies((current) => {
      const next = { ...current };
      delete next[side];
      return next;
    });
    setRawNote(`${side === "request" ? "请求" : "响应"} Body 已从页面内存中清除。`);
  }

  if (!auditID) {
    return (
      <Card className="bg-white/90 shadow-sm xl:sticky xl:top-24">
        <CardContent className="flex min-h-80 items-center justify-center p-8 text-center text-sm text-muted-foreground">
          从左侧选择一条记录查看详情。
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="min-w-0 bg-white/90 shadow-sm xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-y-auto">
      <CardHeader className="border-b px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="text-base">审计详情</CardTitle>
            <CardDescription className="mt-1 truncate font-mono" title={auditID}>
              {auditID}
            </CardDescription>
          </div>
          {detail ? <StatusBadge value={detail.audit.forward_status} /> : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-5 p-5">
        {loading ? <DetailSkeleton /> : null}
        {error ? (
          <Alert className="border-red-200 bg-red-50">
            <AlertTitle className="text-red-900">无法读取详情</AlertTitle>
            <AlertDescription className="text-red-800">{error}</AlertDescription>
          </Alert>
        ) : null}
        {!loading && detail ? (
          <>
            {detail.audit.forward_status === "rejected" ? (
              <Alert className="border-red-200 bg-red-50">
                <AlertTitle className="flex flex-wrap items-center gap-2 text-red-900">
                  请求已在发送至 NewAPI 前被拦截
                  {detail.audit.block_code ? <Badge variant="destructive">{detail.audit.block_code}</Badge> : null}
                </AlertTitle>
                <AlertDescription className="text-red-800">
                  拦截模块：{detail.audit.blocked_by ?? "未知"}。该记录不会包含 NewAPI 请求或响应阶段。
                </AlertDescription>
              </Alert>
            ) : null}

            <Section title="对话审计">
              <ConversationView conversation={detail.conversation} />
            </Section>

            <Section title="请求概览">
              <DefinitionGrid
                items={[
                  ["时间", formatNanoTime(detail.audit.started_at_ns)],
                  ["路由", detail.audit.route_id],
                  ["协议", detail.audit.protocol],
                  ["方法", detail.audit.method],
                  ["路径", detail.audit.path],
                  ["HTTP 状态", detail.audit.status_code ?? "—"],
                  ["转发", <StatusBadge value={detail.audit.forward_status} />],
                  ["捕获", <StatusBadge value={detail.audit.capture_status} />],
                  ["解析", <StatusBadge value={detail.audit.parse_status} />],
                  ["模式", detail.audit.mode ?? "—"],
                  ["Parser", detail.audit.parser_name ?? "—"],
                  ["Token", detail.audit.token_name ?? detail.audit.newapi_token_id ?? "—"],
                ]}
              />
            </Section>

            <Section title="解析摘要">
              {detail.parsed_result ? (
                <DefinitionGrid
                  items={Object.entries(detail.parsed_result)
                    .filter(([, value]) => value !== null && value !== "")
                    .map(([key, value]) => [key, displayValue(value)])}
                />
              ) : (
                <EmptyValue>当前没有解析摘要。</EmptyValue>
              )}
            </Section>

            <HTTPAuditEvidence
              detail={detail}
              rawBodies={rawBodies}
              rawLoading={rawLoading}
              rawNote={rawNote}
              onLoad={loadRawBody}
              onDownload={downloadRawBody}
              onClear={clearRawBody}
            />
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

export function HTTPAuditEvidence({
  detail,
  rawBodies,
  rawLoading,
  rawNote,
  onLoad,
  onDownload,
  onClear,
}: {
  detail: AuditDetail;
  rawBodies: Partial<Record<RawSide, LoadedRawBody>>;
  rawLoading: RawSide | null;
  rawNote: string | null;
  onLoad: (side: RawSide) => void;
  onDownload: (side: RawSide) => void;
  onClear: (side: RawSide) => void;
}) {
  return (
    <details className="overflow-hidden rounded-lg border bg-slate-50/60">
      <summary className="cursor-pointer px-4 py-3 text-sm font-semibold hover:bg-slate-100/80">
        原始 HTTP 证据与完整性
        <span className="ml-2 text-xs font-normal text-muted-foreground">辅助证据 · 默认折叠</span>
      </summary>
      <div className="space-y-5 border-t bg-white/80 p-4">
        <Alert className="bg-slate-50">
          <AlertDescription>
            这里按审计边界保存的字段重建 HTTP 视图，不是 TCP、TLS、HTTP/2 frame 或原始大小写/顺序级别的 wire dump。
            Header 值只随当前详情读取；Body 不会自动加载，点击查看后才会从本机管理 API 解密到页面内存。
          </AlertDescription>
        </Alert>

        <EvidenceSubsection title="原始请求与响应">
          <div className="space-y-3">
            <RawHTTPMessage
              side="request"
              detail={detail}
              loaded={rawBodies.request}
              loading={rawLoading === "request"}
              busy={rawLoading !== null}
              onLoad={() => onLoad("request")}
              onDownload={() => onDownload("request")}
              onClear={() => onClear("request")}
            />
            <RawHTTPMessage
              side="response"
              detail={detail}
              loaded={rawBodies.response}
              loading={rawLoading === "response"}
              busy={rawLoading !== null}
              onLoad={() => onLoad("response")}
              onDownload={() => onDownload("response")}
              onClear={() => onClear("response")}
            />
          </div>
          {rawNote ? <p className="mt-2 text-xs text-muted-foreground">{rawNote}</p> : null}
        </EvidenceSubsection>

        <EvidenceSubsection title="HTTP 阶段">
          <StagesTable stages={detail.stages} />
        </EvidenceSubsection>

        <EvidenceSubsection title="Body 完整性">
          <BodiesTable bodies={detail.bodies} />
        </EvidenceSubsection>

        <EvidenceSubsection title={`Header / Trailer 值（${detail.headers.length}）`}>
          <HeadersTable headers={detail.headers} />
        </EvidenceSubsection>
      </div>
    </details>
  );
}

function EvidenceSubsection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h4>
      {children}
    </section>
  );
}

function RawHTTPMessage({
  side,
  detail,
  loaded,
  loading,
  busy,
  onLoad,
  onDownload,
  onClear,
}: {
  side: RawSide;
  detail: AuditDetail;
  loaded: LoadedRawBody | undefined;
  loading: boolean;
  busy: boolean;
  onLoad: () => void;
  onDownload: () => void;
  onClear: () => void;
}) {
  const stageName = evidenceStage(side);
  const stage = detail.stages.find((candidate) => candidate.stage === stageName);
  const headers = detail.headers.filter((header) => header.stage === stageName && header.kind === "header");
  const trailers = detail.headers.filter((header) => header.stage === stageName && header.kind === "trailer");
  const envelope = buildEvidenceEnvelope(detail, side);
  const available = hasRawBody(detail, side);
  const title = side === "request" ? "发往 NewAPI 的请求" : "从 NewAPI 收到的响应";
  const envelopeText = [envelope.startLine, ...envelope.headerLines].join("\n");

  return (
    <div className="min-w-0 rounded-lg border bg-white p-3 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold">{title}</h4>
          <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground" title={stageName}>
            {stageName}
          </p>
        </div>
        <StatusBadge value={stage?.state} />
      </div>

      <div className="mt-3 grid gap-x-4 gap-y-2 text-xs sm:grid-cols-2">
        {side === "request" ? (
          <>
            <EvidenceMeta label="Host" value={stage?.host || "—"} />
            <EvidenceMeta label="入站 Request-URI" value={detail.request_uri || detail.audit.path || "—"} mono />
          </>
        ) : (
          <>
            <EvidenceMeta label="HTTP 状态" value={stage?.status_code ?? detail.audit.status_code ?? "—"} />
            <EvidenceMeta label="协议" value={stage?.proto || "—"} mono />
          </>
        )}
        <EvidenceMeta label="Content-Length" value={stage?.content_length ?? "—"} />
        <EvidenceMeta label="捕获 Header" value={`${headers.length} 个`} />
      </div>

      <div className="mt-3">
        <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          起始行与 Header（重建）
        </p>
        <pre className="max-h-64 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100">
          {envelopeText}
          {"\n\n"}
        </pre>
      </div>

      <div className="mt-3">
        <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
          <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">原始 Body</p>
          {loaded ? (
            <div className="flex flex-wrap gap-x-3 text-[11px] text-muted-foreground">
              <span>{formatBytes(loaded.download.storedLength)}</span>
              <span>{loaded.preview.contentType}</span>
              <span>{loaded.download.complete ? "完整" : "不完整"}</span>
            </div>
          ) : null}
        </div>

        {!available ? (
          <EmptyValue>该审计边界没有捕获 Body。</EmptyValue>
        ) : loaded?.preview.kind === "text" ? (
          loaded.preview.text ? (
            <pre
              aria-label={`${title}原始 Body`}
              className="max-h-96 overflow-auto rounded-md border bg-slate-950 p-3 font-mono text-[11px] leading-5 text-slate-100"
            >
              {loaded.preview.text}
            </pre>
          ) : (
            <EmptyValue>已捕获空 Body（0 B）。</EmptyValue>
          )
        ) : loaded?.preview.kind === "binary" ? (
          <Alert className="border-amber-200 bg-amber-50/80">
            <AlertTitle className="text-amber-900">二进制 Body 未在页面内渲染</AlertTitle>
            <AlertDescription className="text-amber-800">
              {loaded.preview.reason} 可使用下方下载按钮保存原始字节。
            </AlertDescription>
          </Alert>
        ) : (
          <div className="rounded-md border border-dashed bg-slate-50/60 px-4 py-4 text-sm text-muted-foreground">
            Body 尚未加载。列表与详情切换不会自动请求原始 Body。
          </div>
        )}
      </div>

      {trailers.length > 0 ? (
        <div className="mt-3">
          <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Trailer（独立捕获）
          </p>
          <pre className="max-h-40 overflow-auto rounded-md border bg-slate-50 p-3 font-mono text-[11px] leading-5">
            {envelope.trailerLines.join("\n")}
          </pre>
        </div>
      ) : null}

      <div className="mt-3 flex flex-wrap gap-2">
        {!loaded ? (
          <Button variant="outline" size="sm" onClick={onLoad} disabled={busy || !available}>
            <ViewIcon />
            <span className="ml-2">{loading ? "加载中…" : "加载并查看 Body"}</span>
          </Button>
        ) : (
          <Button variant="ghost" size="sm" onClick={onClear} disabled={busy}>
            从页面清除 Body
          </Button>
        )}
        <Button variant="outline" size="sm" onClick={onDownload} disabled={busy || !available}>
          <DownloadIcon />
          <span className="ml-2">{loading ? "读取中…" : "下载原始 Body"}</span>
        </Button>
      </div>
    </div>
  );
}

function EvidenceMeta({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-muted-foreground">{label}</div>
      <div className={`mt-0.5 break-all font-medium ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function StagesTable({ stages }: { stages: AuditStage[] }) {
  if (stages.length === 0) {
    return <EmptyValue>没有已记录的 HTTP 阶段。</EmptyValue>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="px-2">阶段</TableHead>
          <TableHead className="px-2">状态</TableHead>
          <TableHead className="px-2">HTTP</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {stages.map((stage) => (
          <TableRow key={stage.stage}>
            <TableCell className="px-2 py-3 text-xs">{humanizeStage(stage.stage)}</TableCell>
            <TableCell className="px-2 py-3">
              <StatusBadge value={stage.state} />
            </TableCell>
            <TableCell className="px-2 py-3 text-xs">{stage.status_code ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function BodiesTable({ bodies }: { bodies: AuditBody[] }) {
  if (bodies.length === 0) {
    return <EmptyValue>没有已捕获的 Body。</EmptyValue>;
  }
  return (
    <div className="space-y-2">
      {bodies.map((body) => (
        <div key={body.stage} className="rounded-md border bg-slate-50/60 p-3 text-xs">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="font-medium">{humanizeStage(body.stage)}</span>
            <StatusBadge value={body.state} />
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground">
            <span>观察长度</span>
            <span className="text-right tabular-nums text-foreground">{formatBytes(body.observed_length)}</span>
            <span>保存长度</span>
            <span className="text-right tabular-nums text-foreground">{formatBytes(body.stored_length)}</span>
            <span>SHA-256</span>
            <span className="truncate text-right font-mono text-foreground" title={body.sha256 ?? undefined}>
              {shortHash(body.sha256)}
            </span>
            <span>完整</span>
            <span className="text-right text-foreground">{body.hash_complete && body.eof_seen ? "是" : "否"}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function HeadersTable({ headers }: { headers: AuditHeader[] }) {
  if (headers.length === 0) {
    return <EmptyValue>没有 Header 或 Trailer。</EmptyValue>;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="px-2">阶段</TableHead>
          <TableHead className="px-2">类型</TableHead>
          <TableHead className="px-2">名称</TableHead>
          <TableHead className="px-2">值</TableHead>
          <TableHead className="px-2 text-right">长度</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {headers.map((header) => (
          <TableRow key={`${header.stage}-${header.kind}-${header.name}-${header.value_index}`}>
            <TableCell className="max-w-32 truncate px-2 py-2 text-xs" title={humanizeStage(header.stage)}>
              {humanizeStage(header.stage)}
            </TableCell>
            <TableCell className="px-2 py-2 text-xs">
              <Badge variant="outline" className="font-mono">
                {header.kind}
              </Badge>
            </TableCell>
            <TableCell className="px-2 py-2 font-mono text-xs">{header.name}</TableCell>
            <TableCell className="min-w-64 max-w-lg whitespace-pre-wrap break-all px-2 py-2 font-mono text-xs">
              {header.value || <span className="text-muted-foreground">（空值）</span>}
            </TableCell>
            <TableCell className="px-2 py-2 text-right text-xs tabular-nums">{formatBytes(header.value_length)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <Separator className="mb-5" />
      <h3 className="mb-3 text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function DefinitionGrid({ items }: { items: Array<[string, ReactNode]> }) {
  if (items.length === 0) {
    return <EmptyValue>没有可展示的数据。</EmptyValue>;
  }
  return (
    <dl className="grid gap-x-5 gap-y-3 text-sm sm:grid-cols-2">
      {items.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="mt-1 break-words font-medium">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function EmptyValue({ children }: { children: ReactNode }) {
  return <div className="rounded-md border border-dashed bg-slate-50/60 px-4 py-5 text-center text-sm text-muted-foreground">{children}</div>;
}

function StatusBadge({ value, labelPrefix }: { value: string | null | undefined; labelPrefix?: string }) {
  if (!value) {
    return <Badge variant="outline">—</Badge>;
  }
  return (
    <Badge variant={statusVariant(value)} className="font-mono font-medium">
      {labelPrefix ? `${labelPrefix}:` : ""}
      {value}
    </Badge>
  );
}

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-20 w-full" />
      <div className="grid grid-cols-2 gap-3">
        {Array.from({ length: 6 }, (_, index) => (
          <Skeleton key={index} className="h-10 w-full" />
        ))}
      </div>
      <Skeleton className="h-36 w-full" />
    </div>
  );
}

function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div
      className={
        compact
          ? "grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-slate-950 text-white shadow-sm"
          : "grid h-12 w-12 place-items-center rounded-xl bg-slate-950 text-white shadow-lg"
      }
      aria-hidden="true"
    >
      <svg viewBox="0 0 24 24" width={compact ? 20 : 26} height={compact ? 20 : 26} fill="none">
        <path d="M5 7.5h14M7.5 12h9M9.5 16.5h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        <path d="M4 4h16v16H4z" stroke="currentColor" strokeWidth="1.3" opacity=".5" />
      </svg>
    </div>
  );
}

function RefreshIcon() {
  return (
    <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none">
      <path d="M20 11a8 8 0 1 0-2.34 5.66" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M20 5v6h-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none">
      <path d="M12 3v12m0 0 4-4m-4 4-4-4M5 20h14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ViewIcon() {
  return (
    <svg aria-hidden="true" width="15" height="15" viewBox="0 0 24 24" fill="none">
      <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="12" cy="12" r="2.5" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}

function DocumentIcon() {
  return (
    <svg aria-hidden="true" width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M7 3h7l4 4v14H7z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
      <path d="M14 3v5h5M10 12h5M10 16h5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}

function selectOnKeyboard(event: KeyboardEvent<HTMLTableRowElement>, select: () => void) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    select();
  }
}

function saveDownload(download: RawBodyDownload) {
  const url = URL.createObjectURL(download.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = download.filename;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function downloadMessage(side: RawSide, download: RawBodyDownload): string {
  return `${side === "request" ? "请求" : "响应"}原始 Body 已下载（${formatBytes(download.storedLength)}，${download.complete ? "完整" : "不完整"}）。`;
}

function hasRawBody(detail: AuditDetail, side: RawSide): boolean {
  const expectedStage = side === "request" ? "request_sent_to_newapi" : "response_received_from_newapi";
  return detail.bodies.some((body) => body.stage === expectedStage);
}

function isAbortError(cause: unknown): boolean {
  return cause instanceof DOMException && cause.name === "AbortError";
}

function errorMessage(cause: unknown): string {
  if (cause instanceof Error && cause.message) {
    return cause.message;
  }
  return "请求失败，请检查本地管理服务。";
}
