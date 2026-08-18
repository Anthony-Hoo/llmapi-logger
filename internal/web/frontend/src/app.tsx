import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
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
  formatDurationNS,
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
  DeveloperIdentity,
  NewAPIUser,
  RawBodyDownload,
  RawSide,
  ReconstructedBodyDownload,
  SessionInfo,
  StreamTimeline,
  UserAgentRule,
  UserAgentRuleInput,
} from "./types";

interface LoadedRawBody {
  download: RawBodyDownload;
  preview: RawBodyPreview;
}

export function App() {
  const [authState, setAuthState] = useState<"checking" | "authenticated" | "anonymous">("checking");
  const [authMessage, setAuthMessage] = useState<string | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);

  const handleUnauthorized = useCallback(() => {
    setAuthState("anonymous");
    setSession(null);
    setAuthMessage("登录已失效，请重新登录。");
  }, []);
  const client = useMemo(() => createApiClient(handleUnauthorized), [handleUnauthorized]);

  // Ask the server who we are instead of inferring it from whether the first
  // audit request happens to succeed: the answer also carries the role, which
  // decides what the dashboard may show.
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    client
      .getSession(controller.signal)
      .then((current) => {
        if (!active) {
          return;
        }
        setSession(current);
        setAuthState(current ? "authenticated" : "anonymous");
      })
      .catch(() => {
        if (active) {
          setAuthState("anonymous");
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [client]);

  async function createSession(mode: LoginMode, credential: string) {
    const current =
      mode === "admin"
        ? await client.createSession(credential)
        : await client.createDeveloperSession(credential);
    setSession(current);
    setAuthMessage(null);
    setAuthState("authenticated");
  }

  async function deleteSession() {
    try {
      await client.deleteSession();
      setAuthMessage(null);
    } catch (cause: unknown) {
      setAuthMessage(`退出请求失败：${errorMessage(cause)}`);
    } finally {
      setSession(null);
      setAuthState("anonymous");
    }
  }

  if (authState === "anonymous") {
    return (
      <TokenGate
        message={authMessage}
        onSubmit={createSession}
      />
    );
  }

  return (
    <Dashboard
      client={client}
      session={session}
      checkingSession={authState === "checking"}
      onLogOut={deleteSession}
    />
  );
}

type LoginMode = "admin" | "developer";

const loginModes: { id: LoginMode; label: string; field: string; placeholder: string; hint: string }[] = [
  {
    id: "admin",
    label: "管理员令牌",
    field: "Admin token",
    placeholder: "输入 configs 中配置的 admin_token",
    hint: "管理员可查看全部审计记录与站点策略配置。",
  },
  {
    id: "developer",
    label: "开发者 API Key",
    field: "NewAPI API Key",
    placeholder: "输入你的 NewAPI API Key（sk-…）",
    hint: "使用你自己的 API Key 登录，只能查看该 Key 产生的调用记录，用于审计 agent 调用链。",
  },
];

function TokenGate({
  message,
  onSubmit,
}: {
  message: string | null;
  onSubmit: (mode: LoginMode, credential: string) => Promise<void>;
}) {
  const [mode, setMode] = useState<LoginMode>("admin");
  const [draft, setDraft] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const active = loginModes.find((option) => option.id === mode) ?? loginModes[0];

  function switchMode(next: LoginMode) {
    if (next === mode || submitting) {
      return;
    }
    setMode(next);
    setDraft("");
    setSubmitError(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const credential = draft.trim();
    if (!credential || submitting) {
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      await onSubmit(mode, credential);
      setDraft("");
    } catch (cause: unknown) {
      setSubmitError(errorMessage(cause));
    } finally {
      setSubmitting(false);
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
              建立安全会话后进入审计页面。登录完成后页面不会继续保留凭据，也不会写入浏览器存储。
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
          {submitError ? (
            <Alert className="mb-5 border-red-200 bg-red-50/90">
              <AlertTitle className="text-red-900">登录失败</AlertTitle>
              <AlertDescription className="text-red-800">{submitError}</AlertDescription>
            </Alert>
          ) : null}
          <div className="mb-5 grid grid-cols-2 gap-2 rounded-lg bg-slate-100 p-1" role="tablist">
            {loginModes.map((option) => (
              <button
                key={option.id}
                type="button"
                role="tab"
                aria-selected={option.id === mode}
                onClick={() => switchMode(option.id)}
                disabled={submitting}
                className={
                  option.id === mode
                    ? "rounded-md bg-white px-3 py-2 text-sm font-medium text-slate-900 shadow-sm"
                    : "rounded-md px-3 py-2 text-sm font-medium text-slate-600 hover:text-slate-900"
                }
              >
                {option.label}
              </button>
            ))}
          </div>
          <form className="space-y-4" onSubmit={submit}>
            <div className="space-y-2">
              <label htmlFor="login-credential" className="text-sm font-medium">
                {active.field}
              </label>
              <Input
                id="login-credential"
                autoFocus
                autoComplete="off"
                name="login-credential"
                type="password"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder={active.placeholder}
                disabled={submitting}
              />
              <p className="text-xs leading-relaxed text-muted-foreground">{active.hint}</p>
            </div>
            <Button className="w-full" type="submit" disabled={!draft.trim() || submitting}>
              {submitting ? "正在登录…" : "进入审计页面"}
            </Button>
          </form>
          <p className="mt-5 text-center text-xs leading-relaxed text-muted-foreground">
            登录成功后仅使用服务端设置的 HttpOnly Cookie；页面不会使用 localStorage 或 sessionStorage 保存凭据。
          </p>
        </CardContent>
      </Card>
    </main>
  );
}

function Dashboard({
  client,
  session,
  checkingSession,
  onLogOut,
}: {
  client: ApiClient;
  session: SessionInfo | null;
  checkingSession: boolean;
  onLogOut: () => Promise<void>;
}) {
  // A developer session is scoped to one API key server side. The UI hides the
  // surfaces that scope excludes; the boundary itself is enforced by the API.
  const isDeveloper = session?.role === "developer";
  const [view, setView] = useState<"audits" | "rules">("audits");
  const [page, setPage] = useState<{ items: AuditSummary[]; next_cursor: AuditCursor | null }>({
    items: [],
    next_cursor: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [draftPath, setDraftPath] = useState("");
  const [draftModel, setDraftModel] = useState("");
  const [draftUserAgent, setDraftUserAgent] = useState("");
	const [draftNewAPIUserID, setDraftNewAPIUserID] = useState("");
  const [draftNewAPITokenID, setDraftNewAPITokenID] = useState("");
  const [draftForwardStatus, setDraftForwardStatus] = useState("");
  const [newAPIUsers, setNewAPIUsers] = useState<NewAPIUser[]>([]);
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

  useEffect(() => {
    // The caller directory is administrator-only; a developer already knows
    // whose traffic they are looking at.
    if (isDeveloper) {
      setNewAPIUsers([]);
      return;
    }
    const controller = new AbortController();
    client
      .listNewAPICallers(controller.signal)
	  .then((result) => setNewAPIUsers(result.items))
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
		  setNewAPIUsers([]);
        }
      });
    return () => controller.abort();
  }, [client, isDeveloper, refreshKey]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCursor(null);
    setCursorHistory([]);
    setFilters({
      path: draftPath.trim() || undefined,
      model: draftModel.trim() || undefined,
      user_agent: draftUserAgent.trim() || undefined,
      // Caller filters are rejected outright for a scoped session, so they must
      // never be sent.
	  newapi_user_id: isDeveloper ? undefined : draftNewAPIUserID || undefined,
      newapi_token_id: isDeveloper ? undefined : draftNewAPITokenID || undefined,
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
            {isDeveloper ? (
              <DeveloperBadge identity={session?.identity ?? null} />
            ) : (
              <>
                <Button variant={view === "audits" ? "secondary" : "ghost"} size="sm" onClick={() => setView("audits")}>
                  审计记录
                </Button>
                <Button variant={view === "rules" ? "secondary" : "ghost"} size="sm" onClick={() => setView("rules")}>
                  UA 拦截规则
                </Button>
              </>
            )}
            <Button variant="outline" size="sm" onClick={() => setRefreshKey((value) => value + 1)} disabled={loading}>
              <RefreshIcon />
              <span className="ml-2 hidden sm:inline">刷新</span>
            </Button>
            <Button variant="ghost" size="sm" onClick={() => void onLogOut()}>
              退出
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] space-y-5 px-4 py-5 sm:px-6 lg:px-8">
        {view === "rules" && !isDeveloper ? (
          <UserAgentRulesPanel client={client} />
        ) : (
          <>
        <AuditFiltersPanel
          path={draftPath}
          model={draftModel}
          userAgent={draftUserAgent}
		  newAPIUserID={draftNewAPIUserID}
          newAPITokenID={draftNewAPITokenID}
          forwardStatus={draftForwardStatus}
		  users={newAPIUsers}
          showCallerFilters={!isDeveloper}
          onPathChange={setDraftPath}
          onModelChange={setDraftModel}
          onUserAgentChange={setDraftUserAgent}
		  onNewAPIUserIDChange={setDraftNewAPIUserID}
          onNewAPITokenIDChange={setDraftNewAPITokenID}
          onForwardStatusChange={setDraftForwardStatus}
          onSubmit={applyFilters}
        />

        {checkingSession ? (
          <Alert className="border-blue-200 bg-blue-50/80">
            <AlertDescription className="text-blue-800">正在检查已有管理会话…</AlertDescription>
          </Alert>
        ) : null}

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
          </>
        )}
      </main>
    </div>
  );
}

const emptyRuleInput: UserAgentRuleInput = {
  name: "",
  enabled: true,
  model_pattern: "",
  user_agent_pattern: "",
};

export function UserAgentRulesPanel({ client }: { client: ApiClient }) {
  const [rules, setRules] = useState<UserAgentRule[]>([]);
  const [draft, setDraft] = useState<UserAgentRuleInput>(emptyRuleInput);
  const [editingID, setEditingID] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    client
      .listUserAgentRules(controller.signal)
      .then((result) => setRules(result.items))
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
  }, [client, reloadKey]);

  function edit(rule: UserAgentRule) {
    setEditingID(rule.id);
    setDraft({
      name: rule.name,
      enabled: rule.enabled,
      model_pattern: rule.model_pattern,
      user_agent_pattern: rule.user_agent_pattern,
    });
    setError(null);
    setNotice(null);
  }

  function resetForm() {
    setEditingID(null);
    setDraft(emptyRuleInput);
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving) {
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      if (editingID === null) {
        await client.createUserAgentRule(draft);
        setNotice("规则已创建并立即生效。");
      } else {
        await client.updateUserAgentRule(editingID, draft);
        setNotice("规则已保存并立即生效。");
      }
      resetForm();
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setSaving(false);
    }
  }

  async function toggle(rule: UserAgentRule) {
    setError(null);
    setNotice(null);
    try {
      await client.updateUserAgentRule(rule.id, {
        name: rule.name,
        enabled: !rule.enabled,
        model_pattern: rule.model_pattern,
        user_agent_pattern: rule.user_agent_pattern,
      });
      setNotice(rule.enabled ? "规则已停用。" : "规则已启用并立即生效。");
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  async function remove(rule: UserAgentRule) {
    if (!window.confirm(`确认删除规则“${rule.name}”？删除后立即停止执行。`)) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await client.deleteUserAgentRule(rule.id);
      if (editingID === rule.id) {
        resetForm();
      }
      setNotice("规则已删除。");
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle>UA 拦截规则</CardTitle>
          <CardDescription>
            当模型正则命中时，请求的 User-Agent 必须命中对应正则，否则返回 HTTP 401。多条命中规则全部需要通过。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Alert className="border-blue-200 bg-blue-50/80">
            <AlertDescription className="text-blue-800">
              正则使用 Go RE2 语法，默认区分大小写；修改成功后无需重启。无效正则会被拒绝，当前生效规则保持不变。
            </AlertDescription>
          </Alert>
          {error ? (
            <Alert className="border-red-200 bg-red-50/90">
              <AlertTitle className="text-red-900">操作失败</AlertTitle>
              <AlertDescription className="text-red-800">{error}</AlertDescription>
            </Alert>
          ) : null}
          {notice ? (
            <Alert className="border-emerald-200 bg-emerald-50/90">
              <AlertDescription className="text-emerald-800">{notice}</AlertDescription>
            </Alert>
          ) : null}
          <form className="grid gap-4 lg:grid-cols-[minmax(180px,0.8fr)_minmax(220px,1fr)_minmax(220px,1fr)_auto]" onSubmit={save}>
            <FilterField label="规则名称" htmlFor="rule-name">
              <Input
                id="rule-name"
                value={draft.name}
                onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
                maxLength={128}
                required
                placeholder="例如：GPT 桌面客户端限定"
              />
            </FilterField>
            <FilterField label="模型正则" htmlFor="model-pattern">
              <Input
                id="model-pattern"
                className="font-mono"
                value={draft.model_pattern}
                onChange={(event) => setDraft((current) => ({ ...current, model_pattern: event.target.value }))}
                maxLength={2048}
                required
                placeholder="^gpt"
              />
            </FilterField>
            <FilterField label="User-Agent 正则" htmlFor="ua-pattern">
              <Input
                id="ua-pattern"
                className="font-mono"
                value={draft.user_agent_pattern}
                onChange={(event) => setDraft((current) => ({ ...current, user_agent_pattern: event.target.value }))}
                maxLength={2048}
                required
                placeholder="Codex Desktop"
              />
            </FilterField>
            <div className="flex flex-wrap items-end gap-2">
              <label className="flex h-10 items-center gap-2 rounded-md border bg-white/90 px-3 text-sm">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))}
                />
                启用
              </label>
              <Button type="submit" disabled={saving || !draft.name.trim() || !draft.model_pattern.trim() || !draft.user_agent_pattern.trim()}>
                {saving ? "保存中…" : editingID === null ? "新增规则" : "保存修改"}
              </Button>
              {editingID !== null ? (
                <Button variant="outline" onClick={resetForm}>取消</Button>
              ) : null}
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="text-base">当前规则</CardTitle>
            <CardDescription>{rules.length} 条 · 启用的规则即时参与请求判断</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={() => setReloadKey((value) => value + 1)} disabled={loading}>刷新</Button>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-32 w-full" />
          ) : rules.length === 0 ? (
            <EmptyValue>当前没有 UA 拦截规则。</EmptyValue>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>状态</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>模型正则</TableHead>
                    <TableHead>User-Agent 正则</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell><Badge variant={rule.enabled ? "success" : "outline"}>{rule.enabled ? "启用" : "停用"}</Badge></TableCell>
                      <TableCell className="font-medium">{rule.name}</TableCell>
                      <TableCell className="font-mono text-xs">{rule.model_pattern}</TableCell>
                      <TableCell className="font-mono text-xs">{rule.user_agent_pattern}</TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" onClick={() => edit(rule)}>编辑</Button>
                          <Button variant="outline" size="sm" onClick={() => void toggle(rule)}>{rule.enabled ? "停用" : "启用"}</Button>
                          <Button variant="destructive" size="sm" onClick={() => void remove(rule)}>删除</Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function AuditFiltersPanel({
  path,
  model,
  userAgent,
	newAPIUserID,
  newAPITokenID,
  forwardStatus,
	users,
  showCallerFilters = true,
  onPathChange,
  onModelChange,
  onUserAgentChange,
	onNewAPIUserIDChange,
  onNewAPITokenIDChange,
  onForwardStatusChange,
  onSubmit,
}: {
  path: string;
  model: string;
  userAgent: string;
	newAPIUserID: string;
  newAPITokenID: string;
  forwardStatus: string;
	users: NewAPIUser[];
  /** Hidden for a scoped session, whose caller is already fixed. */
  showCallerFilters?: boolean;
  onPathChange: (value: string) => void;
  onModelChange: (value: string) => void;
  onUserAgentChange: (value: string) => void;
	onNewAPIUserIDChange: (value: string) => void;
  onNewAPITokenIDChange: (value: string) => void;
  onForwardStatusChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <Card className="bg-white/85 shadow-sm">
      <CardContent className="!p-3">
        <form className="space-y-2" aria-label="审计筛选" onSubmit={onSubmit}>
          <div className="grid items-end gap-2 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1.2fr)_minmax(160px,0.8fr)_minmax(240px,1.25fr)_auto]">
			{showCallerFilters ? (
			<FilterField label="调用者" htmlFor="filter-caller">
              <select
				id="filter-caller"
                className="h-9 w-full rounded-md border border-input bg-white px-3 text-sm shadow-sm outline-none focus:ring-2 focus:ring-ring"
				value={newAPIUserID}
				onChange={(event) => onNewAPIUserIDChange(event.target.value)}
              >
                <option value="">全部调用者</option>
				{users.map((user) => (
				  <option key={user.id} value={String(user.id)}>
					{user.display_name?.trim() || user.username} · @{user.username}
                  </option>
                ))}
              </select>
            </FilterField>
			) : null}
            <FilterField label="模型" htmlFor="filter-model">
              <Input
                id="filter-model"
                className="h-9"
                value={model}
                onChange={(event) => onModelChange(event.target.value)}
                placeholder="如 gpt-4o"
              />
            </FilterField>
            <FilterField label="User-Agent" htmlFor="filter-user-agent">
              <Input
                id="filter-user-agent"
                className="h-9"
                value={userAgent}
                onChange={(event) => onUserAgentChange(event.target.value)}
                placeholder="客户端标识"
              />
            </FilterField>
            <div className="flex h-9 items-center xl:justify-end">
              <Button className="h-9 w-full sm:w-auto" size="sm" type="submit">
                应用筛选
              </Button>
            </div>
          </div>

          <details className="rounded-md border bg-slate-50/60">
            <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground">
			  {showCallerFilters ? "高级筛选（路径、Token ID、转发状态）" : "高级筛选（路径、转发状态）"}
            </summary>
			<div className="grid gap-2 border-t px-3 py-2.5 sm:grid-cols-3">
              <FilterField label="路径" htmlFor="filter-path">
                <Input
                  id="filter-path"
                  className="h-9"
                  value={path}
                  onChange={(event) => onPathChange(event.target.value)}
                  placeholder="/v1/chat/completions"
                />
              </FilterField>
			  {showCallerFilters ? (
			  <FilterField label="NewAPI Token ID" htmlFor="filter-token-id">
				<Input
				  id="filter-token-id"
				  className="h-9"
				  inputMode="numeric"
				  value={newAPITokenID}
				  onChange={(event) => onNewAPITokenIDChange(event.target.value)}
				  placeholder="如 42"
				/>
			  </FilterField>
			  ) : null}
              <FilterField label="转发状态" htmlFor="filter-forward-status">
                <select
                  id="filter-forward-status"
                  className="h-9 w-full rounded-md border border-input bg-white px-3 text-sm shadow-sm outline-none focus:ring-2 focus:ring-ring"
                  value={forwardStatus}
                  onChange={(event) => onForwardStatusChange(event.target.value)}
                >
                  <option value="">全部状态</option>
                  <option value="completed">正常完成</option>
                  <option value="rejected">已拦截</option>
                  <option value="client_cancelled">客户端取消</option>
                  <option value="newapi_error">上游错误</option>
                  <option value="proxy_error">代理错误</option>
                  <option value="interrupted">意外中断</option>
                </select>
              </FilterField>
            </div>
          </details>
        </form>
      </CardContent>
    </Card>
  );
}

export function AuditList({
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
      <div className="flex items-center justify-between gap-3 border-b px-4 py-2.5 text-left">
        <div className="min-w-0">
          <CardTitle className="text-sm leading-5">审计记录</CardTitle>
          <CardDescription className="mt-0.5 truncate text-[11px]">按调用者、模型和客户端查看</CardDescription>
        </div>
        {loading ? <Badge variant="secondary">加载中</Badge> : <Badge variant="outline">{items.length} 条</Badge>}
      </div>
      <CardContent className="p-0">
        {loading ? (
          <div className="space-y-2 p-3">
            {Array.from({ length: 7 }, (_, index) => (
              <Skeleton key={index} className="h-[5rem] w-full" />
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
          <ul className="divide-y" aria-label="审计记录列表">
            {items.map((audit) => {
              const selected = audit.audit_id === selectedID;
              const model = audit.response_model?.trim() || audit.request_model?.trim() || "未记录";
              const userAgent = audit.user_agent?.trim() || "未记录";
              const status = auditStatusSummary(audit);
              return (
                <li key={audit.audit_id}>
                  <button
                    type="button"
                    aria-current={selected ? "true" : undefined}
                    className={`block w-full min-w-0 px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring ${
                      selected ? "bg-blue-50/90 hover:bg-blue-50" : "hover:bg-slate-50"
                    }`}
                    onClick={() => onSelect(audit.audit_id)}
                  >
                    <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="text-[11px] tabular-nums text-muted-foreground">
                        {formatNanoTime(audit.started_at_ns)}
                      </span>
                      {status ? <span className="text-[11px] font-medium text-amber-700">{status}</span> : null}
                    </span>
                    <span className="mt-2 grid min-w-0 gap-x-5 gap-y-2 sm:grid-cols-[minmax(10rem,0.85fr)_minmax(6.5rem,0.4fr)_minmax(16rem,2fr)]">
                      <CallerValue audit={audit} />
                      <ListValue label="模型" value={model} mono />
                      <ListValue label="User-Agent" value={userAgent} mono wrap />
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function CallerValue({ audit }: { audit: AuditSummary }) {
  const name = audit.display_name?.trim() || audit.username?.trim();
  const tokenName = audit.token_name?.trim();
  const tokenID = audit.newapi_token_id;
  const hasTokenID = tokenID !== null && tokenID !== undefined && String(tokenID).trim() !== "";
  const fallback = audit.caller_status === "pending"
    ? "识别中"
    : audit.caller_status === "unresolved"
      ? "未识别"
      : "未关联";

  return (
    <span className="min-w-0">
      <span className="block text-[10px] leading-none text-muted-foreground">调用者</span>
      <span className="mt-1 block truncate text-sm font-medium" title={name || fallback}>
        {name || fallback}
      </span>
      {tokenName ? (
        <span className="mt-1 block break-words text-xs leading-4 text-slate-600" title={tokenName}>
          {tokenName}
        </span>
      ) : null}
      {hasTokenID ? (
        <span className="block font-mono text-[11px] leading-4 text-muted-foreground">ID: {tokenID}</span>
      ) : null}
    </span>
  );
}

function ListValue({
  label,
  value,
  mono = false,
  wrap = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  wrap?: boolean;
}) {
  return (
    <span className="min-w-0">
      <span className="block text-[10px] leading-none text-muted-foreground">{label}</span>
      <span
        className={`mt-1 block text-sm font-medium ${wrap ? "whitespace-normal break-words leading-5" : "truncate"} ${
          mono ? "font-mono text-xs" : ""
        }`}
        title={value}
      >
        {value}
      </span>
    </span>
  );
}

function auditStatusSummary(audit: AuditSummary): string | null {
  const httpFailure = typeof audit.status_code === "number" && audit.status_code >= 400;
  const forwardFailure = audit.forward_status !== "completed";
  if (!httpFailure && !forwardFailure) {
    return null;
  }

  const labels: Record<string, string> = {
    rejected: "已拦截",
    client_cancelled: "客户端取消",
    newapi_error: "上游错误",
    proxy_error: "代理错误",
    interrupted: "意外中断",
    in_progress: "处理中",
  };
  const parts = forwardFailure ? [labels[audit.forward_status] ?? "转发异常"] : [];
  if (httpFailure) {
    parts.push(`HTTP ${audit.status_code}`);
  }
  return parts.join(" · ");
}

function AuditDetailPanel({ client, auditID }: { client: ApiClient; auditID: string | null }) {
  const [detail, setDetail] = useState<AuditDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rawBodies, setRawBodies] = useState<Partial<Record<RawSide, LoadedRawBody>>>({});
  const [rawLoading, setRawLoading] = useState<RawSide | null>(null);
  const [rawNote, setRawNote] = useState<string | null>(null);
  const [reconstructedLoading, setReconstructedLoading] = useState<RawSide | null>(null);
  const [reconstructedNote, setReconstructedNote] = useState<string | null>(null);
  const [timelines, setTimelines] = useState<Partial<Record<RawSide, StreamTimeline>>>({});
  const [timelineLoading, setTimelineLoading] = useState<RawSide | null>(null);
  const [timelineNote, setTimelineNote] = useState<string | null>(null);
  const rawController = useRef<AbortController | null>(null);
  const reconstructedController = useRef<AbortController | null>(null);
  const timelineController = useRef<AbortController | null>(null);

  useEffect(() => {
    setRawNote(null);
    setRawBodies({});
    setRawLoading(null);
    setReconstructedNote(null);
    setReconstructedLoading(null);
    setTimelines({});
    setTimelineNote(null);
    setTimelineLoading(null);
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
      reconstructedController.current?.abort();
      reconstructedController.current = null;
      timelineController.current?.abort();
      timelineController.current = null;
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

  async function downloadReconstructed(side: RawSide) {
    if (!auditID) {
      return;
    }
    reconstructedController.current?.abort();
    const controller = new AbortController();
    reconstructedController.current = controller;
    setReconstructedLoading(side);
    setReconstructedNote(null);
    try {
      const result = await client.getReconstructedBody(auditID, side, controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      saveReconstructedDownload(result);
      setReconstructedNote(`${side === "request" ? "请求" : "响应"}已按内容对象和有序引用重建并下载。`);
    } catch (cause: unknown) {
      if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
        setReconstructedNote(errorMessage(cause));
      }
    } finally {
      if (reconstructedController.current === controller) {
        reconstructedController.current = null;
        setReconstructedLoading(null);
      }
    }
  }

  async function loadTimeline(side: RawSide) {
    if (!auditID || timelines[side]) {
      return;
    }
    timelineController.current?.abort();
    const controller = new AbortController();
    timelineController.current = controller;
    setTimelineLoading(side);
    setTimelineNote(null);
    try {
      const result = await client.getStreamTimeline(auditID, side, controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      setTimelines((current) => ({ ...current, [side]: result }));
    } catch (cause: unknown) {
      if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
        setTimelineNote(errorMessage(cause));
      }
    } finally {
      if (timelineController.current === controller) {
        timelineController.current = null;
        setTimelineLoading(null);
      }
    }
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

            <Section title="轮次与内容存储">
              <TurnStoragePanel
                detail={detail}
                loading={reconstructedLoading}
                note={reconstructedNote}
                onDownload={downloadReconstructed}
              />
            </Section>

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
                   ["TTFT", formatDurationNS(detail.audit.ttft_ns)],
                   ["转发", <StatusBadge value={detail.audit.forward_status} />],
                  ["捕获", <StatusBadge value={detail.audit.capture_status} />],
                  ["解析", <StatusBadge value={detail.audit.parse_status} />],
                  ["模式", detail.audit.mode ?? "—"],
                  ["Parser", detail.audit.parser_name ?? "—"],
				  ["调用者", callerSummary(detail.audit)],
				  ["NewAPI Request ID", detail.audit.newapi_request_id ?? "—"],
				  ["身份关联", callerStatusLabel(detail.audit.caller_status)],
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

            <Section title="流式响应时序">
              <StreamTimingPanel
                detail={detail}
                timelines={timelines}
                loading={timelineLoading}
                note={timelineNote}
                onLoad={loadTimeline}
              />
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

export function TurnStoragePanel({
  detail,
  loading,
  note,
  onDownload,
}: {
  detail: AuditDetail;
  loading: RawSide | null;
  note: string | null;
  onDownload: (side: RawSide) => void;
}) {
  const turn = detail.turn;
  if (!turn) {
    return <EmptyValue>当前请求没有可用的内容寻址轮次；异常或暂不支持的协议会继续保留完整原始证据。</EmptyValue>;
  }

  return (
    <div className="space-y-4">
      <Alert className={turn.reconstruction_status === "verified" ? "border-emerald-200 bg-emerald-50/70" : "border-red-200 bg-red-50"}>
        <AlertTitle>{turn.reconstruction_status === "verified" ? "轮次已通过精确重建校验" : "轮次重建校验失败"}</AlertTitle>
        <AlertDescription>
          请求与响应由有序内容引用、二进制对象和协议 envelope 重建；哈希用于验证重建结果与当时的 HTTP Body 一致。
        </AlertDescription>
      </Alert>
      <DefinitionGrid
        items={[
          ["Conversation ID", monoValue(turn.conversation_id)],
          ["Turn ID", monoValue(turn.turn_id)],
          ["父轮次", turn.parent_turn_id ? monoValue(turn.parent_turn_id) : "根轮次"],
          ["父上下文基准", turn.parent_base],
          ["关联原因", turnLinkLabel(turn.link_reason)],
          ["关联置信度", `${turn.link_confidence}%`],
          ["请求 / 响应 item", `${turn.request_item_count} / ${turn.response_item_count}`],
          ["请求 / 响应布局", `${turn.request_layout} / ${turn.response_layout}`],
          ["Previous Response ID", turn.previous_response_id ? monoValue(turn.previous_response_id) : "—"],
          ["Response ID", turn.response_id ? monoValue(turn.response_id) : "—"],
          ["请求序列 SHA-256", hashValue(turn.request_sequence_sha256)],
          ["响应序列 SHA-256", hashValue(turn.response_sequence_sha256)],
          ["请求重建 SHA-256", hashValue(turn.request_reconstruction_sha256)],
          ["响应重建 SHA-256", hashValue(turn.response_reconstruction_sha256)],
        ]}
      />
      <div className="flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onDownload("request")}
          disabled={loading !== null || turn.reconstruction_status !== "verified"}
        >
          <DownloadIcon />
          <span className="ml-2">{loading === "request" ? "重建中…" : "下载重建请求 JSON"}</span>
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onDownload("response")}
          disabled={loading !== null || turn.reconstruction_status !== "verified"}
        >
          <DownloadIcon />
          <span className="ml-2">{loading === "response" ? "重建中…" : "下载重建响应 JSON"}</span>
        </Button>
      </div>
      {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
    </div>
  );
}

export function StreamTimingPanel({
  detail,
  timelines,
  loading,
  note,
  onLoad,
}: {
  detail: AuditDetail;
  timelines: Partial<Record<RawSide, StreamTimeline>>;
  loading: RawSide | null;
  note: string | null;
  onLoad: (side: RawSide) => void;
}) {
  const streams = (["request", "response"] as RawSide[])
    .map((side) => ({ side, body: bodyForSide(detail, side) }))
    .filter((entry): entry is { side: RawSide; body: AuditBody } => Boolean(entry.body && entry.body.stream_event_count > 0));

  return (
    <div className="space-y-3">
      <DefinitionGrid items={[["首字节时间（TTFT）", formatDurationNS(detail.audit.ttft_ns)]]} />
      {streams.length === 0 ? (
        <EmptyValue>该记录没有逻辑 SSE 事件时间线。</EmptyValue>
      ) : (
        streams.map(({ side, body }) => {
          const timeline = timelines[side];
          return (
            <div key={side} className="rounded-lg border bg-slate-50/60 p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold">{side === "request" ? "请求流" : "响应流"}</span>
                <Badge variant={body.stream_timeline_complete ? "success" : "warning"}>
                  {body.stream_timeline_complete ? "时间线完整" : "时间点已截断"}
                </Badge>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground sm:grid-cols-4">
                <span>逻辑事件</span>
                <span className="text-right tabular-nums text-foreground">{body.stream_event_count}</span>
                <span>已保存时间点</span>
                <span className="text-right tabular-nums text-foreground">{timeline?.points.length ?? "按需读取"}</span>
                <span>Body 首次观测</span>
                <span className="text-right text-foreground">{formatNanoTime(body.first_observed_at_ns)}</span>
                <span>Body 最后观测</span>
                <span className="text-right text-foreground">{formatNanoTime(body.last_observed_at_ns)}</span>
                {timeline ? (
                  <>
                    <span>首事件</span>
                    <span className="text-right text-foreground">{formatNanoTime(timeline.first_event_at_ns)}</span>
                    <span>末事件</span>
                    <span className="text-right text-foreground">{formatNanoTime(timeline.last_event_at_ns)}</span>
                  </>
                ) : null}
              </div>
              {!timeline ? (
                <Button variant="outline" size="sm" className="mt-3" onClick={() => onLoad(side)} disabled={loading !== null}>
                  <ViewIcon />
                  <span className="ml-2">{loading === side ? "读取中…" : "读取并校验事件时间线"}</span>
                </Button>
              ) : null}
            </div>
          );
        })
      )}
      {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
    </div>
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
  const body = bodyForSide(detail, side);
  const available = body?.retention_state === "full" && body.state !== "streaming";
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
        <div className="flex flex-wrap gap-2">
          {body ? <Badge variant="outline">{retentionLabel(body.retention_state)}</Badge> : null}
          <StatusBadge value={stage?.state} />
        </div>
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

        {!body ? (
          <EmptyValue>该审计边界没有捕获 Body。</EmptyValue>
        ) : body.retention_state === "metadata" ? (
          <Alert className="border-emerald-200 bg-emerald-50/70">
            <AlertTitle>原始 Body 已完成校验并释放</AlertTitle>
            <AlertDescription>
              长期保留原始长度、SHA-256、Content-Type 和完整性链；请求与响应可从内容对象精确重建，因此不再提供会返回 410 的 raw 下载。
            </AlertDescription>
          </Alert>
        ) : body.retention_state === "pending" || body.state === "streaming" ? (
          <Alert className="bg-slate-50">
            <AlertTitle>Body 正在处理</AlertTitle>
            <AlertDescription>解析、重建验证和保留策略尚未完成，稍后刷新后再查看证据状态。</AlertDescription>
          </Alert>
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

      {available ? <div className="mt-3 flex flex-wrap gap-2">
        {!loaded ? (
          <Button variant="outline" size="sm" onClick={onLoad} disabled={busy}>
            <ViewIcon />
            <span className="ml-2">{loading ? "加载中…" : "加载并查看 Body"}</span>
          </Button>
        ) : (
          <Button variant="ghost" size="sm" onClick={onClear} disabled={busy}>
            从页面清除 Body
          </Button>
        )}
        <Button variant="outline" size="sm" onClick={onDownload} disabled={busy}>
          <DownloadIcon />
          <span className="ml-2">{loading ? "读取中…" : "下载原始 Body"}</span>
        </Button>
      </div> : null}
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
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline">{retentionLabel(body.retention_state)}</Badge>
              <StatusBadge value={body.state} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground">
            <span>字节来源阶段</span>
            <span className="text-right text-foreground">{humanizeStage(body.source_stage)}</span>
            <span>观察长度</span>
            <span className="text-right tabular-nums text-foreground">{formatBytes(body.observed_length)}</span>
            <span>长期 raw 字节</span>
            <span className="text-right tabular-nums text-foreground">{formatBytes(body.stored_length)}</span>
            <span>raw 分块</span>
            <span className="text-right tabular-nums text-foreground">{body.chunk_count}</span>
            <span>SSE 逻辑事件</span>
            <span className="text-right tabular-nums text-foreground">{body.stream_event_count}</span>
            <span>SHA-256</span>
            <span className="truncate text-right font-mono text-foreground" title={body.sha256 ?? undefined}>
              {shortHash(body.sha256)}
            </span>
            <span>完整</span>
            <span className="text-right text-foreground">{body.hash_complete && body.eof_seen ? "是" : "否"}</span>
            <span>首次 / 最后观测</span>
            <span className="text-right text-foreground">
              {formatNanoTime(body.first_observed_at_ns)} / {formatNanoTime(body.last_observed_at_ns)}
            </span>
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

function FilterField({ label, htmlFor, children }: { label: string; htmlFor: string; children: ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="min-w-0 space-y-1">
      <span className="block text-[11px] font-medium leading-none text-muted-foreground">{label}</span>
      {children}
    </label>
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

function monoValue(value: string): ReactNode {
  return <span className="break-all font-mono text-xs" title={value}>{value}</span>;
}

function hashValue(value: string): ReactNode {
  return <span className="font-mono text-xs" title={value}>{shortHash(value)}</span>;
}

function turnLinkLabel(reason: string): string {
  return ({
    root: "根轮次",
    continuation: "连续对话",
    retry: "重试",
    branch: "分支",
    context_edit: "上下文编辑 / 截断",
    retention_checkpoint: "保留期独立检查点",
  } as Record<string, string>)[reason] ?? reason;
}

function retentionLabel(state: string): string {
  return ({
    pending: "保留策略处理中",
    metadata: "仅元数据 + 可重建对象",
    full: "完整原始证据",
  } as Record<string, string>)[state] ?? state;
}

function callerSummary(audit: AuditSummary): string {
  if (audit.caller_status === "pending") {
	return "识别中";
  }
  const callerName = audit.display_name?.trim() || audit.username?.trim();
  const token = audit.token_name?.trim();
  if (!callerName && !token) {
	return audit.caller_status === "unresolved" ? "未识别" : "未关联";
  }
	const tokenID = audit.newapi_token_id;
	const hasTokenID = tokenID !== null && tokenID !== undefined && String(tokenID).trim() !== "";
  return [callerName || "", token || "", hasTokenID ? `ID: ${tokenID}` : ""]
	.filter(Boolean)
	.join(" · ");
}

function callerStatusLabel(status: string | null | undefined): string {
  return ({ none: "未关联", pending: "识别中", resolved: "已关联", unresolved: "未识别" } as Record<string, string>)[status ?? "none"] ?? status ?? "未关联";
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

// DeveloperBadge tells a scoped user whose traffic they are looking at, which
// is the whole answer to "why is this list shorter than I expected".
export function DeveloperBadge({ identity }: { identity: DeveloperIdentity | null }) {
  const name = identity?.token_name?.trim() || identity?.username?.trim();
  return (
    <div className="flex items-center gap-2" title="仅显示该 API Key 产生的调用记录">
      <Badge variant="secondary">开发者</Badge>
      <span className="hidden max-w-[16rem] truncate text-xs text-muted-foreground sm:inline">
        {name ? `${name} 的调用记录` : "本 API Key 的调用记录"}
      </span>
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

function saveDownload(download: RawBodyDownload) {
  saveBlob(download.blob, download.filename);
}

function saveReconstructedDownload(download: ReconstructedBodyDownload) {
  saveBlob(download.blob, download.filename);
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function downloadMessage(side: RawSide, download: RawBodyDownload): string {
  return `${side === "request" ? "请求" : "响应"}原始 Body 已下载（${formatBytes(download.storedLength)}，${download.complete ? "完整" : "不完整"}）。`;
}

function bodyForSide(detail: AuditDetail, side: RawSide): AuditBody | undefined {
  const expectedStage = side === "request" ? "request_sent_to_newapi" : "response_received_from_newapi";
  return detail.bodies.find((body) => body.stage === expectedStage);
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
