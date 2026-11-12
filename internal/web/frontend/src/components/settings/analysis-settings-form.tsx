import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import {
  contextBudget,
  draftChanged,
  draftFromSettings,
  keySourceLabel,
  probeSummary,
  updateFromDraft,
  type AnalysisSettingsDraft,
} from "../../lib/settings/analysis";
import type { AnalysisProbeResult, AnalysisSettingsView } from "../../lib/settings/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";
import { Select } from "../ui/select";
import { Skeleton } from "../ui/skeleton";

function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <label htmlFor={htmlFor} className="block text-body-sm font-medium">
        {label}
      </label>
      {children}
      {hint ? <p className="text-label text-subtle">{hint}</p> : null}
    </div>
  );
}

function formatSaved(ns: string | undefined): string {
  if (!ns) {
    return "";
  }
  return new Date(Number(BigInt(ns) / 1_000_000n)).toLocaleString("zh-CN", { hour12: false });
}

/**
 * The editable settings of session analysis and of its model stage. Pure:
 * the card below owns loading and saving.
 */
export function AnalysisSettingsFields({
  view,
  draft,
  busy,
  onChange,
}: {
  view: AnalysisSettingsView;
  draft: AnalysisSettingsDraft;
  busy: boolean;
  onChange: (patch: Partial<AnalysisSettingsDraft>) => void;
}) {
  const budget = contextBudget(draft, view);
  const modelChanged = draft.model.trim() !== view.settings.llm.model && view.settings.llm.model !== "";
  const text = (key: keyof AnalysisSettingsDraft) => ({
    id: `analysis-${key}`,
    value: draft[key] as string,
    disabled: busy,
    onChange: (event: { target: { value: string } }) => onChange({ [key]: event.target.value }),
  });
  return (
    <div className="space-y-4">
      <fieldset className="space-y-3">
        <legend className="text-body font-semibold">运行</legend>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="每天运行时间" htmlFor="analysis-run_at" hint="24 小时制 HH:MM，按服务所用的时区。改了之后立即按新时间排程。">
            <Input {...text("run_at")} placeholder="02:00" inputMode="numeric" maxLength={5} className="max-w-32" />
          </Field>
          <Field label="会话静默多久后再标注" htmlFor="analysis-l1_settle_hours" hint="单位小时，0–336。静默不满这个时间的会话先不交给模型。">
            <Input {...text("l1_settle_hours")} inputMode="numeric" className="max-w-32" />
          </Field>
        </div>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="text-body font-semibold">模型</legend>
        <label className="flex items-center gap-2 text-body-sm">
          <input type="checkbox" checked={draft.enabled} disabled={busy} onChange={(event) => onChange({ enabled: event.target.checked })} />
          启用模型阶段（会话标注和周度复盘的叙述）。关闭后只计算确定性信号。
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="模型地址"
            htmlFor="analysis-base_url"
            hint={
              view.file_only.allow_non_local
                ? "OpenAI 兼容接口的地址。配置文件已放开非本地地址（allow_non_local）。"
                : "OpenAI 兼容接口的地址，只能是本机或内网地址。检查的是这个地址本身，网关之后转发到哪里不在检查范围内。"
            }
          >
            <Input {...text("base_url")} placeholder="http://127.0.0.1:11434/v1" spellCheck={false} autoComplete="off" />
          </Field>
          <Field label="模型名" htmlFor="analysis-model">
            <Input {...text("model")} spellCheck={false} autoComplete="off" />
          </Field>
        </div>
        {modelChanged ? (
          <Alert variant="warning">
            <AlertDescription>换模型后，已有的标注都不再算数：所有证据包会按“每轮最多会话数”分多轮重新标注，重新计费。</AlertDescription>
          </Alert>
        ) : null}
        <Field
          label="API Key"
          htmlFor="analysis-api_key"
          hint={`当前：${keySourceLabel(view)}。这里不会显示已有的 Key；留空表示不修改。`}
        >
          <div className="flex flex-wrap items-center gap-3">
            <Input
              id="analysis-api_key"
              type="password"
              value={draft.api_key}
              disabled={busy || draft.clear_key}
              autoComplete="new-password"
              placeholder={draft.clear_key ? "保存后不发送 Key" : "输入新的 Key"}
              className="max-w-sm"
              onChange={(event) => onChange({ api_key: event.target.value })}
            />
            <label className="flex items-center gap-2 text-body-sm">
              <input
                type="checkbox"
                checked={draft.clear_key}
                disabled={busy}
                onChange={(event) => onChange({ clear_key: event.target.checked, api_key: event.target.checked ? "" : draft.api_key })}
              />
              不使用 Key
            </label>
          </div>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="结构化输出方式" htmlFor="analysis-structured_output" hint="服务端不支持 json_schema 时改用后两种。">
            <Select
              id="analysis-structured_output"
              value={draft.structured_output}
              disabled={busy}
              onChange={(event) => onChange({ structured_output: event.target.value as AnalysisSettingsDraft["structured_output"] })}
            >
              <option value="json_schema">json_schema</option>
              <option value="json_object">json_object</option>
              <option value="prompt">prompt（只靠提示词）</option>
            </Select>
          </Field>
          <Field label="并发" htmlFor="analysis-max_concurrency" hint="同时发给模型的请求数，1–64。">
            <Input {...text("max_concurrency")} inputMode="numeric" className="max-w-32" />
          </Field>
          <Field label="每轮最多会话数" htmlFor="analysis-max_sessions_per_run" hint="一轮批处理最多标注多少个证据包。">
            <Input {...text("max_sessions_per_run")} inputMode="numeric" className="max-w-32" />
          </Field>
          <Field label="输出上限（Token）" htmlFor="analysis-max_output_tokens" hint="100–32768。思考内容也计入，过小会截断。">
            <Input {...text("max_output_tokens")} inputMode="numeric" className="max-w-32" />
          </Field>
          <Field label="上下文长度（Token）" htmlFor="analysis-context_tokens">
            <Input {...text("context_tokens")} inputMode="numeric" className="max-w-32" />
          </Field>
          <Field label="单次请求超时（秒）" htmlFor="analysis-timeout_seconds">
            <Input {...text("timeout_seconds")} inputMode="numeric" className="max-w-32" />
          </Field>
        </div>
        {budget ? (
          <p className={budget.fits ? "text-label text-subtle" : "text-label text-danger-fg"}>
            上下文预算：证据包 {view.file_only.pack_max_tokens} + 固定提示词 {view.file_only.prompt_reserve_tokens} + 输出上限 = {budget.used}，
            {budget.fits ? `不超过上下文长度 ${budget.limit}。` : `超过了上下文长度 ${budget.limit}，保存会被拒绝。`}
          </p>
        ) : null}
        <label className="flex items-center gap-2 text-body-sm">
          <input type="checkbox" checked={draft.disable_thinking} disabled={busy} onChange={(event) => onChange({ disable_thinking: event.target.checked })} />
          关闭思考模式（向模型发送关闭思考的开关）
        </label>
      </fieldset>
    </div>
  );
}

/** What the page cannot change: these are read from the configuration file. */
export function AnalysisFileOnly({ view }: { view: AnalysisSettingsView }) {
  const rows: Array<[string, string, string]> = [
    ["允许非本地的模型地址", view.file_only.allow_non_local ? "是" : "否", "session_analysis.llm.allow_non_local"],
    ["会话收口的静默时间", `${view.file_only.session_idle_minutes} 分钟`, "session_analysis.session_idle_minutes"],
    ["进入分析的最少用户轮次", `${view.file_only.min_user_turns}`, "session_analysis.min_user_turns"],
    ["进入分析的最少活跃时间", `${view.file_only.min_active_seconds} 秒`, "session_analysis.min_active_seconds"],
    ["证据包上限", `${view.file_only.pack_max_tokens} Token`, "session_analysis.pack.max_tokens"],
  ];
  return (
    <div>
      <h4 className="text-body-sm font-semibold">只能在配置文件里改的项</h4>
      <p className="text-label text-subtle">它们决定会话内容能不能发到外部，以及哪些会话被分析、证据包怎么切；改动后需要重启服务。</p>
      <dl className="mt-1">
        {rows.map(([label, value, key]) => (
          <div key={key} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b py-1.5 last:border-b-0">
            <dt className="w-44 shrink-0 text-body-sm text-muted">{label}</dt>
            <dd className="min-w-0 flex-1 text-body-sm">{value}</dd>
            <span className="font-mono text-label text-subtle">{key}</span>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function ProbeOutcome({ result }: { result: AnalysisProbeResult }) {
  const summary = probeSummary(result);
  return (
    <Alert variant={summary.tone}>
      <AlertDescription>
        <p>{summary.text}</p>
        {summary.notes.length > 0 ? (
          <ul className="mt-1 list-disc pl-5">
            {summary.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}

/** Where the settings in use come from, and when a change takes effect. */
export function AnalysisSettingsStatus({ view }: { view: AnalysisSettingsView }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-body-sm">
      {view.source === "saved" ? <Badge variant="info">页面保存的设置，覆盖配置文件</Badge> : <Badge variant="neutral">来自配置文件</Badge>}
      {view.source === "saved" && view.updated_ns ? <span className="text-subtle">保存于 {formatSaved(view.updated_ns)}</span> : null}
      <span className="text-subtle">{view.running ? "有一轮分析正在运行，它仍按旧设置跑完；改动从下一轮起生效。" : "改动从下一轮分析起生效，不需要重启服务。"}</span>
    </div>
  );
}

/**
 * Settings section "会话分析与周度复盘": loads the settings in use, lets an
 * administrator test, save or reset them.
 */
export function AnalysisSettingsCard({ client }: { client: ApiClient }) {
  const [view, setView] = useState<AnalysisSettingsView | null>(null);
  const [draft, setDraft] = useState<AnalysisSettingsDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [probe, setProbe] = useState<AnalysisProbeResult | null>(null);

  function show(next: AnalysisSettingsView) {
    setView(next);
    setDraft(draftFromSettings(next.settings));
  }

  useEffect(() => {
    const controller = new AbortController();
    client
      .getAnalysisSettings(controller.signal)
      .then(show)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [client]);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setBusy(false);
    }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft) {
      return;
    }
    void run(async () => {
      show(await client.saveAnalysisSettings(updateFromDraft(draft)));
      setProbe(null);
      setNotice("已保存，从下一轮分析起生效。");
    });
  }

  function test() {
    if (!draft) {
      return;
    }
    setProbe(null);
    void run(async () => setProbe(await client.testAnalysisSettings(updateFromDraft(draft))));
  }

  function reset() {
    void run(async () => {
      show(await client.resetAnalysisSettings());
      setProbe(null);
      setNotice("已恢复为配置文件里的值。");
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>会话分析与周度复盘</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error ? (
          <Alert variant="danger">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {notice ? (
          <Alert variant="success">
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        ) : null}
        {!view || !draft ? (
          error ? null : (
            <Skeleton className="h-64 w-full" />
          )
        ) : (
          <form className="space-y-4" onSubmit={save}>
            <AnalysisSettingsStatus view={view} />
            <AnalysisSettingsFields view={view} draft={draft} busy={busy} onChange={(patch) => setDraft((current) => (current ? { ...current, ...patch } : current))} />
            {probe ? <ProbeOutcome result={probe} /> : null}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={busy || !draftChanged(draft, view)}>
                保存
              </Button>
              <Button type="button" variant="outline" disabled={busy} onClick={test} title="按表单里的值向模型地址发一条固定的测试请求，不发送任何会话内容，也不保存">
                测试连接
              </Button>
              {view.source === "saved" ? (
                <Button type="button" variant="ghost" disabled={busy} onClick={reset}>
                  恢复为配置文件的值
                </Button>
              ) : null}
              <span className="text-label text-subtle">测试只发送一条固定的“ping”，不含任何会话内容。</span>
            </div>
            <AnalysisFileOnly view={view} />
          </form>
        )}
      </CardContent>
    </Card>
  );
}
