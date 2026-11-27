import { useEffect, useState, type FormEvent } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import type { CaptureEditableSettings, CaptureSettingsView } from "../../lib/settings/types";
import { cn } from "../../lib/utils";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";
import { Skeleton } from "../ui/skeleton";

/** The largest retry count the server accepts. */
export const MAX_COMMIT_RETRIES = 5;

/** The form's working copy: the number stays text until sent. */
export interface CaptureSettingsDraft {
  commit_retries: string;
}

export function captureDraftFromView(view: CaptureSettingsView): CaptureSettingsDraft {
  return { commit_retries: String(view.settings.commit_retries) };
}

/** Not a whole number: sent as -1 so the server names the field and its range. */
export function captureUpdateFromDraft(draft: CaptureSettingsDraft): CaptureEditableSettings {
  const trimmed = draft.commit_retries.trim();
  return { commit_retries: /^\d+$/.test(trimmed) ? Number(trimmed) : -1 };
}

export function captureDraftChanged(draft: CaptureSettingsDraft, view: CaptureSettingsView): boolean {
  return captureUpdateFromDraft(draft).commit_retries !== view.settings.commit_retries;
}

/**
 * The wait before each retry, in milliseconds: 100 ms before the first,
 * doubling, at most one second (design B.8).
 */
export function retryDelaysMS(retries: number): number[] {
  const delays: number[] = [];
  for (let retry = 1; retry <= retries; retry++) {
    delays.push(Math.min(100 * 2 ** (retry - 1), 1000));
  }
  return delays;
}

/** The most the request handler waits in addition to the attempts themselves. */
export function worstCaseWaitMS(retries: number): number {
  return retryDelaysMS(retries).reduce((total, delay) => total + delay, 0);
}

export function formatWait(ms: number): string {
  return ms === 0 ? "不等待" : `${(ms / 1000).toFixed(1)} 秒`;
}

function formatSaved(ns: string | undefined): string {
  if (!ns) {
    return "";
  }
  return new Date(Number(BigInt(ns) / 1_000_000n)).toLocaleString("zh-CN", { hour12: false });
}

/** What the card shows: the view, the draft and the outcome of the last action. */
export interface CaptureFormState {
  view: CaptureSettingsView | null;
  draft: CaptureSettingsDraft | null;
  error: string | null;
  notice: string | null;
}

export const emptyCaptureForm: CaptureFormState = { view: null, draft: null, error: null, notice: null };

/** An expired session is handled by the sign-in flow, not shown here. */
function failureMessage(cause: unknown): string | null {
  if (isAbortError(cause) || (cause instanceof ApiError && cause.status === 401)) {
    return null;
  }
  return errorMessage(cause);
}

function shown(view: CaptureSettingsView, notice: string | null): CaptureFormState {
  return { view, draft: captureDraftFromView(view), error: null, notice };
}

/** Loads the setting in use. */
export async function loadCaptureForm(client: ApiClient, signal?: AbortSignal): Promise<CaptureFormState> {
  try {
    return shown(await client.getCaptureSettings(signal), null);
  } catch (cause: unknown) {
    return { ...emptyCaptureForm, error: failureMessage(cause) };
  }
}

/** Saves the draft; a rejected value keeps the draft and shows the server's message. */
export async function saveCaptureForm(client: ApiClient, state: CaptureFormState): Promise<CaptureFormState> {
  if (!state.draft) {
    return state;
  }
  try {
    return shown(await client.saveCaptureSettings(captureUpdateFromDraft(state.draft)), "已保存，之后开始的终结提交按新的次数重试。");
  } catch (cause: unknown) {
    return { ...state, error: failureMessage(cause), notice: null };
  }
}

/** Drops the saved value; the configuration file applies again. */
export async function resetCaptureForm(client: ApiClient, state: CaptureFormState): Promise<CaptureFormState> {
  try {
    return shown(await client.resetCaptureSettings(), "已恢复为配置文件里的值。");
  } catch (cause: unknown) {
    return { ...state, error: failureMessage(cause), notice: null };
  }
}

/** The retry field with what it does and what each value costs. Pure. */
export function CaptureSettingsFields({
  view,
  draft,
  busy,
  onChange,
}: {
  view: CaptureSettingsView;
  draft: CaptureSettingsDraft;
  busy: boolean;
  onChange: (next: CaptureSettingsDraft) => void;
}) {
  const edited = captureUpdateFromDraft(draft).commit_retries;
  const valid = edited >= 0 && edited <= MAX_COMMIT_RETRIES;
  const values = Array.from({ length: MAX_COMMIT_RETRIES + 1 }, (_, index) => index);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-body-sm">
        {view.source === "saved" ? <Badge variant="info">页面保存的设置，覆盖配置文件</Badge> : <Badge variant="neutral">来自配置文件</Badge>}
        {view.source === "saved" && view.updated_ns ? <span className="text-subtle">保存于 {formatSaved(view.updated_ns)}</span> : null}
        <span className="text-subtle">保存后立即生效，不需要重启：之后开始的终结提交按新的次数重试。</span>
      </div>
      <p className="text-body-sm text-muted">
        一条请求结束时，它的审计记录在一次“终结提交”里写进数据库。这次写入因为写入队列已满或整批事务失败而没有成功时，按这里的次数重试；约束冲突这类重试也不会成功的错误不重试。重试都失败时，这条记录照常标为写入失败，由恢复流程收尾。
      </p>
      <p className="text-body-sm text-muted">
        只在 <span className="font-mono">audit.write_path</span> 为 <span className="font-mono">unified</span> 时生效；legacy 写入路径不使用这个值。
      </p>
      {view.write_path !== "unified" ? (
        <Alert variant="warning">
          <AlertDescription>
            当前写入路径是 <span className="font-mono">{view.write_path || "legacy"}</span>，这里的值保存后也不会被用到；配置文件改为 unified 并重启后才生效。
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="space-y-1">
        <label htmlFor="capture-commit_retries" className="block text-body-sm font-medium">
          终结提交失败时的重试次数
        </label>
        <Input
          id="capture-commit_retries"
          value={draft.commit_retries}
          disabled={busy}
          inputMode="numeric"
          className="max-w-32"
          onChange={(event) => onChange({ commit_retries: event.target.value })}
        />
        <p className="text-label text-subtle">
          0–{MAX_COMMIT_RETRIES}。0 表示只尝试一次，不重试。配置文件的值是 {view.file.commit_retries}（<span className="font-mono">audit.commit_retries</span>），恢复为配置文件的值后回到它。
        </p>
        {valid ? (
          <p className="text-label text-subtle">
            填 {edited} 时最多尝试 {edited + 1} 次，处理这条请求最多多等 {formatWait(worstCaseWaitMS(edited))}，另加各次尝试本身的时间。
          </p>
        ) : (
          <p className="text-label text-danger-fg">要填 0 到 {MAX_COMMIT_RETRIES} 之间的整数。</p>
        )}
      </div>
      <div>
        <h4 className="text-body-sm font-semibold">每个次数最多多等多久</h4>
        <p className="text-label text-subtle">第 1 次重试之前等 100 毫秒，之后每次翻倍，最长 1 秒。等待期间处理这条请求的函数还没有返回。</p>
        <dl className="mt-1">
          {values.map((value) => (
            <div key={value} className={cn("flex flex-wrap items-baseline gap-x-3 border-b py-1 last:border-b-0", value === edited && "font-semibold")}>
              <dt className="w-24 shrink-0 text-body-sm text-muted">重试 {value} 次</dt>
              <dd className="min-w-0 flex-1 text-body-sm">{formatWait(worstCaseWaitMS(value))}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

/** The card's content for one state: the alerts and the form. Pure. */
export function CaptureSettingsBody({
  state,
  busy,
  onChange,
  onSave,
  onReset,
}: {
  state: CaptureFormState;
  busy: boolean;
  onChange: (next: CaptureSettingsDraft) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  onReset: () => void;
}) {
  const { view, draft, error, notice } = state;
  return (
    <>
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
          <Skeleton className="h-40 w-full" />
        )
      ) : (
        <form className="space-y-4" onSubmit={onSave}>
          <CaptureSettingsFields view={view} draft={draft} busy={busy} onChange={onChange} />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={busy || !captureDraftChanged(draft, view)}>
              保存
            </Button>
            {view.source === "saved" ? (
              <Button type="button" variant="ghost" disabled={busy} onClick={onReset}>
                恢复为配置文件的值
              </Button>
            ) : null}
          </div>
        </form>
      )}
    </>
  );
}

/** Settings section "审计写入": loads the retry count in use, saves or resets it. */
export function CaptureSettingsCard({ client }: { client: ApiClient }) {
  const [state, setState] = useState<CaptureFormState>(emptyCaptureForm);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void loadCaptureForm(client, controller.signal).then((next) => {
      if (!controller.signal.aborted) {
        setState(next);
      }
    });
    return () => controller.abort();
  }, [client]);

  async function run(action: (current: CaptureFormState) => Promise<CaptureFormState>) {
    setBusy(true);
    setState((current) => ({ ...current, error: null, notice: null }));
    try {
      setState(await action(state));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>审计写入</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <CaptureSettingsBody
          state={state}
          busy={busy}
          onChange={(draft) => setState((current) => ({ ...current, draft }))}
          onSave={(event) => {
            event.preventDefault();
            void run((current) => saveCaptureForm(client, current));
          }}
          onReset={() => void run((current) => resetCaptureForm(client, current))}
        />
      </CardContent>
    </Card>
  );
}
