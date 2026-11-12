import { useEffect, useState, type FormEvent, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import { orgDraftChanged, orgDraftFromSettings, orgUpdateFromDraft, type OrgSettingsDraft } from "../../lib/settings/org";
import type { OrgSettingsView } from "../../lib/settings/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";
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

/** The weekly report fields the page edits, and the two it only shows. Pure. */
export function OrgSettingsFields({
  view,
  draft,
  busy,
  onChange,
}: {
  view: OrgSettingsView;
  draft: OrgSettingsDraft;
  busy: boolean;
  onChange: (patch: Partial<OrgSettingsDraft>) => void;
}) {
  const text = (key: keyof OrgSettingsDraft) => ({
    id: `org-${key}`,
    value: draft[key],
    disabled: busy,
    onChange: (event: { target: { value: string } }) => onChange({ [key]: event.target.value }),
  });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-body-sm">
        {view.source === "saved" ? <Badge variant="info">页面保存的设置，覆盖配置文件</Badge> : <Badge variant="neutral">来自配置文件</Badge>}
        {view.source === "saved" && view.updated_ns ? <span className="text-subtle">保存于 {formatSaved(view.updated_ns)}</span> : null}
        <span className="text-subtle">保存后，未冻结的周立即按新值计算；已冻结的周保持原来的快照，要在项目周报页点“重新生成”。</span>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="活跃时长的合并间隔（秒）" htmlFor="org-idle_gap_seconds" hint="同一根会话里，两次请求间隔不超过这个值就算连续活跃。1–3600。">
          <Input {...text("idle_gap_seconds")} inputMode="numeric" className="max-w-32" />
        </Field>
        <Field label="进入时长排名的客户端" htmlFor="org-ranked_clients" hint="词表里的客户端键，小写，用逗号分隔。其他客户端的时长单独显示，不进排名。">
          <Input {...text("ranked_clients")} spellCheck={false} autoComplete="off" />
        </Field>
        <Field label="并行根会话标记阈值" htmlFor="org-max_concurrent_roots" hint="一周内同时进行的根会话峰值超过它就打标记。">
          <Input {...text("max_concurrent_roots")} inputMode="numeric" className="max-w-32" />
        </Field>
        <Field label="单请求根会话标记阈值" htmlFor="org-max_single_request_roots" hint="一周内只有一次请求的根会话数超过它就打标记。">
          <Input {...text("max_single_request_roots")} inputMode="numeric" className="max-w-32" />
        </Field>
      </div>
      <div>
        <h4 className="text-body-sm font-semibold">只能在配置文件里改的项</h4>
        <p className="text-label text-subtle">它们决定每一周从哪里开始、到哪里结束，改动会移动已经保存的周的边界；改动后需要重启服务。</p>
        <dl className="mt-1">
          {[
            ["时区", view.timezone, "org_reports.timezone"],
            ["每周起始日", view.week_start === "sunday" ? "周日" : "周一", "org_reports.week_start"],
          ].map(([label, value, key]) => (
            <div key={key} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b py-1.5 last:border-b-0">
              <dt className="w-44 shrink-0 text-body-sm text-muted">{label}</dt>
              <dd className="min-w-0 flex-1 text-body-sm">{value}</dd>
              <span className="font-mono text-label text-subtle">{key}</span>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

/** Settings section "项目周报": loads the settings in use, saves or resets them. */
export function OrgSettingsCard({ client }: { client: ApiClient }) {
  const [view, setView] = useState<OrgSettingsView | null>(null);
  const [draft, setDraft] = useState<OrgSettingsDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function show(next: OrgSettingsView) {
    setView(next);
    setDraft(orgDraftFromSettings(next.settings));
  }

  useEffect(() => {
    const controller = new AbortController();
    client
      .getOrgReportSettings(controller.signal)
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
      show(await client.saveOrgReportSettings(orgUpdateFromDraft(draft)));
      setNotice("已保存，未冻结的周已按新值计算。");
    });
  }

  function reset() {
    void run(async () => {
      show(await client.resetOrgReportSettings());
      setNotice("已恢复为配置文件里的值。");
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>项目周报</CardTitle>
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
            <Skeleton className="h-40 w-full" />
          )
        ) : (
          <form className="space-y-4" onSubmit={save}>
            <OrgSettingsFields view={view} draft={draft} busy={busy} onChange={(patch) => setDraft((current) => (current ? { ...current, ...patch } : current))} />
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={busy || !orgDraftChanged(draft, view)}>
                保存
              </Button>
              {view.source === "saved" ? (
                <Button type="button" variant="ghost" disabled={busy} onClick={reset}>
                  恢复为配置文件的值
                </Button>
              ) : null}
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
