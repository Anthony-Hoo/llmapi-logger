import { useEffect, useState, type ReactNode } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import type { OrgSettings } from "../../lib/org/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { PageHeader } from "../ui/page-header";
import { Skeleton } from "../ui/skeleton";
import { AnalysisSettingsCard } from "./analysis-settings-form";

function Row({ label, configKey, children }: { label: string; configKey?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b py-1.5 last:border-b-0">
      <dt className="w-44 shrink-0 text-body-sm text-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-body-sm">{children}</dd>
      {configKey ? <span className="font-mono text-label text-subtle">{configKey}</span> : null}
    </div>
  );
}

/** The weekly report parameters as the server runs with them. */
export function OrgSettingsCard({ settings }: { settings: OrgSettings }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>项目周报</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-2 text-label text-subtle">这些参数来自服务的配置文件，这里只读；修改配置文件并重启服务后生效。</p>
        <dl>
          <Row label="时区" configKey="org_reports.timezone">
            {settings.timezone}
          </Row>
          <Row label="每周起始日" configKey="org_reports.week_start">
            {settings.week_start === "sunday" ? "周日" : "周一"}
          </Row>
          <Row label="活跃时长的合并间隔" configKey="org_reports.idle_gap_seconds">
            {settings.idle_gap_seconds} 秒
          </Row>
          <Row label="进入时长排名的客户端" configKey="org_reports.ranked_clients">
            {settings.ranked_clients.length > 0 ? settings.ranked_clients.join("、") : "无"}
          </Row>
          <Row label="并行根会话标记阈值" configKey="org_reports.flags.max_concurrent_roots">
            {settings.max_concurrent_roots}
          </Row>
          <Row label="单请求根会话标记阈值" configKey="org_reports.flags.max_single_request_roots">
            {settings.max_single_request_roots}
          </Row>
        </dl>
      </CardContent>
    </Card>
  );
}

/**
 * Settings section "周报与分析": the parameters the weekly report and the
 * session analysis run with. Session analysis is edited here and saved on the
 * server; the weekly report parameters still come from the configuration
 * file and are shown read-only.
 */
export function ReportSettingsPanel({ client, hasOrgReports, hasSessionAnalysis }: { client: ApiClient; hasOrgReports: boolean; hasSessionAnalysis: boolean }) {
  const [settings, setSettings] = useState<OrgSettings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hasOrgReports) {
      return;
    }
    const controller = new AbortController();
    setError(null);
    client.org
      .settings(controller.signal)
      .then(setSettings)
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setError(errorMessage(cause));
        }
      });
    return () => controller.abort();
  }, [client, hasOrgReports]);

  return (
    <div className="space-y-section">
      <PageHeader title="周报与分析" description="项目周报和会话分析运行所用的参数。在这里保存的值会覆盖配置文件。" />
      {hasSessionAnalysis ? <AnalysisSettingsCard client={client} /> : null}
      {error ? (
        <Alert variant="danger">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {hasOrgReports ? settings ? <OrgSettingsCard settings={settings} /> : error ? null : <Skeleton className="h-40 w-full" /> : null}
    </div>
  );
}
