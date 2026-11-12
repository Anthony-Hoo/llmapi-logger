import type { ApiClient } from "../../api";
import { PageHeader } from "../ui/page-header";
import { AnalysisSettingsCard } from "./analysis-settings-form";
import { OrgSettingsCard } from "./org-settings-form";

/**
 * Settings section "周报与分析": the parameters the weekly report and the
 * session analysis run with. Both are edited here and saved on the server;
 * a saved value overrides the configuration file.
 */
export function ReportSettingsPanel({ client, hasOrgReports, hasSessionAnalysis }: { client: ApiClient; hasOrgReports: boolean; hasSessionAnalysis: boolean }) {
  return (
    <div className="space-y-section">
      <PageHeader title="周报与分析" description="项目周报和会话分析运行所用的参数。在这里保存的值会覆盖配置文件，直到在这里恢复。" />
      {hasSessionAnalysis ? <AnalysisSettingsCard client={client} /> : null}
      {hasOrgReports ? <OrgSettingsCard client={client} /> : null}
    </div>
  );
}
