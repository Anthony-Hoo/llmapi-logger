import { useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage } from "../../lib/errors";
import {
  COLLABORATION_LABELS,
  FIELD_LABELS,
  FRICTION_LABELS,
  labelOf,
  OUTCOME_LABELS,
  parseCalibrationLabels,
  TASK_TYPE_LABELS,
} from "../../lib/session-analysis/format";
import type { AnalysisCalibration, AnalysisFacet } from "../../lib/session-analysis/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";

/**
 * The L1 facet of one session (doc 24 section 7), fetched on an explicit click
 * because every read is written to the analysis view log. Fields the latest
 * calibration put below the agreement bar are not shown.
 */
export function FacetPanel({ client, sessionID }: { client: ApiClient; sessionID: string }) {
  const [facet, setFacet] = useState<AnalysisFacet | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setFacet(await client.getAnalysisFacet(sessionID));
    } catch (cause: unknown) {
      if (cause instanceof ApiError && cause.status === 404) {
        setError("还没有分析结果：会话未静默满设定时长、模型未启用，或还没到下一次批处理。");
      } else if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setLoading(false);
    }
  }

  if (!facet) {
    return (
      <div className="mt-3 space-y-2">
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? "读取中…" : "查看分析结果"}
        </Button>
        {error ? (
          <Alert variant="neutral">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
      </div>
    );
  }
  return <FacetView facet={facet} />;
}

export function FacetView({ facet }: { facet: AnalysisFacet }) {
  if (facet.status !== "ok") {
    return (
      <Alert variant="neutral" className="mt-3">
        <AlertDescription>{facet.status === "invalid" ? "模型两次输出都不是合法 JSON，本会话没有分析结果。" : "调用模型失败，下一次批处理会重试。"}</AlertDescription>
      </Alert>
    );
  }
  const hidden = new Set(facet.hidden_fields);
  const field = (name: string, value: string) =>
    hidden.has(name) ? null : (
      <div key={name} className="flex gap-2">
        <dt className="w-24 shrink-0 text-muted">{FIELD_LABELS[name] ?? name}</dt>
        <dd>{value}</dd>
      </div>
    );
  const evidence = Object.entries(facet.evidence);
  return (
    <div className="mt-3 space-y-2 text-body-sm">
      <p className="text-label text-subtle">
        本地模型 {facet.model}（{facet.prompt_version}）生成，仅供参考{facet.hidden_fields.length > 0 ? `；校准一致率不足而隐藏：${facet.hidden_fields.map((name) => FIELD_LABELS[name] ?? name).join("、")}` : ""}
      </p>
      {facet.goal ? <p className="font-medium">{facet.goal}</p> : null}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        {facet.kind === "session" ? field("task_type", labelOf(TASK_TYPE_LABELS, facet.task_type)) : null}
        {facet.kind === "session" ? field("outcome", labelOf(OUTCOME_LABELS, facet.outcome)) : null}
        {facet.kind === "session" ? field("collaboration", labelOf(COLLABORATION_LABELS, facet.collaboration)) : null}
        {field("friction", facet.friction.length > 0 ? facet.friction.map((value) => FRICTION_LABELS[value] ?? value).join("、") : "无")}
      </dl>
      {facet.kind === "chat_digest" && facet.items.length > 0 && !hidden.has("task_type") ? (
        <ul className="flex flex-wrap gap-1">
          {facet.items.map((item) => (
            <li key={item.ref}>
              <Badge variant="outline">
                {item.ref} {labelOf(TASK_TYPE_LABELS, item.task_type)}
              </Badge>
            </li>
          ))}
        </ul>
      ) : null}
      {facet.instructions.length > 0 ? (
        <div>
          <div className="text-muted">可沉淀的指令</div>
          <ul className="list-disc pl-5">
            {facet.instructions.map((instruction) => (
              <li key={instruction}>{instruction}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {facet.skill_candidate ? <p><span className="text-muted">skill 候选：</span>{facet.skill_candidate}</p> : null}
      {evidence.length > 0 ? (
        <details className="text-label text-muted">
          <summary className="cursor-pointer">证据</summary>
          <ul className="mt-1">
            {evidence.map(([name, refs]) => (
              <li key={name} className="font-mono">
                {FIELD_LABELS[name] ?? name}: {refs.map((ref) => `${ref.label}${ref.audit_id ? ` → ${ref.audit_id}` : ""}`).join("，")}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

/** Administrator form for doc 24 section 7.3: paste human labels, get per-field agreement. */
export function CalibrationPanel({ client, onDone }: { client: ApiClient; onDone: () => void }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState<AnalysisCalibration | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError(null);
    const parsed = parseCalibrationLabels(text);
    if ("error" in parsed) {
      setError(parsed.error);
      return;
    }
    setBusy(true);
    try {
      setResult(await client.calibrateAnalysis(parsed.labels));
      onDone();
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="text-body-sm">
      <summary className="cursor-pointer text-muted">校准：上传人工标注，计算各字段一致率</summary>
      <div className="mt-2 space-y-2">
        <p className="text-label text-subtle">
          粘贴 JSON 数组，每项形如 {"{"}"session_id": "…", "task_type": "bug_fix", "outcome": "achieved", "friction": ["tool_failed"]{"}"}；未填的字段不参与比较。一致率低于 80%（至少 20 条）的字段会在结果中隐藏。
        </p>
        <textarea
          className="h-32 w-full rounded-md border bg-surface p-2 font-mono text-label"
          value={text}
          onChange={(event) => setText(event.target.value)}
          aria-label="人工标注 JSON"
        />
        <Button variant="outline" size="sm" onClick={() => void submit()} disabled={busy || text.trim() === ""}>
          {busy ? "计算中…" : "计算一致率"}
        </Button>
        {error ? (
          <Alert variant="danger">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {result ? <CalibrationSummary calibration={result} /> : null}
      </div>
    </details>
  );
}

export function CalibrationSummary({ calibration }: { calibration: AnalysisCalibration }) {
  const fields = Object.keys(calibration.agreement).sort();
  return (
    <p className="text-label text-subtle">
      校准（{calibration.model} / {calibration.prompt_version}，{calibration.samples} 个样本）：
      {fields.length === 0
        ? "没有可比较的字段"
        : fields.map((name) => `${FIELD_LABELS[name] ?? name} ${(calibration.agreement[name] * 100).toFixed(0)}%（${calibration.compared[name] ?? 0}）`).join("、")}
      {calibration.hidden_fields.length > 0 ? `；已隐藏 ${calibration.hidden_fields.map((name) => FIELD_LABELS[name] ?? name).join("、")}` : ""}
    </p>
  );
}
