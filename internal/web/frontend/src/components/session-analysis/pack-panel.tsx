import { useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { AnalysisPack } from "../../lib/session-analysis/types";
import { Alert, AlertDescription } from "../ui/alert";
import { Button } from "../ui/button";

/**
 * The input pack of one session: exactly what the local model sees (doc 24
 * section 6). It is fetched only on an explicit click, because every read is
 * written to the analysis view log.
 */
export function PackPanel({ client, sessionID, isDeveloper }: { client: ApiClient; sessionID: string; isDeveloper: boolean }) {
  const [pack, setPack] = useState<AnalysisPack | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setPack(await client.getAnalysisPack(sessionID));
    } catch (cause: unknown) {
      if (cause instanceof ApiError && cause.status === 404) {
        setError("这个会话没有输入包：未达门槛、正文不可得，或还没到下一次批处理。");
      } else if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setLoading(false);
    }
  }

  if (!pack) {
    return (
      <div className="mt-3 space-y-2">
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? "读取中…" : "查看输入包"}
        </Button>
        <p className="text-label text-subtle">
          {isDeveloper ? "输入包是本地模型看到的全部内容（已脱敏）。" : "输入包是本地模型看到的全部内容（已脱敏）。管理员每次查看都会写入查看日志。"}
        </p>
        {error ? (
          <Alert variant="neutral">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
      </div>
    );
  }
  return <PackView pack={pack} />;
}

export function PackView({ pack }: { pack: AnalysisPack }) {
  return (
    <div className="mt-3 space-y-2">
      <p className="text-label text-subtle">
        {pack.kind === "chat_digest" ? `聊天汇总包（${pack.members} 个单轮会话）` : "会话输入包"} · 约 {pack.tokens.toLocaleString("zh-CN")} Token
        {pack.truncated ? " · 已按预算截断" : ""}
      </p>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-surface p-3 font-mono text-label">{pack.text}</pre>
      {Object.keys(pack.refs).length > 0 ? (
        <details className="text-label text-muted">
          <summary className="cursor-pointer">证据对应的审计记录</summary>
          <ul className="mt-1 grid grid-cols-1 gap-x-4 sm:grid-cols-2">
            {Object.entries(pack.refs)
              .sort(([left], [right]) => left.localeCompare(right, "en", { numeric: true }))
              .map(([label, auditID]) => (
                <li key={label} className="font-mono">
                  {label} → {auditID}
                </li>
              ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}
