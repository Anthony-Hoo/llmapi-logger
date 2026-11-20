import { useEffect, useState } from "react";

import { ApiError, type ApiClient } from "../../api";
import {
  changedKeys,
  changeDevice,
  detectPlatform,
  formatDateTime,
  INSTALL_AGENTS,
  INSTALL_PLATFORMS,
  installLinkRequest,
  loadChanges,
  outcomeLabels,
  revokeDevice,
  tokenState,
  tokenStateLabels,
  type ClipboardEnv,
} from "../../lib/agent-access/access";
import { tierLabels } from "../../lib/agent-access/authorize";
import type { AgentChange, AgentToken, InstallAgent, InstallLink, InstallPlatform } from "../../lib/agent-access/types";
import { errorMessage, isAbortError } from "../../lib/errors";
import type { SessionInfo } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge, type BadgeVariant } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader } from "../ui/card";
import { Input } from "../ui/input";
import { PageHeader } from "../ui/page-header";
import { Select } from "../ui/select";
import { Skeleton } from "../ui/skeleton";
import { emptyStateClassName } from "../ui/styles";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { CopyableText } from "./copyable-text";

function quietError(cause: unknown): string | null {
  // 401 already sends the app back to the sign-in page.
  if (isAbortError(cause) || (cause instanceof ApiError && cause.status === 401)) {
    return null;
  }
  return errorMessage(cause);
}

/** "Agent 接入": install, authorized devices and (administrators) recent agent changes. */
export function AgentAccessView({ client, session, refreshKey, clipboard }: { client: ApiClient; session: SessionInfo; refreshKey: number; clipboard?: ClipboardEnv }) {
  const isAdmin = session.role === "admin";
  const [tokens, setTokens] = useState<AgentToken[]>([]);
  const [tokensLoading, setTokensLoading] = useState(true);
  const [tokensError, setTokensError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [changes, setChanges] = useState<AgentChange[] | null>(null);
  const [changesLoading, setChangesLoading] = useState(isAdmin);
  const [changesError, setChangesError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setTokensLoading(true);
    setTokensError(null);
    client.agentAccess
      .listTokens(controller.signal)
      .then((result) => setTokens(result.items))
      .catch((cause: unknown) => setTokensError(quietError(cause)))
      .finally(() => {
        if (!controller.signal.aborted) {
          setTokensLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, refreshKey, reloadKey]);

  useEffect(() => {
    if (!isAdmin) {
      return;
    }
    const controller = new AbortController();
    setChangesLoading(true);
    setChangesError(null);
    loadChanges(client.agentAccess, session.role, controller.signal)
      .then((items) => setChanges(items))
      .catch((cause: unknown) => setChangesError(quietError(cause)))
      .finally(() => {
        if (!controller.signal.aborted) {
          setChangesLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, isAdmin, session.role, refreshKey, reloadKey]);

  async function revoke(token: AgentToken) {
    setNotice(null);
    setTokensError(null);
    try {
      const items = await revokeDevice(client.agentAccess, token, (message) => window.confirm(message));
      if (items !== null) {
        setTokens(items);
        setNotice("已撤销。这台设备上的 Agent 需要重新授权才能继续使用。");
      }
    } catch (cause: unknown) {
      setTokensError(quietError(cause));
      setReloadKey((value) => value + 1);
    }
  }

  return (
    <div className="space-y-section">
      <PageHeader
        title="Agent 接入"
        description={
          isAdmin
            ? "让本机的编码 Agent 通过 llmaudit 命令行查询审计数据；读写档还可以修改系统配置。"
            : "让本机的编码 Agent 通过 llmaudit 命令行查询你自己的调用记录，只读。"
        }
      />
      <InstallCard client={client} clipboard={clipboard} />
      <Card>
        <CardHeader>
          <PageHeader
            level="panel"
            as="h2"
            title="已授权设备"
            description={isAdmin ? "全部已签发的 Agent 令牌" : "用当前 API Key 授权的设备"}
            actions={
              <Button variant="outline" size="sm" onClick={() => setReloadKey((value) => value + 1)} disabled={tokensLoading}>
                刷新
              </Button>
            }
          />
        </CardHeader>
        <CardContent className="space-y-stack">
          {tokensError ? (
            <Alert variant="danger">
              <AlertTitle>操作失败</AlertTitle>
              <AlertDescription>{tokensError}</AlertDescription>
            </Alert>
          ) : null}
          {notice ? (
            <Alert variant="success">
              <AlertDescription>{notice}</AlertDescription>
            </Alert>
          ) : null}
          {tokensLoading ? <Skeleton className="h-24 w-full" /> : <DevicesTable tokens={tokens} onRevoke={(token) => void revoke(token)} />}
        </CardContent>
      </Card>
      {isAdmin ? (
        <Card>
          <CardHeader>
            <PageHeader level="panel" as="h2" title="Agent 最近的改动" description="经 Agent 执行的写入与授权事件，最近 50 条" />
          </CardHeader>
          <CardContent className="space-y-stack">
            {changesError ? (
              <Alert variant="danger">
                <AlertTitle>无法读取改动记录</AlertTitle>
                <AlertDescription>{changesError}</AlertDescription>
              </Alert>
            ) : null}
            {changesLoading ? <Skeleton className="h-24 w-full" /> : <ChangesTable changes={changes ?? []} tokens={tokens} />}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function InstallCard({ client, clipboard, initialPlatform }: { client: ApiClient; clipboard?: ClipboardEnv; initialPlatform?: InstallPlatform }) {
  const [agent, setAgent] = useState<InstallAgent>("claude-code");
  const [platform, setPlatform] = useState<InstallPlatform>(() => initialPlatform ?? detectPlatform(typeof navigator === "undefined" ? undefined : navigator));
  const [skillsDir, setSkillsDir] = useState("");
  const [link, setLink] = useState<InstallLink | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generate() {
    if (busy) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setLink(await client.agentAccess.createInstallLink(installLinkRequest(agent, platform, skillsDir)));
    } catch (cause: unknown) {
      setError(quietError(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <PageHeader
          level="panel"
          as="h2"
          title="安装"
          description="生成一段安装提示词，交给你的 Agent 执行：它会下载 llmaudit 命令行和 Skill 包，校验摘要后安装，再引导你登录授权。"
        />
      </CardHeader>
      <CardContent className="space-y-stack">
        <div className="grid gap-3 sm:grid-cols-2">
          <label htmlFor="agent-install-agent" className="min-w-0 space-y-1">
            <span className="block text-label font-medium text-muted">Agent</span>
            <Select id="agent-install-agent" value={agent} onChange={(event) => setAgent(event.target.value as InstallAgent)} disabled={busy}>
              {INSTALL_AGENTS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor="agent-install-platform" className="min-w-0 space-y-1">
            <span className="block text-label font-medium text-muted">平台</span>
            <Select id="agent-install-platform" value={platform} onChange={(event) => setPlatform(event.target.value as InstallPlatform)} disabled={busy}>
              {INSTALL_PLATFORMS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </label>
        </div>
        {agent === "other" ? (
          <label htmlFor="agent-install-skills-dir" className="block min-w-0 space-y-1">
            <span className="block text-label font-medium text-muted">Skills 目录（可选）</span>
            <Input
              id="agent-install-skills-dir"
              className="font-mono"
              value={skillsDir}
              onChange={(event) => setSkillsDir(event.target.value)}
              placeholder="完整路径，例如 /home/me/.my-agent/skills"
              disabled={busy}
              spellCheck={false}
              autoComplete="off"
            />
            <span className="block text-caption text-subtle">填写你的 Agent 读取 Skill 的目录；安装目录固定是其下的 llmapi-audit。</span>
          </label>
        ) : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={() => void generate()} disabled={busy}>
            {busy ? "正在生成…" : link ? "重新生成提示词" : "生成安装提示词"}
          </Button>
          <span className="text-caption text-subtle">提示词里的下载链接是临时的，过期后回到这里重新生成。</span>
        </div>
        {error ? (
          <Alert variant="danger">
            <AlertTitle>生成失败</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {link ? <InstallPrompt link={link} clipboard={clipboard} /> : null}
      </CardContent>
    </Card>
  );
}

export function InstallPrompt({ link, clipboard }: { link: InstallLink; clipboard?: ClipboardEnv }) {
  return (
    <div className="space-y-1.5">
      <CopyableText id="agent-install-prompt" label="安装提示词" value={link.prompt} multiline clipboard={clipboard} />
      <p className="text-caption text-subtle">链接有效期至 {formatDateTime(link.expires_at)}。把整段文字粘贴给 Agent 即可。</p>
    </div>
  );
}

const tokenStateVariants: Record<ReturnType<typeof tokenState>, BadgeVariant> = { active: "success", expired: "outline", revoked: "neutral" };

export function DevicesTable({ tokens, onRevoke, now }: { tokens: AgentToken[]; onRevoke: (token: AgentToken) => void; now?: number }) {
  if (tokens.length === 0) {
    return <div className={emptyStateClassName}>还没有授权过设备。安装后在终端运行 llmaudit login 即可授权。</div>;
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>设备</TableHead>
            <TableHead>档位</TableHead>
            <TableHead>签发时间</TableHead>
            <TableHead>到期时间</TableHead>
            <TableHead>最近使用</TableHead>
            <TableHead>状态</TableHead>
            <TableHead className="text-right">操作</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tokens.map((token) => {
            const state = tokenState(token, now);
            return (
              <TableRow key={String(token.id)}>
                <TableCell>
                  <span className="block max-w-64 truncate font-medium" title={token.device_name}>
                    {token.device_name || "（未命名设备）"}
                  </span>
                  <span className="block text-caption text-subtle">
                    <span className="font-mono">{token.display_prefix}</span>
                    {token.cli_version ? ` · ${token.cli_version}` : ""}
                    {token.role === "admin" ? " · 管理员" : " · 开发者"}
                  </span>
                </TableCell>
                <TableCell>
                  <Badge variant={token.tier === "write" ? "warning" : "info"}>{tierLabels[token.tier] ?? token.tier}</Badge>
                </TableCell>
                <TableCell className="text-label">{formatDateTime(token.created_at)}</TableCell>
                <TableCell className="text-label">{formatDateTime(token.expires_at)}</TableCell>
                <TableCell className="text-label">{formatDateTime(token.last_used_at)}</TableCell>
                <TableCell>
                  <Badge variant={tokenStateVariants[state]}>{tokenStateLabels[state]}</Badge>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end">
                    {state === "active" ? (
                      <Button variant="danger" size="sm" onClick={() => onRevoke(token)}>
                        撤销
                      </Button>
                    ) : null}
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

const outcomeVariants: Record<string, BadgeVariant> = { ok: "success", denied: "warning", failed: "danger" };

export function ChangesTable({ changes, tokens }: { changes: AgentChange[]; tokens: AgentToken[] }) {
  if (changes.length === 0) {
    return <div className={emptyStateClassName}>Agent 还没有做过改动。</div>;
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>时间</TableHead>
            <TableHead>设备 / 令牌</TableHead>
            <TableHead>命令</TableHead>
            <TableHead>对象</TableHead>
            <TableHead>改动的字段</TableHead>
            <TableHead>结果</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {changes.map((change) => {
            const keys = changedKeys(change);
            const object = [change.object_kind, change.object_id].filter(Boolean).join(" ");
            return (
              <TableRow key={String(change.id)}>
                <TableCell className="whitespace-nowrap text-label">{formatDateTime(change.at)}</TableCell>
                <TableCell className="max-w-48 truncate" title={changeDevice(change, tokens)}>
                  {changeDevice(change, tokens)}
                </TableCell>
                <TableCell className="font-mono text-label">{change.command || change.event}</TableCell>
                <TableCell className="font-mono text-label">{object || "—"}</TableCell>
                <TableCell className="text-label">{keys.length > 0 ? keys.join("、") : "—"}</TableCell>
                <TableCell>
                  <Badge variant={outcomeVariants[change.outcome] ?? "outline"}>{outcomeLabels[change.outcome] ?? change.outcome}</Badge>
                  {change.error_code ? <span className="ml-2 font-mono text-caption text-subtle">{change.error_code}</span> : null}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
