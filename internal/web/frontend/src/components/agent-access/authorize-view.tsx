import { useRef, useState, type ReactNode } from "react";

import type { ApiClient } from "../../api";
import { formatDateTime } from "../../lib/agent-access/access";
import {
  browserAddressBar,
  clearAuthorizeParams,
  identityLabel,
  isFramed,
  submitDecision,
  tierLabels,
  tierOptions,
  tokenLifetimeText,
  type AddressBar,
  type AuthorizeParse,
  type AuthorizeRequest,
  type DecisionOutcome,
} from "../../lib/agent-access/authorize";
import type { AgentTier, AuthorizationDecision } from "../../lib/agent-access/types";
import { errorMessage } from "../../lib/errors";
import type { SessionInfo } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../ui/card";
import { ThemeSwitch } from "../ui/theme-switch";
import { CopyableText } from "./copyable-text";

export interface AuthorizeEnv {
  framed: boolean;
  addressBar: AddressBar | null;
  navigate: (url: string) => void;
}

function browserEnv(): AuthorizeEnv {
  return {
    framed: isFramed(),
    addressBar: browserAddressBar(),
    navigate: (url) => window.location.assign(url),
  };
}

/**
 * The confirm view a `llmaudit login` opens (contract §3.1). It replaces the
 * dashboard while an authorization request is in the address bar.
 */
export function AgentAuthorizeView({
  client,
  session,
  parse,
  onDone,
  env: envOverride,
}: {
  client: ApiClient;
  /** Null only while the request is invalid: that view needs no sign-in. */
  session: SessionInfo | null;
  parse: Exclude<AuthorizeParse, { kind: "none" }>;
  onDone: () => void;
  env?: AuthorizeEnv;
}) {
  const [env] = useState<AuthorizeEnv>(() => envOverride ?? browserEnv());
  const options = session ? tierOptions(session.role, session.agent_write_allowed === true) : [];
  const [tier, setTier] = useState<AgentTier>("read");
  const [submitting, setSubmitting] = useState(false);
  const [outcome, setOutcome] = useState<DecisionOutcome | null>(null);
  const inFlight = useRef(false);

  function leave() {
    clearAuthorizeParams(env.addressBar);
    onDone();
  }

  // A framed page could be overlaid to trick the click: show nothing actionable.
  if (env.framed) {
    return (
      <AuthorizeShell>
        <Alert variant="danger">
          <AlertTitle>不能在嵌入的页面里授权</AlertTitle>
          <AlertDescription>这个授权页被嵌在了其他页面里。请直接在浏览器地址栏打开命令行给出的地址。</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }

  if (parse.kind === "invalid") {
    return (
      <AuthorizeShell action={<Button onClick={leave}>进入管理页面</Button>}>
        <Alert variant="danger">
          <AlertTitle>授权地址无效</AlertTitle>
          <AlertDescription>{parse.reason} 没有向服务器发送任何请求。请在终端重新运行 llmaudit login。</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }

  if (!session) {
    return null;
  }

  if (session.agent_access_enabled !== true) {
    return (
      <AuthorizeShell action={<Button onClick={leave}>进入管理页面</Button>}>
        <Alert variant="warning">
          <AlertTitle>本部署没有开启 Agent 接入</AlertTitle>
          <AlertDescription>请联系管理员开启后，在终端重新运行 llmaudit login。</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }

  const request = parse.request;
  const signedIn: SessionInfo = session;
  const effectiveTier: AgentTier = options.includes(tier) ? tier : "read";

  async function decide(decision: AuthorizationDecision) {
    if (inFlight.current) {
      return;
    }
    inFlight.current = true;
    setSubmitting(true);
    try {
      const result = await submitDecision(
        {
          api: client.agentAccess,
          navigate: env.navigate,
          clearAddressBar: () => clearAuthorizeParams(env.addressBar),
          describeError: errorMessage,
        },
        request,
        effectiveTier,
        decision,
      );
      setOutcome(result);
      // A retryable failure lets the user decide again.
      if (result.kind === "error" && !result.final) {
        inFlight.current = false;
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (outcome?.kind === "code") {
    return <PasteCodeResult code={outcome.code} expiresIn={outcome.expiresIn} onDone={onDone} />;
  }
  if (outcome?.kind === "denied") {
    return (
      <AuthorizeShell action={<Button onClick={onDone}>进入管理页面</Button>}>
        <Alert variant="neutral">
          <AlertTitle>已拒绝</AlertTitle>
          <AlertDescription>没有签发任何令牌。终端里的 llmaudit login 不会收到授权码，可以直接结束它。</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }
  if (outcome?.kind === "redirected") {
    return (
      <AuthorizeShell>
        <Alert variant="info">
          <AlertTitle>正在返回命令行…</AlertTitle>
          <AlertDescription>浏览器会跳转到本机的命令行。完成后回到终端查看结果，这个标签页可以关闭。</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }
  if (outcome?.kind === "error" && outcome.final) {
    return (
      <AuthorizeShell action={<Button onClick={onDone}>进入管理页面</Button>}>
        <Alert variant="danger">
          <AlertTitle>授权没有完成</AlertTitle>
          <AlertDescription>{outcome.message}</AlertDescription>
        </Alert>
      </AuthorizeShell>
    );
  }

  return (
    <AuthorizeConfirm
      request={request}
      session={signedIn}
      options={options}
      tier={effectiveTier}
      onTierChange={setTier}
      submitting={submitting}
      error={outcome?.kind === "error" ? outcome.message : null}
      onApprove={() => void decide("approve")}
      onDeny={() => void decide("deny")}
    />
  );
}

function AuthorizeShell({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <main className="relative flex min-h-screen items-center justify-center px-gutter py-12">
      <div className="absolute right-gutter top-4">
        <ThemeSwitch />
      </div>
      <Card className="w-full max-w-lg overflow-hidden">
        <div className="h-1 bg-primary" />
        <CardHeader className="gap-1.5 p-6 pb-4">
          <CardTitle className="text-heading">授权命令行访问</CardTitle>
          <CardDescription>llmaudit 命令行请求以你的身份访问 LLM API Audit。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-stack p-6 pt-0">
          {children}
          {action ? <div className="flex justify-end gap-2">{action}</div> : null}
        </CardContent>
      </Card>
    </main>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[6rem_minmax(0,1fr)] gap-3">
      <dt className="text-label font-medium text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-body">{children}</dd>
    </div>
  );
}

export function AuthorizeConfirm({
  request,
  session,
  options,
  tier,
  onTierChange,
  submitting,
  error,
  onApprove,
  onDeny,
}: {
  request: AuthorizeRequest;
  session: SessionInfo;
  options: AgentTier[];
  tier: AgentTier;
  onTierChange: (tier: AgentTier) => void;
  submitting: boolean;
  error: string | null;
  onApprove: () => void;
  onDeny: () => void;
}) {
  return (
    <AuthorizeShell
      action={
        <>
          <Button variant="outline" onClick={onDeny} disabled={submitting}>
            拒绝
          </Button>
          <Button onClick={onApprove} disabled={submitting}>
            {submitting ? "正在提交…" : "授权"}
          </Button>
        </>
      }
    >
      {error ? (
        <Alert variant="danger">
          <AlertTitle>提交失败</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <dl className="space-y-2 rounded-md border bg-surface-muted p-3">
        {/* Device name and version come from the URL: plain text only. */}
        <Fact label="设备">{request.deviceName || "（未提供）"}</Fact>
        <Fact label="命令行版本">{request.cliVersion || "（未提供）"}</Fact>
        <Fact label="当前身份">{identityLabel(session)}</Fact>
        <Fact label="授权方式">{request.mode === "loopback" ? `浏览器回跳到本机端口 ${request.port}` : "在终端粘贴授权码"}</Fact>
        <Fact label="到期时间">{tokenLifetimeText(session.role, tier, session.expires_at, formatDateTime)}</Fact>
      </dl>
      <fieldset className="space-y-2">
        <legend className="text-label font-medium text-muted">档位</legend>
        {options.length === 1 ? (
          <p className="text-body">
            <Badge variant="info">{tierLabels.read}</Badge>
            <span className="ml-2 text-body-sm text-muted">
              {session.role === "developer" ? "开发者会话只能授权只读档。" : "本部署关闭了经 Agent 的写入，只能授权只读档。"}
            </span>
          </p>
        ) : (
          <div className="grid gap-2 sm:grid-cols-2">
            {options.map((option) => (
              <label key={option} className="flex items-start gap-2 rounded-md border border-border-strong bg-surface px-3 py-2 text-body shadow-xs">
                <input
                  className="mt-1 accent-primary"
                  type="radio"
                  name="agent-tier"
                  value={option}
                  checked={tier === option}
                  onChange={() => onTierChange(option)}
                  disabled={submitting}
                />
                <span>
                  <span className="block font-medium">{tierLabels[option]}</span>
                  <span className="block text-label text-subtle">{option === "read" ? "只能查询，有效 30 天" : "可修改系统配置，有效 7 天"}</span>
                </span>
              </label>
            ))}
          </div>
        )}
      </fieldset>
      {tier === "write" ? (
        <Alert variant="warning">
          <AlertTitle>读写档可以修改系统配置</AlertTitle>
          <AlertDescription>持有读写令牌的 Agent 可以修改拦截规则、项目组与项目、周报与分析设置等系统配置，改动立即生效。只在你信任这台设备和其上的 Agent 时选择。</AlertDescription>
        </Alert>
      ) : null}
      <p className="text-caption text-subtle">只授权你自己刚刚在终端发起的登录。不认识这台设备或这个请求时，请点“拒绝”。</p>
    </AuthorizeShell>
  );
}

export function PasteCodeResult({ code, expiresIn, onDone }: { code: string; expiresIn: number; onDone: () => void }) {
  const minutes = Math.max(1, Math.round(expiresIn / 60));
  return (
    <AuthorizeShell action={<Button variant="outline" onClick={onDone}>进入管理页面</Button>}>
      <Alert variant="success">
        <AlertTitle>已授权</AlertTitle>
        <AlertDescription>把下面的一次性授权码粘贴到终端里等待输入的 llmaudit login。授权码 {minutes} 分钟内有效，只能使用一次，离开本页后不会再显示。</AlertDescription>
      </Alert>
      <CopyableText id="agent-paste-code" label="一次性授权码" value={code} />
    </AuthorizeShell>
  );
}
