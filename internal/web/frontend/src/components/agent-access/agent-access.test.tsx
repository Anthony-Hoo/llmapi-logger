import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ApiClient } from "../../api";
import { agentAccessEnabled, Dashboard } from "../../app";
import { parseAuthorizeParams, type AuthorizeParse } from "../../lib/agent-access/authorize";
import type { AgentChange, AgentToken } from "../../lib/agent-access/types";
import type { SessionInfo } from "../../types";
import { AgentAccessView, ChangesTable, DevicesTable, InstallCard, InstallPrompt } from "./agent-access-view";
import { AgentAuthorizeView, AuthorizeConfirm, PasteCodeResult, type AuthorizeEnv } from "./authorize-view";

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const admin: SessionInfo = { status: "ok", role: "admin", agent_access_enabled: true, agent_write_allowed: true };
const developer: SessionInfo = {
  status: "ok",
  role: "developer",
  expires_at: "2026-11-25T08:00:00Z",
  identity: { username: "alice", token_name: "laptop-key" },
  agent_access_enabled: true,
  agent_write_allowed: true,
};

function parse(params: Record<string, string>): Exclude<AuthorizeParse, { kind: "none" }> {
  const parsed = parseAuthorizeParams(`?${new URLSearchParams(params)}`);
  if (parsed.kind === "none") {
    throw new Error("expected an authorization request");
  }
  return parsed;
}

const loopback = { agent_authorize: "1", challenge, state: "st-1", port: "53123", device: "work-laptop", cli: "0.1.0" };

function env(overrides: Partial<AuthorizeEnv> = {}): AuthorizeEnv {
  return { framed: false, addressBar: null, navigate: vi.fn(), ...overrides };
}

function renderAuthorize(session: SessionInfo | null, params: Record<string, string>, environment = env()): string {
  return renderToStaticMarkup(<AgentAuthorizeView client={{} as ApiClient} session={session} parse={parse(params)} onDone={() => undefined} env={environment} />);
}

describe("authorization confirm view", () => {
  it("shows the device, version, identity, tier and expiry with both actions", () => {
    const html = renderAuthorize(admin, loopback);
    expect(html).toContain("work-laptop");
    expect(html).toContain("0.1.0");
    expect(html).toContain("管理员");
    expect(html).toContain("本机端口 53123");
    expect(html).toContain("授权后 30 天");
    expect(html).toContain(">授权<");
    expect(html).toContain(">拒绝<");
  });

  it("offers administrators read (default) and write when the deployment allows it", () => {
    const html = renderAuthorize(admin, loopback);
    expect(html.match(/type="radio"/g)?.length).toBe(2);
    expect(html).toMatch(/checked="" value="read"/);
    expect(html).toContain("读写");
    // The warning belongs to the write choice only.
    expect(html).not.toContain("读写档可以修改系统配置");
    const parsed = parse(loopback);
    if (parsed.kind !== "valid") {
      throw new Error("expected a valid request");
    }
    const write = renderToStaticMarkup(
      <AuthorizeConfirm
        request={parsed.request}
        session={admin}
        options={["read", "write"]}
        tier="write"
        onTierChange={() => undefined}
        submitting={false}
        error={null}
        onApprove={() => undefined}
        onDeny={() => undefined}
      />,
    );
    expect(write).toMatch(/checked="" value="write"/);
    expect(write).toContain("读写档可以修改系统配置");
    expect(write).toContain("改动立即生效");
    expect(write).toContain("授权后 7 天");

    const readOnly = renderAuthorize({ ...admin, agent_write_allowed: false }, loopback);
    expect(readOnly).not.toContain('type="radio"');
    expect(readOnly).not.toContain('value="write"');
    expect(readOnly).toContain("本部署关闭了经 Agent 的写入");
  });

  it("preselects the tier `llmaudit login --write` asks for when it is allowed", () => {
    const html = renderAuthorize(admin, { ...loopback, tier: "write" });
    expect(html).toMatch(/checked="" value="write"/);
    expect(html).toContain("读写档可以修改系统配置");
    expect(renderAuthorize(admin, { ...loopback, tier: "read" })).toMatch(/checked="" value="read"/);
  });

  it("falls back to read and says why when the asked-for write tier is not allowed", () => {
    const writesOff = renderAuthorize({ ...admin, agent_write_allowed: false }, { ...loopback, tier: "write" });
    expect(writesOff).not.toContain('value="write"');
    expect(writesOff).toContain("命令行申请了读写档，但本部署关闭了经 Agent 的写入，已改为只读档。");
    const developerWrite = renderAuthorize(developer, { ...loopback, tier: "write" });
    expect(developerWrite).not.toContain('value="write"');
    expect(developerWrite).toContain("命令行申请了读写档，但开发者会话只能授权只读档，已改为只读档。");
    expect(renderAuthorize(admin, loopback)).not.toContain("命令行申请了读写档");
  });

  it("gives developer sessions read only, expiring with the web session", () => {
    const html = renderAuthorize(developer, loopback);
    expect(html).not.toContain('type="radio"');
    expect(html).not.toContain('value="write"');
    expect(html).toContain("开发者会话只能授权只读档");
    expect(html).toContain("开发者 · alice · Key laptop-key");
    expect(html).toContain("同当前网页会话，最长 7 天");
  });

  it("refuses to render inside a frame", () => {
    const html = renderAuthorize(admin, loopback, env({ framed: true }));
    expect(html).toContain("不能在嵌入的页面里授权");
    expect(html).not.toContain(">授权<");
    expect(html).not.toContain("work-laptop");
  });

  it("explains an invalid request without anything to approve, signed in or not", () => {
    for (const session of [admin, null]) {
      const html = renderAuthorize(session, { ...loopback, port: "80" });
      expect(html).toContain("授权地址无效");
      expect(html).toContain("1024–65535");
      expect(html).not.toContain(">授权<");
      expect(html).not.toContain(">拒绝<");
    }
  });

  it("says so when the deployment has agent access off", () => {
    const html = renderAuthorize({ ...admin, agent_access_enabled: false }, loopback);
    expect(html).toContain("本部署没有开启 Agent 接入");
    expect(html).not.toContain(">授权<");
  });

  it("renders untrusted device text as capped plain text", () => {
    const html = renderAuthorize(admin, { ...loopback, device: `<img src=x onerror=alert(1)>\u0007‮${"d".repeat(100)}` });
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("\u0007");
    expect(html).not.toContain("‮");
    expect(html).toContain(`&gt;${"d".repeat(36)}<`);
    expect(html).not.toContain("d".repeat(37));
  });

  it("shows the one-time code in a copyable field with its validity", () => {
    const html = renderToStaticMarkup(<PasteCodeResult code="one-time-code" expiresIn={300} onDone={() => undefined} />);
    expect(html).toContain('value="one-time-code"');
    expect(html).toContain("readOnly");
    expect(html).toContain("5 分钟内有效");
    expect(html).toContain("粘贴到终端");
    expect(html).toContain(">复制<");
  });
});

const token: AgentToken = {
  id: 7,
  display_prefix: "lla_AbCd",
  role: "developer",
  tier: "read",
  device_name: "laptop",
  cli_version: "0.1.0",
  created_at: "2026-11-01T00:00:00Z",
  expires_at: "2026-12-01T00:00:00Z",
  last_used_at: "2026-11-18T09:00:00Z",
  revoked_at: null,
};

describe("Agent 接入 page", () => {
  it("lists devices with a revoke button for active ones only", () => {
    const now = Date.parse("2026-11-19T00:00:00Z");
    const html = renderToStaticMarkup(
      <DevicesTable tokens={[token, { ...token, id: 8, device_name: "old", revoked_at: "2026-11-10T00:00:00Z" }]} onRevoke={() => undefined} now={now} />,
    );
    expect(html).toContain("laptop");
    expect(html).toContain("lla_AbCd");
    expect(html).toContain("只读");
    expect(html).toContain("有效");
    expect(html).toContain("已撤销");
    expect(html.match(/>撤销</g)?.length).toBe(1);
    expect(renderToStaticMarkup(<DevicesTable tokens={[]} onRevoke={() => undefined} />)).toContain("还没有授权过设备");
  });

  it("lists agent changes", () => {
    const change: AgentChange = {
      id: 1,
      at: "2026-11-19T00:00:00Z",
      event: "write_failed",
      token_id: 7,
      role: "admin",
      command: "apply",
      cli_version: "0.1.0",
      object_kind: "ua-rule",
      object_id: "12",
      changed_keys: ["enabled"],
      outcome: "failed",
      error_code: "VERSION_CONFLICT",
    };
    const html = renderToStaticMarkup(<ChangesTable changes={[change]} tokens={[token]} />);
    for (const text of ["laptop", "apply", "ua-rule 12", "enabled", "失败", "VERSION_CONFLICT"]) {
      expect(html).toContain(text);
    }
    expect(renderToStaticMarkup(<ChangesTable changes={[]} tokens={[]} />)).toContain("还没有做过改动");
  });

  it("shows the recent changes section to administrators only", () => {
    const client = { agentAccess: { listTokens: vi.fn(), listChanges: vi.fn() } } as unknown as ApiClient;
    const forAdmin = renderToStaticMarkup(<AgentAccessView client={client} session={admin} refreshKey={0} />);
    expect(forAdmin).toContain("Agent 最近的改动");
    expect(forAdmin).toContain("已授权设备");
    const forDeveloper = renderToStaticMarkup(<AgentAccessView client={client} session={developer} refreshKey={0} />);
    expect(forDeveloper).not.toContain("Agent 最近的改动");
    expect(forDeveloper).toContain("已授权设备");
  });

  it("offers every agent and platform and shows the server's prompt read-only", () => {
    const html = renderToStaticMarkup(<InstallCard client={{} as ApiClient} initialPlatform="linux-arm64" />);
    for (const label of ["Claude Code", "Codex", "Cursor", "Gemini CLI", "其他"]) {
      expect(html).toContain(label);
    }
    for (const value of ["windows-amd64", "linux-amd64", "linux-arm64", "darwin-arm64", "darwin-amd64"]) {
      expect(html).toContain(`value="${value}"`);
    }
    expect(html).toMatch(/value="linux-arm64" selected=""/);
    // The Skills directory belongs to "其他" only.
    expect(html).not.toContain("agent-install-skills-dir");
    expect(html).not.toContain("<textarea");

    const prompt = renderToStaticMarkup(<InstallPrompt link={{ prompt: "安装 llmaudit：第一步…", expires_at: "2026-11-19T08:30:00Z" }} />);
    expect(prompt).toContain("<textarea");
    expect(prompt).toContain("readOnly");
    expect(prompt).toContain("安装 llmaudit：第一步…");
    expect(prompt).toContain("链接有效期至");
    expect(prompt).toContain(">复制<");
  });
});

describe("navigation entry", () => {
  function nav(session: SessionInfo): string {
    return renderToStaticMarkup(<Dashboard client={{} as ApiClient} session={session} checkingSession={false} onLogOut={async () => undefined} />);
  }

  it("is shown to both roles only when the feature is enabled", () => {
    expect(agentAccessEnabled(null)).toBe(false);
    expect(agentAccessEnabled({ ...admin, agent_access_enabled: undefined })).toBe(false);
    expect(nav(admin)).toContain("Agent 接入");
    expect(nav(developer)).toContain("Agent 接入");
    // Developers have no settings menu; the entry does not live inside it.
    expect(nav(developer)).not.toContain("系统配置");
    expect(nav({ ...admin, agent_access_enabled: false })).not.toContain("Agent 接入");
    expect(nav({ ...developer, agent_access_enabled: undefined })).not.toContain("Agent 接入");
  });
});
