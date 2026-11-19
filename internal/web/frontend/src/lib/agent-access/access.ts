// Behaviour of the "Agent 接入" page, kept out of the components so it can be
// tested without a DOM. Every boundary is enforced by the server; these only
// decide what to ask for and how to show it.

import type { SessionRole } from "../../types";
import type { AgentAccessApi, AgentChange, AgentToken, InstallAgent, InstallLinkRequest, InstallPlatform } from "./types";

export const INSTALL_AGENTS: ReadonlyArray<{ value: InstallAgent; label: string }> = [
  { value: "claude-code", label: "Claude Code" },
  { value: "codex", label: "Codex" },
  { value: "cursor", label: "Cursor" },
  { value: "gemini-cli", label: "Gemini CLI" },
  { value: "other", label: "其他" },
];

export const INSTALL_PLATFORMS: ReadonlyArray<{ value: InstallPlatform; label: string }> = [
  { value: "windows-amd64", label: "Windows（x64）" },
  { value: "linux-amd64", label: "Linux（x64）" },
  { value: "linux-arm64", label: "Linux（ARM64）" },
  { value: "darwin-arm64", label: "macOS（Apple 芯片）" },
  { value: "darwin-amd64", label: "macOS（Intel）" },
];

/**
 * A best guess from what the browser says about itself: macOS defaults to
 * Apple silicon and Linux to x64 unless the user agent names ARM.
 */
export function detectPlatform(nav: { userAgent?: string; platform?: string } | undefined): InstallPlatform {
  const ua = `${nav?.userAgent ?? ""} ${nav?.platform ?? ""}`.toLowerCase();
  if (ua.includes("win")) {
    return "windows-amd64";
  }
  if (ua.includes("mac")) {
    // Apple silicon Macs also report "Intel Mac OS X"; the user can switch.
    return "darwin-arm64";
  }
  if (ua.includes("linux") || ua.includes("x11")) {
    return ua.includes("aarch64") || ua.includes("arm64") || ua.includes("armv8") ? "linux-arm64" : "linux-amd64";
  }
  return "linux-amd64";
}

/** The request body; the Skills directory only goes with "其他" and only when typed. */
export function installLinkRequest(agent: InstallAgent, platform: InstallPlatform, skillsDir: string): InstallLinkRequest {
  const dir = skillsDir.trim();
  return agent === "other" && dir !== "" ? { agent, platform, skills_dir: dir } : { agent, platform };
}

export interface ClipboardEnv {
  isSecureContext: boolean;
  clipboard?: { writeText: (text: string) => Promise<void> } | null;
}

export function browserClipboardEnv(): ClipboardEnv {
  if (typeof window === "undefined") {
    return { isSecureContext: false };
  }
  return { isSecureContext: window.isSecureContext, clipboard: typeof navigator === "undefined" ? null : navigator.clipboard };
}

/**
 * Copies with the clipboard API where the browser allows it. Plain HTTP on a
 * non-local origin is not a secure context and has no clipboard API; then (and
 * when writing fails) the caller selects the text and asks for a manual copy.
 */
export async function copyText(text: string, env: ClipboardEnv): Promise<"copied" | "manual"> {
  if (!env.isSecureContext || !env.clipboard || typeof env.clipboard.writeText !== "function") {
    return "manual";
  }
  try {
    await env.clipboard.writeText(text);
    return "copied";
  } catch {
    return "manual";
  }
}

export const MANUAL_COPY_HINT = "当前页面不是安全连接（HTTPS 或本机地址），浏览器不允许网页写入剪贴板。文字已选中，请按 Ctrl+C（macOS 为 ⌘C）复制。";

/** Only administrators see agent changes; a developer session never asks. */
export async function loadChanges(api: Pick<AgentAccessApi, "listChanges">, role: SessionRole, signal?: AbortSignal): Promise<AgentChange[] | null> {
  if (role !== "admin") {
    return null;
  }
  return (await api.listChanges(50, signal)).items;
}

/**
 * Revokes after the user confirms, then reloads the list from the server
 * (which scopes it per role; nothing is filtered here). Null means the user
 * cancelled and nothing was sent.
 */
export async function revokeDevice(
  api: Pick<AgentAccessApi, "revokeToken" | "listTokens">,
  token: AgentToken,
  confirm: (message: string) => boolean,
): Promise<AgentToken[] | null> {
  const name = token.device_name || token.display_prefix || `#${token.id}`;
  if (!confirm(`确认撤销设备“${name}”的授权？撤销后这台设备上的 Agent 立即无法再调用接口，需要重新运行 llmaudit login。`)) {
    return null;
  }
  await api.revokeToken(token.id);
  return (await api.listTokens()).items;
}

export type TokenState = "active" | "expired" | "revoked";

export function tokenState(token: AgentToken, now: number = Date.now()): TokenState {
  if (token.revoked_at) {
    return "revoked";
  }
  const expires = Date.parse(token.expires_at);
  return Number.isFinite(expires) && expires <= now ? "expired" : "active";
}

export const tokenStateLabels: Record<TokenState, string> = { active: "有效", expired: "已过期", revoked: "已撤销" };

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

/** changed_keys is a list of key names; a JSON-encoded list is accepted too. */
export function changedKeys(change: AgentChange): string[] {
  const value = change.changed_keys;
  if (Array.isArray(value)) {
    return value.filter((key): key is string => typeof key === "string");
  }
  if (typeof value === "string" && value.trim() !== "") {
    try {
      const parsed: unknown = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.filter((key): key is string => typeof key === "string") : [];
    } catch {
      return [];
    }
  }
  return [];
}

/** The device behind a change: the row's own name, the token list's, or the token number. */
export function changeDevice(change: AgentChange, tokens: AgentToken[]): string {
  if (change.device_name) {
    return change.device_name;
  }
  if (change.token_id === null || change.token_id === undefined || change.token_id === "") {
    return "—";
  }
  const token = tokens.find((item) => String(item.id) === String(change.token_id));
  return token?.device_name || `令牌 #${change.token_id}`;
}

export const outcomeLabels: Record<string, string> = { ok: "成功", denied: "被拒绝", failed: "失败" };
