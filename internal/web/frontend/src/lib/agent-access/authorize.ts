// The authorization confirm view is the first place the app reads the address
// bar (doc/features/25-agent-access-contract.md §3.1). Everything that touches
// URL state lives here as small pure functions; the view only wires them up.

import type { SessionInfo, SessionRole } from "../../types";
import type { AgentAccessApi, AgentTier, AuthorizationDecision, AuthorizationMode } from "./types";

/** Every parameter the CLI adds; all of them are removed when the flow ends. */
export const AUTHORIZE_PARAM_KEYS = ["agent_authorize", "challenge", "state", "port", "mode", "device", "cli"] as const;

export const MAX_DEVICE_NAME_CHARS = 64;
export const MAX_CLI_VERSION_CHARS = 64;
const MAX_STATE_CHARS = 512;

export interface AuthorizeRequest {
  challenge: string;
  state: string;
  mode: AuthorizationMode;
  /** Present exactly when mode is "loopback". */
  port?: number;
  /** Sanitised: what is shown is what is sent. */
  deviceName: string;
  cliVersion: string;
}

export type AuthorizeParse =
  | { kind: "none" }
  | { kind: "invalid"; reason: string }
  | { kind: "valid"; request: AuthorizeRequest };

// C0/C1 controls plus the bidirectional overrides and isolates, which can make
// a device name read differently from what it is.
const CONTROL_CHARACTERS = /[\p{Cc}‎‏‪-‮⁦-⁩]/gu;

/**
 * Text from the URL is untrusted: control characters are dropped, the rest is
 * trimmed and capped by code points (not UTF-16 units) and rendered as text.
 */
export function sanitizeUntrustedText(value: string | null | undefined, maxChars: number): string {
  if (!value) {
    return "";
  }
  return Array.from(value.replace(CONTROL_CHARACTERS, "").trim()).slice(0, maxChars).join("").trim();
}

/** BASE64URL(SHA-256(verifier)) without padding is always 43 characters. */
const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** A decimal number without sign, spaces, leading zeros, hex or fraction. */
const PORT_PATTERN = /^[1-9]\d{3,4}$/;

/** Reads the authorization request out of a location search string. */
export function parseAuthorizeParams(search: string): AuthorizeParse {
  const params = new URLSearchParams(search);
  if (!params.has("agent_authorize")) {
    return { kind: "none" };
  }
  const single = (key: string): string | null | "duplicate" => {
    const values = params.getAll(key);
    if (values.length > 1) {
      return "duplicate";
    }
    return values.length === 1 ? values[0] : null;
  };
  for (const key of AUTHORIZE_PARAM_KEYS) {
    if (single(key) === "duplicate") {
      return { kind: "invalid", reason: `授权地址里的参数 ${key} 出现了不止一次。` };
    }
  }
  if (params.get("agent_authorize") !== "1") {
    return { kind: "invalid", reason: "授权地址的格式不对。" };
  }

  const challenge = params.get("challenge") ?? "";
  if (!CHALLENGE_PATTERN.test(challenge)) {
    return { kind: "invalid", reason: "授权地址缺少校验串，或校验串的格式不对。" };
  }
  const state = params.get("state") ?? "";
  if (state === "" || state.length > MAX_STATE_CHARS || sanitizeUntrustedText(state, MAX_STATE_CHARS) !== state) {
    return { kind: "invalid", reason: "授权地址缺少 state 参数，或它的格式不对。" };
  }

  const port = params.get("port");
  const mode = params.get("mode");
  if (port !== null && mode !== null) {
    return { kind: "invalid", reason: "授权地址同时指定了端口和粘贴方式，只能二选一。" };
  }
  let parsedPort: number | undefined;
  let resolvedMode: AuthorizationMode;
  if (port !== null) {
    const value = PORT_PATTERN.test(port) ? Number(port) : NaN;
    if (!Number.isInteger(value) || value < 1024 || value > 65535) {
      return { kind: "invalid", reason: "授权地址里的端口必须是 1024–65535 之间的十进制整数。" };
    }
    parsedPort = value;
    resolvedMode = "loopback";
  } else if (mode !== null) {
    if (mode !== "paste") {
      return { kind: "invalid", reason: "授权地址里的 mode 只能是 paste。" };
    }
    resolvedMode = "paste";
  } else {
    return { kind: "invalid", reason: "授权地址既没有端口也没有指定粘贴方式。" };
  }

  return {
    kind: "valid",
    request: {
      challenge,
      state,
      mode: resolvedMode,
      ...(parsedPort !== undefined ? { port: parsedPort } : {}),
      deviceName: sanitizeUntrustedText(params.get("device"), MAX_DEVICE_NAME_CHARS),
      cliVersion: sanitizeUntrustedText(params.get("cli"), MAX_CLI_VERSION_CHARS),
    },
  };
}

/** The address without the authorization parameters, relative to the origin. */
export function stripAuthorizeParams(href: string): string {
  const url = new URL(href);
  for (const key of AUTHORIZE_PARAM_KEYS) {
    url.searchParams.delete(key);
  }
  const search = url.searchParams.toString();
  return `${url.pathname}${search ? `?${search}` : ""}${url.hash}`;
}

export interface AddressBar {
  href: string;
  search: string;
  replace: (url: string) => void;
}

/** The browser's address bar, or null outside a browser (tests, SSR). */
export function browserAddressBar(): AddressBar | null {
  if (typeof window === "undefined") {
    return null;
  }
  return {
    href: window.location.href,
    search: window.location.search,
    replace: (url) => window.history.replaceState(window.history.state, "", url),
  };
}

/** Removes the authorization parameters so a reload does not repeat the flow. */
export function clearAuthorizeParams(bar: AddressBar | null): void {
  if (!bar) {
    return;
  }
  const next = stripAuthorizeParams(bar.href);
  const current = new URL(bar.href);
  if (next !== `${current.pathname}${current.search}${current.hash}`) {
    bar.replace(next);
  }
}

/**
 * Reads the request once at start-up. An invalid request is final: its
 * parameters are removed at once. A valid one stays in the address bar until
 * the user decides, so signing in first does not lose it.
 */
export function takeAuthorizeRequest(bar: AddressBar | null): AuthorizeParse {
  if (!bar) {
    return { kind: "none" };
  }
  const parsed = parseAuthorizeParams(bar.search);
  if (parsed.kind === "invalid") {
    clearAuthorizeParams(bar);
  }
  return parsed;
}

/** The only callback a loopback login may be sent to. */
export function loopbackRedirectURI(port: number): string {
  return `http://127.0.0.1:${port}/callback`;
}

/**
 * Exact string comparison, deliberately not URL parsing: normalisation would
 * let userinfo, a trailing dot, `localhost` or a default port slip through.
 */
export function isExpectedRedirect(uri: unknown, port: number): boolean {
  return typeof uri === "string" && uri === loopbackRedirectURI(port);
}

export function isFramed(win: { top: unknown; self: unknown } | undefined = typeof window === "undefined" ? undefined : window): boolean {
  if (!win) {
    return false;
  }
  try {
    return win.top !== win.self;
  } catch {
    return true;
  }
}

/** Developers authorize read-only tokens; administrators may pick write when allowed. */
export function tierOptions(role: SessionRole, writeAllowed: boolean): AgentTier[] {
  return role === "admin" && writeAllowed ? ["read", "write"] : ["read"];
}

export const tierLabels: Record<AgentTier, string> = { read: "只读", write: "读写" };

/** When the token will expire; the server computes the exact time. */
export function tokenLifetimeText(role: SessionRole, tier: AgentTier, sessionExpiresAt: string | undefined, format: (iso: string) => string): string {
  if (role === "developer") {
    const until = sessionExpiresAt ? format(sessionExpiresAt) : "";
    return until && until !== "—" ? `同当前网页会话，最长 7 天（${until} 到期）` : "同当前网页会话，最长 7 天";
  }
  return tier === "write" ? "授权后 7 天，不续期" : "授权后 30 天，不续期";
}

export function identityLabel(session: SessionInfo): string {
  if (session.role === "admin") {
    return "管理员";
  }
  const identity = session.identity;
  const parts = [identity?.username?.trim(), identity?.token_name?.trim() ? `Key ${identity.token_name.trim()}` : ""].filter(Boolean);
  return parts.length > 0 ? `开发者 · ${parts.join(" · ")}` : "开发者（当前 API Key）";
}

export type DecisionOutcome =
  | { kind: "redirected"; url: string }
  | { kind: "code"; code: string; expiresIn: number }
  | { kind: "denied" }
  | { kind: "error"; message: string; final: boolean };

export interface DecisionDeps {
  api: Pick<AgentAccessApi, "authorize">;
  /** Leaves the page for the CLI's loopback listener. */
  navigate: (url: string) => void;
  /** Removes the authorization parameters from the address bar. */
  clearAddressBar: () => void;
  describeError: (cause: unknown) => string;
}

const TAMPERED_REDIRECT = "服务器返回的回跳地址不是本机命令行的地址，已停止跳转。请在终端重新运行 llmaudit login。";

/**
 * Sends the decision and carries it out. The address bar is cleared before
 * leaving the page or showing the result, so a reload never repeats it.
 */
export async function submitDecision(
  deps: DecisionDeps,
  request: AuthorizeRequest,
  tier: AgentTier,
  decision: AuthorizationDecision,
): Promise<DecisionOutcome> {
  let response: unknown;
  try {
    response = await deps.api.authorize({
      challenge: request.challenge,
      mode: request.mode,
      ...(request.mode === "loopback" ? { port: request.port } : {}),
      device_name: request.deviceName,
      cli_version: request.cliVersion,
      tier,
      decision,
    });
  } catch (cause: unknown) {
    return { kind: "error", message: deps.describeError(cause), final: false };
  }
  const body = (typeof response === "object" && response !== null ? response : {}) as { code?: unknown; expires_in?: unknown; redirect_uri?: unknown; denied?: unknown };

  if (decision === "approve" && (typeof body.code !== "string" || body.code === "")) {
    deps.clearAddressBar();
    return { kind: "error", message: "服务器没有返回授权码。请在终端重新运行 llmaudit login。", final: true };
  }

  if (request.mode === "loopback") {
    const port = request.port ?? 0;
    if (!isExpectedRedirect(body.redirect_uri, port)) {
      deps.clearAddressBar();
      return { kind: "error", message: TAMPERED_REDIRECT, final: true };
    }
    const query =
      decision === "approve"
        ? new URLSearchParams({ code: body.code as string, state: request.state })
        : new URLSearchParams({ error: "access_denied", state: request.state });
    const url = `${loopbackRedirectURI(port)}?${query}`;
    deps.clearAddressBar();
    deps.navigate(url);
    return { kind: "redirected", url };
  }

  deps.clearAddressBar();
  if (decision === "deny") {
    return { kind: "denied" };
  }
  const expiresIn = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 300;
  return { kind: "code", code: body.code as string, expiresIn };
}
