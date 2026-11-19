import { describe, expect, it, vi } from "vitest";

import {
  clearAuthorizeParams,
  identityLabel,
  isExpectedRedirect,
  isFramed,
  parseAuthorizeParams,
  sanitizeUntrustedText,
  stripAuthorizeParams,
  submitDecision,
  takeAuthorizeRequest,
  tierOptions,
  tokenLifetimeText,
  type AddressBar,
  type AuthorizeRequest,
  type DecisionDeps,
} from "./authorize";
import type { AuthorizationRequest } from "./types";

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

function search(params: Record<string, string>): string {
  return `?${new URLSearchParams(params)}`;
}

const loopback = { agent_authorize: "1", challenge, state: "st-123_abc", port: "53123", device: "laptop", cli: "0.1.0" };
const paste = { agent_authorize: "1", challenge, state: "st-123_abc", mode: "paste", device: "server", cli: "0.1.0" };

describe("authorization URL parameters", () => {
  it("ignores an address without the authorization flag", () => {
    expect(parseAuthorizeParams("")).toEqual({ kind: "none" });
    expect(parseAuthorizeParams("?challenge=x&port=8080")).toEqual({ kind: "none" });
  });

  it("accepts a loopback request", () => {
    expect(parseAuthorizeParams(search(loopback))).toEqual({
      kind: "valid",
      request: { challenge, state: "st-123_abc", mode: "loopback", port: 53123, deviceName: "laptop", cliVersion: "0.1.0" },
    });
    expect(parseAuthorizeParams(search({ ...loopback, port: "1024" })).kind).toBe("valid");
    expect(parseAuthorizeParams(search({ ...loopback, port: "65535" })).kind).toBe("valid");
  });

  it("accepts a paste request", () => {
    const parsed = parseAuthorizeParams(search(paste));
    expect(parsed).toEqual({
      kind: "valid",
      request: { challenge, state: "st-123_abc", mode: "paste", deviceName: "server", cliVersion: "0.1.0" },
    });
    expect(parsed.kind === "valid" && "port" in parsed.request).toBe(false);
  });

  it("rejects every malformed request", () => {
    const cases: Record<string, string>[] = [
      { ...loopback, agent_authorize: "yes" },
      { ...loopback, challenge: "" },
      { ...loopback, challenge: challenge.slice(1) },
      { ...loopback, challenge: `${challenge.slice(1)}=` },
      { ...loopback, challenge: `${challenge.slice(1)}+` },
      { ...loopback, state: "" },
      { ...loopback, state: "a\nb" },
      { ...loopback, state: " padded" },
      { ...loopback, state: "x".repeat(513) },
      { ...loopback, port: "1023" },
      { ...loopback, port: "65536" },
      { ...loopback, port: "0" },
      { ...loopback, port: "08080" },
      { ...loopback, port: " 8080" },
      { ...loopback, port: "8080.0" },
      { ...loopback, port: "0x1F90" },
      { ...loopback, port: "-8080" },
      { ...loopback, port: "" },
      { ...loopback, mode: "paste" },
      { ...paste, mode: "loopback" },
      { ...paste, mode: "" },
    ];
    const withoutPort: Record<string, string> = { ...loopback };
    delete withoutPort.port;
    cases.push(withoutPort);
    const withoutChallenge: Record<string, string> = { ...loopback };
    delete withoutChallenge.challenge;
    cases.push(withoutChallenge);
    const withoutState: Record<string, string> = { ...paste };
    delete withoutState.state;
    cases.push(withoutState);
    for (const params of cases) {
      const parsed = parseAuthorizeParams(search(params));
      expect(parsed.kind, JSON.stringify(params)).toBe("invalid");
    }
    // A repeated parameter is ambiguous, so it is refused too.
    expect(parseAuthorizeParams(`${search(loopback)}&port=60000`).kind).toBe("invalid");
    expect(parseAuthorizeParams(`${search(loopback)}&state=other`).kind).toBe("invalid");
    expect(parseAuthorizeParams(`${search(loopback)}&agent_authorize=1`).kind).toBe("invalid");
  });

  it("strips control characters and caps untrusted text", () => {
    expect(sanitizeUntrustedText("lap\u0000top\u0007\u001b[31m", 64)).toBe("laptop[31m");
    expect(sanitizeUntrustedText("evil‮gnp.exe", 64)).toBe("evilgnp.exe");
    expect(sanitizeUntrustedText("  name\r\n", 64)).toBe("name");
    expect(sanitizeUntrustedText(null, 64)).toBe("");
    expect(Array.from(sanitizeUntrustedText("设".repeat(100), 64))).toHaveLength(64);
    // Capped by code points: an astral character is not split in half.
    expect(sanitizeUntrustedText("😀".repeat(70), 64)).toBe("😀".repeat(64));
    const parsed = parseAuthorizeParams(search({ ...loopback, device: `<b>x</b>\u0007${"d".repeat(80)}`, cli: "1.0\u0000\n" }));
    expect(parsed.kind === "valid" && parsed.request.deviceName).toBe(`<b>x</b>${"d".repeat(56)}`);
    expect(parsed.kind === "valid" && parsed.request.cliVersion).toBe("1.0");
  });
});

describe("address bar", () => {
  function bar(href: string): AddressBar & { replaced: string[] } {
    const replaced: string[] = [];
    const url = new URL(href);
    return { href, search: url.search, replace: (next) => void replaced.push(next), replaced };
  }

  it("removes only the authorization parameters", () => {
    expect(stripAuthorizeParams(`https://audit.example/ui/${search(loopback)}`)).toBe("/ui/");
    expect(stripAuthorizeParams(`https://audit.example/ui/?keep=1&${new URLSearchParams(paste)}#top`)).toBe("/ui/?keep=1#top");
  });

  it("clears an invalid request at once and keeps a valid one until the decision", () => {
    const invalid = bar(`https://audit.example/ui/${search({ ...loopback, port: "80" })}`);
    expect(takeAuthorizeRequest(invalid).kind).toBe("invalid");
    expect(invalid.replaced).toEqual(["/ui/"]);

    const valid = bar(`https://audit.example/ui/${search(loopback)}`);
    expect(takeAuthorizeRequest(valid).kind).toBe("valid");
    expect(valid.replaced).toEqual([]);

    const none = bar("https://audit.example/ui/");
    expect(takeAuthorizeRequest(none).kind).toBe("none");
    clearAuthorizeParams(none);
    expect(none.replaced).toEqual([]);
    expect(takeAuthorizeRequest(null)).toEqual({ kind: "none" });
  });
});

describe("loopback redirect", () => {
  it("accepts only the exact 127.0.0.1 callback on the same port", () => {
    expect(isExpectedRedirect("http://127.0.0.1:53123/callback", 53123)).toBe(true);
    for (const uri of [
      "http://localhost:53123/callback",
      "http://127.0.0.1:53124/callback",
      "http://127.0.0.1:53123/callback/",
      "http://127.0.0.1:53123/other",
      "https://127.0.0.1:53123/callback",
      "http://127.0.0.1:53123/callback?x=1",
      "http://user@127.0.0.1:53123/callback",
      "http://127.0.0.1.evil.example:53123/callback",
      "http://evil.example/callback",
      "//127.0.0.1:53123/callback",
      " http://127.0.0.1:53123/callback",
      "",
      undefined,
      null,
      42,
    ]) {
      expect(isExpectedRedirect(uri, 53123), String(uri)).toBe(false);
    }
  });
});

describe("framing", () => {
  it("detects a framed page", () => {
    const self = {};
    expect(isFramed({ top: self, self })).toBe(false);
    expect(isFramed({ top: {}, self })).toBe(true);
    const hostile = {
      self,
      get top(): unknown {
        throw new Error("cross-origin");
      },
    };
    expect(isFramed(hostile)).toBe(true);
    expect(isFramed(undefined)).toBe(false);
  });
});

describe("tiers and identity", () => {
  it("offers write only to administrators on a deployment that allows it", () => {
    expect(tierOptions("developer", false)).toEqual(["read"]);
    expect(tierOptions("developer", true)).toEqual(["read"]);
    expect(tierOptions("admin", false)).toEqual(["read"]);
    expect(tierOptions("admin", true)).toEqual(["read", "write"]);
  });

  it("states when the token expires", () => {
    const format = (iso: string) => `F(${iso})`;
    expect(tokenLifetimeText("admin", "read", undefined, format)).toContain("30 天");
    expect(tokenLifetimeText("admin", "write", undefined, format)).toContain("7 天");
    expect(tokenLifetimeText("developer", "read", "2026-11-20T00:00:00Z", format)).toBe("同当前网页会话，最长 7 天（F(2026-11-20T00:00:00Z) 到期）");
    expect(tokenLifetimeText("developer", "read", undefined, format)).toBe("同当前网页会话，最长 7 天");
  });

  it("names the identity that will own the token", () => {
    expect(identityLabel({ status: "ok", role: "admin" })).toBe("管理员");
    expect(identityLabel({ status: "ok", role: "developer", identity: { username: "alice", token_name: "laptop" } })).toBe("开发者 · alice · Key laptop");
    expect(identityLabel({ status: "ok", role: "developer", identity: null })).toBe("开发者（当前 API Key）");
  });
});

describe("submitting the decision", () => {
  const loopbackRequest: AuthorizeRequest = { challenge, state: "st/1", mode: "loopback", port: 53123, deviceName: "laptop", cliVersion: "0.1.0" };
  const pasteRequest: AuthorizeRequest = { challenge, state: "st/1", mode: "paste", deviceName: "server", cliVersion: "0.1.0" };

  function deps(response: unknown | (() => Promise<unknown>)) {
    const events: string[] = [];
    const authorize = vi.fn(async (request: AuthorizationRequest) => {
      events.push(`authorize:${request.decision}`);
      return typeof response === "function" ? (response as () => Promise<unknown>)() : response;
    });
    const value: DecisionDeps & { events: string[] } = {
      api: { authorize: authorize as unknown as DecisionDeps["api"]["authorize"] },
      navigate: (url) => void events.push(`navigate:${url}`),
      clearAddressBar: () => void events.push("clear"),
      describeError: (cause) => (cause instanceof Error ? cause.message : "failed"),
      events,
    };
    return { deps: value, authorize };
  }

  it("approves a loopback login and returns to the callback after clearing the address bar", async () => {
    const { deps: d, authorize } = deps({ code: "c0de", expires_in: 60, redirect_uri: "http://127.0.0.1:53123/callback" });
    const outcome = await submitDecision(d, loopbackRequest, "write", "approve");
    expect(authorize).toHaveBeenCalledWith({
      challenge,
      mode: "loopback",
      port: 53123,
      device_name: "laptop",
      cli_version: "0.1.0",
      tier: "write",
      decision: "approve",
    });
    const url = "http://127.0.0.1:53123/callback?code=c0de&state=st%2F1";
    expect(outcome).toEqual({ kind: "redirected", url });
    expect(d.events).toEqual(["authorize:approve", "clear", `navigate:${url}`]);
  });

  it("denies a loopback login and still returns to the callback", async () => {
    const { deps: d } = deps({ denied: true, redirect_uri: "http://127.0.0.1:53123/callback" });
    const outcome = await submitDecision(d, loopbackRequest, "read", "deny");
    const url = "http://127.0.0.1:53123/callback?error=access_denied&state=st%2F1";
    expect(outcome).toEqual({ kind: "redirected", url });
    expect(d.events).toEqual(["authorize:deny", "clear", `navigate:${url}`]);
  });

  it("refuses to follow a tampered redirect", async () => {
    for (const redirect of ["http://localhost:53123/callback", "http://127.0.0.1:1/callback", "http://127.0.0.1:53123/steal", "https://evil.example/callback", undefined]) {
      for (const decision of ["approve", "deny"] as const) {
        const { deps: d } = deps(decision === "approve" ? { code: "c0de", expires_in: 60, redirect_uri: redirect } : { denied: true, redirect_uri: redirect });
        const outcome = await submitDecision(d, loopbackRequest, "read", decision);
        expect(outcome.kind, String(redirect)).toBe("error");
        expect(outcome.kind === "error" && outcome.final).toBe(true);
        expect(d.events.some((event) => event.startsWith("navigate:"))).toBe(false);
        expect(d.events).toContain("clear");
      }
    }
  });

  it("shows the one-time code for a paste login", async () => {
    const { deps: d, authorize } = deps({ code: "paste-code", expires_in: 300 });
    const outcome = await submitDecision(d, pasteRequest, "read", "approve");
    expect(authorize.mock.calls[0][0]).toEqual({ challenge, mode: "paste", device_name: "server", cli_version: "0.1.0", tier: "read", decision: "approve" });
    expect("port" in authorize.mock.calls[0][0]).toBe(false);
    expect(outcome).toEqual({ kind: "code", code: "paste-code", expiresIn: 300 });
    expect(d.events).toEqual(["authorize:approve", "clear"]);
  });

  it("reports a paste denial without leaving the page", async () => {
    const { deps: d } = deps({ denied: true });
    expect(await submitDecision(d, pasteRequest, "read", "deny")).toEqual({ kind: "denied" });
    expect(d.events).toEqual(["authorize:deny", "clear"]);
  });

  it("keeps the request on a server error so the user can decide again", async () => {
    const { deps: d } = deps(async () => {
      throw new Error("服务暂时不可用");
    });
    expect(await submitDecision(d, loopbackRequest, "read", "approve")).toEqual({ kind: "error", message: "服务暂时不可用", final: false });
    expect(d.events).toEqual(["authorize:approve"]);
  });

  it("treats an approval without a code as final", async () => {
    const { deps: d } = deps({ expires_in: 300 });
    const outcome = await submitDecision(d, pasteRequest, "read", "approve");
    expect(outcome.kind === "error" && outcome.final).toBe(true);
    expect(d.events).toEqual(["authorize:approve", "clear"]);
  });
});
