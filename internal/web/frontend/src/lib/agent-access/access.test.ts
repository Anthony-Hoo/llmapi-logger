import { describe, expect, it, vi } from "vitest";

import { changedKeys, changeDevice, copyText, detectPlatform, installLinkRequest, loadChanges, revokeDevice, tokenState } from "./access";
import type { AgentChange, AgentToken } from "./types";

const token: AgentToken = {
  id: 7,
  display_prefix: "lla_AbCd",
  role: "admin",
  tier: "read",
  device_name: "laptop",
  cli_version: "0.1.0",
  created_at: "2026-11-01T00:00:00Z",
  expires_at: "2026-12-01T00:00:00Z",
  last_used_at: null,
  revoked_at: null,
};

describe("install form", () => {
  it("preselects the platform from the browser", () => {
    expect(detectPlatform({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", platform: "Win32" })).toBe("windows-amd64");
    expect(detectPlatform({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", platform: "MacIntel" })).toBe("darwin-arm64");
    expect(detectPlatform({ userAgent: "Mozilla/5.0 (X11; Linux x86_64)", platform: "Linux x86_64" })).toBe("linux-amd64");
    expect(detectPlatform({ userAgent: "Mozilla/5.0 (X11; Linux aarch64)", platform: "Linux aarch64" })).toBe("linux-arm64");
    expect(detectPlatform(undefined)).toBe("linux-amd64");
  });

  it("sends the Skills directory only for 其他 and only when typed", () => {
    expect(installLinkRequest("claude-code", "linux-amd64", "/x")).toEqual({ agent: "claude-code", platform: "linux-amd64" });
    expect(installLinkRequest("other", "linux-amd64", "  ")).toEqual({ agent: "other", platform: "linux-amd64" });
    expect(installLinkRequest("other", "darwin-arm64", " /home/me/skills ")).toEqual({ agent: "other", platform: "darwin-arm64", skills_dir: "/home/me/skills" });
  });
});

describe("clipboard", () => {
  it("copies in a secure context", async () => {
    const writeText = vi.fn(async () => undefined);
    expect(await copyText("prompt", { isSecureContext: true, clipboard: { writeText } })).toBe("copied");
    expect(writeText).toHaveBeenCalledWith("prompt");
  });

  it("falls back to a manual copy without a usable clipboard", async () => {
    const writeText = vi.fn(async () => undefined);
    // Plain HTTP on a non-local origin: not a secure context.
    expect(await copyText("prompt", { isSecureContext: false, clipboard: { writeText } })).toBe("manual");
    expect(writeText).not.toHaveBeenCalled();
    expect(await copyText("prompt", { isSecureContext: true, clipboard: undefined })).toBe("manual");
    expect(await copyText("prompt", { isSecureContext: true, clipboard: { writeText: async () => Promise.reject(new Error("denied")) } })).toBe("manual");
  });
});

describe("devices and changes", () => {
  it("never asks for changes from a developer session", async () => {
    const listChanges = vi.fn(async () => ({ items: [] as AgentChange[] }));
    expect(await loadChanges({ listChanges }, "developer")).toBeNull();
    expect(listChanges).not.toHaveBeenCalled();
    expect(await loadChanges({ listChanges }, "admin")).toEqual([]);
    expect(listChanges).toHaveBeenCalledWith(50, undefined);
  });

  it("revokes only after confirmation and then reloads the list", async () => {
    const calls: string[] = [];
    const api = {
      revokeToken: vi.fn(async (id: number | string) => void calls.push(`revoke:${id}`)),
      listTokens: vi.fn(async () => {
        calls.push("list");
        return { items: [{ ...token, revoked_at: "2026-11-19T00:00:00Z" }] };
      }),
    };
    const declined = vi.fn((_message: string) => false);
    expect(await revokeDevice(api, token, declined)).toBeNull();
    expect(declined.mock.calls[0][0]).toContain("laptop");
    expect(calls).toEqual([]);

    const items = await revokeDevice(api, token, () => true);
    expect(calls).toEqual(["revoke:7", "list"]);
    expect(items?.[0].revoked_at).toBe("2026-11-19T00:00:00Z");
  });

  it("derives the token state", () => {
    const now = Date.parse("2026-11-19T00:00:00Z");
    expect(tokenState(token, now)).toBe("active");
    expect(tokenState({ ...token, expires_at: "2026-11-18T00:00:00Z" }, now)).toBe("expired");
    expect(tokenState({ ...token, revoked_at: "2026-11-02T00:00:00Z" }, now)).toBe("revoked");
  });

  it("reads changed keys and names the device of a change", () => {
    // The row exactly as GET /api/v1/agent-access/changes writes it.
    const change: AgentChange = {
      id: 1,
      at: "2026-11-19T00:00:00Z",
      event: "write_applied",
      token_id: 7,
      role: "admin",
      command: "apply",
      cli_version: "0.1.0",
      object_kind: "content-rule",
      object_id: "12",
      changed_keys: ["enabled", "name"],
      outcome: "ok",
      error_code: "",
    };
    expect(changedKeys(change)).toEqual(["enabled", "name"]);
    expect(changedKeys({ ...change, changed_keys: [] })).toEqual([]);
    expect(changedKeys({ ...change, changed_keys: "not a list" as unknown as string[] })).toEqual([]);
    expect(changeDevice(change, [token])).toBe("laptop");
    expect(changeDevice({ ...change, token_id: 9 }, [token])).toBe("令牌 #9");
    expect(changeDevice({ ...change, token_id: null }, [token])).toBe("—");
  });
});
