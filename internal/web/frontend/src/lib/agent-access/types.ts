// Web-side Agent access endpoints (doc/features/25-agent-access-contract.md
// §3.2). They answer like the other /api/v1 routes: plain JSON, errors as
// {"error":{"code","message"}}; no facade envelope.

import type { SessionRole } from "../../types";

export type AgentTier = "read" | "write";
export type AuthorizationMode = "loopback" | "paste";
export type AuthorizationDecision = "approve" | "deny";

export interface AuthorizationRequest {
  challenge: string;
  mode: AuthorizationMode;
  /** Loopback only; sent as a JSON number. */
  port?: number;
  device_name: string;
  cli_version: string;
  tier: AgentTier;
  decision: AuthorizationDecision;
}

export interface AuthorizationApproved {
  code: string;
  /** Seconds the one-time code stays valid (60 loopback, 300 paste). */
  expires_in: number;
  /** Loopback only: http://127.0.0.1:<port>/callback, without a query. */
  redirect_uri?: string;
}

export interface AuthorizationDenied {
  denied: true;
  redirect_uri?: string;
}

export type AuthorizationResponse = AuthorizationApproved | AuthorizationDenied;

/** One authorized device; timestamps are RFC 3339 strings. */
export interface AgentToken {
  id: number | string;
  display_prefix: string;
  role: SessionRole;
  tier: AgentTier;
  device_name: string;
  cli_version: string;
  created_at: string;
  expires_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
}

export interface AgentTokenList {
  items: AgentToken[];
}

export type InstallAgent = "claude-code" | "codex" | "cursor" | "gemini-cli" | "other";

export type InstallPlatform = "windows-amd64" | "linux-amd64" | "linux-arm64" | "darwin-arm64" | "darwin-amd64";

export interface InstallLinkRequest {
  agent: InstallAgent;
  platform: InstallPlatform;
  skills_dir?: string;
}

export interface InstallLink {
  prompt: string;
  expires_at: string;
}

/**
 * One row of GET /api/v1/agent-access/changes (contract §3.2): a write_applied,
 * write_failed or write_denied row of agent_audit_log, newest first. Absent
 * text columns are empty strings; the device name comes from the token list.
 */
export interface AgentChange {
  id: number;
  /** RFC 3339 UTC. */
  at: string;
  event: "write_applied" | "write_failed" | "write_denied" | string;
  token_id: number | null;
  role: string;
  /** The command the client reported, e.g. "apply"; recorded, never trusted. */
  command: string;
  cli_version: string;
  /** e.g. "content-rule", "analysis-settings", "plan". */
  object_kind: string;
  object_id: string;
  /** Names of the changed fields only, never values. */
  changed_keys: string[];
  outcome: "ok" | "denied" | "failed" | string;
  /** The facade error code of a failed or denied write; empty otherwise. */
  error_code: string;
}

export interface AgentChangeList {
  items: AgentChange[];
}

export interface AgentAccessApi {
  authorize: (request: AuthorizationRequest, signal?: AbortSignal) => Promise<AuthorizationResponse>;
  listTokens: (signal?: AbortSignal) => Promise<AgentTokenList>;
  /** Idempotent: 204 also for revoked, expired or unknown tokens. */
  revokeToken: (id: number | string, signal?: AbortSignal) => Promise<void>;
  createInstallLink: (request: InstallLinkRequest, signal?: AbortSignal) => Promise<InstallLink>;
  /** Administrators only. */
  listChanges: (limit?: number, signal?: AbortSignal) => Promise<AgentChangeList>;
}
