export type NanoTime = number | string;

export type SessionRole = "admin" | "developer";

/** Ownership of the NewAPI key a developer signed in with, for display only. */
export interface DeveloperIdentity {
  user_id?: number;
  username?: string;
  token_id?: number;
  token_name?: string;
}

export interface SessionInfo {
  status: string;
  role: SessionRole;
  expires_at?: string;
  identity?: DeveloperIdentity | null;
}

export interface AuditCursor {
  before_started_at_ns: NanoTime;
  before_id: string;
}

export interface AuditSummary {
  audit_id: string;
  started_at_ns: NanoTime;
  ended_at_ns?: NanoTime | null;
  route_id: string;
  protocol: string;
  parser_name?: string;
  method: string;
  path: string;
  mode?: string;
  status_code?: number | null;
  ttft_ns?: NanoTime | null;
  forward_status: string;
  capture_status: string;
  parse_status: string;
  blocked_by?: string | null;
  block_code?: string | null;
  error_code?: string | null;
  request_model?: string | null;
  response_model?: string | null;
  newapi_request_id?: string | null;
  caller_status?: "none" | "pending" | "resolved" | "unresolved" | string;
  newapi_user_id?: number | string | null;
  username?: string | null;
  display_name?: string | null;
  newapi_token_id?: number | string | null;
  token_name?: string | null;
  user_agent?: string | null;
  conversation_id?: string | null;
  conversation_turns?: number | string | null;
}

export interface AuditListPage {
  items: AuditSummary[];
  next_cursor: AuditCursor | null;
}

export interface AuditStage {
  stage: string;
  state: string;
  proto?: string;
  method?: string;
  host?: string;
  status_code?: number | null;
  content_length?: number | null;
  started_at_ns?: NanoTime;
  ended_at_ns?: NanoTime | null;
  error_code?: string | null;
}

export interface AuditHeader {
  stage: string;
  kind: string;
  name: string;
  value_index: number;
  value_length: number;
  value: string;
}

export interface AuditBody {
  stage: string;
  source_stage: string;
  observed_length: number;
  stored_length: number;
  sha256?: string | null;
  hash_complete: boolean;
  eof_seen: boolean;
  state: string;
  retention_state: "pending" | "metadata" | "full" | string;
  first_observed_at_ns?: NanoTime | null;
  last_observed_at_ns?: NanoTime | null;
  chunk_count: number;
  stream_event_count: number;
  stream_timeline_complete: boolean;
  error_code?: string | null;
}

export type ParsedResult = Record<string, string | number | boolean | null>;

export type ConversationPhase = "request" | "response";

export type ConversationDirection = "client_to_upstream" | "upstream_to_client";

export interface ConversationTextPart {
  index: number;
  type: "text";
  text?: string | null;
}

export interface ConversationReasoningPart {
  index: number;
  type: "reasoning";
  text?: string | null;
}

export interface ConversationToolCallPart {
  index: number;
  type: "tool_call";
  id?: string | null;
  name?: string | null;
  arguments?: string | null;
}

export interface ConversationToolResultPart {
  index: number;
  type: "tool_result";
  tool_call_id?: string | null;
  name?: string | null;
  result?: string | null;
}

export interface ConversationUnknownPart {
  index: number;
  type: "unknown";
  data?: string | null;
}

export type ConversationPart =
  | ConversationTextPart
  | ConversationReasoningPart
  | ConversationToolCallPart
  | ConversationToolResultPart
  | ConversationUnknownPart;

export interface ConversationMessage {
  index: number;
  role: string;
  phase: ConversationPhase;
  direction: ConversationDirection;
  name?: string | null;
  tool_call_id?: string | null;
  content: ConversationPart[];
}

export interface Conversation {
  schema_version: number;
  messages: ConversationMessage[];
}

export interface TokenLink {
  newapi_request_id?: string | null;
  newapi_user_id?: number | string | null;
  username?: string | null;
  newapi_token_id?: number | string | null;
  token_name?: string | null;
  linked_at_ns?: NanoTime | null;
}

export interface AuditTurn {
  turn_id: string;
  conversation_id: string;
  parent_turn_id?: string | null;
  parent_base: string;
  link_reason: string;
  link_confidence: number;
  request_layout: string;
  response_layout: string;
  request_item_count: number;
  response_item_count: number;
  request_sequence_sha256: string;
  response_sequence_sha256: string;
  request_reconstruction_sha256: string;
  response_reconstruction_sha256: string;
  reconstruction_status: string;
  previous_response_id?: string | null;
  response_id?: string | null;
  created_at_ns: NanoTime;
}

export interface TimelinePoint {
  offset: number;
  at_ns: NanoTime;
}

export interface StreamTimeline {
  stage: string;
  observed_length: number;
  event_count: number;
  first_event_at_ns?: NanoTime | null;
  last_event_at_ns?: NanoTime | null;
  complete: boolean;
  points: TimelinePoint[];
}

export interface NewAPIUser {
  id: number;
  username: string;
  display_name: string;
  status: number;
  group: string;
}

export interface NewAPIUserList {
  items: NewAPIUser[];
  refreshed_at: string | null;
}

export interface UserAgentRule {
  id: number;
  name: string;
  enabled: boolean;
  model_pattern: string;
  user_agent_pattern: string;
  created_at_ns: NanoTime;
  updated_at_ns: NanoTime;
}

export interface UserAgentRuleInput {
  name: string;
  enabled: boolean;
  model_pattern: string;
  user_agent_pattern: string;
}

export interface UserAgentRuleList {
  items: UserAgentRule[];
}

export interface AuditDetail {
  audit: AuditSummary;
  request_uri?: string | null;
  stages: AuditStage[];
  headers: AuditHeader[];
  bodies: AuditBody[];
  conversation: Conversation | null;
  parsed_result: ParsedResult | null;
  turn: AuditTurn | null;
  token_link: TokenLink | null;
}

export interface AuditFilters {
  path?: string;
  model?: string;
  user_agent?: string;
  newapi_user_id?: string;
  newapi_token_id?: string;
  forward_status?: string;
  conversation?: string;
  collapse?: boolean;
}

export type RawSide = "request" | "response";

export interface RawBodyDownload {
  blob: Blob;
  filename: string;
  contentType: string;
  observedLength: string | null;
  storedLength: string | null;
  sha256: string | null;
  complete: boolean;
}

export interface ReconstructedBodyDownload {
  blob: Blob;
  filename: string;
  contentType: string;
}
