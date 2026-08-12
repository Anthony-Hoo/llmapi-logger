export type NanoTime = number | string;

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
  newapi_token_id?: number | string | null;
  token_name?: string | null;
  user_agent?: string | null;
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
  observed_length: number;
  stored_length: number;
  sha256?: string | null;
  hash_complete: boolean;
  eof_seen: boolean;
  state: string;
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

export interface AuditDetail {
  audit: AuditSummary;
  request_uri?: string | null;
  stages: AuditStage[];
  headers: AuditHeader[];
  bodies: AuditBody[];
  conversation: Conversation | null;
  parsed_result: ParsedResult | null;
  token_link: TokenLink | null;
}

export interface AuditFilters {
  path?: string;
  model?: string;
  user_agent?: string;
  newapi_user_id?: string;
  newapi_token_id?: string;
  forward_status?: string;
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
