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
  /** False when the server runs without context insights; its routes would 404. */
  insights_enabled?: boolean;
}

export interface AuditCursor {
  before_started_at_ns: NanoTime;
  before_id: string;
}

export type BillingState = "unchecked" | "billed" | "unbilled";

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
  /** null when the audit has no NewAPI link. */
  billing_state?: BillingState | null;
  newapi_quota?: number | null;
  cost_usd?: number | null;
  billed_prompt_tokens?: number | null;
  billed_completion_tokens?: number | null;
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
  status_class?: string;
  status_code?: string;
}

export type RawSide = "request" | "response";

export interface RawBodyDownload {
	missingChunks?: boolean;
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

// ---------------------------------------------------------------------------
// Context insights (doc/features/20-context-insights.md). Mirrors the JSON tags
// of internal/insights/apitypes.go and types.go. Nanosecond timestamps are JSON
// strings there (like the audit API; epoch ns exceed 2^53), hence NanoTime;
// nullable numbers mean "not reported" or "unknown price".
// ---------------------------------------------------------------------------

export type CategoryKey =
  | "system"
  | "tools"
  | "user"
  | "injected"
  | "assistant"
  | "reasoning"
  | "tool_result"
  | "media";

export type CategoryValues = Record<CategoryKey, number>;

export interface InsightsUsage {
  uncached_input: number | null;
  cache_read: number | null;
  cache_write: number | null;
  output: number | null;
  reasoning: number | null;
}

export interface UsageTotals {
  requests: number;
  uncached_input: number;
  cache_read: number;
  cache_write: number;
  output: number;
  reasoning: number;
  prompt_total: number;
  cache_hit_rate: number | null;
  /** Actual NewAPI billing in USD of the billed requests; null when none is billed. */
  cost_usd: number | null;
  billed_requests: number;
  /** Requests without a billing result (not looked up, pending, unresolved, or no consume log). */
  unbilled_requests: number;
}

export type InsightsGroupBy = "model" | "protocol" | "client" | "caller" | "token";
export type InsightsSessionSort = "recent" | "tokens" | "context";

export interface DailyUsage {
  day: string;
  usage: UsageTotals;
}

export interface HeatmapDay {
  day: string;
  requests: number;
  sessions: number;
}

export interface GroupUsage {
  key: string;
  label: string;
  usage: UsageTotals;
}

export interface OverviewResponse {
  from_ns: NanoTime;
  to_ns: NanoTime;
  totals: UsageTotals;
  sessions: number;
  trees: number;
  daily: DailyUsage[];
  heatmap: HeatmapDay[];
  group_by: string;
  groups: GroupUsage[];
  composition: CategoryValues;
  /** False when the server has no NewAPI admin credentials, so no cost is available. */
  billing_enabled: boolean;
}

export interface SessionCaller {
  username?: string;
  token_name?: string;
}

export interface SessionCard {
  session_id: string;
  session_link: string;
  tree_id?: string;
  protocol: string;
  client: string;
  role: string;
  first_ns: NanoTime;
  last_ns: NanoTime;
  steps: number;
  turns: number;
  models: string[];
  usage: UsageTotals;
  last_composition: CategoryValues;
  last_prompt_total: number | null;
  context_window: number | null;
  subagents: number;
  caller: SessionCaller | null;
}

export interface SessionsResponse {
  items: SessionCard[];
  next_cursor?: string;
  billing_enabled: boolean;
}

export type InsightsEvent =
  | "model_switch"
  | "compaction"
  | "prune"
  | "system_changed"
  | "tools_changed"
  | "injected";

export type ResponseKind = "thinking" | "tool_call" | "text";

export interface TrendStep {
  audit_id: string;
  started_at_ns: NanoTime;
  turn: number;
  turn_start: boolean;
  model: string;
  role: string;
  estimate: CategoryValues;
  usage: InsightsUsage;
  prompt_total: number | null;
  events: string[];
  appended_items: number | null;
  removed_items: number | null;
  stop_reason?: string;
  response_kinds: string[];
  first_event_ms: number | null;
  generation_ms: number | null;
  client_gap_ms: number | null;
  cost_usd: number | null;
}

export interface TrendResponse {
  session_id: string;
  tree_id?: string;
  context_window: number | null;
  truncated: boolean;
  steps: TrendStep[];
}

export interface TreeNode {
  node_id: string;
  parent_node_id?: string;
  visible: boolean;
  session_id?: string;
  client: string;
  role: string;
  first_ns: NanoTime;
  last_ns: NanoTime;
  steps: number;
  aux_requests: number;
  usage: UsageTotals;
  last_composition: CategoryValues;
  last_prompt_total: number | null;
  context_window: number | null;
  link_source?: string;
  link_confidence?: number;
}

export interface TreeResponse {
  tree_id: string;
  truncated: boolean;
  nodes: TreeNode[];
}

export interface CompositionItem {
  index: number;
  category: string;
  role: string;
  /** text | thinking | tool_call | tool_result | image | file | tool_def | system */
  kind: string;
  tokens: number;
  label?: string;
  summary?: string;
  /** added | kept; absent without a previous step. */
  change?: string;
}

export interface ToolDef {
  name: string;
  tokens: number;
  /** builtin | mcp:<server> | custom */
  source: string;
}

export interface FileOp {
  tool: string;
  /** read | write | search | shell */
  op: string;
  path?: string;
  added_lines?: number;
  removed_lines?: number;
}

export interface AgentIdentity {
  client: string;
  role: string;
  root_id?: string;
  node_id?: string;
  parent_id?: string;
  name?: string;
  link_source?: string;
  confidence?: number;
}

export interface CompositionDiff {
  added_items: number;
  removed_items: number;
  by_category: CategoryValues;
}

export interface CompositionResponse {
  audit_id: string;
  analysis_version: number;
  model: string;
  usage: InsightsUsage;
  prompt_total: number | null;
  estimate: CategoryValues;
  anchored: CategoryValues | null;
  context_window: number | null;
  items: CompositionItem[];
  tools: ToolDef[];
  file_ops: FileOp[];
  agent: AgentIdentity;
  previous_audit_id?: string;
  diff: CompositionDiff | null;
  events: string[];
  truncated: boolean;
}

export interface OverviewQuery {
  from_ns: string;
  to_ns: string;
  tz_offset_min: number;
  group_by: InsightsGroupBy;
}

export interface SessionsQuery {
  from_ns?: string;
  to_ns?: string;
  sort?: InsightsSessionSort;
  limit?: number;
  cursor?: string;
}
