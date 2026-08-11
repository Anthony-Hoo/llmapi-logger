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
  newapi_token_id?: number | string | null;
  token_name?: string | null;
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

export interface TokenLink {
  newapi_token_id?: number | string | null;
  token_name?: string | null;
  linked_at_ns?: NanoTime | null;
}

export interface AuditDetail {
  audit: AuditSummary;
  request_uri?: string | null;
  stages: AuditStage[];
  headers: AuditHeader[];
  bodies: AuditBody[];
  parsed_result: ParsedResult | null;
  token_link: TokenLink | null;
}

export interface AuditFilters {
  path?: string;
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
