import type { AuditDetail, AuditHeader, RawBodyDownload, RawSide } from "../types";

const stageBySide: Record<RawSide, string> = {
  request: "request_sent_to_newapi",
  response: "response_received_from_newapi",
};

export type RawBodyPreview =
  | {
      kind: "text";
      text: string;
      contentType: string;
    }
  | {
      kind: "binary";
      reason: string;
      contentType: string;
    };

export interface EvidenceEnvelope {
  startLine: string;
  headerLines: string[];
  trailerLines: string[];
}

export async function createRawBodyPreview(
  download: RawBodyDownload,
  contentTypeHint?: string | null,
): Promise<RawBodyPreview> {
  const contentType =
    normalizedContentType(contentTypeHint) || normalizedContentType(download.contentType) || "application/octet-stream";
  const bytes = new Uint8Array(await download.blob.arrayBuffer());

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return {
      kind: "binary",
      reason: "Body 不是有效的 UTF-8 文本。",
      contentType,
    };
  }

  if (hasBinaryControls(text)) {
    return {
      kind: "binary",
      reason: "Body 包含二进制控制字节，未作为文本渲染。",
      contentType,
    };
  }

  return { kind: "text", text, contentType };
}

export function capturedContentType(headers: AuditHeader[], side: RawSide): string | null {
  const match = headers.find(
    (header) =>
      header.stage === stageBySide[side] &&
      header.kind === "header" &&
      header.name.toLowerCase() === "content-type",
  );
  return match?.value || null;
}

export function evidenceStage(side: RawSide): string {
  return stageBySide[side];
}

export function buildEvidenceEnvelope(detail: AuditDetail, side: RawSide): EvidenceEnvelope {
  const stageName = stageBySide[side];
  const stage = detail.stages.find((candidate) => candidate.stage === stageName);
  const headers = detail.headers.filter((header) => header.stage === stageName && header.kind === "header");
  const trailers = detail.headers.filter((header) => header.stage === stageName && header.kind === "trailer");
  const names = new Set(headers.map((header) => header.name.toLowerCase()));
  const headerLines: string[] = [];

  if (side === "request" && stage?.host && !names.has("host")) {
    headerLines.push(`Host: ${stage.host}`);
  }
  headerLines.push(...headers.map(headerLine));
  if (
    stage?.content_length !== null &&
    stage?.content_length !== undefined &&
    stage.content_length >= 0 &&
    !names.has("content-length")
  ) {
    headerLines.push(`Content-Length: ${stage.content_length}`);
  }

  return {
    startLine:
      side === "request"
        ? `${stage?.method || detail.audit.method} ${requestTarget(detail)} ${stage?.proto || "HTTP"}`
        : `${stage?.proto || "HTTP"} ${stage?.status_code ?? detail.audit.status_code ?? "—"}`,
    headerLines,
    trailerLines: trailers.map(headerLine),
  };
}

function requestTarget(detail: AuditDetail): string {
  const requestURI = detail.request_uri || detail.audit.path || "/";
  if (requestURI.startsWith("/") || requestURI === "*") {
    return requestURI;
  }
  try {
    const absolute = new URL(requestURI);
    return `${absolute.pathname || "/"}${absolute.search}`;
  } catch {
    return detail.audit.path || "/";
  }
}

function normalizedContentType(value: string | null | undefined): string {
  return value?.trim() || "";
}

function hasBinaryControls(value: string): boolean {
  let controls = 0;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code === 0) {
      return true;
    }
    if (code < 32 && character !== "\n" && character !== "\r" && character !== "\t") {
      controls += 1;
    }
  }
  return controls > 4 && controls / Math.max(value.length, 1) > 0.01;
}

function headerLine(header: AuditHeader): string {
  return `${header.name}: ${header.value}`;
}
