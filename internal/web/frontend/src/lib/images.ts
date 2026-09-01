import { formatBytes } from "./format";

/** One inline base64 image recovered from tool call arguments or results. */
export interface ExtractedImage {
  /** data: URL, safe for an <img> src without touching the network. */
  src: string;
  mediaType: string;
  /** Approximate decoded size in bytes. */
  bytes: number;
}

export interface StructuredContent {
  /** Display text with base64 payloads replaced by short placeholders. */
  text: string;
  /** True when the value parsed as JSON and was pretty-printed. */
  formatted: boolean;
  images: ExtractedImage[];
  /** Valid images beyond the gallery cap: replaced in text, not rendered. */
  omittedImages: number;
}

// Providers embed images in tool traffic in three shapes: a data URL string
// (OpenAI image_url / computer screenshots), a base64 source object
// (Anthropic {type:"image",source:{media_type,data}}), and inline_data
// (Gemini {mime_type,data}). All of them survive intact inside the
// conversation DTO because tool arguments/results keep the full provider
// JSON as a string.
const imageMediaTypes = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/bmp",
  "image/svg+xml",
  "image/avif",
]);

const dataUrlPattern = /data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})/gi;

// Below ~32 base64 chars nothing decodes into a real image; this also keeps
// short accidental matches (e.g. examples in prose) out of the gallery.
const minBase64Length = 32;
const maxImagesPerPart = 24;

function isBase64Payload(value: string): boolean {
  return value.length >= minBase64Length && /^[A-Za-z0-9+/\r\n]+={0,2}$/.test(value.replace(/\s+/g, ""));
}

function decodedBytes(base64: string): number {
  const compact = base64.replace(/\s+/g, "");
  const padding = compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((compact.length * 3) / 4) - padding);
}

class ImageCollector {
  readonly images: ExtractedImage[] = [];
  private total = 0;

  get omitted(): number {
    return this.total - this.images.length;
  }

  // Returning null keeps the original text, so it is reserved for values
  // that are not inline images at all. A valid image past the gallery cap
  // still gets its payload replaced: the cap bounds thumbnail count, and a
  // wall of raw base64 in the JSON is exactly what the placeholder exists
  // to prevent.
  add(mediaType: string, base64: string): string | null {
    const normalizedType = mediaType.toLowerCase();
    if (!imageMediaTypes.has(normalizedType) || !isBase64Payload(base64)) {
      return null;
    }
    this.total += 1;
    const bytes = decodedBytes(base64);
    const label = `图片 #${this.total} ${normalizedType} ${formatBytes(bytes)}`;
    if (this.images.length >= maxImagesPerPart) {
      return `[${label}，超出缩略图上限]`;
    }
    this.images.push({
      src: `data:${normalizedType};base64,${base64.replace(/\s+/g, "")}`,
      mediaType: normalizedType,
      bytes,
    });
    return `[${label}]`;
  }
}

/** Replaces every inline data-URL image inside plain text with a placeholder. */
function replaceDataUrls(text: string, collector: ImageCollector): string {
  return text.replace(dataUrlPattern, (match, mediaType: string, payload: string) => {
    return collector.add(mediaType, payload) ?? match;
  });
}

function mediaTypeOf(node: Record<string, unknown>): string | null {
  for (const key of ["media_type", "mediaType", "mime_type", "mimeType"]) {
    const value = node[key];
    if (typeof value === "string" && value.toLowerCase().startsWith("image/")) {
      return value;
    }
  }
  return null;
}

// Rewrites the parsed JSON in place: base64 payloads become placeholders so
// the rendered JSON stays readable, while the extracted images are collected
// for the gallery. Only display copies are touched, never stored evidence.
function walkValue(value: unknown, collector: ImageCollector): unknown {
  if (typeof value === "string") {
    return replaceDataUrls(value, collector);
  }
  if (Array.isArray(value)) {
    return value.map((item) => walkValue(item, collector));
  }
  if (value === null || typeof value !== "object") {
    return value;
  }

  const node = { ...(value as Record<string, unknown>) };
  const mediaType = mediaTypeOf(node);
  const payload = node.data;
  if (mediaType && typeof payload === "string" && isBase64Payload(payload)) {
    const placeholder = collector.add(mediaType, payload);
    if (placeholder) {
      node.data = placeholder;
    }
    return node;
  }
  for (const key of Object.keys(node)) {
    node[key] = walkValue(node[key], collector);
  }
  return node;
}

/**
 * Pretty-prints tool call arguments / tool results and pulls inline base64
 * images out of them. Non-JSON text keeps its original layout and only has
 * embedded data URLs swapped for placeholders.
 */
export function extractStructuredContent(value: string): StructuredContent {
  const collector = new ImageCollector();
  if (!value.trim()) {
    return { text: value, formatted: false, images: [], omittedImages: 0 };
  }

  try {
    const rewritten = walkValue(JSON.parse(value), collector);
    return { text: JSON.stringify(rewritten, null, 2), formatted: true, images: collector.images, omittedImages: collector.omitted };
  } catch {
    return { text: replaceDataUrls(value, collector), formatted: false, images: collector.images, omittedImages: collector.omitted };
  }
}
