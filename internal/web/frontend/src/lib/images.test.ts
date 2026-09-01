import { describe, expect, it } from "vitest";

import { extractStructuredContent } from "./images";

// A real 1x1 PNG so <img> rendering of the produced data URL is plausible.
const pngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

describe("extractStructuredContent", () => {
  it("extracts OpenAI-style data URL images and replaces them with placeholders", () => {
    const value = JSON.stringify({
      output: [{ type: "input_image", image_url: `data:image/png;base64,${pngBase64}` }],
    });

    const result = extractStructuredContent(value);

    expect(result.formatted).toBe(true);
    expect(result.images).toHaveLength(1);
    expect(result.images[0].src).toBe(`data:image/png;base64,${pngBase64}`);
    expect(result.images[0].mediaType).toBe("image/png");
    expect(result.images[0].bytes).toBeGreaterThan(0);
    expect(result.text).toContain("[图片 #1 image/png");
    expect(result.text).not.toContain(pngBase64);
  });

  it("extracts Anthropic base64 source blocks and keeps surrounding metadata", () => {
    const value = JSON.stringify([
      { type: "image", source: { type: "base64", media_type: "image/png", data: pngBase64 } },
      { type: "text", text: "screenshot attached" },
    ]);

    const result = extractStructuredContent(value);

    expect(result.images).toHaveLength(1);
    expect(result.images[0].src).toBe(`data:image/png;base64,${pngBase64}`);
    expect(result.text).toContain("media_type");
    expect(result.text).toContain("screenshot attached");
    expect(result.text).toContain("[图片 #1 image/png");
    expect(result.text).not.toContain(pngBase64);
  });

  it("extracts Gemini inline data with camelCase mime type", () => {
    const value = JSON.stringify({ inlineData: { mimeType: "image/jpeg", data: pngBase64 } });

    const result = extractStructuredContent(value);

    expect(result.images).toHaveLength(1);
    expect(result.images[0].mediaType).toBe("image/jpeg");
    expect(result.text).not.toContain(pngBase64);
  });

  it("replaces data URLs inside plain non-JSON text", () => {
    const value = `screenshot: data:image/png;base64,${pngBase64} end`;

    const result = extractStructuredContent(value);

    expect(result.formatted).toBe(false);
    expect(result.images).toHaveLength(1);
    expect(result.text).toBe("screenshot: [图片 #1 image/png 70 B] end");
  });

  it("ignores non-image data URLs and payloads that are not base64", () => {
    const pdf = extractStructuredContent(`data:application/pdf;base64,${pngBase64}`);
    expect(pdf.images).toHaveLength(0);
    expect(pdf.text).toContain("application/pdf");

    const invalid = extractStructuredContent(
      JSON.stringify({ source: { media_type: "image/png", data: "not base64 at all !!!" } }),
    );
    expect(invalid.images).toHaveLength(0);
    expect(invalid.text).toContain("not base64 at all !!!");
  });

  it("ignores payloads too short to be a real image", () => {
    const result = extractStructuredContent(JSON.stringify({ image_url: "data:image/png;base64,QUJD" }));
    expect(result.images).toHaveLength(0);
    expect(result.text).toContain("QUJD");
  });

  it("keeps ordinary tool JSON untouched", () => {
    const result = extractStructuredContent('{"city":"Shanghai"}');
    expect(result).toEqual({ text: '{\n  "city": "Shanghai"\n}', formatted: true, images: [], omittedImages: 0 });
  });

  it("passes through empty and plain text values", () => {
    expect(extractStructuredContent("")).toEqual({ text: "", formatted: false, images: [], omittedImages: 0 });
    expect(extractStructuredContent("plain\nresult")).toEqual({
      text: "plain\nresult",
      formatted: false,
      images: [],
      omittedImages: 0,
    });
  });

  it("keeps replacing payloads after the thumbnail cap so no base64 leaks into the text", () => {
    const blocks = Array.from({ length: 30 }, () => ({
      type: "image",
      source: { type: "base64", media_type: "image/png", data: pngBase64 },
    }));

    const result = extractStructuredContent(JSON.stringify(blocks));

    expect(result.images).toHaveLength(24);
    expect(result.omittedImages).toBe(6);
    expect(result.text).not.toContain(pngBase64);
    expect(result.text).toContain("[图片 #24 image/png");
    expect(result.text).toContain("[图片 #30 image/png 70 B，超出缩略图上限]");
  });
});
