import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Conversation } from "../types";
import { ConversationView, formatStructuredText } from "./conversation-view";

const conversation: Conversation = {
  schema_version: 1,
  messages: [
    {
      index: 0,
      role: "system",
      phase: "request",
      direction: "client_to_upstream",
      content: [{ index: 0, type: "text", text: "Follow the audit policy." }],
    },
    {
      index: 1,
      role: "developer",
      phase: "request",
      direction: "client_to_upstream",
      content: [{ index: 0, type: "text", text: "Use tools when needed." }],
    },
    {
      index: 2,
      role: "user",
      phase: "request",
      direction: "client_to_upstream",
      content: [{ index: 0, type: "text", text: "What is the weather?" }],
    },
    {
      index: 3,
      role: "assistant",
      phase: "response",
      direction: "upstream_to_client",
      content: [
        { index: 0, type: "reasoning", text: "I should use the weather tool." },
        {
          index: 1,
          type: "tool_call",
          id: "call_weather_1",
          name: "get_weather",
          arguments: "{\"city\":\"Shanghai\"}",
        },
        { index: 2, type: "text", text: "I will check that now." },
      ],
    },
    {
      index: 4,
      role: "tool",
      phase: "request",
      direction: "client_to_upstream",
      tool_call_id: "call_weather_1",
      content: [
        {
          index: 0,
          type: "tool_result",
          tool_call_id: "call_weather_1",
          name: "get_weather",
          result: "{\"temperature\":30}",
        },
      ],
    },
  ],
};

describe("conversation audit view", () => {
  it("keeps message order and exposes tool call and result evidence", () => {
    const html = renderToStaticMarkup(<ConversationView conversation={conversation} />);

    expect(html.indexOf("Follow the audit policy.")).toBeLessThan(html.indexOf("Use tools when needed."));
    expect(html.indexOf("Use tools when needed.")).toBeLessThan(html.indexOf("What is the weather?"));
    expect(html.indexOf("What is the weather?")).toBeLessThan(html.indexOf("get_weather"));
    expect(html).toContain("call_weather_1");
    expect(html).toContain("Arguments");
    expect(html).toContain("Result");
    expect(html).toContain("上游响应");
    expect(html).toContain("请求上下文");
  });

  it("renders reasoning separately in a disclosure that is collapsed by default", () => {
    const html = renderToStaticMarkup(<ConversationView conversation={conversation} />);

    expect(html).toContain("推理内容（默认折叠）");
    expect(html).toContain("I should use the weather tool.");
    expect(html).toContain("<details");
    expect(html).not.toContain("<details open");
  });

  it("escapes message text instead of treating it as markup", () => {
    const unsafe: Conversation = {
      schema_version: 1,
      messages: [
        {
          index: 0,
          role: "user",
          phase: "request",
          direction: "client_to_upstream",
          content: [{ index: 0, type: "text", text: "<script>alert('audit')</script>" }],
        },
      ],
    };

    const html = renderToStaticMarkup(<ConversationView conversation={unsafe} />);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("renders GFM only for assistant text and drops raw HTML", () => {
    const markdown: Conversation = {
      schema_version: 1,
      messages: [
        {
          index: 0,
          role: "user",
          phase: "request",
          direction: "client_to_upstream",
          content: [{ index: 0, type: "text", text: "**request stays literal**" }],
        },
        {
          index: 1,
          role: "assistant",
          phase: "request",
          direction: "client_to_upstream",
          content: [{ index: 0, type: "text", text: "**prior assistant output**" }],
        },
        {
          index: 2,
          role: "assistant",
          phase: "response",
          direction: "upstream_to_client",
          content: [
            {
              index: 0,
              type: "text",
              text: [
                "# Audit result",
                "",
                "- first",
                "- second",
                "",
                "| key | value |",
                "| --- | --- |",
                "| model | gpt-4o |",
                "",
                "```json",
                "{\"ok\":true}",
                "```",
                "",
                "![tracking pixel](https://tracker.example/pixel.png)",
                "",
                "<script>alert('unsafe')</script>",
              ].join("\n"),
            },
          ],
        },
      ],
    };

    const html = renderToStaticMarkup(<ConversationView conversation={markdown} />);
    expect(html).toContain("**request stays literal**");
    expect(html).not.toContain("<strong>request stays literal</strong>");
    expect(html).toContain("<strong>prior assistant output</strong>");
    expect(html).toContain("<h1");
    expect(html).toContain("<ul");
    expect(html).toContain("<table");
    expect(html).toContain("<pre");
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("unsafe");
    expect(html).not.toContain("<img");
    expect(html).toContain("图片：tracking pixel");
    expect(html).toContain("https://tracker.example/pixel.png");
  });

  it("keeps safe links external and degrades unsafe protocols to plain text", () => {
    const markdown: Conversation = {
      schema_version: 1,
      messages: [
        {
          index: 0,
          role: "assistant",
          phase: "response",
          direction: "upstream_to_client",
          content: [
            {
              index: 0,
              type: "text",
              text: [
                "[safe](https://example.com/docs?q=1)",
                "[mail](mailto:audit@example.com)",
                "[relative](../history)",
                "[script](javascript:alert('xss'))",
                "[data](data:text/html;base64,PHNjcmlwdD4=)",
              ].join(" "),
            },
          ],
        },
      ],
    };

    const html = renderToStaticMarkup(<ConversationView conversation={markdown} />);
    expect(html).toContain('href="https://example.com/docs?q=1"');
    expect(html).toContain('href="mailto:audit@example.com"');
    expect(html).toContain('href="../history"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noreferrer noopener"');
    expect(html).toContain('referrerPolicy="no-referrer"');
    expect(html).not.toContain("javascript:");
    expect(html).not.toContain("data:text/html");
    expect(html).toContain("script");
    expect(html).toContain("data");
  });

  it("pretty prints valid structured values and preserves non-JSON text", () => {
    expect(formatStructuredText("{\"city\":\"Shanghai\"}")).toEqual({
      text: "{\n  \"city\": \"Shanghai\"\n}",
      formatted: true,
    });
    expect(formatStructuredText("plain\nresult")).toEqual({ text: "plain\nresult", formatted: false });
  });
});
