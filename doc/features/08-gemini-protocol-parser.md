# 模块 08：Gemini GenerateContent 协议解析器

## 1. 支持范围

首版只解析明确配置进 LLM API 白名单的两个 operation：

- `/v1beta/models/{model}:generateContent`
- `/v1beta/models/{model}:streamGenerateContent`

显式配置 `/v1/models/{model}:...` 时复用同一 parser，但不接管其他 Gemini API；这些是带模型参数的生成 operation，不是 NewAPI 的 models 列表接口。NewAPI health、login、admin、models 列表、UI 和其他安全非 LLM 路径走 passthrough。

parser 异步读取已持久化证据，不进入 HTTP 转发链。请求模型来自受控路径参数，Body 中同名字段不能覆盖路径模型。

对应包：`internal/parser/gemini`。

## 2. 输入与公共输出

请求 Body 来自 `request_for_newapi_received_from_nginx`，响应 Body 来自 `response_received_from_newapi`；`request_sent_to_newapi` 与 `response_from_newapi_sent_to_nginx` 只补充实际转发和完整性状态。

公共 `parsed_results` 字段：

- `request_model`（URL `{model}`）、`response_model`（`modelVersion`）
- `requested_stream`、`observed_stream`、`response_id`、input/output/total usage
- `error_type`、`error_code`、消息和工具调用数量

contents、system instruction、输出文本/thought、函数名称/call id/参数/结果会规范化到 conversation，并只随加密 `parsed_json_enc` 落盘。文件/图片数据、safety/grounding 详情和完整错误消息不进入公共列；未知大块最多复制 4 KiB 到 conversation，完整内容保留在 raw Body。

## 3. 请求解析

读取 contents 数量/role/part 类型、`systemInstruction`、tools/toolConfig、generationConfig、safetySettings 和 cachedContent。

首版识别常见 Part：

- `text`，`thought=true` 时映射为 reasoning
- `inlineData`、`fileData`
- `functionCall`、`functionResponse`
- `executableCode`、`codeExecutionResult`

未知 Part 以有界 unknown part 保存。inline/base64 数据不复制到公共摘要或完整 conversation，也不下载 file URI 指向的内容。纯 functionResponse 的 user content 在 conversation 中规范为 tool role。

`streamGenerateContent` 的 `requested_stream=true`；`generateContent=false`。Query 中的 `alt=sse` 只影响响应表示方式。

## 4. 非流式响应

读取 `GenerateContentResponse` 的：

- `candidates` 数量
- candidate content/part 类型和 finish reason
- `promptFeedback`
- `usageMetadata`
- `modelVersion`
- `responseId`

usage 映射：

- input = `promptTokenCount`
- output = `candidatesTokenCount`
- total = `totalTokenCount`

thought 文本进入 conversation reasoning；缓存和细分 token 字段不映射时只存在于加密 raw Body。多个 candidate 不合并成一段输出；公共 finish/error 只保存安全摘要。

没有 candidates 但存在 prompt block reason 时仍是有效解析结果，不应误记为 parser error。

## 5. 流式处理

REST `streamGenerateContent?alt=sse` 的每个 `data:` 通常是一条 `GenerateContentResponse`。

```text
SSE event*
  -> candidates/content parts
  -> finish reason snapshot
  -> usage snapshot
  -> clean EOF
```

规则：

- 有 candidate index 时按 index 聚合。
- 没有 index 且每个事件只有一个 candidate 时按单候选顺序追加。
- text/thought part 只与同一 candidate 聚合，thought 单独形成 reasoning。
- function call/response 仅解析结构、不执行，并按 candidate 去重后形成 tool_call/tool_result part。
- usage 使用最后一个有效 snapshot，不累加多个事件。
- Gemini 流没有强制 `[DONE]` 或 `message_stop`；证据完整且最后事件闭合的 clean EOF 即正常完成。
- Body 截断、SSE 最后事件未闭合或客户端取消时设 `partial`。
- 未知事件或 Part 保存/忽略后继续。

如果兼容部署返回单个 JSON object，可按非流式响应解析并把 `observed_stream=false`；首版不自动猜测 NDJSON。

## 6. 错误与限额

常见错误对象：

```json
{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"..."}}
```

status/code 可进入公共字段，message/details 只存在于加密 raw Body，不进入 compact 摘要或 conversation。非 JSON 错误只保留 HTTP 状态和安全错误码。

统一限额：

- 请求侧解码后最多 64 MiB。
- 响应侧解码后最多 64 MiB。
- gzip 最大解压比 50:1。

单个 candidate/Part/event 畸形时尽量继续并设 `partial`；顶层完全无法解析时设 `error`。限额和解析失败均不影响原始证据。

## 7. parsed_results 写入

```text
parser_name = gemini.generate_content | gemini.stream_generate_content
parser_version = 2
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
```

reparse 覆盖当前结果并更新 `audit_records.parse_status`，数据库只保留最新解析结果。

## 8. 最少测试

- generateContent 文本、多个 candidates、prompt blocked 和 usage。
- streamGenerateContent 文本/thought SSE、function call/result、最后 usage snapshot 和 clean EOF。
- 缺 candidate index、未知 Part、单事件畸形和截断 EOF。
- Body 中 model 不覆盖路径模型。
- Google error JSON、gzip、64 MiB/50:1 限额。
- inline data、函数名称/参数和输出文本不出现在明文列。

## 9. 实施任务

1. 定义两个 operation、route model 和精简 Content/Part DTO。
2. 实现请求、非流式响应、usage 和 error 解析。
3. 实现 GenerateContentResponse SSE 聚合与 clean EOF 规则。
4. 写入公共字段与 conversation，并加密 `parsed_json` envelope。
5. 完成正常、流式、blocked、function 和异常 fixtures。

## 10. 官方参考

- [GenerateContent API](https://ai.google.dev/api/generate-content)
- [streamGenerateContent](https://ai.google.dev/api/rest/v1beta/models/streamGenerateContent)
