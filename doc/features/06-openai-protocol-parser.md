# 模块 06：OpenAI 兼容协议解析器

## 1. 支持范围

首版只解析 kickoff 默认且明确配置进 LLM API 白名单的四个端点：

| Endpoint | Path |
| --- | --- |
| Chat Completions | `/v1/chat/completions` |
| Completions | `/v1/completions` |
| Responses | `/v1/responses` |
| Responses Compact | `/v1/responses/compact` |

parser 异步读取已持久化证据，不参与代理转发，不修改请求或响应。兼容实现的未知普通字段忽略；未知内容块只在 conversation 中保存有界占位，完整供应商对象始终可从加密 raw Body 读取。

NewAPI health、login、admin、`/v1/models`、UI 和其他安全非 LLM 路径走 passthrough，不进入本 parser。

对应包：`internal/parser/openai`。

## 2. 输入与输出

请求 Body 来自 `request_for_newapi_received_from_nginx`，响应 Body 来自 `response_received_from_newapi`；`request_sent_to_newapi` 与 `response_from_newapi_sent_to_nginx` 只补充实际转发和完整性状态。

公共输出只写入 `parsed_results`：

- `request_model`、`response_model`、`requested_stream`、`observed_stream`、`response_id`
- input/output/total usage、`error_type`、`error_code`、消息和工具调用数量

消息、prompt、input、instructions、输出文本、reasoning、工具/函数名称、call id、参数和结果会规范化到 conversation，并与其他敏感解析数据一起保存到加密 `parsed_json_enc`。compact `ParsedJSON` 和公共列仍不包含这些正文。

## 3. 请求解析

### Chat Completions

读取 `model`、`stream`、messages 数量/role、tools/tool call 数量；conversation 保留 system/developer/user/assistant/tool 顺序。旧式 `role=function` 规范为工具结果，`function_call` 与 `tool_calls` 统一为 tool_call part。

`messages[].content` 可以是字符串或数组；已知 text/reasoning/tool block 转为对应 part，图片或其他未知 block 最多保存 4 KiB 占位数据，完整内容仍在 raw Body。

### Completions

读取 `model`、`stream` 和 prompt 数量摘要；prompt 转为 user conversation message。suffix、stop、logprobs 等未映射配置只存在于加密 raw Body。

### Responses / Responses Compact

读取 `model`、`stream`、input item 数量、tools 数量、`previous_response_id` 等已知字段。Compact 返回的压缩或 `encrypted_content` 数据只做不透明加密保存，不尝试解密内部内容。

## 4. 非流式响应

Chat/Completions 读取 `id`、`model`、choices 数量、`finish_reason`、message/text/tool call 摘要和 usage，并为每个 choice 生成 assistant conversation message。

Responses 读取 `id`、`model`、`status`、output item/工具调用数量、usage、error 和 incomplete details。message、function_call、function_call_output 和 reasoning summary 分别映射为 text/tool_call/tool_result/reasoning。

Compact 只读取明确存在的 ID、model、status 和对象类型；其余内容进入加密 `parsed_json`。

模型展示优先响应中的 model；响应缺失时才回退请求 model。

## 5. SSE 基本处理

Chat Completions 与 Completions：

```text
data: <JSON chunk>
...
data: [DONE]
```

- 按 choice index 累积文本与 reasoning，最终每个 choice 只产生一个 assistant message。
- tool-call id/name/arguments 按 tool index 聚合，arguments 保留原始拼接字符串，由 UI 尝试 JSON 格式化。
- 最后一个 usage chunk 可更新 usage；不能丢弃 choices 为空的 usage chunk。
- EOF 前没有 `[DONE]` 时记为 `partial`。

Responses 使用 JSON 事件中的 `type`：

- 识别 response 生命周期、文本/reasoning delta、output item、函数参数、completed/failed/incomplete。
- 未知 event type 保存到加密 JSON 或忽略，不中止后续事件。
- terminal event 中的 response/output/usage 优先作为最终快照，不能和此前 delta 重复生成消息。
- clean EOF 没有 terminal event 时记为 `partial`。

Compact 若返回 SSE，只按 Responses 风格事件解析；不能误当 Chat chunk。

## 6. 错误与限额

常见错误对象：

```json
{"error":{"message":"...","type":"...","code":"..."}}
```

`type` 和 `code` 可进入公共字段，message 只存在于加密 raw Body，不进入 compact 摘要或 conversation。非 JSON 错误只保留 HTTP 状态和安全错误码。

统一限额：

- 请求侧解码后最多 16 MiB。
- 响应侧解码后最多 16 MiB。
- gzip 最大解压比 50:1。

单个 JSON/SSE 事件畸形时尽量继续解析后续事件；顶层完全无法解析则设 `parse_status=error`。超限或流提前结束设 `partial`，不影响原始证据。

## 7. parsed_results 写入

```text
parser_name = openai.chat_completions | openai.completions | openai.responses | openai.responses_compact
parser_version = 2
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
```

reparse 直接覆盖该 audit 的最新行，并同步更新 `audit_records.parse_status`，数据库只保留最新解析结果。

## 8. 最少测试

- 四个端点各一个正常请求/响应 fixture。
- Chat SSE 文本、tool call、usage-only final chunk 和缺少 `[DONE]`。
- Chat SSE reasoning 与 tool arguments 分片聚合；旧式 role=function 工具结果。
- Responses typed SSE 的 completed、failed、reasoning summary、terminal 去重和未知事件。
- 未知 JSON 字段、畸形 JSON、单个畸形 SSE 事件。
- gzip 正常/损坏、16 MiB 和 50:1 限额。
- error envelope、工具名称/参数和正文不出现在明文列。

## 9. 实施任务

1. 定义四个 endpoint 分发和精简 DTO。
2. 实现请求、非流式响应和 error envelope 解析。
3. 实现 Chat/Completions `[DONE]` 与 Responses typed SSE。
4. 映射公共字段与 conversation，并加密 `parsed_json` envelope。
5. 完成四端点 fixtures 和异常测试。

## 10. 官方参考

- [Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create/)
- [Completions](https://developers.openai.com/api/reference/resources/completions/methods/create/)
- [Responses](https://developers.openai.com/api/reference/resources/responses/methods/create/)
- [Responses Compact](https://developers.openai.com/api/reference/resources/responses/methods/compact/)
