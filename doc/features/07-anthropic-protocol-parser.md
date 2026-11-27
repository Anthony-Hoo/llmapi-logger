# 模块 07：Anthropic Messages 协议解析器

## 1. 支持范围

首版只解析明确配置进 LLM API 白名单的 `/v1/messages`，支持非流式 JSON 和 Messages SSE。NewAPI health、login、admin、models、UI 和其他安全非 LLM 路径走 passthrough，不进入本 parser。

parser 异步读取已落盘证据，不进入 HTTP 转发链，不修改 content block 或事件。未知普通字段/event 忽略；未知 content block 只在 conversation 中保存有界占位；完整对象在 raw Body（异常记录）或请求与非流式响应的 content object（verified 记录）中，verified 流式响应的保留范围见 §8。

本 parser 同时实现内容寻址 normalizer（§8）：普通成功记录的请求与非流式响应可从加密 content object 精确重建 provider JSON，流式响应保留事件摘要和聚合结果，raw 释放为 `metadata`；异常记录的响应侧仍保留 full raw，请求侧按[模块 18](18-content-addressed-conversation-storage.md) §6 决定。

对应包：`internal/parser/anthropic`。

## 2. 输入与公共输出

按实际存在性读取最多四阶段证据：

1. `request_for_newapi_received_from_nginx`
2. `request_sent_to_newapi`
3. `response_received_from_newapi`
4. `response_from_newapi_sent_to_nginx`

请求和响应 Body 分别使用第一、第三阶段；第二、第四阶段只补充实际转发和完整性状态。

公共 `parsed_results` 字段：

- `request_model`、`response_model`
- `requested_stream`、`observed_stream`
- `response_id`
- input/output usage
- `error_type`、`error_code`
- `message_count`、`tool_call_count`、`has_tool_call`

system、消息正文、工具名称/call id/参数/结果、thinking 和未知 block 进入协议无关 conversation。verified 记录的 conversation 在查询时从 turn graph 重建，不落第二份；没有 turn 的记录（异常、normalization 失败）才随加密 `parsed_json_enc` 落盘。signature、图片/文档 source 和完整错误消息不进入公共列；未知大块最多复制 4 KiB 到 conversation；完整内容的去向同 §1。

## 3. 请求解析

读取：

- `model`、`stream`、`max_tokens`
- `system`
- `messages` 数量和 role
- content block 类型和数量
- `tools`、`tool_choice`
- thinking、metadata 和其他已知配置

`system` 和 `content` 可以是字符串或 block 数组。识别 text、tool_use、tool_result、thinking 等常见 block；纯 tool_result 的 user message 在 conversation 中规范为 tool role，混合文本与结果时仍保持 user role。未知 block 以有界 unknown part 保存，不作为错误。

公共字段不保存工具名称，只保存数量和 `has_tool_call`。

## 4. 非流式响应

读取：

- `id`、`type`、`role`、`model`
- content block 数量和类型
- `stop_reason`、`stop_sequence`
- usage 的 `input_tokens`、`output_tokens` 和缓存字段
- error type

content 文本、tool input/result 和 thinking 进入加密 conversation，signature 只存在于该响应的 content object 或 raw Body。没有明确 total token 字段时，不在公共字段中伪造供应商报告的 total。

常见错误对象中的 type 可查询，message 只存在于加密 raw Body（非 2xx 记录保留 full），不进入 compact 摘要或 conversation。HTTP 200 的 SSE 中也可能出现协议 error，需与 HTTP 状态分别保留。错误 envelope 的明确策略 code 或 cyber/安全提示短语会在内存中派生 `upstream_error_class`（[模块 22](22-content-policy.md)），message 仍不落公共列。

## 5. SSE 基本状态机

正常序列通常为：

```text
message_start
  -> content_block_start
  -> content_block_delta*
  -> content_block_stop
  -> message_delta
  -> message_stop
```

处理规则：

- 以 content block `index` 关联事件。
- `text_delta` 按 content block index 拼接文本。
- `input_json_delta.partial_json` 按 tool block index 拼接原始字符串，conversation 保留 call id/name/arguments。
- `thinking_delta` 拼接为独立 reasoning part；signature delta 不复制进 conversation。
- `message_delta` 更新 stop reason 和最后一个有效 usage snapshot，不累加多个 snapshot。
- `ping` 忽略语义但允许存在。
- 未知 event/delta 保存或忽略，并继续后续事件。
- `error` event 设协议错误；已有内容可以保存为 `partial`。
- clean EOF 没有 `message_stop` 时设 `partial`。

## 6. 限额与错误行为

- 请求侧解码后最多 64 MiB。
- 响应侧解码后最多 64 MiB。
- gzip 最大解压比 50:1。

顶层 JSON 无法解析时设 `error`。单个 block/event 畸形时跳过该项并尽量产生 `partial`。证据截断、缺少终止事件或达到限额时设 `partial`。

parser panic 由公共 worker recover。安全错误不得包含正文、partial JSON、thinking、Header value 或 token。

## 7. parsed_results 写入

```text
parser_name = anthropic.messages
parser_version = 3
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
```

`parsed_json_enc` 在写出 verified turn 时只含窄摘要；没有 turn 时才附带 conversation 回退副本。版本 2 写入的记录没有 turn graph，保持 full raw 和带 conversation 的 `parsed_json_enc`，读取路径不变，不做迁移。

reparse 直接覆盖当前结果并更新 `audit_records.parse_status`，数据库只保留最新解析结果。

## 8. 内容寻址 normalizer

公共规则见[模块 05](05-parser-framework.md) 与[模块 18](18-content-addressed-conversation-storage.md)。Agent 客户端每次调用都重发完整历史，所以以 message 为粒度拆分：同一条 message 不论重发多少次只存一份。

请求（布局 `anthropic.messages.request.system_none|system_single|system_array`）：

- envelope 是根对象去掉 `messages` 和 `system` 后的部分；`tools` 留在 envelope 内，会话内不变时按 hash 复用。
- `messages` 必须是数组，每个元素是一个 slot `messages` 的 item。
- `system` 是字符串时为一个 slot `system` 的 item，是数组时每个 block 一个 item；`system` 缺失或为 `null` 时没有 item（`null` 留在 envelope）。
- item 序列中 `messages` 在前、`system` 在后。父轮次推断只比较序列前缀：同一客户端的无关会话共用 system prompt，system 排在前面会被算作公共历史；而且有的客户端第一个 system block 每个请求都不同，排在前面会让同一会话的各轮也对不上前缀。system 按 block 拆分也是为了让这个变化的 block 不连累其余不变的大块。
- 没有 `previous_response_id`。conversation key 取客户端声明的会话 ID，规则与洞察的会话归属共用 `insights.DeclaredSessionID`：`metadata.session_id`/`conversation_id`/`thread_id`，或 Claude Code 放在 `metadata.user_id` 里的会话 ID。只有用户 ID 的 `metadata.user_id` 不作 key（见模块 18 §7）。
- 不启用 `file_data`/`file_content`/`attachment_data` 键名的 inline file 提取（`Turn.SkipInlineFileData`）。Messages 没有这种约定，而 `tool_use.input` 是调用方自定义的 JSON，同名参数是普通文本；按 Base64 解码再编码会改掉内容，解不出来则整条 normalization 失败。data URL 的处理与 OpenAI 相同（模块 18 §4.1）：按解码字节寻址，重建为等价 data URL；声明了 base64 却解不出时 normalization 失败并保留 full raw。

非流式响应（布局 `marker_envelope`）：`content` 数组的每个 block 是一个 slot `content` 的 item，envelope 中换成受控 marker；没有 `content` 数组的错误体整体留在 envelope。

流式响应（布局 `anthropic.stream.response`）：与 OpenAI 流式相同，envelope 保存每个 SSE event 的事件名、data 长度和 SHA-256，items 是 parser 聚合出的响应 message（slot `aggregate`）。`summary` 除 `response_id`、`usage`、错误码外还保存 `normalized_usage`（不含缓存的输入、缓存读、缓存写、输出）和 `stop_reason`，raw 释放后这两项无处可取，洞察回填靠它们恢复。

流式响应不是逐字节重建：重建校验比较的是 envelope 与聚合结果自身。raw 释放后可得的是每个事件的名称、长度、SHA-256 和 parser 聚合出的文本、thinking、工具调用；`signature_delta`、`citations_delta`、未识别的 delta，以及未知 block 超出 4 KiB 占位的部分不再可得。这与 OpenAI 流式的保留范围一致（模块 18 §10）。

已知局限：

- `cache_control` 是 message 的一部分。客户端每轮把它挪到最新的 message 上，带过标记的 message 会以带标记和不带标记两种形态各存一次。
- 上面这一点加上排在后面的 system item，使短历史达不到模块 18 的 70% 公共前缀门槛，每轮成为新的根；content object 照常复用，只是没有血缘。历史变长后各轮正常连成链，每轮只存增量。
- `source.type=base64` 的图片/文档数据不是 data URL，目前随所在 message 整体去重，不单独提取为 binary object。
- data URL 规则按字符串生效，不看它出现在哪里（message 文本、`tool_use.input`、`tool_result`、system、工具描述）。以 `data:` 开头且带 `;base64` 的字符串按解码字节寻址，重建时换行、padding 和前缀大小写会规范化，不是逐字节原样；以 `data:` 开头而全串没有逗号（例如 `data: [DONE]`、YAML 的顶层 `data:` 键），或声明了 base64 却解不出时，normalization 失败：该记录为 `partial` + `reconstruction_failed`，raw 保持 full，conversation 走 `parsed_json_enc` 回退。客户端每轮重发历史，这样一条 message 进入历史后，该会话之后的每一轮都会失败并保留 full raw。这是模块 18 §4.1 与模块 05 §7 的既有规则，OpenAI 相同；关闭 inline file 键名提取只去掉了其中由键名触发的那一类。
- 响应内容存两次：一次是本轮的响应 item，一次在下一轮重发的 assistant message 里。两者形态不同（content block 或聚合结果，对整条 message），hash 不会相同。
- 没有声明会话 ID 的客户端走内容推断，候选是本协议最近 32 个 turn，不区分调用方：不同调用方发出完全相同的请求会被连成 retry 并归入同一个 conversation（包括别人带 key 的 conversation），与无 key 的 OpenAI 请求行为相同。

## 9. 最少测试

- 最小 messages 请求/响应、system 数组和未知 block。
- text SSE、多个 block、ping 和正常 `message_stop`。
- tool `input_json_delta` 任意分块与最终非法 JSON。
- thinking 独立 reasoning、纯 tool_result role、HTTP 200 中的 error event、缺少 message_stop。
- usage snapshot 不被错误累加。
- gzip、64 MiB/50:1 限额和敏感字段明文泄漏扫描。
- normalizer：system 缺失/null/字符串/数组各布局精确重建，保留 marker 与非数组 `messages` 被拒绝；声明的会话 ID 成为 conversation key 而单独的用户 ID 不是；名为 `file_content` 等的工具参数保持原文；流式 summary 含缓存用量与 `stop_reason`；重发历史复用对象且 message 前缀不受 system 变化影响；JSON 与 SSE 响应重建出的 conversation 与 parser 解析结果一致；多轮会话的对象数随唯一 message 数增长。

## 10. 实施任务

1. 定义 Messages 请求、响应、block 和 usage 的精简 DTO。
2. 实现非流式 JSON 与 error 解析。
3. 实现 message/content-block SSE 状态机。
4. 写入公共字段与 conversation，并加密 `parsed_json` envelope。
5. 完成正常、工具、thinking、错误和限额 fixtures。

## 11. 官方参考

- [Messages API](https://docs.anthropic.com/en/api/messages)
- [Streaming Messages](https://docs.anthropic.com/en/api/messages-streaming)
