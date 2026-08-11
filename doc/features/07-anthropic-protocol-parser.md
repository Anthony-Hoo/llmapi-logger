# 模块 07：Anthropic Messages 协议解析器

## 1. 支持范围

首版只解析明确配置进 LLM API 白名单的 `/v1/messages`，支持非流式 JSON 和 Messages SSE。NewAPI health、login、admin、models、UI 和其他安全非 LLM 路径走 passthrough，不进入本 parser。

parser 异步读取已落盘证据，不进入 HTTP 转发链，不修改 content block 或事件。未知字段、block 和 event 忽略或保存在加密 `parsed_json`。

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

system、消息正文、图片/文档 source、工具/函数名称与参数、thinking/signature 和完整错误消息只进入加密 `parsed_json_enc`。

## 3. 请求解析

读取：

- `model`、`stream`、`max_tokens`
- `system`
- `messages` 数量和 role
- content block 类型和数量
- `tools`、`tool_choice`
- thinking、metadata 和其他已知配置

`system` 和 `content` 可以是字符串或 block 数组。首版识别 text、image/document source、tool use、tool result、thinking 等常见 block；未知 block 保留在加密 JSON，不作为错误。

公共字段不保存工具名称，只保存数量和 `has_tool_call`。

## 4. 非流式响应

读取：

- `id`、`type`、`role`、`model`
- content block 数量和类型
- `stop_reason`、`stop_sequence`
- usage 的 `input_tokens`、`output_tokens` 和缓存字段
- error type

content 文本、tool input、thinking 和 signature 全部加密。没有明确 total token 字段时，不在公共字段中伪造供应商报告的 total；如需展示本地相加值，应在加密 JSON 中标记为 computed。

常见错误对象中的 type 可查询，message 必须加密。HTTP 200 的 SSE 中也可能出现协议 error，需与 HTTP 状态分别保留。

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
- `text_delta` 按顺序拼接文本。
- `input_json_delta.partial_json` 只拼接字符串，到 block stop 后再尝试 JSON decode。
- thinking/signature delta 只进入加密结果。
- `message_delta` 更新 stop reason 和最后一个有效 usage snapshot，不累加多个 snapshot。
- `ping` 忽略语义但允许存在。
- 未知 event/delta 保存或忽略，并继续后续事件。
- `error` event 设协议错误；已有内容可以保存为 `partial`。
- clean EOF 没有 `message_stop` 时设 `partial`。

## 6. 限额与错误行为

- 请求侧解码后最多 16 MiB。
- 响应侧解码后最多 16 MiB。
- gzip 最大解压比 50:1。

顶层 JSON 无法解析时设 `error`。单个 block/event 畸形时跳过该项并尽量产生 `partial`。证据截断、缺少终止事件或达到限额时设 `partial`。

parser panic 由公共 worker recover。安全错误不得包含正文、partial JSON、thinking、Header value 或 token。

## 7. parsed_results 写入

```text
parser_name = anthropic
parser_version = <当前实现版本>
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
```

reparse 直接覆盖当前结果并更新 `audit_records.parse_status`，数据库只保留最新解析结果。

## 8. 最少测试

- 最小 messages 请求/响应、system 数组和未知 block。
- text SSE、多个 block、ping 和正常 `message_stop`。
- tool `input_json_delta` 任意分块与最终非法 JSON。
- thinking/signature、HTTP 200 中的 error event、缺少 message_stop。
- usage snapshot 不被错误累加。
- gzip、16 MiB/50:1 限额和敏感字段明文泄漏扫描。

## 9. 实施任务

1. 定义 Messages 请求、响应、block 和 usage 的精简 DTO。
2. 实现非流式 JSON 与 error 解析。
3. 实现 message/content-block SSE 状态机。
4. 写入公共字段和加密 `parsed_json`。
5. 完成正常、工具、thinking、错误和限额 fixtures。

## 10. 官方参考

- [Messages API](https://docs.anthropic.com/en/api/messages)
- [Streaming Messages](https://docs.anthropic.com/en/api/messages-streaming)
