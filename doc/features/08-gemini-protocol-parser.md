# 模块 08：Gemini GenerateContent 协议解析器

## 1. 支持范围

首版只解析明确配置进 LLM API 白名单的两个 operation：

- `/v1beta/models/{model}:generateContent`
- `/v1beta/models/{model}:streamGenerateContent`

显式配置 `/v1/models/{model}:...` 时复用同一 parser，但不接管其他 Gemini API；这些是带模型参数的生成 operation，不是 NewAPI 的 models 列表接口。NewAPI health、login、admin、models 列表、UI 和其他安全非 LLM 路径走 passthrough。

parser 异步读取已持久化证据，不进入 HTTP 转发链。请求模型来自受控路径参数，Body 中同名字段不能覆盖路径模型。

本 parser 同时实现内容寻址 normalizer（§8）：普通成功记录的请求与响应可从加密 content object 精确重建，流式响应保留事件描述、折叠出的 GenerateContentResponse 和残留，raw 释放为 `metadata`；异常记录按[模块 18](18-content-addressed-conversation-storage.md) §6 按侧保留。

对应包：`internal/parser/gemini`。

## 2. 输入与公共输出

请求 Body 来自 `request_for_newapi_received_from_nginx`，响应 Body 来自 `response_received_from_newapi`；`request_sent_to_newapi` 与 `response_from_newapi_sent_to_nginx` 只补充实际转发和完整性状态。

公共 `parsed_results` 字段：

- `request_model`（URL `{model}`）、`response_model`（`modelVersion`）
- `requested_stream`、`observed_stream`、`response_id`、input/output/total usage
- `error_type`、`error_code`、消息和工具调用数量

contents、system instruction、输出文本/thought、函数名称/call id/参数/结果会规范化到 conversation。verified 记录的 conversation 在查询时从 turn graph 重建，不落第二份；没有 turn 的记录（异常、normalization 失败、版本 2 写入的旧记录）才随加密 `parsed_json_enc` 落盘。文件/图片数据、safety/grounding 详情和完整错误消息不进入公共列；未知大块最多复制 4 KiB 到 conversation，完整内容在 raw Body 或 content object 中。

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

thought 文本进入 conversation reasoning；缓存和细分 token 字段不映射到公共列，只存在于 raw Body 或 content object。多个 candidate 不合并成一段输出；公共 finish/error 只保存安全摘要。

没有 candidates 但存在 prompt block reason 时仍是有效解析结果，不应误记为 parser error。

## 5. 流式处理

REST `streamGenerateContent?alt=sse` 的每个 `data:` 是一条 `GenerateContentResponse`（下称 chunk），以 CRLF 分隔，没有事件名，也没有 `[DONE]` 或 `message_stop` 这类结束事件。

```text
chunk*  （每个 chunk 带本次增量的 parts，通常也带累计的 usageMetadata）
  -> 最后一个 chunk：candidate 带 finishReason
  -> clean EOF
```

规则：

- 有 candidate index 时按 index 聚合，没有时按它在 chunk 内的位置。
- chunk 折叠成非流式的 GenerateContentResponse（§5.1），conversation 从折叠体读出，与非流式响应走同一段代码，所以同一回答流式与非流式的 conversation 相同。
- function call 仅解析结构、不执行；工具调用数是各 chunk 的 `functionCall` part 之和。
- usage 使用最后一个有效 snapshot，不累加多个事件。
- Body 截断、SSE 最后事件未闭合、有事件不是 JSON 对象或客户端取消时设 `partial`。

**完整性。** 一条流完整，当且仅当它以 Gemini 流的方式之一结束：

| 结束方式 | 线上形态 | 判定 |
| --- | --- | --- |
| 正常结束、命中 stop sequence | candidate `finishReason=STOP` | 完整 |
| 函数调用 | 带 `functionCall` part，`finishReason=STOP`（Gemini 不为工具调用另设原因） | 完整 |
| 输出上限 | `finishReason=MAX_TOKENS` | 完整 |
| 输出被拦截 | `finishReason=SAFETY`、`RECITATION`、`BLOCKLIST`、`PROHIBITED_CONTENT`、`SPII`、`LANGUAGE`、`IMAGE_*` 等，content 可以缺失 | 完整 |
| 工具调用异常 | `MALFORMED_FUNCTION_CALL`、`UNEXPECTED_TOOL_CALL`、`TOO_MANY_TOOL_CALLS` 等 | 完整 |
| 其他原因 | `OTHER`、`MALFORMED_RESPONSE`、`CONTINUATION` 等任何非空原因 | 完整 |
| 提示词被拦截 | `promptFeedback.blockReason`（不是 `BLOCK_REASON_UNSPECIFIED`），没有 candidate | 完整 |
| 流内错误 | chunk 带 `error` 对象 | 结束但不是完整回答：`partial`，`error_code` 为错误对象的 `code`（缺失时为 `stream_error`） |
| 两个 chunk 之间干净断开 | 最后一个 chunk 没有 `finishReason` | `partial`，`missing_finish_reason` |

有多个 candidate（`candidateCount>1`）时每个出现过的 candidate 都要报告过 `finishReason`；`FINISH_REASON_UNSPECIFIED` 不算。`partial` 的流不会生成 verified turn，raw 保持 full。normalizer 自己也拒绝不完整的流（`errIncompleteStream`），即使调用方绕过了 parse 状态。不带 `alt=sse` 的 JSON 数组流按同一规则判定。

版本 2 没有这项检查：在两个 chunk 之间干净结束的流解析为 `ok`，与完整的流无法区分（设计文档附录 B.5）。

**采集侧。** `internal/parser/streamterminal` 没有 Gemini 的终止行匹配：结束标志在 `data:` 行的 JSON 里，而采集探针只看每行前 48 字节，并且后面没有任何短的结束行。客户端在收到最后一个 chunk 之后、传输 EOF 之前断开时，记录按取消处理，raw 保留，与没有 normalizer 时相同。

### 5.1 折叠与残留

按模块 05 §2.3 折叠。Gemini 只有一种事件类型，chunk；下表是折叠器读取的字段（代码里是 `gemini.ConsumedChunkFields`、`ConsumedCandidateFields`、`ConsumedContentFields`）。表外的字段按原位置进入残留（envelope 的 `residue`，格式见模块 18 §10）；data 不是 JSON 对象的事件整条进入残留（这样的流本身已是 `partial`）。

| 层级 | 读取的字段 | 折叠方式 |
| --- | --- | --- |
| chunk | `candidates` | 按 candidate index 聚合，见下 |
| chunk | `usageMetadata` `modelVersion` `responseId` `createTime` `promptFeedback` `modelStatus` `error` | snapshot：折叠体保留最后报告的值，`null` 不覆盖已有值；被后来的 chunk 覆盖的旧值（对象逐键比较，只留不同的键）留在发出它的 chunk 下 |
| candidate | `index` `finishReason` `finishMessage` `safetyRatings` `citationMetadata` `tokenCount` `groundingAttributions` `groundingMetadata` `avgLogprobs` `logprobsResult` `urlContextMetadata` `continuationToken` | snapshot，规则同上 |
| candidate | `content` | `role` 是 snapshot；`parts` 按顺序追加，见下 |
| part | 整个 part | 原样追加；相邻文本合并 |

相邻文本合并：一个 part 只有 `text`、`thought`、`thoughtSignature` 三个键时是文本 part。新来的文本 part 与前一个 part 都是文本 part、`thought` 相同（都没有，或值相等）、且新来的没有 `thoughtSignature` 时，文本拼接到前一个 part；否则单独成为一个 part。带 `thoughtSignature` 的文本总是开始一个新 part，签名因此留在携带它的那一段上，随后的文本并入它。`functionCall` 等其他 part 从不合并，也不去重。折叠体里每个 candidate 的 content 因此与非流式响应的写法一致：一段 thought、一段正文、每个函数调用一个 part。

一条普通的流通常只留一类残留：每个 chunk 都重复累计的 `usageMetadata`，最后一个之前的各个 snapshot 中与最终值不同的计数（通常是 `candidatesTokenCount`、`totalTokenCount`）留在各自的 chunk 下。分段方式（每个 chunk 带了哪一段文本）与其他协议的 delta 边界一样不保留，只保留拼接结果。

`summary.stop_reason` 是最后报告的 `finishReason`（逐 chunk 取第一个报告了原因的 candidate，后面的 chunk 覆盖前面的），与 insights 读 raw 流的口径相同。

## 6. 错误与限额

常见错误对象：

```json
{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"..."}}
```

status/code 可进入公共字段，message/details 只存在于加密 raw Body 或 content object，不进入 compact 摘要或 conversation。非 JSON 错误只保留 HTTP 状态和安全错误码。错误 envelope 的策略标识，以及 HTTP 200 的 `promptFeedback.blockReason` / `finishReason=SAFETY`，会在内存中派生 `upstream_error_class`（[模块 22](22-content-policy.md)）。

统一限额：

- 请求侧解码后最多 64 MiB。
- 响应侧解码后最多 64 MiB。
- gzip 最大解压比 50:1。

单个 candidate/Part/event 畸形时尽量继续并设 `partial`；顶层完全无法解析时设 `error`。限额和解析失败均不影响原始证据。

## 7. parsed_results 写入

```text
parser_name = gemini.generate_content | gemini.stream_generate_content
parser_version = 3
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
```

版本 3 增加 normalizer、从折叠体读流式 conversation，并要求流以 §5 的方式结束才为 `ok`。`parsed_json_enc` 在写出 verified turn 时只含窄摘要；没有 turn 时才附带 conversation 回退副本。版本 2 写入的记录没有 turn graph，保持 full raw 和带 conversation 的 `parsed_json_enc`，读取路径不变，不做迁移；parser 版本只随记录保存，不触发重新解析。

reparse 覆盖当前结果并更新 `audit_records.parse_status`，数据库只保留最新解析结果。

## 8. 内容寻址 normalizer

公共规则见[模块 05](05-parser-framework.md) 与[模块 18](18-content-addressed-conversation-storage.md)。客户端每次调用都在 `contents` 里重发完整历史，所以以 Content 为粒度拆分。两个 parser 名共用同一个 normalizer，按响应的形态（SSE、JSON 数组、JSON 对象，顺序与 Parse 相同）而不是 operation 选择 layout。

请求（布局 `gemini.generate_content.request.system_none|system_single`）：

- envelope 是根对象去掉 `contents` 和 `systemInstruction` 后的部分；`tools`、`generationConfig`、`safetySettings`、`cachedContent` 留在 envelope 内。
- `contents` 必须是数组，每个 Content 是一个 slot `contents` 的 item，kind 为 `<role>_content`（没有 role 时为 `content`）。
- `systemInstruction` 是一个 Content，作为一个 slot `systemInstruction`、kind `system_instruction` 的 item，排在 contents 之后，理由同模块 07 §8 的 system；缺失或为 `null` 时没有 item。snake_case 的 `system_instruction` 不拆，整体留在 envelope。
- 没有会话 key。GenerateContent 请求里没有会话标识：公开 API 没有这类字段；`cachedContent` 指向的上下文缓存可以被任意请求共用，不是会话；`labels` 只是 Vertex 的计费标签；Gemini CLI 在 API Key 模式下只发 `User-Agent` 和可选的 `x-gemini-api-privileged-user-id`（安装 ID，跨会话不变），会话 ID 只发给 Code Assist 端点，不经过这两个路由。父轮次因此走无 key 的内容推断（模块 18 §7）。
- 不启用 `file_data`/`file_content`/`attachment_data` 键名的 inline file 提取（`Turn.SkipInlineFileData`）：`functionCall.args` 是调用方自定义的 JSON。改为启用 Gemini 的 inline part 规则（`Turn.InlineDataParts`）：`inlineData`（或 `inline_data`）对象的 `data` 字符串按解码字节存为 binary object，重建为同一字符串。只有标准带 padding 的 Base64 才提取，其他写法（无 padding、URL 安全字母表、带换行）原样留在 content object 里，不报错也不规范化。data URL 规则与其他协议相同。

非流式响应（布局 `marker_envelope`）：每个 candidate 的 `content` 是一个 slot `content` 的 item，kind 与请求里的 Content 用同一规则（模型的回答是 `model_content`），envelope 中换成 marker。客户端在下一轮原样重发这段 content 时，请求里的 item 与本轮响应的 item 是同一个 content object。没有 candidate content 的错误体和提示词拦截整体留在 envelope。

流式响应（布局 `gemini.stream.response`）：与 OpenAI、Anthropic 流式相同（模块 05 §2.3）。envelope 的 `aggregate` 键下是折叠出的 GenerateContentResponse，按非流式响应的拆分把每个 candidate 的 content 存为一个 item，因此与同一回答的非流式响应共用这些对象；envelope 保存紧凑事件描述、`summary`（`response_id`、`usage`、`normalized_usage`、`stop_reason`、错误码）和残留 `residue`（§5.1）。残留超过 `streamevidence.MaxResidueBytes` 时放弃，返回 `streamevidence.ErrResidueTooLarge`，raw 保留。

JSON 数组流（不带 `alt=sse`）：整个数组作为 `marker_envelope` 的 envelope，没有 item。它是一个 JSON body，与其他 JSON body 一样按 canonical JSON 精确保存；不折叠，是因为事件描述和残留只为 SSE 事件定义。conversation 重建时按 Parse 的方式折叠数组。

已知局限：

- system instruction 排在 contents 之后，短历史达不到模块 18 的 70% 公共前缀门槛：带 system instruction 的会话第二轮成为新的根，第三轮起才接到上一轮（`context_edit`）；没有 system instruction 时第二轮起即接上（`continuation`）。content object 照常复用（第二轮请求引用第一轮的回答对象），只是早期轮次没有血缘。与模块 07 §8 相同。
- 流式回答与下一轮请求共用对象的前提是客户端按折叠体的写法重发：文本合并成一段、签名留在原处。按 chunk 原样把每段增量各作为一个 part 重发的客户端，下一轮请求的 content 与折叠体不同，各存一份。
- 带签名的文本段：签名开启新的 part（§5.1）。如果 API 把签名放在最后一个空文本 chunk 上，折叠体里这段签名是单独的一个空文本 part，而非流式响应会把它放在正文 part 上，两者的 content 不同。

## 9. 最少测试

- generateContent 文本、多个 candidates、prompt blocked 和 usage。
- streamGenerateContent 文本/thought SSE、function call/result、最后 usage snapshot、各种结束方式（§5 表）和缺少 finish reason 的截断。
- 缺 candidate index、未知 Part、单事件畸形和截断 EOF。
- Body 中 model 不覆盖路径模型。
- Google error JSON、gzip、64 MiB/50:1 限额。
- inline data、函数名称/参数和输出文本不出现在明文列。
- normalizer：两种请求布局精确重建，非数组 `contents` 与保留 marker 被拒绝；没有会话 key；回答被下一轮原样重发时两轮共用该对象（`TestResentAnswerIsTheSameObject`）；inlineData 按解码字节存为 binary object，非标准 Base64 与 `file_data` 参数保持原文；JSON 数组流按 JSON body 存。
- 流式折叠：同一回答流式与非流式存出相同的 content item、得到相同的 conversation；每个已消费字段上的未知字段和未知形状的 chunk 在 raw 释放后可找回（`probe_test.go`）；残留超限时放弃并保留 raw。

## 10. 实施任务

1. 定义两个 operation、route model 和精简 Content/Part DTO。
2. 实现请求、非流式响应、usage 和 error 解析。
3. 实现 GenerateContentResponse SSE 聚合与结束判定。
4. 写入公共字段与 conversation，并加密 `parsed_json` envelope。
5. 完成正常、流式、blocked、function 和异常 fixtures。

## 11. 官方参考

- [GenerateContent API](https://ai.google.dev/api/generate-content)
- [streamGenerateContent](https://ai.google.dev/api/rest/v1beta/models/streamGenerateContent)
