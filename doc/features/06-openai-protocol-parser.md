# 模块 06：OpenAI 兼容协议解析器

## 1. 支持范围

首版只解析 kickoff 默认且明确配置进 LLM API 白名单的四个端点：

| Endpoint | Path |
| --- | --- |
| Chat Completions | `/v1/chat/completions` |
| Completions | `/v1/completions` |
| Responses | `/v1/responses` |
| Responses Compact | `/v1/responses/compact` |

parser 异步读取已持久化证据，不参与代理转发，不修改请求或响应。当前四个 OpenAI parser 同时实现内容寻址 normalizer：普通成功请求可从加密 content/binary objects 精确重建 provider JSON；异常记录仍可从加密 raw Body 读取。

NewAPI health、login、admin、`/v1/models`、UI 和其他安全非 LLM 路径走 passthrough，不进入本 parser。

对应包：`internal/parser/openai`。

## 2. 输入与输出

请求 Body 来自 `request_for_newapi_received_from_nginx`，响应 Body 来自 `response_received_from_newapi`；`request_sent_to_newapi` 与 `response_from_newapi_sent_to_nginx` 只补充实际转发和完整性状态。

公共输出只写入 `parsed_results`：

- `request_model`、`response_model`、`requested_stream`、`observed_stream`、`response_id`
- input/output/total usage、`error_type`、`error_code`、消息和工具调用数量

消息、prompt、input、instructions、输出文本、reasoning、工具/函数名称、call id、参数和结果会拆成内容对象。verified turn 的 conversation 在查询时从这些对象重建，不再复制进 `parsed_json_enc`；compact `ParsedJSON` 和公共列只保存窄摘要。

## 3. 请求解析

### Chat Completions

读取 `model`、`stream`、messages 数量/role、tools/tool call 数量；conversation 保留 system/developer/user/assistant/tool 顺序。旧式 `role=function` 规范为工具结果，`function_call` 与 `tool_calls` 统一为 tool_call part。

`messages[].content` 可以是字符串或数组；已知 text/reasoning/tool block 转为对应 part。data URL 图片会严格 Base64 解码并按原始二进制 hash 复用，外部 `file_id` 仍作为加密引用保存。未知 provider 字段保留在 canonical item 中，不因为 UI 不展示就丢失。

### Completions

读取 `model`、`stream` 和 prompt 数量摘要；prompt 转为 user conversation message。suffix、stop、logprobs 等未映射配置仍保留在加密 request envelope content object 中，可随 provider JSON 精确重建，不进入公共摘要列。

### Responses / Responses Compact

读取 `model`、`stream`、input item 数量、tools 数量、`previous_response_id` 等已知字段。`instructions` 和每个 input item 独立寻址；`previous_response_id`、conversation/thread/cache key 用于父轮次关联。Compact 返回的压缩或 `encrypted_content` 数据只做不透明加密保存，不尝试解密内部内容。

## 4. 非流式响应

Chat/Completions 读取 `id`、`model`、choices 数量、`finish_reason`、message/text/tool call 摘要和 usage，并为每个 choice 生成 assistant conversation message。

Responses 读取 `id`、`model`、`status`、output item/工具调用数量、usage、error 和 incomplete details。message、function_call、function_call_output 和 reasoning summary 分别映射为 text/tool_call/tool_result/reasoning。

Compact 只把明确存在的 ID、model、status 和对象类型映射到公共摘要；其余 provider 字段仍保留在加密 envelope/item content object 中。

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
- 未知 event type 不中止后续事件，整条进入残留。
- terminal event 中的 response/output/usage 优先作为最终快照，不能和此前 delta 重复生成消息。
- clean EOF 没有 terminal event 时记为 `partial`。

Compact 若返回 SSE，只按 Responses 风格事件解析；不能误当 Chat chunk。

### 5.1 折叠与残留

流按模块 05 §2.3 折叠成该端点的非流式 body，parser 的 conversation 也从折叠体读出，所以同一回答流式与非流式的 conversation 相同。下表是折叠器消费的内容；表外的事件整条、已消费事件中表外的字段按原位置进入残留（envelope 的 `residue`，格式见模块 18 §10）。

Chat Completions 与 Completions 只有一种事件，即 chunk，外加终止行 `[DONE]`（不留任何东西）：

| 层级 | 消费的字段 | 折叠方式 |
| --- | --- | --- |
| chunk | `id` `object` `created` `model` `service_tier` `system_fingerprint` | 取最后一次报告的非 null 值；`object` 保持 chunk 的值 |
| chunk | `usage` | 最后一次报告的非 null 对象整体替换 |
| chunk | `choices` | 按 `index`（缺省为数组位置）归入 `choices[]`，结果按 index 排序，每个元素带 `index` |
| choice | `finish_reason` | 最后一次报告的非 null 值 |
| choice | `text` | 拼接（Completions） |
| choice | `logprobs` | 逐字段：数组按序拼接（Chat 的 `content`、`refusal`，Completions 的 `tokens` 等），null 只补缺 |
| choice | `message` | 整个 message 作为该 choice 的 message；此时该 choice 的 delta 全部进残留 |
| choice | `delta` | 见下 |
| delta | `role` `name` | 最后一次报告的非 null 值 |
| delta | `content` `refusal` `reasoning_content` `reasoning` `thinking` | 各自拼接到 message 的同名字段 |
| delta | `tool_calls[]` | 按 `index`（缺省为数组位置）归入 message 的 `tool_calls[]`，按首次出现排序，每个元素保留 `index`；`id`、`type` 取最后报告值，`function.name`、`function.arguments` 拼接 |
| delta | `function_call` | `name`、`arguments` 拼接到 message 的 `function_call` |

Responses 消费以下事件类型，每种只读列出的顶层字段：

| 事件类型 | 读取的字段 | 折叠方式 |
| --- | --- | --- |
| `response.created` `response.queued` `response.in_progress` `response.completed` `response.failed` `response.incomplete` | `type` `sequence_number` `response` | 各快照按顺序合并（null 不覆盖已报告值），终态快照最后合并；终态没有 output 时由下面的事件构造 output |
| `response.output_item.added` / `.done` | `type` `sequence_number` `output_index` `item` | 与 `output[output_index]` 比较 |
| `response.content_part.added` / `.done` | 上列加 `item_id` `content_index` `part` | 与 `output[i].content[j]` 比较 |
| `response.output_text.delta` / `.done` | `item_id` `output_index` `content_index`，delta 读 `delta` `logprobs`，done 读 `text` `logprobs` | 拼接后与 `content[j].text`、`content[j].logprobs` 比较 |
| `response.refusal.delta` / `.done` | 同上，done 读 `refusal` | 与 `content[j].refusal` 比较 |
| `response.function_call_arguments.delta` / `.done` | `item_id` `output_index`，delta 读 `delta`，done 读 `arguments` | 与 `output[i].arguments` 比较 |
| `response.reasoning_summary_part.added` / `.done` | `item_id` `output_index` `summary_index` `part` | 与 `output[i].summary[k]` 比较 |
| `response.reasoning_summary_text.delta` / `.done` | 同上，delta 读 `delta`，done 读 `text` | 与 `summary[k].text` 比较 |
| `response.reasoning_text.delta` / `.done` | `item_id` `output_index` `content_index`，delta 读 `delta`，done 读 `text` | 与 `content[j].text` 比较 |

所有已消费的 Responses 事件都读 `type` 和 `sequence_number`；`sequence_number` 等于事件编号时视为持有，否则进残留。`item_id` 等于 `output[i].id` 时视为持有。快照、item 和 part 与折叠体逐键比较，只有不同的键进残留（例如 `response.created` 的 `"status":"in_progress"`）。

生产流量里常见的残留：

- `obfuscation`（OpenAI 为抵御侧信道给每个 delta 加的随机填充）不在任何清单里，每个 delta 事件留一条，约 40 字节；
- Responses 每条流留 `response.created`/`in_progress` 的 `"status":"in_progress"` 和每个 item 的 `"status":"in_progress"`，约 100 字节；
- 清单外的事件，例如 `response.output_text.annotation.added`、托管工具的 `response.*_call.*` 进度事件，整条保留。

`summary.stop_reason`：Chat 与 Completions 存最后一个报告了 `finish_reason` 的 chunk 中第一个非空的 `finish_reason`；Responses 没有供应商停止原因，存终态映射后的值：`completed` 为 `end_turn`，`incomplete` 为 `incomplete_details.reason`（没有时为 `other`），`failed`、`cancelled` 为 `other`。两者都是 insights 读 raw 流会得到的停止原因，回填据此恢复（模块 05 §2.3）。

管理端可重建折叠体、事件次序和每个事件的全部字段值，但不宣称重建原始 SSE 空白、delta 切分、HTTP chunk framing 或 TCP frame；异常时 full raw 仍保留原字节。

## 6. 错误与限额

常见错误对象：

```json
{"error":{"message":"...","type":"...","code":"..."}}
```

`type` 和 `code` 可进入公共字段，message 不进入 compact 摘要或 conversation；JSON error envelope 仍存在于加密 response envelope object 中，且非 2xx/3xx 记录的响应侧保留 full raw（请求侧按[模块 18](18-content-addressed-conversation-storage.md) §6 决定）。非 JSON 错误只保留 HTTP 状态、安全错误码和 full raw。错误 envelope 中的明确策略 code 以及 cyber/安全提示短语会在内存中派生 `upstream_error_class`（`cyber_policy`/`content_policy`/`safety_policy` 等），message 本身仍不落公共列。

统一限额：

- 请求侧解码后最多 64 MiB。
- 响应侧解码后最多 64 MiB。
- gzip 最大解压比 50:1。

单个 JSON/SSE 事件畸形时尽量继续解析后续事件；顶层完全无法解析则设 `parse_status=error`。超限或流提前结束设 `partial`，不执行 raw compaction。512 MiB 代理入站上限不改变 parser 的 64 MiB 单侧 normalizer 内存上限。

## 7. parsed_results 写入

```text
parser_name = openai.chat_completions | openai.completions | openai.responses | openai.responses_compact
parser_version = 3
status = ok | partial | error | skipped
公共字段 = 模型、流式、ID、usage、错误、消息/工具数量
parsed_json_enc = nonce || ciphertext || tag
turn/content/binary objects = verified provider request/response
```

版本 3 改的只是流式响应的存储形状（§5.1，layout `openai.stream.response.v2`：紧凑事件描述、折叠体和残留）和从流读出 conversation 的方式（改为读折叠体）。版本号只写进 `parsed_results.parser_version`，进入新写入行的完整性摘要，并在详情里显示；没有任何逻辑按版本号重新解析、回填或迁移，已有行不改写。版本 2 写入的流式行保留 layout `openai.stream.response`，按原方式组装和还原 conversation（`internal/parser/openai/testdata/legacy_stream_response.json` 钉住）。

`SaveParsedAudit` 原子覆盖该 audit 的最新摘要、保存或复用内容对象、写 turn delta、验证 reconstruction hash，再按侧切换 raw retention：普通成功两侧 metadata，有 verified turn 的异常记录按模块 18 §6 通常只释放请求侧。任何一步失败都保留 full raw。

## 8. 最少测试

- 四个端点各一个正常请求/响应 fixture。
- Chat SSE 文本、tool call、usage-only final chunk 和缺少 `[DONE]`。
- Chat SSE reasoning 与 tool arguments 分片聚合；旧式 role=function 工具结果。
- Responses typed SSE 的 completed、failed、reasoning summary、terminal 去重和未知事件。
- 每种已消费事件类型的未知字段、未知事件类型在 raw 释放后可找回；raw 与重建两条路径的 conversation、usage、工具调用和停止原因一致（模块 05 §2.3）。
- parser 版本 2 的流式行按原方式重建。
- 未知 JSON 字段、畸形 JSON、单个畸形 SSE 事件。
- gzip 正常/损坏、64 MiB 和 50:1 限额。
- error envelope、工具名称/参数和正文不出现在明文列。
- Responses/Chat 的 developer、reasoning、并行工具、图片、`file_id` 和 inline file data 可精确重建。
- retry、continuation、branch、truncate、edit、rollback 和 summary 的 turn 关系及有序引用正确。
- 相同 PNG 在后续完整上下文和不同 Base64/MIME 写法中只保存一个 binary object。

## 9. 实施任务

1. 定义四个 endpoint 分发和精简 DTO。
2. 实现请求、非流式响应和 error envelope 解析。
3. 实现 Chat/Completions `[DONE]` 与 Responses typed SSE。
4. 映射公共字段与 conversation，并实现 content-addressed normalizer。
5. 完成四端点、重建、多模态、分支和异常 fixtures。

## 10. 官方参考

- [Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create/)
- [Completions](https://developers.openai.com/api/reference/resources/completions/methods/create/)
- [Responses](https://developers.openai.com/api/reference/resources/responses/methods/create/)
- [Responses Compact](https://developers.openai.com/api/reference/resources/responses/methods/compact/)
