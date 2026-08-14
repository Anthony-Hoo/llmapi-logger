# 模块 05：协议解析与审计 normalizer

## 1. 目标与边界

parser 在 HTTP 请求完成后异步读取已落盘证据，生成模型、usage、错误和工具调用数量等窄摘要。实现 `AuditNormalizer` 的协议还会把 provider request/response 拆成可复用的 envelope、context item、response item 和 binary object，并在保存前完成精确重建校验。

硬性边界：

- parser/normalizer 不进入 HTTP 转发链；
- passthrough、fail-closed 和 interceptor rejected 不进入普通 parser；
- normalizer 失败不能修改已经返回给客户端的字节；
- 只有重建验证通过的普通成功请求才能删除长期 raw chunks；
- 不推断 NewAPI 后方的供应商请求、渠道选择、内部重试或渠道密钥。

## 2. 接口

~~~go
type Parser interface {
    Name() string
    Version() string
    Parse(context.Context, Input) Result
}

type AuditNormalizer interface {
    NormalizeAudit(context.Context, Input, Result) (auditmodel.Turn, error)
}
~~~

`Parser` 负责安全摘要和协议无关 conversation；`AuditNormalizer` 负责无损 provider 对象拆分。worker 先执行 Parse，只有以下条件全部满足才执行 NormalizeAudit：

- parser status 为 `ok`；
- request 证据完整；
- response 若存在也完整；
- parser 实现了 `AuditNormalizer`。

normalizer 返回的 plaintext 只存在于 worker 内存。`auditmodel.Prepare` 会 canonicalize、提取多模态二进制、压缩、加密并本地重建验证，输出不含 provider 明文的 `PreparedTurn`。

## 3. 当前协议范围

| 协议 | 摘要 / conversation | 内容寻址 normalizer | raw 保留 |
| --- | --- | --- | --- |
| OpenAI Chat Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Responses / Compact | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| Anthropic Messages | 保持既有 JSON/SSE 解析和对话展示 | 尚未实现 | full |
| Gemini GenerateContent | 保持既有 JSON/SSE 解析和对话展示 | 尚未实现 | full |

当前生产容量优化重点覆盖 OpenAI Responses 和 Chat Completions。Anthropic/Gemini 仍保持代理协议兼容和审计可读性，但在没有 normalizer 前不会删除 raw evidence，也不宣称获得 item/binary 级 O(n) 增长。

## 4. Result 与敏感数据

~~~go
type Result struct {
    Status          string
    RequestModel    string
    ResponseModel   string
    RequestedStream *bool
    ObservedStream  *bool
    ResponseID      string
    Usage           Usage
    ErrorType       string
    ErrorCode       string
    MessageCount    *int
    ToolCallCount   *int
    HasToolCall     *bool
    Conversation    *conversation.Conversation
    ParsedJSON      []byte
}
~~~

明文列只保存窄摘要。`Conversation` 只在 worker 内存使用：

- OpenAI verified turn 的详情 conversation 从内容对象重建，不再写第二份 conversation；
- 没有 normalizer 的协议或 normalization/reconstruction 异常，raw 本来就会保留 full，此时可把 conversation 作为 `parsed_json_enc` 内的加密回退副本保存，避免现有详情能力退化；
- 列表、普通日志和明文 SQLite 列永远不包含消息正文、reasoning、工具参数或结果。

## 5. 队列与 worker

- 一个容量 100 的内存 channel；
- 固定一个 worker，避免多个大 JSON normalizer 同时放大内存；
- audit 完成后非阻塞 Notify；队列满时 DB 行保持 pending；
- 每 30 秒扫描 pending；
- 启动时把 processing 重置为 pending，再扫描恢复；
- claim 使用条件更新，重复通知不会重复处理同一完成状态；
- parser panic 被 recover，并写稳定 `parser_panic`。

保存使用 `SaveParsedAudit` 单事务写 parsed summary、turn graph、对象、raw retention 和完整性事件。保存失败后 processing 被释放回 pending，等待后续重试。

## 6. 证据读取

parser 读取：

1. `request_for_newapi_received_from_nginx`；
2. `response_received_from_newapi`。

阶段缺失不能解释为空 Body。reader 会按 `source_stage` 读取 owning chunks，逐块验证 seq、offset、compression、GCM、明文长度和最终 SHA-256，再处理 HTTP `Content-Encoding`。

当前单 worker 对每侧最多保留 64 MiB 解码后数据，encoded 上限为 128 MiB，gzip 最大解压比为 50:1。超过限额会得到稳定 `body_too_large`，parse 变为 partial/error，保留 full raw；不会截断后仍标记 verified。512 MiB 入站限制是代理/interceptor 的传输上限，不等同于 normalizer 内存上限。

## 7. OpenAI normalizer

OpenAI 请求拆分规则：

- Chat：envelope 移除 `messages`，每条 message 成为一个有序 item；
- Responses：`instructions` 与 `input` item 分离，保留 single/array/none 原布局；
- Completions：`prompt` 单值或数组分离；
- `previous_response_id`、conversation/thread/cache key 作为父轮次关联证据；
- `metadata` 中可能的 conversation/session 标识只用于域分离 hash，不进入普通日志。

非流式响应把 choices message/text 或 Responses output item 替换为受控 marker。SSE 响应保存 event 类型、data 长度与 SHA-256 描述，以及 parser 聚合后的 assistant/reasoning/tool output items；不复制每个网络 chunk。

provider 输入若包含保留 marker 名、畸形 JSON、错误 data URL/Base64、未知重建布局或重建 hash 不一致，normalizer 必须失败并保留 full raw。

## 8. 状态语义

`audit_records.parse_status`：

- `pending`：等待处理；
- `processing`：worker 已 claim；
- `ok`：摘要可信；若有 normalizer，turn 也已 verified；
- `partial`：证据、协议或 normalization/reconstruction 只完成一部分；
- `error`：无法得到可信结果；
- `skipped`：被拦截、无 Body、未注册 parser 或不支持的编码。

`normalization_failed` 和 `reconstruction_failed` 都是稳定错误码；它们会清除可能不一致的 parsed payload、保留 full raw，并写 `reconstruction_failed` 完整性事件。parser 错误文本不得包含 Body、Header value、工具参数、文件引用或密钥。

## 9. 查询派生

OpenAI verified turn 的管理 conversation 由 query 层执行以下步骤后生成：

1. 恢复 request/response refs；
2. 解密并验证 content/binary objects；
3. 按原布局重建 provider JSON；
4. 比较 sequence/reconstruction SHA-256；
5. 再从重建 provider 值生成协议无关 conversation。

这样列表和详情不需要保存第二份消息正文。Anthropic/Gemini 在当前版本从加密 parsed fallback 读取 conversation，同时 full raw 仍是权威证据。

## 10. 最少测试

- queue 满、pending scan、processing 恢复、panic 隔离和保存失败重试。
- chunk 顺序、offset、压缩、GCM、SHA-256、gzip ratio 和 64 MiB 限额。
- OpenAI Chat/Responses/Completions JSON 与 SSE 摘要。
- developer/system/user/assistant/tool/reasoning/tool result 的顺序和 call id。
- provider JSON 请求与响应精确重建。
- data URL 解码字节去重、inline file data、`file_id` 外部引用。
- normalization/reconstruction 失败时四阶段 raw 保持 full 且可完整下载。
- verified OpenAI parsed JSON 不含第二份 conversation；无 normalizer 的协议仍能从加密 fallback 展示 conversation。
- parser/query/UI 不把敏感正文写入列表、日志或明文列。
