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

### 2.1 协议适配器注册表

每个 parser 名对应一个 `parser.Adapter`，集中放这个协议特有的东西：

~~~go
type Adapter struct {
    Parser       Parser                // 摘要解析；实现 AuditNormalizer 时同时负责规范化
    Conversation ConversationRebuilder // 从重建出的 request/response 生成 conversation，仅 normalizer 有
    Layouts      []string              // normalizer 现在会写出的全部 request/response layout，仅 normalizer 有
}
~~~

`parser.NewRegistry` 按 parser 名建索引，并在构造时拒绝：重名、缺 parser 或版本、有 normalizer 却没有 `Conversation` 或 `Layouts`（以及反过来）、声明了 `auditmodel` 不认识的 layout。

注册表只有一份，由 `internal/parser/builtin` 用显式列表构造；包初始化时构造失败直接 panic，任何二进制在启动时就会停下，不会等到第一次重建才报 unsupported。没有 `init` 注册，也没有可变的全局状态。使用方：

- `builtin.All()` 从注册表取 parser，交给 worker（`internal/app` 以及经它启动的 `audit-bench`）；
- query 服务重建 turn 时用 `builtin.Registry().RebuildConversation` 按 parser 名取 `Conversation`，不再 import 单个协议包；未注册或没有 normalizer 的 parser 名得到 `ErrUnknownParser`，查询侧仍表现为 `conversation_projection` 完整性错误。

layout 怎么拼回 provider 值不放在适配器里，而是放在 `auditmodel` 的 layout 表（`internal/auditmodel/layout.go`）。原因是 layout 名属于存储格式：`auditmodel.Prepare` 写入前要用它校验，query、`storage/migrate` 的离线导入校验和以后的冷归档读取都要在没有代理、不加载任何 parser 的情况下重建已存的行，而 `auditmodel` 是这些读者都会 import 的底层包，不能反过来 import parser。表里每个 layout 只是数据：

- `none` 原样返回 envelope，`marker_envelope` 把 envelope 里的 item marker 换回 item；
- 其他 layout 要求 envelope 是 JSON 对象，按 slot 规则写回：`array`（全部 item 组成数组，可为空）、`one`（恰好一个）、`optional`（零或一个，零个时不写键）、`absent`（必须没有）；规则以外的 slot 被忽略；
- 流式响应 layout 另带 stream 标记，`auditmodel.StreamLayout` 据此判断响应是 SSE 描述加聚合消息，而不是 JSON Body（insights 回填用它决定走流式还是 JSON 路径）。

layout 名一经写入就不能改名或删除；形状变化要新增 layout 名，旧行仍按旧名读取。被新版本取代、不再写出的 layout 从适配器的 `Layouts` 移到 `builtin_test.go` 的 `retiredLayouts`，表里的行保留不动，旧行照常组装，conversation 仍由该 parser 名的适配器还原。`internal/auditmodel/layout_test.go` 钉住全部 layout 名和 stream 标记，`internal/parser/builtin/builtin_test.go` 钉住全部 parser 名与版本，要求表里每个 layout 要么有适配器写出、要么列为 retired，并用协议夹具和手写请求驱动每个 normalizer：写出的 layout 必须在适配器声明里，声明的每个 layout 都要被实际写出过，并且能 Prepare、Assemble、再经注册表还原成 conversation。

### 2.2 新增一个协议

1. 在协议包里实现 `Parser`，需要内容寻址时再实现 `AuditNormalizer` 和从重建值生成 conversation 的函数；
2. 若 normalizer 需要新的 layout，在 `auditmodel/types.go` 加 layout 名常量，在 `auditmodel/layout.go` 的表里加一行，并把新名加进 layout 钉住测试；
3. 在协议包里写 `Adapter()`，返回上面三项；
4. 在 `builtin.adapters()` 加一行，并把 parser 名与版本加进钉住测试。

turn 的重建与还原不需要改 query 或 worker。注册表之外仍有几处按协议区分的逻辑，它们不属于重建，按需单独修改：

- `internal/parser/streamterminal`：采集路径上判断流在逻辑上结束的终止行。它按 parser 名的协议前缀分派，是采集层唯一依赖的 parser 侧叶子包，不引入各协议包；协议有可靠的流内终止标记时在这里加一支；
- `internal/contentpolicy/extract.go`：内容策略拦截器从请求 Body 取待检文本，按 parser 名分派（模块 22）；
- `internal/insights`：上下文分析按协议族解析请求和响应（模块 20），是分析口径，不是证据重建。

## 3. 当前协议范围

| 协议 | 摘要 / conversation | 内容寻址 normalizer | raw 保留 |
| --- | --- | --- | --- |
| OpenAI Chat Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Responses / Compact | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| Anthropic Messages | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| Gemini GenerateContent | 保持既有 JSON/SSE 解析和对话展示 | 尚未实现 | full |

当前生产容量优化覆盖 OpenAI Responses、Chat Completions 和 Anthropic Messages。Gemini 仍保持代理协议兼容和审计可读性，但在没有 normalizer 前不会删除 raw evidence，也不宣称获得 item/binary 级 O(n) 增长。Anthropic 的 `source.data` 图片/文档目前随所在 message 对象整体去重，不单独提取为 binary object。

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
    UpstreamErrorClass string
    MessageCount    *int
    ToolCallCount   *int
    HasToolCall     *bool
    Conversation    *conversation.Conversation
    ParsedJSON      []byte
}
~~~

明文列只保存窄摘要。`Conversation` 只在 worker 内存使用：

- OpenAI 与 Anthropic verified turn 的详情 conversation 从内容对象重建，不再写第二份 conversation；
- 没有 normalizer 的协议或 normalization/reconstruction 异常，raw 本来就会保留 full，此时可把 conversation 作为 `parsed_json_enc` 内的加密回退副本保存，避免现有详情能力退化。这份副本动辄数 MB，所以 `parsed_json_enc` 在加密前按需 gzip，格式见[模块 9](09-security-encryption-and-redaction.md) §5.1；
- 列表、普通日志和明文 SQLite 列永远不包含消息正文、reasoning、工具参数或结果。

`ErrorType`/`ErrorCode` 保存 parser 看到的原始错误标识；`UpstreamErrorClass` 是由[模块 22](22-content-policy.md)定义的稳定策略拒绝分类（如 `cyber_policy`），只保存枚举、不保存 message，并且是 `parsed_results` 中不参与完整性摘要的派生列。

## 5. 队列与 worker

- 一个容量 100 的内存 channel；
- 固定一个 worker，避免多个大 JSON normalizer 同时放大内存；
- audit 完成后非阻塞 Notify；队列满时 DB 行保持 pending；
- 每 30 秒扫描 pending；
- 启动时把 processing 重置为 pending，再扫描恢复；
- claim 使用条件更新，重复通知不会重复处理同一完成状态；
- parser panic 被 recover，并写稳定 `parser_panic`。

保存使用 `SaveParsedAudit` 在一个 writer 操作内原子写入 parsed summary、turn graph、对象、raw retention 和完整性事件；保存点隔离保证它以局部错误（约束冲突、对象身份、turn 图或重建校验失败）失败时不会回滚同批采集；存储级错误仍按 writer 规则整批失败。保存失败后的 release 将失败次数持久化，前四次分别退避 30、60、120、240 秒并回到 pending；扫描和 claim 都检查到期时间，重复通知不能绕过退避，重启也不清空预算。第 5 次失败写入 `parse_status=error` 和 `parsed_results.error_code=parsed_result_save_failed`，保留 full raw，不再自动重试。错误摘要不保存底层错误文本，无法确定 parser 版本时标记为 `unknown`。迟到的 release 不改变已提交的成功结果。

如果数据库本身不可写，release 也可能失败；此时记录保留 processing，日志只记录 `parse_release_failed`。单 worker 在内存中保留最多 100 条待 release 的 audit，每 30 秒先重试 release，再扫描 pending；同一 audit 在 release 确认成功前不能重新 claim，积压达到上限时也不再 claim 新记录。一次扫描遇到 release 失败即结束本轮恢复，避免存储故障时集中重试。数据库恢复后无需重启即可恢复处理，失败次数和到期时间仍由既有 writer 事务维护；已提交但确认失败的 release 重试不会重复计数，也不会覆盖成功终态。进程退出后的 processing 仍由启动恢复重置。这类存储故障不能承诺成功持久化重试次数，但不会篡改已经完成的转发结果。

worker 生命周期取消或超时导致的保存中止不计入写入失败预算，也不调用带计数的 release：保存可能尚未尝试，也可能已入队但等待 Ack 被取消。尚未完成的 processing 留给下次启动恢复，已经提交的终态保持不变；多次正常停机不会把同一条长耗时解析误判为永久保存失败。

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

Anthropic Messages 的拆分规则见[模块 07](07-anthropic-protocol-parser.md) §8，失败语义与上一段相同。

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

OpenAI 与 Anthropic verified turn 的管理 conversation 由 query 层执行以下步骤后生成：

1. 恢复 request/response refs；
2. 解密并验证 content/binary objects；
3. 按原布局重建 provider JSON；
4. 比较 sequence/reconstruction SHA-256；
5. 再从重建 provider 值生成协议无关 conversation。

这样列表和详情不需要保存第二份消息正文。第 3 步按 `auditmodel` 的 layout 表执行，第 5 步由写入该 turn 的 parser 的适配器完成（`builtin.Registry().RebuildConversation` 按 parser 名查找，见 §2.1）。Gemini 在当前版本从加密 parsed fallback 读取 conversation，同时 full raw 仍是权威证据；升级前写入的 Anthropic 记录没有 turn graph，读取方式同 Gemini。

## 10. 最少测试

- queue 满、pending scan、processing 恢复、panic 隔离、保存失败持久化退避及终态、release 暂时失败后不重启恢复、迟到 release 的幂等性。
- chunk 顺序、offset、压缩、GCM、SHA-256、gzip ratio 和 64 MiB 限额。
- OpenAI Chat/Responses/Completions JSON 与 SSE 摘要。
- developer/system/user/assistant/tool/reasoning/tool result 的顺序和 call id。
- provider JSON 请求与响应精确重建。
- layout 名、parser 名与版本钉住；每个 normalizer 写出的 layout 都已声明、可组装，且 conversation 重建已接到注册表（§2.1）。
- data URL 解码字节去重、inline file data、`file_id` 外部引用。
- normalization/reconstruction 失败时四阶段 raw 保持 full 且可完整下载。
- verified OpenAI/Anthropic parsed JSON 不含第二份 conversation；无 normalizer 的协议仍能从加密 fallback 展示 conversation。
- parser/query/UI 不把敏感正文写入列表、日志或明文列。
