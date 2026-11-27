# 模块 05：协议解析与审计 normalizer

## 1. 目标与边界

parser 在 HTTP 请求完成后异步读取已落盘证据（unified 写入路径下改用采集会话交来的同一份明文，§5.1），生成模型、usage、错误和工具调用数量等窄摘要。实现 `AuditNormalizer` 的协议还会把 provider request/response 拆成可复用的 envelope、context item、response item 和 binary object，并在保存前完成精确重建校验。

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
- 流式响应 layout 另带 stream 标记，`auditmodel.StreamLayout` 据此判断响应是 SSE 描述加聚合结果，而不是 JSON Body（insights 回填用它决定走流式还是 JSON 路径）。现行的流式 layout（`openai.stream.response.v2`、`anthropic.stream.response`、`gemini.stream.response`）属于 marker 类：envelope 的 `aggregate` 键下是折叠出的非流式 body，其中的 item 换成 marker，组装方式与 `marker_envelope` 相同（§2.3）；最早的 `openai.stream.response` 的 `aggregate` 是展示用 message 的数组。

layout 名一经写入就不能改名或删除；形状变化要新增 layout 名，旧行仍按旧名读取。被新版本取代、不再写出的 layout 从适配器的 `Layouts` 移到 `builtin_test.go` 的 `retiredLayouts`，表里的行保留不动，旧行照常组装，conversation 仍由该 parser 名的适配器还原。`internal/auditmodel/layout_test.go` 钉住全部 layout 名和 stream 标记，`internal/parser/builtin/builtin_test.go` 钉住全部 parser 名与版本，要求表里每个 layout 要么有适配器写出、要么列为 retired，并用协议夹具和手写请求驱动每个 normalizer：写出的 layout 必须在适配器声明里，声明的每个 layout 都要被实际写出过，并且能 Prepare、Assemble、再经注册表还原成 conversation。

### 2.2 新增一个协议

1. 在协议包里实现 `Parser`，需要内容寻址时再实现 `AuditNormalizer` 和从重建值生成 conversation 的函数；
2. 若 normalizer 需要新的 layout，在 `auditmodel` 加 layout 名常量（`types.go`，或像 `LayoutOpenAIStreamResponseV2` 那样紧挨表放在 `layout.go`），在 `auditmodel/layout.go` 的表里加一行，并把新名加进 layout 钉住测试；
3. 在协议包里写 `Adapter()`，返回上面三项；
4. 在 `builtin.adapters()` 加一行，并把 parser 名与版本加进钉住测试；
5. 流式响应的 normalizer 遵守 §2.3：折叠成非流式 body、留残留、写同样的 `summary`。注册后保真夹具测试自动覆盖它。

turn 的重建与还原不需要改 query 或 worker。注册表之外仍有几处按协议区分的逻辑，它们不属于重建，按需单独修改：

- `internal/parser/streamterminal`：采集路径上判断流在逻辑上结束的终止行。它按 parser 名的协议前缀分派，是采集层唯一依赖的 parser 侧叶子包，不引入各协议包；协议有可靠的流内终止标记时在这里加一支。Gemini 没有这一支：它的结束标志是 candidate 的 `finishReason`，位于很长的 data 行内，采集探针只看 48 字节的行首，见模块 08 §5；
- `internal/contentpolicy/extract.go`：内容策略拦截器从请求 Body 取待检文本，按 parser 名分派（模块 22）；
- `internal/insights`：上下文分析按协议族解析请求和响应（模块 20），是分析口径，不是证据重建。

### 2.3 流式响应的折叠与保真

普通成功的流式响应经验证后释放 raw，此后只剩 envelope 和 item。为了不在这一步丢内容，每个流式 normalizer 遵守同一套约定（实现共用 `internal/parser/streamevidence`）。

**SSE 解码。** 事件按 `parser.DecodeSSEWithStatus` 从解码后的响应 Body（已去掉 HTTP `Content-Encoding`）切分，全程按字节处理，不做 UTF-8 校验，也不去掉 BOM：行以 LF、CRLF 或单独的 CR 结束；以 `:` 开头的行是注释，忽略；其余行在第一个 `:` 处分成字段名和值，值开头的一个空格去掉，没有 `:` 的行是值为空的字段；`event` 字段设置事件名（同一事件内后出现的覆盖先出现的），每个 `data` 字段贡献一行，多行以单个 LF 连接成事件的 data（末尾不加 LF）；空行派发事件，没有 data 行的事件不派发且其事件名作废；`id`、`retry` 等其他字段忽略；Body 末尾没有空行结束的最后一个事件也派发（这样的流解析为 `partial`，不会被规范化）。事件按派发顺序从 0 编号。残留的 `index` 和事件描述都按这个编号。

**事件描述。** envelope 的 `events` 是整条流的紧凑描述，取代旧的逐事件描述（每个事件一个事件名、data 长度和十六进制 SHA-256）：

~~~json
{"names": [["message_start", 1], ["content_block_delta", 2], ["", 1]],
 "data_lengths": [7, 7, 7, 6],
 "sha256": "3f21d1539f9e9828f6fb8859dd7fc9e917b028b6ae46fe8b726422ad37c16c86"}
~~~

- `names` 是事件名按顺序的游程编码：每段是 `[事件名, 连续个数]`，没有 `event` 字段的事件名为空字符串；各段个数之和等于事件数；
- `data_lengths` 是每个事件 data 的字节数，按顺序；
- `sha256` 是覆盖全部事件的哈希，小写十六进制：

~~~text
SHA-256( "llmapi-logger/sse-events/v1" || 0x00 ||
         对每个事件按顺序：
             uint64be(len(name)) || name || uint64be(len(data)) || data )
~~~

  其中 name 是事件名的 UTF-8 字节，data 是上面解码规则得到的 data 字节（多个 data 行以 LF 连接，不含最后的换行），`uint64be` 是 8 字节大端无符号长度。前缀和逐字段长度使哈希同时绑定事件顺序、事件个数、事件名和 data 字节，任意两个字段之间的边界都无歧义。持有 raw SSE 的读者按上面的解码规则切出事件即可重算；上例是四个事件 `message_start`/`{"a":1}`、`content_block_delta`/`{"b":2}`、`content_block_delta`/`{"c":3}`、无名/`[DONE]` 的结果（`internal/parser/streamevidence` 的测试钉住，并在 Go 之外按此定义独立算过）。
- 注释行、`id`/`retry` 字段、行结束符的写法和 HTTP 分块不在哈希内；整条 raw Body 的字节另有 `body_streams.sha256`。

**折叠体。** normalizer 把事件折叠成该端点的非流式响应 body，再交给该协议的非流式响应拆分代码（`normalizeJSONResponse`）按同样的方式拆成 envelope 与 item：Chat 每个 choice 的 `message`、Completions 每个 choice 的 `text`、Responses 每个 `output` 元素、Anthropic 每个 content block、Gemini 每个 candidate 的 `content` 各是一个 item，body 中换成 marker。拆分后的 body 放在流 envelope 的 `aggregate` 键下，事件描述、摘要和残留在它旁边。因此同一回答流式与非流式存出的 response item 是同一批 content object，下一轮请求复用它们的情形与非流式完全相同（例如客户端原样重发 Responses 的 output item 或 Chat 的 assistant message）。Responses 的终态 response 还回显请求的 `instructions` 和 `tools`，流式 layout 把它们各存为一个 item（slot `instructions`/`tools`，kind 同名）：`instructions` 与请求里的 instructions item 是同一个对象，`tools` 在同一会话的各轮之间去重。parser 自己的 conversation 也从折叠体读出（与非流式响应走同一段代码），所以 raw 解析得到的 conversation 与从图重建的完全一致，同一回答流式与非流式的 conversation 也一致。折叠体能装下的内容优先装进去（例如 Anthropic 的 `signature`、`citations` 本来就是 content block 的字段）。各协议消费的事件类型和字段见模块 06 §5、模块 07 §5、模块 08 §5.1。

**残留。** 事件里折叠体给不回来的内容进入 envelope 的 `residue`（格式见模块 18 §10）。一个事件的值是否已由折叠体持有，按以下规则判断，对象逐键递归：

1. 与折叠体同一位置的值相等，视为持有；
2. `null` 在折叠体有该位置时视为持有：它表示“尚未报告”，折叠体保存后来报告的值；
3. 空字符串、空数组、空对象在折叠体同一位置是同类型的值时视为持有：这是该字段的起始值，后续事件填充；
4. 拼接类字段（文本 delta、参数片段）按顺序拼接，拼接结果等于折叠体中的值时，各片段视为持有；不相等时片段全部进残留；
5. 位置类字段（事件序号、`output_index`、`content_index`、`item_id` 等）能由折叠体位置推出时视为持有，推不出（例如 `sequence_number` 不等于事件编号）时进残留；
6. 其余一律进残留：清单外的事件整条保留，已消费事件中不读的字段按原嵌套位置保留，被后一事件覆盖的旧值留在发出它的事件下。

Gemini 不带 `alt=sse` 时把同样的 chunk 放在一个 JSON 数组里返回。它不是 SSE，事件描述和残留无从定义，按 JSON body 整体存入 envelope（模块 08 §8）。

折叠体中的块或 item 位置不连续时（例如 content block 下标跳号），流无法无损表示，normalizer 返回错误。事件中出现保留 marker 键同样返回错误。

**摘要。** envelope 的 `summary` 固定有 `response_id`、`usage`（解析结果的 `Usage`，键为 `Input`/`Output`/`Total`）、`normalized_usage`（不含缓存的输入、缓存读、缓存写、输出、reasoning）、`stop_reason`、`error_type`、`error_code`。raw 释放后，insights 回填只读 `usage`、`normalized_usage`、`stop_reason` 和重建的 conversation（`query.ReconstructBodies`）。`stop_reason` 必须是 insights 停止原因映射读来与读 raw 流结果相同的值：有供应商原值的协议存原值（Anthropic 的 `stop_reason`、Chat/Completions 最后报告的 `finish_reason`、Gemini 最后报告的 `finishReason`），只有状态的协议存映射后的值（Responses，见模块 06 §5）。

**上限与放弃。** 残留的 canonical JSON 超过 `streamevidence.MaxResidueBytes`（1 MiB）时，normalizer 返回 `streamevidence.ErrResidueTooLarge`（即 `parser.ErrStreamResidueTooLarge`）。worker 把它与其他 normalizer 错误分开：响应完整且已解析，只是没有被规范化，所以记录得到只有请求的轮次（模块 18 §6）。解析保持 `ok`，错误码为 `response_not_normalized`（解析已带错误码时保留原码），响应侧 raw 保持 `full`，请求侧 raw 按模块 18 §6 释放，回答消息存在 `parsed_json_enc` 的 `partial_response_messages`，写 `semantic_compacted` 事件，不写 `reconstruction_failed`。请求也规范化不了时才走 `normalization_failed` 路径。其他 normalizer 错误的处理不变：解析记为 `partial`、`error_code=normalization_failed`，不生成 turn，四阶段 raw 保持 `full`，conversation 作为 `parsed_json_enc` 回退副本保存，并写 `reconstruction_failed` 完整性事件。

**保真夹具。** `internal/parser/builtin/fidelity_test.go` 对注册表里每个有 normalizer 的 parser，取协议夹具目录（`internal/protofixture`）里所有交给它的交换，加上目录没有协议的 parser 的手写流，各走两条路径：从 raw 解析，以及只用密封后的对象重建（不读 raw）。要求两边的 conversation、用量（`summary.usage`、`summary.normalized_usage` 与解析结果一致，折叠体按非流式 body 重新解析也一致）、工具调用数和停止原因（insights 从 raw 流得到的，与回填从 `summary.stop_reason` 和从折叠体得到的一致）相同，流的事件描述与从 raw 重算的相同。每个 normalizer 至少要有一个交换通过；目录里有流给它的，至少要有一个流通过。新协议注册 normalizer 后自动纳入，不通过则测试失败。`probe_test.go` 给每种已消费事件类型及其嵌套对象注入未知字段，再加未知事件类型和未知 delta 类型，要求所有值都能从重建结果中找回，并要求探针覆盖各协议列出的全部消费事件类型。`dedup_test.go` 要求同一回答流式与非流式存出相同的 response item 对象（Responses 流另有 `instructions`、`tools` 两个 item），并在全量重发历史的两轮会话里要求第二轮请求复用第一轮响应对象的情形与非流式相同、回显的 `instructions`/`tools` 两轮合计只插入一次。

## 3. 当前协议范围

| 协议 | 摘要 / conversation | 内容寻址 normalizer | raw 保留 |
| --- | --- | --- | --- |
| OpenAI Chat Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Completions | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| OpenAI Responses / Compact | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| Anthropic Messages | 支持 JSON/SSE | 支持 | verified 的 2xx/3xx 成功为 metadata |
| Gemini GenerateContent / StreamGenerateContent | 支持 JSON/SSE/JSON 数组流 | 支持 | verified 的 2xx/3xx 成功为 metadata |

当前生产容量优化覆盖全部内置协议：OpenAI Responses、Chat Completions、Completions、Anthropic Messages 和 Gemini GenerateContent（parser 版本 3 起，见模块 08 §8）。Anthropic 的 `source.data` 图片/文档目前随所在 message 对象整体去重，不单独提取为 binary object；Gemini 的 `inlineData.data` 按解码字节存为 binary object。

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

- 有 verified turn 的记录（OpenAI、Anthropic、Gemini）的详情 conversation 从内容对象重建，不再写第二份 conversation；
- 只有请求的轮次（响应不完整、因响应而解析为 `partial`，或响应未被规范化，模块 18 §6）只把 conversation 中 `phase=response` 的消息存进 `parsed_json_enc` 的 `partial_response_messages`，读取时接在重建出的请求消息之后（`query.MergePartialResponse`），不存第二份完整 conversation；
- 没有 turn 的记录（normalization/reconstruction 异常、请求不可用，以及升级前没有 turn 的旧记录），raw 本来就会保留 full，此时可把 conversation 作为 `parsed_json_enc` 内的加密回退副本保存，避免现有详情能力退化。这份副本动辄数 MB，所以 `parsed_json_enc` 在加密前按需 gzip，格式见[模块 9](09-security-encryption-and-redaction.md) §5.1；
- 列表、普通日志和明文 SQLite 列永远不包含消息正文、reasoning、工具参数或结果。

`ErrorType`/`ErrorCode` 保存 parser 看到的原始错误标识；`UpstreamErrorClass` 是由[模块 22](22-content-policy.md)定义的稳定策略拒绝分类（如 `cyber_policy`），只保存枚举、不保存 message，并且是 `parsed_results` 中不参与完整性摘要的派生列。

## 5. 队列与 worker

- 一个有界 FIFO（容量 `FinalizeQueueCapacity` = 4096），两种输入共用：`Notify` 和 pending 扫描在队列里已有 100 个作业（`QueueCapacity`，不论作业从哪里来）时拒绝，unified 写入路径的 `Submit`（§5.1）在 4096 个时拒绝。解析顺序就是入队顺序。`/readyz` 的 `parser_queue` 报告这个队列的长度，最多到 4096；
- 固定一个 worker，避免多个大 JSON normalizer 同时放大内存；
- audit 完成后非阻塞 Notify 或 Submit；队列满时 DB 行保持 pending；
- 每 30 秒扫描 pending；
- 启动时把 processing 重置为 pending，再扫描恢复；
- claim 使用条件更新，重复通知不会重复处理同一完成状态；
- parser panic 被 recover，并写稳定 `parser_panic`；
- normalization 和轮次准备（`NormalizeAudit`、`PrepareWithLookup`）也在 recover 之下（`prepareSafely`）：panic 时什么都不保存，以 `normalize_panic` 记日志并 release，release 计一次失败，所以每次都 panic 的记录在第 5 次后终结为 `parsed_result_save_failed`；
- 每个出队的作业（`Notify`、扫描、`Submit`，两条写入路径都一样）从读审计行、claim 到保存最多 2 分钟。超时后以 `parse_deadline_exceeded` 记日志，并显式 release：在保存之前到期，或者保存的等待因到期而结束（这时 release 排在那次保存之后执行，保存已提交时 release 不改变任何东西，并按确认丢失的规则记 `backfillUnsure`）；claim 的等待到期时同样 release。期限打断不了不看 context 的计算，它限住的是每次等待存储，并在保存之前检查一次。保存之后的分析不受期限约束；worker 自己停止时仍把 processing 留给启动恢复。

保存使用 `SaveParsedAudit` 在一个 writer 操作内原子写入 parsed summary、turn graph、对象、raw retention 和完整性事件；保存点隔离保证它以局部错误（约束冲突、对象身份、turn 图或重建校验失败）失败时不会回滚同批采集；存储级错误仍按 writer 规则整批失败。保存失败后的 release 将失败次数持久化，前四次分别退避 30、60、120、240 秒并回到 pending；扫描和 claim 都检查到期时间，重复通知不能绕过退避，重启也不清空预算。第 5 次失败写入 `parse_status=error` 和 `parsed_results.error_code=parsed_result_save_failed`，保留 full raw，不再自动重试。错误摘要不保存底层错误文本，无法确定 parser 版本时标记为 `unknown`。迟到的 release 不改变已提交的成功结果。

如果数据库本身不可写，release 也可能失败；此时记录保留 processing，日志只记录 `parse_release_failed`。单 worker 在内存中保留最多 100 条待 release 的 audit，每 30 秒先重试 release，再扫描 pending；同一 audit 在 release 确认成功前不能重新 claim，积压达到上限时也不再 claim 新记录。一次扫描遇到 release 失败即结束本轮恢复，避免存储故障时集中重试。数据库恢复后无需重启即可恢复处理，失败次数和到期时间仍由既有 writer 事务维护；已提交但确认失败的 release 重试不会重复计数，也不会覆盖成功终态。进程退出后的 processing 仍由启动恢复重置。这类存储故障不能承诺成功持久化重试次数，但不会篡改已经完成的转发结果。

worker 生命周期取消导致的保存中止不计入写入失败预算，也不调用带计数的 release：保存可能尚未尝试，也可能已入队但等待 Ack 被取消。尚未完成的 processing 留给下次启动恢复，已经提交的终态保持不变；多次正常停机不会把同一条长耗时解析误判为永久保存失败。作业期限到期不同：它按上面的规则 release，计一次失败。

### 5.1 `Submit` 与终结器

unified 写入路径（模块 03 §13.8）在 `CommitAudit` 成功之后调 `Worker.Submit(job)`；`internal/app` 只在 unified 下把它装到审计管理器上，legacy 仍用 `Notify`。终结器就是这个 worker 的 goroutine，多了一种输入，不另起 goroutine：回填水位、`pendingReleases` 等状态只由它访问（`internal/parser/backfill.go`），另起一个会破坏“每条保存为 ok 或 partial 的解析都走到 analyze”这一不变式。

- **作业。** `parser.FinalizeJob`（即 `internal/parser/handover` 的 `Job`）是已提交 audit 的身份与终态，加可选的明文证据 `Evidence`。没有证据的是 id 作业，处理与 `Notify` 进来的 audit 完全相同，从库里读。会话什么时候只交 id 见模块 03 §13.8：终态被降级、起始行没有入站阶段、有块落过暂存、明文不完整或全局预算不够时。
- **明文的归属。** `Submit` 接管作业的明文；作业的 `Release` 恰好调用一次：被拒绝时、处理完之后，或 `Close` 时清掉 goroutine 没有处理到的作业时。它清零明文，并把这份明文占的内存预算还给审计管理器。
- **带证据的作业**（`finalize`）与 `process` 只差两处：不调 `LoadParserAudit`；`Input` 从证据构造（`inputFromEvidence`），不从库里读。claim 保留，因为 `SaveParsedAudit` 只更新 `processing` 的行；解析、normalization、准备、保存和分析是同一段代码（`parseClaimed`）。
- **从证据构造的 `Input` 就是库里那份。** Body 经同一个 `assembleBody`（§6 的每项检查：seq 与 offset 连续、解码上限、存储长度、行上的 SHA-256 和完整性），块来自会话的内存段；内容头按采集版本取：版本 2 对 Header 字段用 `headerblock.ContentHeaders`，也就是阶段行上两列的取值规则，版本 1 解密已加密的 `content-type`、`content-encoding` 行；白名单 Header 按同样的过滤与排序取，版本 2 过滤字段并清掉其余的值，版本 1 只解密选中的行；状态码取自提交的阶段行。`internal/parser/finalize_equivalence_test.go` 对夹具流量比较两种方式构造的 `Input`。
- **失败时。** 带证据的作业 panic、超时或保存失败，都按上一节 release，记录保持 pending，失败计数和退避照旧，之后由现有路径从库里解析。`retention_state` 不动，仍是 `pending`，不预先标 `full`。
- **顺序。** 只有一个 FIFO，id 作业也在其中，所以除了队列满退到扫描的记录以外，解析顺序就是各请求 `CommitAudit` 确认的顺序，与 `Notify` 的保证相同。退到扫描的记录可能被交接在它之后的记录超过，这在 legacy 下同样存在，而且 `Notify` 的上限更低。

## 6. 证据读取

parser 读取：

1. `request_for_newapi_received_from_nginx`；
2. `response_received_from_newapi`。

阶段缺失不能解释为空 Body。reader 会按 `source_stage` 读取 owning chunks，逐块验证 seq、offset、compression、GCM、明文长度和最终 SHA-256，再处理 HTTP `Content-Encoding`。这套检查在 `assembleBody` 里，块来源可以是库里的行，也可以是 §5.1 的内存段。

Header 按采集版本读（模块 09 §5.2）：

- **内容头。** 版本 1 由 `LoadParserStage` 读该阶段 `content-type`、`content-encoding` 的密文行再解密，各取第一个非空值；版本 2 直接读阶段行上的 `content_type`、`content_encoding` 两列，不打开块。回填判断 raw 状态时也走 `LoadParserStage`，所以版本 2 的回填扫描从不解密块。
- **白名单 Header**（洞察与项目标识用，`loadRequestHeaders` → `LoadParserHeaderSource`）。版本 1 在 SQL 里按小写名称过滤，只解密名单内的值；版本 2 取回整块，在进程内经 `headerblock.Expand` 打开，留下 `request_received` 中名单内的 Header，清掉其余的值。这是维护者接受的明文边界变化，见模块 09 §8。块打不开或不满足读取规则时整组丢弃，记 `request_headers_load_failed`，不降级解析状态。

当前单 worker 对每侧最多保留 64 MiB 解码后数据，encoded 上限为 128 MiB，gzip 最大解压比为 50:1。超过限额会得到稳定 `body_too_large`，parse 变为 partial/error，保留 full raw；不会截断后仍标记 verified。512 MiB 入站限制是代理/interceptor 的传输上限，不等同于 normalizer 内存上限。

## 7. OpenAI normalizer

OpenAI 请求拆分规则：

- Chat：envelope 移除 `messages`，每条 message 成为一个有序 item；
- Responses：`instructions` 与 `input` item 分离，保留 single/array/none 原布局；
- Completions：`prompt` 单值或数组分离；
- `previous_response_id`、conversation/thread/cache key 作为父轮次关联证据；
- `metadata` 中可能的 conversation/session 标识只用于域分离 hash，不进入普通日志。

非流式响应把 choices message/text 或 Responses output item 替换为受控 marker。SSE 响应按 §2.3 折叠成非流式 body（layout `openai.stream.response.v2`，parser 版本 3），envelope 保存事件描述、摘要和残留；不复制每个网络 chunk。parser 版本 2 写入的流（layout `openai.stream.response`，每个事件一个描述、展示用 message 作为聚合）按原方式读取。

provider 输入若包含保留 marker 名、畸形 JSON、错误 data URL/Base64、未知重建布局或重建 hash 不一致，normalizer 必须失败并保留 full raw。

Anthropic Messages 的拆分规则见[模块 07](07-anthropic-protocol-parser.md) §8，Gemini 的见[模块 08](08-gemini-protocol-parser.md) §8，失败语义与上一段相同。

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

有 verified turn 的记录的管理 conversation 由 query 层执行以下步骤后生成：

1. 恢复 request/response refs；
2. 解密并验证 content/binary objects；
3. 按原布局重建 provider JSON；
4. 比较 sequence/reconstruction SHA-256；
5. 再从重建 provider 值生成协议无关 conversation。

这样列表和详情不需要保存第二份消息正文。第 3 步按 `auditmodel` 的 layout 表执行，第 5 步由写入该 turn 的 parser 的适配器完成（`builtin.Registry().RebuildConversation` 按 parser 名查找，见 §2.1）。升级前写入、没有 turn graph 的记录（Anthropic 版本 2、Gemini 版本 2）从加密 parsed fallback 读取 conversation，full raw 仍是权威证据，读取方式不变。

## 10. 最少测试

- queue 满、pending scan、processing 恢复、panic 隔离、保存失败持久化退避及终态、release 暂时失败后不重启恢复、迟到 release 的幂等性。
- normalization panic 与作业期限：release 计入失败、第 5 次终结、保存后到期的 release 不改已提交的结果，两条写入路径都覆盖；失败后 `retention_state` 仍是 `pending`。
- `Submit`：从证据构造的 `Input` 与读库构造的相同；同一会话紧挨着结束的两轮，前一轮带明文、只交 id 或退到扫描时，后一轮都挂在它下面；明文的预算在作业完成后归还；终态被降级的提交只交 id；经 `Submit` 解析的记录同样进入回填水位；PostgreSQL 上带明文的解析不读任何阶段和块（`tests/integration`）。
- chunk 顺序、offset、压缩、GCM、SHA-256、gzip ratio 和 64 MiB 限额。
- OpenAI Chat/Responses/Completions JSON 与 SSE 摘要。
- developer/system/user/assistant/tool/reasoning/tool result 的顺序和 call id。
- provider JSON 请求与响应精确重建。
- layout 名、parser 名与版本钉住；每个 normalizer 写出的 layout 都已声明、可组装，且 conversation 重建已接到注册表（§2.1）。
- 流式保真（§2.3）：每个 normalizer 过保真夹具；每种已消费事件类型的未知字段、未知事件类型和未知 delta 类型在 raw 释放后仍可找回；残留超限时放弃并保留 raw；退役 layout 的旧行按捕获的夹具原样重建。
- data URL 解码字节去重、inline file data、`file_id` 外部引用。
- normalization/reconstruction 失败时四阶段 raw 保持 full 且可完整下载。
- verified OpenAI/Anthropic parsed JSON 不含第二份 conversation；无 normalizer 的协议仍能从加密 fallback 展示 conversation。
- parser/query/UI 不把敏感正文写入列表、日志或明文列。
