# 模块 18：内容寻址的对话、轮次与多模态审计存储

## 1. 目标

本模块把长期审计存储从“每个 HTTP 观察阶段保存一份完整 Body”改为以下四层：

1. HTTP audit 与四阶段元数据；
2. 可分支的 conversation/turn 图；
3. 内容寻址的文本、JSON、reasoning、工具调用和工具结果对象；
4. 按解码后原始字节寻址的图片、文件和附件对象。

普通成功请求只长期保留 Body 的原始长度、SHA-256、Content-Type、阶段状态、流式时间信息、语义重建哈希和防篡改链。raw 的保留按请求侧、响应侧分别决定（§6）：上游异常时，已通过重建校验且两个请求阶段一致的请求体同样只保留上述元数据，响应侧保留完整原始证据；被拦截、解析失败、重建验证失败或没有 turn 时，两侧都保留完整原始证据；两个请求阶段不完整或不一致时，请求侧也保留。

目标是在 Agent 连续对话反复携带完整历史时，让大对象增长由请求级近似 O(n²) 降为“唯一内容对象 + 每轮小增量”的近似 O(n)，同时避免把 SSE/network read 的小块各自写成 SQLite 行。

## 2. 不兼容边界

这是审计 schema 的不兼容换代，不迁移旧 audit 数据。新版本使用新的 schema generation；部署时清理旧数据库及 WAL/SHM 后创建空库。动态 User-Agent 规则属于配置数据，仍由当前 migration 创建默认规则。

代理路由、透明转发、调用者关联、UA 拦截语义和管理鉴权不因本模块改变。

## 3. 哈希与 canonicalization

所有内容地址使用 32-byte SHA-256，但不同对象必须使用域分离，禁止直接把裸 SHA-256 混在同一个命名空间：

~~~text
content object = SHA-256("llmapi-logger/content/v1\0" || canonical JSON)
binary object  = SHA-256("llmapi-logger/binary/v1\0"  || raw decoded bytes)
sequence       = SHA-256("llmapi-logger/sequence/v1\0" || ordered slot/hash refs)
reconstruction = SHA-256("llmapi-logger/rebuild/v1\0"  || canonical rebuilt value)
~~~

JSON 使用 `json.Decoder.UseNumber`，拒绝尾随第二个 JSON 值，再由标准 JSON encoder 生成键排序稳定的紧凑表示。对象 hash 在压缩和加密之前计算；随机 nonce 不参与内容地址。

一个内容对象的 occurrence 属性不得进入内容 hash，例如 request/response 方向、turn id、顺序号和阶段名称。相同 assistant/tool item 从上一轮响应进入下一轮请求时必须复用同一个对象。slot、方向和顺序只保存在 turn 引用中。

## 4. 多模态对象

### 4.1 data URL

遍历 request envelope、context item、response item 和逻辑 SSE event 中的字符串。匹配合法 `data:<media-type>;base64,...` 时：

1. 严格 Base64 解码；
2. 对解码后的原始字节计算 binary object hash；
3. 内容 JSON 中以受控 marker 替换原字符串；
4. binary object 只保存一次；
5. 重建时根据 marker、media type 和二进制对象重新编码为等价 data URL。

禁止只对 Base64 字符串做 hash，因为不同换行、padding 或编码形式可能表示相同二进制内容。

### 4.2 文件与附件

- `file_id` 等外部引用保留在 canonical item 中，并记录引用类型和 JSON pointer；代理没有读取到文件字节时不得伪造本地 binary object。
- `file_data`、明确的 Base64 附件或 data URL 中实际出现的文件字节按 binary object 保存。
- 一个 content object 到 binary/external object 的引用单独建表，既用于审计展示，也用于 retention 后的可达性清理。

## 5. 压缩与加密

顺序固定为：canonical plaintext -> 可选压缩 -> AES-256-GCM。

- 文本、JSON、SSE 逻辑事件集合和其他可压缩数据使用 gzip；只有压缩后确实变小时才标记 `gzip`。
- **压缩结果不是对象身份的一部分。** 同一份明文在不同编译产物下可以压出不同字节数——`compress/flate` 的 `BestSpeed` 策略随 Go 版本变化，升级工具链即可改变 `encoded_length`（解压结果不变，DEFLATE 只规定解码器）。因此 `compression` 与 `encoded_length` 只描述某一行是怎么存下来的，复用已有对象时不得拿它们判定冲突或损坏，否则一次工具链升级就会让旧库里的每个对象被误判。
- binary object 的压缩选择只依据原始字节 magic，不能信任 occurrence 的 MIME 标签，避免调用方用伪造标签影响压缩行为。存储表示不属于对象身份，同一 binary hash 可以复用其他编码器版本写入的对象。PNG、JPEG、GIF、WebP、ZIP、GZIP、PDF 等已压缩格式使用 `none`；未知格式只在试压缩确实节省空间时使用 gzip。
- AAD 绑定对象域、object hash、kind 和 compression；数据库只保存 `nonce || ciphertext || tag`。
- 原始异常证据也先按大块自适应压缩，再独立加密；不再把每个 32 KiB read 写成一行。
- 没有 verified turn 时存进 `parsed_results.parsed_json_enc` 的回退 conversation 同样先按需 gzip 再加密。该列没有 compression 元数据，靠解密后的 gzip magic 区分新旧两种形式；规则和解压上限见[模块 9](09-security-encryption-and-redaction.md) §5.1。

## 6. HTTP Body 观察与保留策略

四阶段在传输期间先各自采集。终结事务只在 request-received/request-sent 或 response-received/response-sent 都完整、chunk 聚合自洽且长度/hash 一致时，删除后一阶段重复 chunks 并改为引用前一 payload source。每个阶段仍保留自己的开始/结束时间、长度、hash、状态和错误；短写、取消或字节不一致保留两份 raw 并标记 `body_stage_mismatch`/partial。

采集缓冲按实际字节量惰性增长，上限约 1 MiB；即使单次 Read 返回更大的数据也按块处理。Body 结束时立即 flush 尾块并释放暂存容量，避免长 SSE 会话继续持有已结束请求阶段的缓冲。四个观察点仍独立采集，只有终结事务验证长度与 hash 一致后才合并。 同一 Session 在已有互斥锁内复用最多一个 raw/timeline gzip writer，各块仍是独立可解码流；终结采集后立即释放 writer。该 writer 不跨请求共享，私有压缩缓冲只属于当前会话，可能保留部分明文直到复用或 GC，不声称安全擦除。

flush 表示压缩、加密并向异步 writer 入队，不等于数据库事务已经提交，更不等于新增的 fsync 保证。进程崩溃可能丢失尚未 flush 的尾部，以及已经入队但仍未提交的块或批次；启动 recovery 将未完成记录标记 partial。FinishAudit 的同步完成屏障才确认终结事务处理完成，底层持久性仍服从数据库配置。

canonical Prepare 在同一轮内先以规范化明文 hash 去重，再压缩、加密；每个唯一对象仍检查 kind、明文长度和 semantic hash，完整请求/响应仍做重建校验。一个 Prepare 最多惰性创建一个 gzip writer，在对象之间 Reset，返回时解除输出引用并丢弃，不使用跨请求全局池。Reset 保证独立压缩流但不是安全擦除；压缩器私有缓冲可能保留明文直到覆盖或 GC。编码字节、压缩大小和随机 nonce 不参与对象身份，不能因 Go/codec 版本变化而把同一明文误判为冲突。

跨轮次复用采用一次批量 lookup（数据库内部按参数上限分批），不逐对象往返查询。当前请求仍完整规范化、计算 hash 并校验重建，再读取已存在对象的密文与身份元数据。命中必须通过 AEAD/AAD、kind、semantic hash、明文/编码长度及完整逐字节比对；gzip 必须读到 EOF 并通过校验和，不能只信存在标志。验证后复用原压缩格式与密文，未命中才压缩加密。数据库查询失败或任何损坏都中止 normalized turn，不能静默退化为可信命中。验证 decoder 同样限于单次 Prepare，使用 32 KiB 暂存比较缓冲，没有全局明文缓存。

写入时只发送库里还没有的对象。lookup 在事务开始前走读连接，retention 的对象 GC 可能在这之间删掉未被引用的对象，因此是否已存在由 writer 事务自己判定：按 hash 分批（每批 400 个）查询 `content_objects`、`binary_objects` 和已存在对象的 `content_binary_refs`、`content_external_refs`，只取键和身份列，不取 `data_enc`、`value_enc`。GC 与对象写入都在同一个 writer 上执行，事务内读到的结果在提交前不会变，不需要行锁。已存在的行按原规则核对身份（content 为 `semantic_hash`、`kind`、`plaintext_length`；binary 为 `media_type`、`plaintext_length`；binary 引用为 `media_type`、`encoding`；external 引用为 `value_hash`），不一致按存储对象完整性故障处理，已存在的行不改写。缺失的对象和引用行用多行 INSERT 写入，每条最多 400 行、对象密文合计约 4 MiB；对象还在而引用行缺失时补写该行。所以一轮引用 N 个已存在对象时，往返次数只随批数增长，不再随 N 增长，也不再把整段上下文的密文发回数据库。

`retention_state`：

| 状态 | 含义 |
| --- | --- |
| pending | 等待 parser/normalizer 和重建验证，raw chunk 暂存 |
| metadata | 该侧已由 verified turn 覆盖；删除 raw chunk，只保留长度/hash/类型/时间/链 |
| full | 异常证据；保留可认证解密的完整 raw chunk |

保留状态按侧决定。请求侧是 `request_for_newapi_received_from_nginx` 和 `request_sent_to_newapi`，响应侧是另外两个阶段；同一侧的两个阶段状态相同。释放一侧时删除该侧的 chunks（合并后它们属于 `source_stage` 指向的那个阶段，合并不跨侧），并把该侧两行的 `stored_length`、`chunk_count` 置 0。判定规则是 `internal/storage` 的 `DecideRawRetention`，PostgreSQL 与 SQLite 两个存储调用同一个函数：

1. 没有 verified turn，或解析结果不是 `ok`：两侧都 `full`。这包括 interceptor 拒绝、解析 error/partial/skipped、内容编码不支持、超过解码上限、binary/data URL 解码失败、normalization 或重建失败、对象写入失败；也包括 turn 已准备好、但解析结果在保存前因加密失败降为 error 的记录。
2. 正常结果（forward `completed`、capture `complete`、状态 2xx/3xx）：两侧都 `metadata`。
3. 其余结果：响应侧一律 `full`。请求侧只有同时满足下面三条才 `metadata`，否则 `full`：
   - turn 重建出了请求（request layout 不是 `none`）。重建校验比较的是重建结果与解码后 `request_for_newapi_received_from_nginx` Body 的 canonical JSON 哈希，再加上落库后请求序列哈希的复读比较。它保证语义 JSON 一致，不复原键序、空白和 Content-Encoding，与普通成功请求释放 raw 时得到的保证相同；
   - `request_sent_to_newapi.source_stage = request_for_newapi_received_from_nginx`：两个请求阶段长度与 SHA-256 一致并已合并，两个阶段都是 `complete`，没有 `body_stage_mismatch`。不一致时两份请求 raw 都保留；
   - 结果在下表中为“释放”。

| 结果 | 请求侧 |
| --- | --- |
| 5xx | 释放 |
| 401、403、408、409、429、499 | 释放 |
| 400、422，`upstream_error_class` 非空 | 释放 |
| 400、422，`upstream_error_class` 为空 | 保留：可能是请求本身畸形，需要逐字节检查 |
| 客户端中途取消（forward `client_cancelled`），没有状态码或状态为 2xx/3xx | 释放 |
| 402、404、405、413、415 等其他非 2xx/3xx 状态 | 保留（待维护者确认） |
| 2xx/3xx 但 forward 或 capture 异常（不是客户端取消）；没有状态码且不是客户端取消 | 保留（待维护者确认） |

保留优先于取消：客户端在一个上表判为保留的状态之后取消，请求侧仍保留。表中“待维护者确认”的两行是设计 5.9 没有点名的情形，问题已提交维护者；在答复之前按原规则保留请求 raw，不丢任何证据。答复只需改 `abnormalRequestRelease` 里的一行。

没有 turn 的异常记录（例如客户端在流中途断开、响应不完整）两侧都保留 `full`，“只有请求的轮次”另行实现。

`upstream_error_class` 是不签名的派生列，判定只在保存解析结果时读取一次；之后改写该列不影响已定的保留状态。每一侧的 `retention_state` 进入 `semantic_compacted` 事件的摘要，新行按写入时的状态签名，摘要格式、schema 和约束都不变。按旧规则写入的异常记录四个阶段都是 `full`，不迁移、不改写，照常通过校验和读取。回滚到旧二进制时，它能照常读取按新规则写入的行（`metadata` 一侧按已释放处理），但这些记录已经没有请求 raw 可以返回，只能下载响应 raw 或读取重建请求。

## 7. conversation 与 turn 图

每个 audit 最多生成一个 turn。turn 保存：

- conversation id；
- 可空 parent turn；
- parent base（父请求上下文或父请求上下文 + 父响应 items）；
- parent link reason/confidence；
- request/response envelope object；
- request context 的增量操作；
- response item 的有序引用；
- request/response sequence hash、重建 hash和验证状态；
- response id、previous response id、模型参数、usage、错误和时间信息。

父轮次优先按协议显式字段关联，例如 `previous_response_id`，命中即链接。其次使用稳定 conversation/thread key 的域分离 hash；没有显式 id 时，只在最近候选中存在强内容关系时使用 item sequence 推断；证据不足则创建新根轮次（无 key 时即新 conversation），禁止为了形成线性链而强行关联。

Anthropic Messages 的 key 取客户端声明的会话 ID（`insights.DeclaredSessionID`：`metadata.session_id`/`conversation_id`/`thread_id`，或 Claude Code 放在 `metadata.user_id` 里的会话 ID）。`metadata.user_id` 本身标识的是用户而不是会话，只有用户 ID 时不作 key，否则一个用户的全部会话会并进同一个 conversation；这类请求走上一段末尾的内容推断，规则与无 key 的 OpenAI 请求相同。Anthropic 的 conversation 用于主列表的折叠、筛选和轮次计数；[模块 20](20-context-insights.md) 的会话归属不使用它（`insights.Link` 只对 OpenAI 采用 turn conversation），Anthropic 记录在洞察中的会话规则不变。

conversation key 只确定“属于哪个客户端会话”，不确定“接在哪一轮后面”。OpenAI 的 key 依次取 `conversation_id`、`conversation`/`conversation.id`、`prompt_cache_key`、`thread_id`、`metadata.*`。上游托管的会话 ID 排在前面，因为多个托管会话可能复用同一个 `prompt_cache_key`。而 Codex 会把根会话 ID 同时填进主 Agent 与所有子 Agent 的 `prompt_cache_key`，OpenCode ≥ v2.0.10 则把直接父会话 ID 填进子 Agent 的 `prompt_cache_key`，所以同一 key 下可能并发跑着多条 Agent 链。

服务端托管上下文的请求是例外。这类请求带顶层 `conversation_id`、`conversation` 或 `conversation.id`，上游会把已存的会话 items 拼在前面，请求本身只含新输入，内容无法证明父子关系。所以这类请求仍按命中 key 直接挂到该 conversation 中早于本轮的最新一轮，原因 `conversation_key`、置信度 95。只带其中一种字段的请求，key 的取值与 hash 不变，已有 conversation 照常命中。同时带 `conversation` 和 `prompt_cache_key`（或 `thread_id`）的请求，修正后改用 `conversation` 作 key。升级后，这类会话的下一轮会在新的 keyed conversation 中成为新根，之前的轮次留在按 cache key 分组的旧 conversation 里，重建不受影响。

其余 key（`prompt_cache_key`、`thread_id`、`metadata.*` 等）只用于分组，客户端会自行重发上下文。命中这类 key 后：

- 候选是该 keyed conversation 中早于本轮的最近 32 轮（`parentCandidateLimit`），不只是最新一轮。
- 每个候选都要通过与无 key 推断相同的强内容关系判定（retry、continuation 或 ≥70% 公共前缀的 context edit），在通过者中选 delta 代价最小的，代价相同取较新的。链接原因记为 `conversation_key`，置信度 95；retry/branch 的判定照旧覆盖原因。
- 都不通过时，本轮成为同一 keyed conversation 中的新根，例如子 Agent 的首个请求，或一次把历史大幅改写的压缩。该 key 的首轮也一样：没有候选就新建以该 key 命名的 conversation 并作为根。带 key 的轮次从不走全协议范围的内容搜索，否则可能被挂进别的会话并丢掉 key，后续同 key 的轮次就找不到它了。
- 所以一个 keyed conversation 可以有多个根，每个 Agent 一条链。conversation 计数仍按整个客户端会话统计，即主 Agent 加子 Agent。`conversations` 上 `(protocol, key_hash)` 的唯一索引决定了同一 key 只能对应一个 conversation。

内容判定仍无法区分“子 Agent 的首个请求”与“对父 Agent 早期请求的编辑”。若两者共享的前缀足够长（≥70%），子 Agent 首轮会作为 branch 挂在父 Agent 的那一轮下面。重建不受影响，只是血缘表现为分叉。要彻底按 Agent 分链，需要把显式 Agent 节点 ID（如 Codex 的 `thread-id` Header）引入 conversation key。但 normalizer 目前只拿得到 Body，这一项留作后续。

修正前写入的旧行不做迁移。它们保留当时强制挂到最新一轮的 `conversation_key` 血缘，可能把父子 Agent 交错串成一条链；每轮的 delta 自包含于其 parent base，重建和完整性校验仍然逐字节正确。父轮次的选择不参与 `capturePayloadDigest` 和 `appendParsedResultDigest`；`parent_turn_id`、`link_reason` 也不进入 semantic payload digest，新旧行都能通过既有校验。

同一 parent 可有多个 child。retry 可以选择父 request 作为 base；普通 continuation 通常选择父 post-turn context；回退、修改、上下文截断和总结压缩通过 delete/insert 增量表示。并行工具调用保留 item 顺序和 call id，不要求对话是单链。

conversation id 作为查询维度暴露给[模块 10](10-query-api-and-minimal-web-ui.md) 的列表 API 和 React UI：列表可按 conversation 精确筛选或用唯一合法值 `collapse=conversation` 按 conversation 折叠展示，其他 `collapse` 值返回 `400 invalid_query`，但这只是查询层的过滤/展示逻辑，不改变本模块的存储或重建语义。开发者会话下的折叠代表记录与轮次计数均只覆盖该 API Key 的 scope。

## 8. 增量序列

request context 不为每一轮重复保存完整引用列表，而保存把 parent base 转换为当前 context 的操作：

~~~text
retain N
delete N
insert slot + content_object_hash
~~~

根轮次由一组 insert 构成。实现先保留公共前缀和后缀，对中间区域做有界 diff；输入过大时退化为单次 delete + insert，始终保证可重建正确性，优化程度不能影响正确性。

response item 只属于当前轮，按 ordinal 保存引用。下一轮若把它们带回 request，内容对象复用，request delta 通常只增加新的 user/tool item。

## 9. 重建与验证

重建任意 turn 时：

1. 沿 parent 指针取得 base sequence；
2. 严格应用本轮 retain/delete/insert；越界、缺对象或顺序错误立即失败；
3. 解密并解压 envelope/content object；
4. 按 slot 恢复 `messages`、`input`、`instructions`、`system`、`output`、`content` 或 choice message；
5. 按 binary marker 读取二进制对象并恢复 data URL/附件；
6. 计算 sequence/reconstruction hash，与 turn 保存值常量时间比较；
7. 生成管理 UI 的协议无关 conversation，并保留原始 provider item 供受保护详情读取。

parser 只有在上述验证通过后才允许把 raw retention 从 pending 改为 metadata。验证失败必须写稳定错误码、保留 full evidence，并追加完整性事件。

## 10. 流式响应

网络 read/write chunk 只用于临时采集，不作为长期事件模型。成功 SSE 响应保存：

- 折叠体：normalizer 把全部事件折叠成该端点的非流式响应 body，作为唯一的 `aggregate` item（content object）。同一回答流式与非流式得到的 conversation 相同；
- 残留（residue）：事件里折叠体给不回来的内容，见下；
- 事件描述与摘要，放在响应 envelope 里。事件描述是紧凑形式：事件名的游程编码、data 长度序列和一个按顺序覆盖全部事件名与 data 的 SHA-256（定义见模块 05 §2.3），不再为每个事件存一个 SHA-256；整条 Body 的字节另有 `body_streams.sha256`；
- TTFT、首事件、末事件、事件数量；
- 必要时保存 delta 编码的事件时间/字节偏移 timeline，而不是每个 token 一行。

**raw 释放后不丢内容。** 每个协议在模块 06、07 列出折叠器消费的事件类型和各类型读取的字段。下列内容进入 envelope 的 `residue` 数组：清单外的事件（整条 data），已消费事件里折叠器不读的字段，以及折叠体装不下的值（例如被后一事件覆盖的旧值、与折叠体不一致的 delta）。判断某个值是否已由折叠体持有的规则见模块 05 §2.3。`residue` 的格式：

~~~json
[
  {"index": 0, "data": {"message": {"usage": {"output_tokens": 1}}}},
  {"index": 4, "count": 3, "data": {"obfuscation": "..."}},
  {"index": 9, "text": "not json"}
]
~~~

- `index` 是事件在流中的序号（从 0 起，按模块 05 §2.3 的 SSE 解码规则计）；`count` 表示从 `index` 起连续 `count` 个事件的残留相同，省略时为 1；
- `data` 只含该事件留下的字段，嵌套位置照原样，数组写成以元素下标（十进制字符串）为键的对象，只列有残留的元素；整条保留的事件，`data` 就是它的完整 JSON；
- data 不是 JSON 的事件以 `text` 保存原文（必须是 UTF-8）；
- 没有残留时不写 `residue` 键。

残留有上限：canonical JSON 超过 1 MiB 的流不释放 raw。normalizer 放弃这条流，走既有的 `normalization_failed` 路径：解析记为 `partial`，四阶段 raw 保持 `full`，conversation 存回退副本（模块 05 §2.3）。

因此可以复原输出、事件次序和每个事件的全部字段值，但不宣称恢复 TCP frame、HTTP chunk framing、完全相同的 SSE 空白格式、delta 的切分边界，或 JSON 的键序与空白（与所有 content object 一样按 canonical JSON 保存）。SSE 注释行和 `id:`、`retry:` 字段在解码时即被忽略，不在保存范围内。

重建响应（模块 10 §5 的 `reconstructed/response`）的形状是：`format`（`sse`）、`events`、`summary`、可选的 `residue`，以及 `aggregate`（折叠体）。OpenAI parser 版本 2 写入的旧行（layout `openai.stream.response`）没有 `residue`，`aggregate` 是展示用的 message 数组，按原方式读取。

## 11. 防篡改链

使用从 audit 主密钥域分离出的 HMAC-SHA-256 key 创建 append-only integrity events。每个 event 绑定：

- 上一个 event MAC；
- audit id 和 event type；
- 捕获元数据/body hash 或语义 turn/object/重建 hash 的 canonical digest；
- event 时间。

至少写 `capture_finalized` 和 `semantic_compacted` 两类事件。启动时验证链；验证失败使审计存储 not-ready。该链能检测 DB 内事件或 digest 被修改以及中间事件被删除，但数据库尾部截断仍需要外部备份/锚点才能完全证明。

## 12. SQLite 表

新 schema 的审计主体包括：

| 表 | 用途 |
| --- | --- |
| audit_records | 请求终态、调用者状态、TTFT 与整体状态 |
| http_stages/http_headers | 四阶段元数据和加密 Header/Trailer |
| body_streams/body_chunks | Body hash/保留状态，以及 pending/full 的大块原证据 |
| parsed_results | 仅窄摘要列，不再复制完整 conversation |
| content_objects | canonical 文本/JSON/item/envelope 的压缩加密对象 |
| binary_objects | 解码后图片、文件和附件原始字节 |
| content_binary_refs/content_external_refs | 多模态与外部文件引用 |
| conversations/turns | 可分支对话图和轮次元数据 |
| turn_context_ops | 父上下文到当前请求上下文的增量 |
| turn_response_items | 当前响应 item 的有序引用 |
| stream_timelines | TTFT/事件数量和压缩时间线 |
| integrity_events | HMAC 防篡改链 |
| token_links/audit_gaps/user_agent_rules/content_policy_rules | 保持既有/独立职责 |

retention 删除 audit/turn 引用后，在同一 writer 事务中删除已不可达 content object，再删除已不可达 binary object。任何 GC 都必须以外键和 NOT EXISTS 可达性检查为准，不能依赖可能失真的手工 ref_count。

## 13. 发布门禁

本模块在生产切换前必须通过：

- OpenAI Responses/Chat Completions 与 Anthropic Messages 的 JSON 与 SSE 单元/集成测试；
- data URL 按解码字节去重、外部 file id 保留、已压缩二进制不重复 gzip；
- 复用由另一套编码器产物写入的既有对象（`compression`/`encoded_length`/`data_enc` 整体不同而明文一致）不被判为冲突，两轮保存后每个对象仍可 `OpenObject`/`OpenBinary` 打开且完整性 payload 校验通过；
- 身份字段（content 的 `kind`/`plaintext_length`/`semantic_hash`，binary 的 `media_type`/`plaintext_length`）被逐一篡改时，再次保存同一内容必须报冲突并整体回滚；
- 连续、retry、truncate、edit、summary、rollback、parallel tools 和 branch 重建测试；
- 任意轮 turn reconstruction hash 校验；
- 异常自动保留 full evidence、普通成功清除 raw chunk；
- 同一 HTTP Body 的双阶段终结去重，以及长度/hash 不一致时各自保留的测试；
- 内容对象/二进制对象/增量操作的容量基准；
- DB/WAL、Git diff、构建产物和日志脱敏扫描；
- 前端、Go test、vet、CGO=0 构建和本地容器 smoke test。

生产清库、部署、Git commit/push 必须在本地验收结果提交给维护者并获得明确批准后执行。
