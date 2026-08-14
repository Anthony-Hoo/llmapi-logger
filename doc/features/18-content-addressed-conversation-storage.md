# 模块 18：内容寻址的对话、轮次与多模态审计存储

## 1. 目标

本模块把长期审计存储从“每个 HTTP 观察阶段保存一份完整 Body”改为以下四层：

1. HTTP audit 与四阶段元数据；
2. 可分支的 conversation/turn 图；
3. 内容寻址的文本、JSON、reasoning、工具调用和工具结果对象；
4. 按解码后原始字节寻址的图片、文件和附件对象。

普通成功请求只长期保留 Body 的原始长度、SHA-256、Content-Type、阶段状态、流式时间信息、语义重建哈希和防篡改链。被拦截、采集不完整、解析失败、上游异常或重建验证失败时，升级为完整原始证据保留。

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

- 文本、JSON、SSE 逻辑事件集合和其他可压缩数据使用确定性 gzip；只有压缩后确实变小时才标记 `gzip`。
- binary object 的压缩选择只依据原始字节 magic，不能信任 occurrence 的 MIME 标签，否则相同 binary hash 可能得到不同存储表示。PNG、JPEG、GIF、WebP、ZIP、GZIP、PDF 等已压缩格式使用 `none`；未知格式只在试压缩确实节省空间时使用 gzip。
- AAD 绑定对象域、object hash、kind 和 compression；数据库只保存 `nonce || ciphertext || tag`。
- 原始异常证据也先按大块自适应压缩，再独立加密；不再把每个 32 KiB read 写成一行。

## 6. HTTP Body 观察与保留策略

四阶段在传输期间先各自采集。终结事务只在 request-received/request-sent 或 response-received/response-sent 都完整、chunk 聚合自洽且长度/hash 一致时，删除后一阶段重复 chunks 并改为引用前一 payload source。每个阶段仍保留自己的开始/结束时间、长度、hash、状态和错误；短写、取消或字节不一致保留两份 raw 并标记 `body_stage_mismatch`/partial。

采集块固定合并到约 1 MiB 后再压缩、加密并提交。Body 结束时立即 flush 尾块；进程崩溃最多损失尚未 flush 的尾部并由 recovery 标记 partial。

`retention_state`：

| 状态 | 含义 |
| --- | --- |
| pending | 等待 parser/normalizer 和重建验证，raw chunk 暂存 |
| metadata | 普通成功请求已验证；删除 raw chunk，只保留长度/hash/类型/时间/链 |
| full | 异常证据；保留可认证解密的完整 raw chunk |

升级为 `full` 的条件至少包括：interceptor 拒绝、forward/capture 非完整成功、非 2xx/3xx HTTP 结果、解析 error/partial/skipped、内容编码不支持、binary/data URL 解码失败、对象写入失败、重建 hash 不一致和完整性链失败。

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

父轮次优先按协议显式字段关联，例如 `previous_response_id`。其次使用稳定 conversation/thread key 的域分离 hash。没有显式 id 时，只在最近候选中存在强内容关系时使用 item sequence 推断；证据不足则创建新 conversation，禁止为了形成线性链而强行关联。

同一 parent 可有多个 child。retry 可以选择父 request 作为 base；普通 continuation 通常选择父 post-turn context；回退、修改、上下文截断和总结压缩通过 delete/insert 增量表示。并行工具调用保留 item 顺序和 call id，不要求对话是单链。

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
4. 按 slot 恢复 `messages`、`input`、`instructions`、`output` 或 choice message；
5. 按 binary marker 读取二进制对象并恢复 data URL/附件；
6. 计算 sequence/reconstruction hash，与 turn 保存值常量时间比较；
7. 生成管理 UI 的协议无关 conversation，并保留原始 provider item 供受保护详情读取。

parser 只有在上述验证通过后才允许把 raw retention 从 pending 改为 metadata。验证失败必须写稳定错误码、保留 full evidence，并追加完整性事件。

## 10. 流式响应

网络 read/write chunk 只用于临时采集，不作为长期事件模型。成功 SSE 响应保存：

- 聚合后的 assistant/reasoning/tool output items；
- 内容对象中的有序 event descriptors（事件名、数据长度和 SHA-256）及聚合终态，用于语义复核；不额外复制每个 event payload；
- TTFT、首事件、末事件、事件数量；
- 必要时保存 delta 编码的事件时间/字节偏移 timeline，而不是每个 token 一行。

因此可以复原输出和事件次序，但不宣称恢复 TCP frame、HTTP chunk framing 或完全相同的 SSE 空白格式。

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
| token_links/audit_gaps/user_agent_rules | 保持既有职责 |

retention 删除 audit/turn 引用后，在同一 writer 事务中删除已不可达 content object，再删除已不可达 binary object。任何 GC 都必须以外键和 NOT EXISTS 可达性检查为准，不能依赖可能失真的手工 ref_count。

## 13. 发布门禁

本模块在生产切换前必须通过：

- OpenAI Responses/Chat Completions 的 JSON 与 SSE 单元/集成测试；
- data URL 按解码字节去重、外部 file id 保留、已压缩二进制不重复 gzip；
- 连续、retry、truncate、edit、summary、rollback、parallel tools 和 branch 重建测试；
- 任意轮 turn reconstruction hash 校验；
- 异常自动保留 full evidence、普通成功清除 raw chunk；
- 同一 HTTP Body 的双阶段终结去重，以及长度/hash 不一致时各自保留的测试；
- 内容对象/二进制对象/增量操作的容量基准；
- DB/WAL、Git diff、构建产物和日志脱敏扫描；
- 前端、Go test、vet、CGO=0 构建和本地容器 smoke test。

生产清库、部署、Git commit/push 必须在本地验收结果提交给维护者并获得明确批准后执行。
