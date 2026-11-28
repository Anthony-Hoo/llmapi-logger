# 模块 03：审计会话与证据采集

## 1. 目标

一次命中明确 LLM API route 的请求对应一个 audit。NewAPI health、login、admin、models、UI 和其他安全非 LLM 请求即使经本程序 passthrough，也不进入本模块。会话按实际执行路径接收最多四阶段 Header/Trailer/Body，计算长度与 SHA-256，聚合大块原始证据并记录逻辑 SSE 时间；只有到达可解析终态的转发请求才触发异步 parser/normalizer。

固定阶段名称如下，但记录按触发惰性创建：

1. request_for_newapi_received_from_nginx
2. request_sent_to_newapi
3. response_received_from_newapi
4. response_from_newapi_sent_to_nginx

被入站 interceptor 拒绝的请求通常只有第一个阶段；未调用 NewAPI 时不得预建后三个空阶段。本模块不负责 HTTP 转发和 SQL 实现。

## 2. ID 与状态

audit_id 为 crypto/rand 生成的 16-byte 随机值，编码为 apx_ 加 26 位 Base32。随机源失败时 available 继续并写无 ID 日志，strict 返回 503；禁止 math/rand 或时间戳回退。

audit_records 使用简化状态：

| 字段 | 值 |
| --- | --- |
| forward_status | in_progress、completed、rejected、client_cancelled、newapi_error、proxy_error、interrupted |
| capture_status | pending、complete、partial、failed |
| parse_status | pending、processing、ok、partial、error、skipped |
| stage state | not_started、streaming、complete、partial |

状态只能向终态前进，Finish 用 sync.Once 保证幂等。

## 3. 会话结构

~~~go
type Session struct {
    AuditID string
    Mode    Mode
    RouteID string
    Started time.Time
    BlockedBy string
    BlockCode string
    Stages  map[Stage]*StageCapture
}
type StageCapture struct {
    State          StageState
    ObservedLength int64
    StoredLength   int64
    Hash           hash.Hash
    HashComplete   bool
    NextSeq        int64
    NextOffset     int64
}
~~~

Session 持有阶段状态、hash、最多 100,000 个逻辑 SSE 时间点，以及内存预算以内的 Body 明文，直到写库为止（§13，超出预算的部分加密落本地暂存）；Stages 是稀疏 map，只包含已经触发的观察点。

## 4. interceptor 拒绝终态

route match 后先建立 audit 并记录已看到的入站 metadata，再执行 interceptor chain。首个主动 reject、body 上限拒绝、模块 error、panic、非法 Decision 或非客户端取消的 Body 读取失败，都以一次原子的终结提交（`CommitAudit`）写入以下结果：

- forward_status=rejected。
- blocked_by 保存配置中的 interceptor id；框架自身在无法归属模块时使用 `interceptor_chain`。
- block_code 保存稳定、低基数代码，不保存 error 文本、Header、Query 或 Body。
- status_code 保存代理实际返回的 4xx 或 503。
- parse_status=skipped，不入 parser queue。

模块主动 reject 使用其约定的安全 4xx；body 超限固定为 413 和 `body_too_large`。error、panic、非法 Decision 和非客户端取消的 Body 读取失败固定为 503，并分别使用 `interceptor_error`、`interceptor_panic`、`interceptor_invalid_decision`、`interceptor_body_read_error`。这些 fail-closed 行为与 available/strict 无关。客户端取消使用 forward_status=client_cancelled，不设 blocked_by/block_code。blocked_by/block_code 只对 rejected 非空，普通 NewAPI 4xx/5xx 仍是实际转发结果，不能误标为 rejected。

**终止事件后的断开视为完成，而非取消。** Codex 等客户端在收到流的协议级终止事件（`data: [DONE]`、`event: response.completed` 等）后会立即关闭连接、不读到传输层 EOF，这会取消请求 context 并撕掉上游读取。判定规则：当响应已完整接收（传输层 EOF，或已派发完整的终止 SSE 事件——只在事件的终止空行到达后确认，`event:` 行本身只算候选），且接收长度满足已声明的 Content-Length，且 response_sent 阶段已把全部接收字节写给客户端（无 `body_write_error`、写出长度不小于接收长度）时，其后的客户端断开按 forward_status=completed 收尾，接收 body 以逻辑 EOF 封口，解析与轮次重建照常进行；不满足上述任一条件的断开仍是 client_cancelled。采集内部故障（落盘、加密失败）不改变这一传输层分类，只体现在 capture_status。终止事件的识别由 parser 层的 `internal/parser/streamterminal` 按协议提供匹配器，采集层只消费不解释：匹配基于逐行有界探针（48 字节，逐行清零、不落盘），超长行永不匹配。探针读的是上游原始字节，因此审计路由固定向 NewAPI 请求 `identity`（见 02 的 Rewrite 规则）；若上游仍然返回 content-encoded 的流，则不做识别、保持原取消分类，而不是在读不懂的字节上封口。投递失败由 body 上独立的 writeFailed 标志判定，不复用会被落盘、加密失败覆写的 error_code。

stage、body_stream 和 chunk 只在真实观察开始时创建。没有调用 NewAPI 时，request_sent_to_newapi 及两个响应阶段必须不存在，而不是保存 not_started 空行。metadata reject 不为审计而 drain 入站 Body；若存在未读 Body，则第一个阶段和 capture_status 标 partial。body interceptor 已预读到 EOF 且证据成功落盘时，拒绝本身不导致 capture_status=partial。未触发的后三阶段也不计为采集缺失。

## 5. Body 采集

Observe 顺序固定：

1. 增加 observed_length 并更新 SHA-256。
2. 按 1 MiB 的块网格保留明文，在单阶段和全局预算之内留在内存里，超出的封好落暂存（§13.3、§13.4）；Body 终结时结束尾块。
3. 检查点或终结提交写这些块时，按 Content-Type 和 magic 自适应 gzip；已压缩二进制保持 `none`。
4. 每块独立 AES-GCM 加密（`sealChunkLocked`）。
5. 随那次写交给 writer；失败的处理见 §13.2、§13.5。

第 1 步和 SSE 时间、终止事件探针、写失败标志是观察层；第 2 到 5 步是保留层（`internal/audit/retain.go`）。块的格式、边界和 AAD 与已删去的 legacy 路径逐块写入时相同，所以两者写下的块行一样。

只有观察到 EOF 时 hash_complete=true；唯一例外是上节的逻辑 EOF——响应已完整接收且全部写给客户端后的客户端断开按 EOF 封口，此时 hash 覆盖完整 body。除此之外，取消、Read/Write error 或进程退出时，hash 只代表已观察前缀。seq/offset 是应用层采集顺序，不是 TCP 或 HTTP chunk。SSE 另外按完整逻辑 event 记录结束 offset 和时间；总事件超过 100,000 时停止追加时间点，但继续统计实际 event count。

成对阶段在内存里判定（§13.3）；少数情形留给终结事务在库里合并：只有在成对阶段都完整、各自 chunk 聚合自洽、observed/stored length 相等且 SHA-256 完全一致时，才删除后一阶段的重复 chunks，并把其 `body_streams.source_stage` 改为前一阶段（已删去的 legacy 路径对每一对都这样做）。若长度或 hash 不一致，后一阶段标记 `body_stage_mismatch`/partial，两个阶段的原始字节都保留，不能因预先共享掩盖短写、取消或代理改写错误。

body interceptor 按 route 中最大的模块上限加一个判定字节有界预读，且必须通过 request_for_newapi_received_from_nginx observer，因此它仍计算入站长度/hash并保存原始字节。多个模块共享同一只读缓存；放行时 proxy 使用未修改的缓存字节重建 Body，request_sent_to_newapi observer 再记录实际 replay；两阶段差异视为实现错误。metadata-only chain 不触发预读，继续由 Transport 的正常流式读取驱动两个请求 observer。

## 6. Header、Trailer 与 URI

http_headers 每个值保存 audit_id、stage、kind、name、value_index、value_length、value_enc。重复值不合并；Host、Method、Status、HTTP 版本和 ContentLength 放 http_stages。

Request-URI 可能包含 key，保存在 audit_records.request_uri_enc。无法保证 Header 原始大小写、全局线缆顺序或 request Trailer 经 Nginx 后仍存在。

以上是采集版本 1。PostgreSQL 上会话写采集版本 2：一个 audit 的全部 Header 和 Trailer 编成一段明文，压缩加密为一个块（`http_header_blocks`），另有单独加密的入站 User-Agent（`audit_records.user_agent_enc`）和阶段行上的 `content_type`、`content_encoding`。会话在阶段开始时深拷贝该阶段的 Header，在 Trailer 到达时拷贝 Trailer；名称和值按逐值写行的同一个循环取（`headerblock.Snapshot`）。格式、读取规则和明文边界见模块 09 §5.2、§8。SQLite 存储只写版本 1；已删去的 legacy 写入路径在 PostgreSQL 上写的也是版本 1，这些旧行照常读取和校验。

## 7. AES-256-GCM

key_path 指向一个 32-byte 主密钥：存在则读取；不存在且数据库既没有 audit 记录也没有完整性事件时用 crypto/rand 原子生成（规则见[模块 09](09-security-encryption-and-redaction.md) §3）。Unix 创建权限为 0600；Windows 使用当前用户私有数据目录的 ACL。

每个 Header 值、压缩后的 Body chunk、Request-URI、parsed result、content/binary object 和 stream timeline 使用独立 12-byte 随机 nonce：

~~~go
ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
~~~

数据库把 `nonce || ciphertext || tag` 保存为一个 BLOB。AAD 使用 NUL 分隔的受控字段：Request-URI 绑定 audit id/object type；Header 再绑定 stage/kind/name/value index；Body chunk v2 再绑定 owning stage/seq/compression；解析结果绑定 audit id/parser name。内容对象、二进制对象和 timeline 使用各自域分离 AAD。调用方不得自行定义其他格式。

首版只使用这个本地主密钥，不提供多层密钥、轮换或重写工具。需要更换时先完整备份旧数据库和旧 key，再创建新的空数据库和 key。

## 8. Writer 接口与模式

采集只提交 BeginAudit、Checkpoint、CommitAudit 和 AddGap（§13.2）。存储仍保留逐操作的 StartStage、AddHeaders、AddChunk、FinishStage、FinishAudit（SQLite 的 Checkpoint 和 CommitAudit 由它们组成，版本 1 夹具和离线导入也用它们），但没有会话再发出它们。parser 使用 SaveParsedAudit 原子写摘要、turn graph、对象、raw retention 和完整性事件。queue 固定 1024 ops。

Session 通过 `CommitAudit` 获取提交后的实际 capture status/error code，再生成不可变的 TerminalSummary。被保存点隔离或整批存储故障丢弃的采集写入，必须在终结事务前标记对应 audit 为 failed；失败终结还会将遗留的 streaming stage/body 修复为 partial，使已提交 raw 可按不完整证据读取。终结本身失败或队列满时，writer 保留有界终态元数据并在恢复后补写；原请求日志记录当时的终结失败，异步恢复不会重写这条日志或原请求结果。队列屏障、恢复容量及进程退出边界见[模块 04](04-sqlite-storage-and-migrations.md)。

已提交的块有缺失时（失败批次里的检查点，或旧版本的异步分块失败），终结也必须按实际落盘分块修正存储长度和计数，不能继续把采集器内存中的完整聚合当作已保存证据。缺块只保留并导出剩余片段，明确标记 `capture_chunk_missing`；不能承诺恢复未落盘字节。逻辑 SSE 时间线在观察字节时生成，缺块不改变已封存时间线的完整性。

available：queue/DB/key 失败时不阻塞代理，标 partial/failed，写结构化日志；DB 不可用时合并一个内存 gap，下一次成功写入时补记。

strict：BeginAudit 必须使用已加载的 key 同步 COMMIT；本次提交失败时返回 503，parser queue 不参与 admission。上一批写入留下的健康快照不替代这次提交，也不会永久阻止后续重试。Begin 成功后的检查点不等待，晚到故障只标 partial/failed，不提供逐块 durable ack；终结提交照旧等待。

## 9. audit_gaps

audit_gaps 只做进程级运维提示，字段为 id、started_at_ns、ended_at_ns、reason、request_count、detail、created_at_ns，不精确关联某个 audit。reason 使用 db_unavailable、queue_full、encryption_error、write_error、process_exit；detail 只能保存稳定错误码和计数，不保存请求数据。

进程内按固定 reason 各保留一个聚合 gap，同一 audit session 最多计数一次。DB 恢复时插入并清空；提前退出只能依赖日志，这是 available 的已知限制。

## 10. Parser

非 rejected 的 audit Finalize 后：

1. audit_records.parse_status 设为 pending。
2. audit_id 非阻塞放入内存 queue（交给 `Submit` 的作业可以带着会话手里的明文，§13.8）；满时只保留 pending。
3. 启动时及每 30 秒扫描少量 pending 记录补入队列。
4. worker 用条件更新把 pending 改为 processing，未抢到则跳过。
5. worker 从数据库读取、解密并解析；带明文的作业不读回。
6. 在同一 writer 事务中 UPSERT parsed_results；若 normalizer 可用则保存 verified turn graph，并按结果把请求侧、响应侧的 raw retention 分别更新为 metadata/full（规则见[模块 18](18-content-addressed-conversation-storage.md) §6），再更新 parse_status。

rejected audit 在终结提交时直接设为 skipped，永不入队。重启时先把遗留 processing 重置为 pending，再扫描已结束且 pending 的 audit 重新入队；解析结果只保留最新版本。

## 11. NewAPI 调用者身份

若成对配置 `newapi.access_token` 与 `newapi.user_id`，应用按[模块 11](11-newapi-request-identity.md)启用只读 NewAPI 管理集成。审计会话在 `response_received_from_newapi` 开始时读取合法的 `X-Oneapi-Request-Id`，并在终结提交（`CommitAudit`）中与终态一起持久化；存在 request ID 时将 `caller_status` 设为 `pending`，再唤醒单个后台 worker。

worker 通过 NewAPI 全站日志精确查询该 request ID，成功后只保存 `newapi_user_id`、`username`、`newapi_token_id`、`token_name` 和关联时间。没有访问 NewAPI 的 interceptor 拒绝、本地 fail-closed、passthrough、无上游响应或无 request ID 的记录不会进入身份解析。识别结果只用于审计展示和筛选，不参与放行；管理接口延迟、失败或最终未识别均不改变已完成的转发结果。

## 12. 崩溃恢复

启动后先验证 HMAC integrity event chain，导入上次留下的暂存文件（§13.6），再把 ended_at_ns 为空的 audit 改为 forward_status=interrupted：无采集故障的记录写 capture_status=partial、error_code=process_exit，已标记采集失败的记录先复用正常终结的分块对账并保留 failed 状态；仍为 streaming 的 stage/stream 改为 partial，raw retention 强制为 full，并按 owning chunks 修复可证明长度。每条恢复记录写 capture event，随后把遗留 processing 重置为 pending 并重新入队。不补造 Trailer、缺失 chunk、SHA-256 或精确结束时间；SQLite WAL 只保证已提交事务一致。

## 13. 写入路径

会话把一条 audit 写成最多四个 writer 操作（有阶段落暂存时，每个这样的阶段另加一个只写行的检查点，§13.4），Body 在内存里留到写库为止。这是 issue #59 第 3 阶段加的 unified 写入路径；当时默认的 legacy 路径（每个阶段、每组 Header、每个 1 MiB 块各是一个 writer 操作，一条典型流式请求 22 个）在 A/B 之后删去，`audit.write_path` 不再选择任何东西（模块 01 §4 第 18 项）。设计与维护者的决定见 [issue #59 第 3 阶段设计](../design/issue-59-stage3-write-path.md)，与设计不同的地方和删去 legacy 的记录见它的“实施记录”（R.8）。下文与 legacy 的对照只用来说明差别和旧的采集版本 1 记录是什么样子。

存储声明自己不能承担这条写入路径时（`SupportsUnifiedWrite`），构造 `audit.Manager` 失败，审计不可用。PostgreSQL 存储写采集版本 2（Header 块），SQLite 存储只写版本 1（`captureVersionFor`）。观察层、阶段与 Body 的终态判定（`finishStageLocked`）和时钟读取与 legacy 路径相同，所以长度、SHA-256、状态、错误码、`body_stage_mismatch` 和“终止事件之后断开算完成”的规则都没有变；变的只是保留层和写库方式。

### 13.1 阶段开始时做什么

阶段开始只记在内存里：版本 1 当场按 legacy 的循环和 AAD 把 Header 逐值加密成待写的行组；版本 2 当场深拷贝 Header 字段（§6）。阶段行、Header 和 Body 行由之后的写带上。会话为每个阶段记住哪些已经写过：阶段行、各 Header 组、Body 行、每个块；块版本 2 另记最后一次写出的块覆盖了哪些阶段和 Trailer。每次写只带自上次以来新增的内容，没有新增内容时不发出。

### 13.2 四次写

| 写 | 何时 | 写什么 | 等待 |
| --- | --- | --- | --- |
| `BeginAudit` | 路由命中后，拦截器之前 | 起始行；`request_received` 的阶段行和 Header（版本 1 逐值行；版本 2 为 `user_agent_enc` 和只含这一阶段的块） | 同步 |
| 检查点 1 | `request_sent` 的 Body 结束：EOF（在 Trailer 采到之后）、读错误或 Close（`observedReadCloser` → `readBodyEnded`） | 还没写过的阶段行和 Header；两个请求阶段的 Body 行（初值）；请求侧封好的块；版本 2 为到此为止的整块 | 否 |
| 检查点 2 | `response_sent` 开始，即响应头转发给客户端的那一刻（`observedResponseWriter.start` → `responseSentStarted`），且 `response_received` 已存在 | 两个响应阶段的行和 Header；检查点 1 还没写到的请求侧内容 | 否 |
| `CommitAudit` | `Finish` | 其余全部：响应 Body 行和块、未写的 Header 组（主要是 Trailer）或完整的块、各行的终值；然后终结并签名 | 同步，失败时按 §13.5 重试 |

另有一种只在 Body 超出内存预算时才有的检查点，见 §13.4。

- **检查点只写封好的块**：满 1 MiB 的块，或 Body 结束时的尾块。所以块边界与 legacy 相同（全局预算吃紧时的例外见 §13.4）。响应 Body 的块只由 `CommitAudit` 写。
- **两个检查点都要求 forward 仍在进行**（`forwardInProgressLocked`：没有开始构造提交、`forward_status` 仍是 `in_progress`、请求 context 没有取消）。所以下面的请求没有检查点或只有一个：被拦截器拒绝的（没有 `request_sent`，也没有响应阶段，通常只有 `BeginAudit` 和 `CommitAudit`）；上游不可达、由代理自己回错误 JSON 的（没有 `response_received`，没有检查点 2）；客户端已经取消的（之后的触发点都跳过）。
- **没有请求 Body 的请求**（例如 GET）不触发检查点 1，`request_sent` 的行和 Header 由检查点 2 带上。
- **上游在读完请求之前就回了响应头**：检查点 2 先发生，带上请求侧到那时为止的阶段行、Body 行和封好的块；这时请求 Body 还没结束，不能在内存里合并（§13.3），请求对留给终结时在库里合并。请求 Body 之后结束时，检查点 1 照常写剩下的块。
- **检查点入队时队列满**：内容都还在内存里，并入下一次写；记一条 `audit capture degraded` 日志，`error_code=capture_checkpoint_deferred`，附 `storage_error`；不记 gap，证据不少。版本 2 的块封不出来时同样不发这个检查点、记同一条日志。下一次写会重新封这些块（新的 nonce）。

`BeginAudit` 和 `CommitAudit` 的同步等待与 legacy 路径的 `BeginAudit`、`FinishAuditWithResult` 一一对应，处理函数路径上仍是两次同步等待；检查点不等待，不影响转发时序。流结束时刻与终结提交的先后（`internal/proxy/stream_end_order_test.go`）与 legacy 路径相同。writer 内每个操作写什么、失败怎样记账，见[模块 04](04-sqlite-storage-and-migrations.md) §5.1。

### 13.3 成对阶段在内存里的判定

`request_sent` 是 `request_received` 的重复阶段，`response_sent` 是 `response_received` 的重复阶段。

- **借用。** 重复阶段的字节与来源阶段相同时，它不复制字节，只按自己的偏移在来源的字节上延伸块网格。出现第一个不相等的字节，或者来源还没有保留到的字节（重复阶段读到了来源前面），重复阶段从这里起自己保留字节，此前的前缀 `[0, d)` 继续向来源借用。重复阶段出现之后，来源阶段在它比对过一个块之前不释放这个块（重复阶段还没出现时不受此限，见 §13.4）；被借用的块只会落暂存，不会丢弃，重复阶段封自己的块时再从暂存读回。
- **请求对在检查点 1 判定。** 两个请求 Body 都已结束、没有故障、全部保留、长度和 SHA-256 相同时（`mergeableNow`），检查点 1 把 `request_sent` 的 Body 行写成 `source_stage = request_for_newapi_received_from_nginx`，不写它的块。
- **`Finish` 时按终值再判一次**（`finalMergeable`，即库内合并的条件）。仍然满足：`CommitAudit` 写合并后的终值。不再满足（例如检查点 1 之后 Close 返回错误，记了 `body_close_error`）：`CommitAudit` 把 `source_stage` 改回自身，并写入重复阶段自己的块，块由借用的前缀加上自己的字节按它自己的阶段名和 AAD 重新封成。
- **响应对在 `Finish` 判定**，规则相同。
- **留给库内合并**（`AuditCommit.DedupInDB`，由 `deduplicateEquivalentBodyPair` 按 legacy 的方式合并）的情形：重复阶段的 Body 行或块已经按未合并的形态写过（上游先回响应头、请求还没结束时的检查点 2，或重复阶段自己落暂存时的检查点），以及请求对在起始行没有入站阶段时（§13.9）。
- 合并后的行形态与 legacy 路径相同；legacy 先写后删的那一份块和 Body 行不再写。

**与 legacy 路径的差别：** legacy 在已存 `capture_status` 为 failed 时跳过成对合并，两份 raw 都保留。会话在内存里合并时不知道库里的失败标记，所以一条最终 failed 的 audit，其合并了的重复阶段仍以指向来源的形态存储。两份字节已按长度和 SHA-256 证明相同。

### 13.4 内存预算与本地暂存

预算按明文字节计（`internal/audit/budget.go`）。`audit.memory.stage_bytes` 限制每个阶段自己保留的字节，借用的不算；`audit.memory.global_bytes` 是全进程的原子计数，另外计入暂存待写队列里的密文（只加不检查上限）和交给 parser 作业的明文（§13.8），所以它是软上限。

某个阶段或全局预算满了时，会话先释放内存，再接着保留（`stageOneChunkLocked`）：

1. 检查点已经写进库的块，其明文只是留给解析的缓存（重复阶段还在借用的除外），先丢掉；
2. 否则按 seq 顺序，把这个阶段第一个还没落暂存的块封好交给暂存（`internal/audit/staging`），内存里只留索引项。按 seq 顺序是为了让暂存文件总是接着库里已有的块；
3. 全局预算吃紧、这个阶段只剩正在攒的块时，提前结束这个块，它短于 1 MiB。这是块边界唯一可能与 legacy 不同的地方。单阶段预算不小于 1 MiB，单靠它不会切出短块。

重复阶段出现之后，来源阶段的块还没被它比对过时不能落暂存。两个阶段交替读取时重复阶段最多落后一次读（`ReverseProxy` 的拷贝缓冲 32 KiB），这一次读的字节越过预算照收，不结束保留。

**应用里请求 Body 总是先读完。** 交替读取只在没有预读 Body 的拦截器时出现。应用给每条路由都加上 `uaguard` 和 `contentpolicy` 两个全局拦截器（`internal/app/app.go` 的 `WithGlobal`），它们不论有没有启用的规则都声明需要 Body，框架于是先把请求 Body 读到末尾再回放（`interceptor.readAndReplayBody`）：`request_received` 在 `request_sent` 出现之前就读完了。后果有两条：

- 请求 Body 不超过 `stage_bytes`（默认 8 MiB）时没有影响，请求对照常在检查点 1 合并。
- 超过时，来源阶段在预读中就把块落了暂存；重复阶段从偏移 0 起比对不到这些块，转为自持，自己也落暂存，并由它自己的落暂存检查点写出指向自身的 Body 行。请求对因此不在检查点 1 合并：检查点 1 写两份块，`CommitAudit` 置 `DedupInDB`，由库内合并删掉重复阶段的块。终态的行与内存合并的相同；以 failed 终结的 audit 不做库内合并，两份都保留，与 legacy 相同。比起内存合并，每条这样的 audit 多一个 writer 操作、一条暂存记录、两行先写后删的块。实测和可选的改法见设计文档实施记录 R.1 第 11 条与 R.7。

另外，预读期间整个请求 Body 的明文本来就在拦截器的缓冲里（上限 512 MiB），这部分不计入 `audit.memory` 的预算：预算约束的是会话为审计保留的明文，不是进程为转发持有的。

**落暂存时的检查点。** 一个阶段第一次落暂存时，会话排一个只写行的检查点：到此为止的阶段行和 Header，以及这个阶段的 Body 行，不写块，也不写其他阶段的 Body 行，所以来源阶段落暂存本身不妨碍请求对在检查点 1 合并（重复阶段自己也落暂存时除外，见上）。这样进程在检查点 1 或提交之前退出时，暂存的块有它们所属的行可接（§13.6）。这个检查点没能入队时，该阶段下次落暂存再试。

**暂存文件。** 每条 audit 一个文件 `<dir>/<audit_id>.stg`，以 `O_EXCL` 和 0600 创建，文件里只有一个指明 audit 的文件头和逐块记录，块是与 `body_chunks.data_enc` 逐字节相同的密文，带 CRC 帧，可以原样插入库里。后台 writer 每批最多攒 5 ms，写完后对本批涉及的每个文件 fsync 一次，新建文件后再 fsync 目录；暂存从不阻塞调用方。块的密文在写进文件之前留在内存里，写失败的块仍可读。检查点和提交读暂存的块不取会话锁，也不等暂存 writer；读失败是那一次写的本地错误，该 audit 记为 failed（模块 04 §5.1）。构造提交之后不再落暂存。

**保留到何时。** `CommitAudit` 得到确认后，会话丢弃该 audit 还在队列里的记录并删除文件（`Stager.Discard`）；提交最终失败时文件留在目录里（`Stager.Keep`），计入 `max_bytes`，由 writer 恢复把块写进库之后删除，进程先停下时由下次启动导入（§13.5 第三条）。

**耗尽。** 暂存拒绝一个块时，该阶段停止保留后续字节，只继续计算哈希、长度、时间和 SSE：

| 原因 | 阶段与 Body 的错误码 |
| --- | --- |
| 暂存目录达到 `audit.staging.max_bytes`、待写队列满（4096 条）、磁盘满、暂存已关闭、提交已在构造 | `capture_budget_exhausted` |
| 这条 audit 的暂存文件此前写入或 fsync 失败 | `staging_write_failed` |

Body 标为故障，阶段 partial，`capture_status` 为 partial，raw 保留 `full`；available 模式记一次 `queue_full` gap（`audit_gaps.reason` 有 CHECK 约束，真实原因在阶段错误码上）。已经保留的部分照常写库。转发不受影响。

### 13.5 `CommitAudit` 的重试与最终失败

`Finish` 构造一个 `AuditCommit` 并等它（`commitWithRetries`）。只重试两类错误：入队时的 `ErrQueueFull`，以及整批回滚的 `ErrWriteBatchFailed`（包括结果不确定的 COMMIT；重试遇到已终结的行只读回已提交的终态，不重复签名）。操作级失败（约束、本地校验、对象完整性）、`ErrRecoveryOverflow`、`ErrClosed` 和输入校验错误不重试。

- **次数**：`Manager.CommitRetries`，取自 `audit.commit_retries` 或管理页面保存的值（模块 10 §11），0 到 5。会话在第一次尝试之前读一次，所以改动对之后开始的提交生效；最后一次尝试带 `FinalAttempt`。
- **间隔**：第 k 次重试之前等 `min(100 ms × 2^(k-1), 1 s)`，默认 3 次最多多等 0.7 秒，5 次最多 2.5 秒，另加各次尝试本身的时间。等待时不持有会话锁。
- **与 writer 恢复表的配合**：只有最后一次尝试在批次失败或队列满时把终态交给恢复表；操作级失败不重试，无论第几次都立即交给恢复表，并把 audit 标为 `capture_write_failed`（模块 04 §5.1）。
- **最终失败**：与 legacy 路径上 `FinishAudit` 失败时相同。完成日志和 `TerminalSummary` 为 `capture_status=partial`、`error_code=audit_finalize_failed`，记一条 `audit capture degraded`（`error_code=finish_audit_failed`）和对应的 gap；writer 恢复把 audit 以 failed 终结，检查点写进去的行收尾为 partial、raw `full`。终态没有提交，不交给 parser（§13.8），由 pending 扫描按现有路径解析。

已知的限制：

1. **重试救不回检查点丢在失败批次里的 audit。** 检查点所在批次失败时，writer 把它记进恢复表；该 audit 的 `CommitAudit` 在终结之前先写这些失败标记（`prepareFinalization`），所以即使重试的提交成功，audit 也以 failed 终结。快请求的检查点常与它的提交同批，故障期间发出的检查点也是这样。
2. **响应大时 `Finish` 更慢，响应小时更快。** 响应侧保留的块在 `Finish` 时才压缩加密（请求侧已在检查点 1 封好），分块响应和 HTTP/2 响应的结束（晚于终结提交的那几类）随之推后这段时间；另一方面 unified 的终结只有一个 writer 操作。实测见设计文档实施记录 R.7：PostgreSQL 上响应为几十到一百多 kB 的合成负载，`Finish` 的 p50 从 18–21 ms 降到 13–14 ms；SQLite 上单条流式响应 8 MiB 时从 26 ms 升到 38 ms，16 MiB 时从 16 ms 升到 68 ms，64 MiB 时从 24 ms 升到 153 ms。
3. **最终失败的提交丢掉仍在内存里的那部分 Body。** 最终失败时会话把暂存文件留下（`Stager.Keep`），存储把这次失败连同对暂存块的引用（文件位置，不是密文，`storage.StagedChunkHolder`）记进恢复表。存储恢复可写之后，writer 恢复（`recoverCaptureEntry`，每 5 秒一轮，进程关闭时还有一轮）在把 audit 以 failed 终结的同一个事务里，先把这些块插到各自的 Body 行下（`insertStagedChunks`，规则同启动导入：只插接得上库里已有块的、Body 行属于自己的），`finalizeIncompleteCapture` 再像对待其他已存的块一样按它们收尾长度和块数；事务提交之后才删除文件。插入被单独拒绝时（例如块被约束拒绝），audit 照样以 failed 终结，文件保留，记 `audit staged chunks not recovered`，下次启动把它改名为 `.orphan`。进程在这之前停下时，下次启动的导入把块插进仍未终结的 audit，再由 `RecoverInterruptedAudits` 以 interrupted 终结。与 legacy 在同样故障下相比：会话还在内存里的部分（每个阶段最多 `stage_bytes`，通常是最后不足一块的尾部）丢失；响应对在 `Finish` 时才定，提交失败后 `response_sent` 只有检查点 2 写的阶段行、没有 Body 行；legacy 则丢掉与它失败的 `FinishAudit` 同批的那些异步写，其余的块都在。提交根本没有发出（版本 2 的块封不出来，或入队前的校验失败）时没有记入恢复表，文件留给下次启动导入。

### 13.6 启动导入

启动顺序：验证完整性链 → 导入暂存 → `RecoverInterruptedAudits` → 构造 Manager（`internal/app/app.go` 的 `assembleAuditWithStore`）。`audit.staging.dir` 必填；目录可用时启动导入（`Stager.Import`），不可用时审计在两种模式下都不可用（模块 01 §4 第 18 项），这个判断在 `RecoverInterruptedAudits` 之后做。每个文件用一个 writer 操作 `RestoreStagedChunks`（模块 04 §5.1）：

| 情形 | 处理 |
| --- | --- |
| audit 已终结，文件里的块库里都有（提交之后、或恢复写入失败提交的暂存块之后，删文件之前停了） | 只删文件 |
| audit 已终结，但缺文件里的块（恢复插入时被拒绝） | 不改动已终结的 audit，文件改名为 `.orphan` |
| 没有这条 audit | 改名为 `.orphan` |
| 某个阶段有块却没有 Body 行（落暂存时的检查点丢了） | 导入其他阶段，文件改名为 `.orphan` |
| 正常 | 逐条校验 CRC、块元数据、AEAD，以及每个阶段的 seq、offset 向前推进；插入接着库里已有块的那些，然后删文件 |
| 最后一条记录不完整 | 视为进程停下的位置，丢弃 |
| 中间记录校验失败、文件头指向别的 audit，或块与库里的接不上 | 导入此前校验通过的部分，文件改名为 `.corrupt` |
| 合并了的重复阶段的块（Body 行指向来源） | 不插入，来源的块就是证据 |

改名的文件不删，计入 `max_bytes`，由运维确认后清理。文件读不出来或存储报错时导入中止，审计不可用：否则之后的恢复会终结这些 audit，下次启动会把完好的文件当作已终结删掉。导入是幂等的，已有的 seq 跳过。之后的 `RecoverInterruptedAudits` 用现有逻辑收尾这些 audit：它按 `source_stage` 聚合块，所以合并了的重复阶段从来源得到长度和块数。

### 13.7 崩溃时留下的证据

以一条流式请求为例，进程在不同时刻退出、重启恢复之后库里有什么。legacy 一列是已删去的路径，留作对照：上一个版本留下的采集版本 1 记录就是这个样子。检查点和 legacy 的异步操作一样，入队后几毫秒内提交，下表忽略这段时间。“预算”指 `stage_bytes`（默认 8 MiB）。

| 退出时刻 | legacy | unified | 差别 |
| --- | --- | --- | --- |
| 拦截器执行中，包括 body 拦截器预读 | 起始行；`request_received` 的行和 Header；预读超过 1 MiB 时已满的块 | 起始行；`request_received` 的行和 Header（版本 2 含 `user_agent_enc` 和只含入站阶段的块）；预读超过预算时，落暂存的块和它的 Body 行 | 预算以内的预读字节没有 |
| 入站 Body 已收完，正在转发给上游 | 起始行；`request_received` 的行、Header 和整个 Body；`request_sent` 的行和 Header，以及它已满 1 MiB 的块 | 同上一行；请求 Body 超过预算时，另有 `request_sent` 落暂存时的检查点写的行、Header、Body 行和它落暂存的块 | 预算以内的请求 Body 一个字节也没有，而 legacy 这时已有完整的入站 Body；`request_sent` 的行和 Header（与入站几乎逐条相同）在没落暂存时没有 |
| 请求读完，响应头还没到 | 以上全部，加两个请求阶段的尾块和请求 Trailer | 检查点 1：两个请求阶段的行、Header 和请求 Trailer（版本 2 为残缺块），Body 行，请求侧全部块 | 合并了的 `request_sent` 没有自己的块，`source_stage` 指向来源 |
| 响应流到一半 | 以上全部，加两个响应阶段的行和 Header，各自已满 1 MiB 的块 | 检查点 1 和 2；响应 Body 只有超出预算后落暂存的块 | 预算以内的响应 Body 没有（legacy 只丢最后不足 1 MiB） |
| 响应已读完，`Finish` 提交之前 | 以上全部，加两个响应阶段的尾块和上游响应 Trailer（EOF 时异步写出） | 同上一行 | 同上一行；随 Body 结束到达的上游响应 Trailer 也没有，它只由 `CommitAudit` 写 |
| `Finish` 提交之后 | 完整 | 完整 | 无 |

恢复把这些 audit（包括上一个版本以 legacy 路径留下的）终结为 `interrupted`，未完成的阶段和 Body 收尾为 partial、`process_exit`，raw `full`，并签名；版本 2 签的是最后一次写出的残缺块（模块 09 §8）。SSE 响应体通常远小于预算，所以响应侧的差别在实际流量里影响小；请求侧的差别是维护者接受的（设计决定 1、4）。

第二行需要说明：应用里全局拦截器总是先把请求 Body 读完（§13.4），所以客户端上传发生在第一行那段时间里，第二行是把缓冲的 Body 发给上游的时间。检查点 1 的触发点是 `request_sent` 的 Body 结束，不是入站 Body 收完，因为成对阶段要等两边都结束才能判定。于是从入站收完到发完给上游这一段（连接上游加发送，上游在本机时是毫秒级，上游迟迟不收时更长），unified 的库里没有预算以内的请求 Body，legacy 有完整的入站 Body。设计稿 B.7 的表按交替读取写了“请求 Body 正在上传”一行，没有单独列出这一段。

### 13.8 交给 parser

`CommitAudit` 成功、解析状态为 pending 时，会话把 audit 交给 Manager 的交接回调（`internal/audit/handover.go`）。`internal/app` 总是把它设为 `parser.Worker.Submit`；没有设时（只在直接构造 Manager 的测试里）退回 `Notify`。处理函数只等提交，不等解析；`Submit` 不阻塞。

交接的作业要么带着会话手里的明文，要么只有 audit id（id 作业，worker 从库里读）。带明文的条件全部满足：

- 提交返回的终态没有被降级：`capture_status`、`forward_status`、`error_code` 与提交的相同，解析状态仍是 pending。例如检查点失败使 capture 变为 failed 时，库里的证据不是会话手里的那份；
- 起始行带着入站阶段（§13.9）；
- 没有任何块落过暂存；
- `request_received` 和 `response_received` 的每个已存块都完整留在内存里、连续，合起来正好是提交的 `stored_length` 和块数；
- 全局预算还容得下同样多的字节（只检查，不另占）。

带明文的作业把这份明文在预算里的份额从会话转给作业，作业的 `Release` 恰好调用一次（被拒绝、解析完成或 worker 关闭时）把它还回并清零明文。版本 2 的作业还带着两个接收阶段 Header 字段的明文（parser 从中取内容头和白名单 Header），版本 1 带的是已加密的 Header 行。`Submit` 的队列满时什么都不交，记录留在 pending，由 30 秒一次的扫描接手。worker 怎样从作业构造输入见[模块 05](05-parser-framework.md) §5.1。

### 13.9 起始行没有入站阶段

`BeginAudit` 在同一个操作里写起始行和入站阶段，阶段行和 Header 各在一个嵌套 savepoint 里（模块 04 §5.1）。入站阶段行被可隔离的错误拒绝时，起始行照常提交并被标为 failed，`BeginAudit` 返回包着 `storage.ErrInboundStageNotStored` 的错误（批次提交之后才返回）。会话把它当作准入成功，按 legacy 处理 `StartStage` 失败的方式处理这个阶段：

- 阶段标故障，错误码 `start_stage_failed`，会话的采集记为有故障（提交返回的终态是库里已标的 failed），记一条 `audit capture degraded`（`stage=request_for_newapi_received_from_nginx`）；不记 gap，失败已由 writer 记在库里；
- 这一阶段的行不再提交，也不进任何 Header 块；它的 Body 同样标 `start_stage_failed`；
- 请求对不在内存里合并（合并的一方指向一个没有行的阶段就存不下），`request_sent` 按未合并的形态写自己的块，请求对交给库内合并；
- 不交明文作业，只交 id 作业。

Header 插入被拒绝而阶段行保留时 `BeginAudit` 返回 nil；整批失败时 `BeginAudit` 照旧失败，strict 回 `503`。`storage.ErrorClass` 把这个值报告为 `inbound_stage_not_stored`。

## 14. 测试

- audit_id 格式与随机源失败。
- 四阶段独立 length/hash。
- 0、1、约 1 MiB 边界和尾块 flush。
- n>0 同时返回 EOF/error。
- available writer queue 满继续；strict admission 503；parser queue 满不影响两种模式的转发。
- interceptor 主动 reject、body 超限、error、panic、非法 Decision 和非取消的 Body 读取失败均写 rejected、blocked_by/block_code、实际 status_code 和 skipped；客户端取消写 client_cancelled。
- metadata reject 未读 Body 时 capture 为 partial；body 预读完成后 reject 可完整结束入站证据。
- 未调用 NewAPI 的 audit 不存在后三个 stage/body_stream/chunk，不进入 parser，也没有 request ID 或调用者关联。
- 上游 response Header 中合法的 `X-Oneapi-Request-Id` 随终态保存并触发 caller worker；无效、多余或缺失值不会创建 pending 任务。
- body interceptor 放行后的两个请求阶段 length/hash 一致；不一致时标记 `body_stage_mismatch` 并保留各自证据。
- 相同 request/response Body 只在终结校验后合并为一份 owning chunks，source_stage 可正确 raw 读取；不相同的成对阶段不会误合并。
- SSE 网络分块合并为逻辑 event timeline，超过 100,000 事件时保留实际总数和截断标志。
- GCM 随机 nonce、AAD/密文篡改失败。
- DB/WAL 无测试 token/Header/Body 明文。
- Finish 幂等、kill 后 partial、pending parser 重启恢复。
- 经真实代理处理函数跑同一组夹具（`internal/protofixture` 全部交换加额外形态），客户端字节、完成日志、提交时与解析后的各表行、查询视图、Agent 门面导出和解析结果与 legacy 路径逐项相同；SQLite 上比版本 1，PostgreSQL 上比版本 2。legacy 一侧是 legacy oracle：删去 legacy 路径之前由它在 oracle 提交上写下、冻结在各包 `testdata/legacy-oracle` 的金文件（`internal/legacyoracle`，规范化方式见设计实施记录 R.8），不能再生成。
- 上一个版本以 legacy 路径留下、未终结的 audit（采集版本 1）在新版本第一次启动时被恢复终结并通过校验，SQLite 与 PostgreSQL 各一遍（`internal/app` 的 `TestFirstStartRecoversAnAuditTheLegacyPathLeftOpen`）。
- 成对判定：检查点 1 合并、`Finish` 时拆开；重复阶段在块中间、开头、更长、更短处分歧；响应超过 1 MiB，完整与截断；上游先回响应头。
- §13.7 每个退出时刻恢复后的行与 legacy oracle 的差别只在表中所列；版本 2 恢复后签名残缺块并读回 legacy 的 Header。
- 检查点入队失败并入下一次写、不记 gap；`CommitAudit` 的重试矩阵（批次失败一次后恢复、持续失败、约束失败、0 次、结果不确定的 COMMIT）；页面保存 0 与 2 后同一进程内的尝试次数。
- 一块的单阶段预算下请求、响应经暂存，请求对在 `Finish` 拆开时重复阶段从来源暂存的字节封块；暂存写满记 `capture_budget_exhausted` 与 `queue_full` gap；上传中、响应中途和提交后删文件前退出时的导入。
- 起始行没有入站阶段时请求对不在内存里合并，各表与 legacy oracle 在同一触发器下相同（响应对合并的差别见 §13.3）。
- 被拒绝的写：检查点被可隔离错误拒绝时整个回滚，提交被拒绝时立即最终失败，audit 以 failed 终结，其余已存证据可读并通过校验。
