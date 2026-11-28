# Issue #59 第 3 阶段详细设计：阶段性提交、单一 Header 块、解析不读回

状态：已实施（提交 `0faae0a` 之后的第 3 阶段提交，到 `008f3fc` 为止）。正文是实施前的定稿，保留原样；代码与正文不同的地方列在文末“实施记录”，以那里和模块文档为准：会话见模块 03 §13，writer 操作见模块 04 §5.1，迁移见模块 04 §3.8、§3.9，parser 见模块 05 §5，Header 块与明文边界见模块 09。迁移编号取 007，因为 006 是另一项改动加的 `turns (created_at_ns, turn_id)` 索引。A/B 之后 legacy 写入路径已删去，unified 是唯一的写入路径，正文里的开关与回退都是历史，见实施记录 R.8。

本阶段对应方案 `doc/design/issue-59-unified-write-cold-archive.md` 第 6 节的 P2：4.2 的第一步和第二步、决策 5.10、`audit.write_path` 开关。4.2 第三步不在范围内。

## 0. 决定记录

设计初稿提了四个需要维护者定的问题，维护者的决定如下。正文按这些决定写成；与方案 4.2 字面不同的地方，以本节为准。

| # | 问的是什么 | 决定 | 落在哪里 |
| --- | --- | --- | --- |
| 1 | 只在 `Finish` 时提交一次，在途请求崩溃时留下的证据会比现在少（A.4）。四种处理方式：甲接受；乙超时落本地暂存；丙每条请求落本地暂存；丁阶段性提交到数据库 | 选丁。请求 Body 读完时、响应头转发出去时，各排一个不等待的写操作，提交到那时为止已知的阶段行、Header 和请求 Body；`Finish` 提交其余部分，并且照旧等待。不做按时间的落盘，也不让每条请求都落本地暂存 | B 节；崩溃证据见 B.7 |
| 2 | Header 块是一段密文，还是把凭据值拆成单独一段；parser 解密整块是否可以接受 | 一段。parser 在进程内解密整块，再按白名单过滤；这是内网的内部工具，可以接受，写进模块 09。C、D 两节按初稿批准，只按决定 1 补上残缺块 | C.8、D.4 |
| 3 | `CommitAudit` 失败时是否落暂存、之后重放 | 不重放。`Finish` 有限次重试，仍失败就按现在的路径以 failed 终结。重试次数是运行参数，在管理界面的设置页修改，默认 3 | B.8、H.3 |
| 4 | 每阶段内存预算的默认值 | 默认 8 MiB，可以在配置文件里覆盖 | F.1、F.3 |

决定 3 之后，暂存只剩一个用途：放超出内存预算的 Body，它变成罕见路径（F.3）。初稿里暂存的终态记录、重放循环和按时间落盘都删掉了。

记号：

- 〔核〕：作者读代码直接核对过（提交 `0faae0a`），给出文件与函数。
- 〔推〕：推断，没有测试或实测证实。
- 〔设〕：本文的设计。

文中路径都相对仓库根目录。

---

## A. 现在的采集路径

### A.1 一条请求经过的代码

按时间顺序。“异步”指 `submitAsync`：入队即返回，不等提交；“同步”指 `submitSync`：等所在批次提交后的 ack（`internal/storage/postgres/writer.go`）〔核〕。

| 时刻 | 代码 | 写入操作 | 等待 |
| --- | --- | --- | --- |
| 路由命中后 | `internal/proxy/proxy.go` `handler.ServeHTTP` → `beginAudit` → `internal/audit/manager.go` `Manager.Begin` | 生成 id；Request-URI 用 AAD `(audit_id, "request_uri")` 加密；算 `api_key_fpr`；`BeginAudit` | 同步 |
| 同上 | `Manager.Begin` → `Session.WrapRequestReceived` → `startStage` | `StartStage(request_received)`；`addHeadersLocked` 逐值加密后一次 `AddHeaders` | 异步 |
| 紧接着 | `proxy.go` 注册 `defer session.Finish()`，早于拦截器 | — | — |
| 拦截器 | `h.engine.Evaluate`；拒绝时依次 `MarkRejected`、`closeRequestBody`、`writeJSON`。拒绝路径的 ResponseWriter 没有被包装，所以没有 `response_sent` 阶段 | — | — |
| 放行 | `WrapResponseWriter`，`defer observedResponse.CaptureTrailers()`，然后 `reverseProxy.ServeHTTP` | — | — |
| Rewrite | `newReverseProxy` 的 `Rewrite`：Accept-Encoding 改为 identity，`WrapRequestSent` → `startStage(request_sent)` | `StartStage`、`AddHeaders` | 异步 |
| Transport 读出站 Body | 出站 Body 包着入站的 observed reader，所以每次 Read 先 `observeRead(request_received)`，再 `observeRead(request_sent)`（`internal/audit/body.go` `observedReadCloser.Read`） | 首次观察时 `ensureBodyLocked` → `StartBody`；`observeBodyLocked` 攒满 1 MiB 时 `flushBodyLocked` → `AddChunk` | 异步 |
| 请求 Body EOF | `observeRead` 收到 `io.EOF`：`flushBodyLocked(force=true)` 写尾块，置 `eofSeen`、`hashComplete`；`captureTrailers` → `AddHeaders(trailer)` | `AddChunk`、`AddHeaders` | 异步 |
| 响应头到达 | `ModifyResponse` → `WrapResponseReceived`：读 `X-Oneapi-Request-Id`，`startStage(response_received)` | `StartStage`、`AddHeaders` | 异步 |
| 响应 Body | 拷贝循环读 upstream（`observeRead(response_received)`；SSE 事件和终止事件探针只在这一阶段），写 `observedResponseWriter.Write`。首次写时 `start` → `startStage(response_sent)`，然后 `observeWrite` | 每个阶段一次 `StartBody`，每 1 MiB 一个 `AddChunk` | 异步 |
| 响应 EOF | 同请求 EOF：尾块、trailer | `AddChunk`、`AddHeaders` | 异步 |
| 处理函数返回 | defer 逆序执行：先 `CaptureTrailers`（`response_sent` 的 trailer），再 `session.Finish` | `AddHeaders` | 异步 |
| `Finish` | `internal/audit/session.go` `finish`：定 forward status；按阶段顺序 `finishStageLocked`（强制 flush、`response_sent` 的逻辑 EOF、封存时间线、成对 `body_stage_mismatch` 检查）；逐个 `FinishStage`；`FinishAuditWithResult` | `FinishStage`×n 异步，`FinishAudit` 同步 | 等终结批次提交，没有超时 |
| 提交之后 | 解析状态为 pending 时 `notify`（`parser.Worker.Notify`，队列满就放弃）；有 request id 时 `callerNotify`；生成 `TerminalSummary` | — | — |
| 最后 | `proxy.go` 最外层的 defer 写“请求完成”日志 | — | — |

以上全部〔核〕。

`finishAudit`（`internal/storage/postgres/writer.go`）在一个 savepoint 里依次做〔核〕：

1. `ended_at_ns` 已有值时只读回已提交的终态（`loadFinishedOutcome`），不改任何东西。
2. 已存的 `capture_status = 'failed'` 时沿用 failed，跳过成对合并；否则调 `deduplicateEquivalentBodyStages`。
3. `CaptureStatus != complete` 时调 `finalizeIncompleteCapture`：按已提交的块修正长度和计数，把仍在 streaming 的阶段和 Body 收尾为 partial。
4. 更新 `audit_records` 的终态和调用者状态。
5. 结果异常时，把全部 `body_streams.retention_state` 设为 `full`。异常指：forward 不是 completed、capture 不是 complete、没有状态码或状态码不在 2xx/3xx、解析状态为 skipped。
6. 调 `capturePayloadDigest`，再 `appendIntegrityEvent(capture_finalized)`。

`applyWrite` 处理 `writeFinishAudit` 时，会先对该 audit 未写标记的恢复条目执行 `recoverCaptureEntry`，再检查恢复溢出〔核〕。

### A.2 一条典型流式请求的操作数和提交数

前提：四个阶段都到达，各阶段 Body 小于 1 MiB，没有 trailer。

| 来源 | 操作 | 个数 | 同步 |
| --- | --- | --- | --- |
| `Begin` | `BeginAudit` | 1 | 是 |
| 每个阶段 | `StartStage`、`AddHeaders`、`StartBody`、`AddChunk` | 4×4 = 16 | 否 |
| `Finish` | `FinishStage`×4、`FinishAudit` | 5 | `FinishAudit` 是 |
| 解析 worker | `ClaimPendingParse`、`SaveParsedAudit` | 2 | 都是 |

采集共 22 个操作〔核，按代码数出〕。每多 1 MiB，该阶段多一个 `AddChunk`；每组 trailer 多一个 `AddHeaders`。

每个操作有自己的 `SAVEPOINT writer_operation`。批次最多 64 个操作，或者等 5 ms（`types.go` 的 `writerBatchSize`，`open.go` 的 `writerBatchDelay`）〔核〕。所以提交数取决于并发和时序，从代码推不出。附录 B.2 的实测是每条 audit 27.74 次（heavy）和 17.76 次（small），其中包括读连接上的只读语句。

### A.3 各种失败怎么处理

| 情形 | 代码 | 结果〔核〕 |
| --- | --- | --- |
| 队列满 | `submitAsync` 不阻塞，直接返回 `ErrQueueFull`；如果是 `FinishAudit`，先调 `rememberFailedWrite` | 依失败的操作而定：`StartStage` 失败，阶段 `faulted`、错误码 `start_stage_failed`，阶段不持久，也不写 Header；`StartBody` 失败，`start_body_failed`；`AddChunk` 失败，`add_chunk_failed`，`storedLength` 不增加；`AddHeaders` 失败，`add_headers_failed`；`FinishStage` 失败，`captureStatus=partial`、`audit_finalize_failed`。available 模式记一次 `queue_full` gap，一个会话最多记一次（`recordGapReasonLocked` 的 `gapRecorded`） |
| 可隔离的写失败（SQLSTATE 23xxx、本地校验错误等，见 `canIsolateWriteError`） | `commitBatch` 回滚到该操作的 savepoint，然后 `markCaptureWriteFailed` | audit 标 `capture_status='failed'`、`capture_write_failed`；Header 写失败的阶段标 `capture_headers_failed`；缺块的 Body 标 `capture_chunk_missing`。同批的其他操作照常执行 |
| 存储级失败 | 整批回滚，每个操作调 `rememberFailedWrite`，writer 置为不健康 | `recoverCaptureWrites` 每 5 秒处理至多 16 个 audit：补记失败标记，并在队列屏障之后补写终态。恢复表上限 1024 条，满了锁定溢出状态，拒绝新的准入 |
| strict 与 available | `proxy.go` `beginAudit` | 只在 `BeginAudit` 上有区别：strict 失败回 503，available 失败照常转发、不建 audit。会话只在 available 模式记 gap（`newSession`）。`BeginAudit` 之后的写失败在两种模式下都只降级证据 |
| 客户端取消 | `MarkClientCancelled`、`markFailure`、`observeWrite` 和 `observeRead` 里对 `request.Err()` 的判断 | 记为 `client_cancelled`，置 `captureFault`。终止事件之后的断开按 completed 处理（`responseLogicallyCompleteLocked`） |
| 上游中断 | `observeRead(response_received)` 读错误 | `body_read_error`，`newapi_error`/`upstream_body_read_error`；上游不可达时，`ErrorHandler` 自己写 502 或 504 的 JSON |
| 进程退出 | 下次启动时，`internal/app/app.go` 在 `EnableIntegrity` 之后调 `RecoverInterruptedAudits`（`internal/storage/postgres/recovery.go`） | `ended_at_ns IS NULL` 的 audit 改为 `interrupted`；streaming 的阶段和 Body 改为 partial、`process_exit`；按已提交的块修正长度；raw 一律 `full`；每条签一个 `capture_finalized`；插入一条聚合的 `process_exit` gap |

### A.4 legacy 崩溃时库里有什么

以一条流式请求为例：它在不同时刻崩溃时，legacy 已经提交的内容如下。依据都在 A.1。

| 崩溃时刻 | legacy 已提交〔核〕 |
| --- | --- |
| 请求 Body 正在上传 | 起始行；两个请求阶段的行（streaming）及其 Header；两个请求阶段各自已满 1 MiB 的块 |
| 请求读完，响应头还没到 | 以上全部；加上两个请求阶段的尾块和请求 trailer |
| 响应流到一半 | 以上全部；加上两个响应阶段的行及其 Header；两个响应阶段各自已满 1 MiB 的块 |

丁下的对照见 B.7。

### A.5 流结束时刻与终结提交的先后

`internal/proxy/stream_end_order_test.go` 用一个包着 `*sqlite.Store` 的 `blockingFinishStore`，挡住 `FinishAuditWithResult`〔核〕。它固定了方案 2.2 那张表，各类响应结束的时刻相对终结提交如下：

| 响应类型 | 响应结束 |
| --- | --- |
| HTTP/1.1 分块 | 晚于终结提交 |
| HTTP/2 | 晚于终结提交 |
| 带 `Content-Length` 的 HTTP/1.1 | 早于终结提交 |
| 代理自己生成的错误 JSON | 连状态行都晚于终结提交 |

### A.6 本阶段不能改变的东西

1. **转发字节和时序。** 能变的只是“终结提交”写了什么；它挡住处理函数返回这件事不变，所以 A.5 那张表在 `unified` 下必须逐格相同。检查点是不等待的，不影响时序。
2. **`BeginAudit` 同步。** 两种模式下都同步（5.6）；strict 只在准入时生效。
3. **defer 的顺序：** 先 `CaptureTrailers`，再 `Finish`（等提交），最后写完成日志。完成日志和 `TerminalSummary` 取的都是已提交的终态。
4. **四个阶段独立采集。** 各阶段有自己的长度、SHA-256、时间、状态和错误码；`body_stage_mismatch` 的判定、“终止事件之后断开算完成”的规则、gap 的语义都不变。
5. **成对合并。** 合并的条件和合并后的行形态都不变（B.5）。
6. **raw 保留。** 异常结果的 raw 保留为 `full`；`DecideRawRetention` 的按侧规则不动。
7. **已有数据。** 旧行和旧事件照常读取和校验，不重写任何已有的行。

---

## B. 阶段性提交：两个检查点和 `CommitAudit`

### B.1 一条请求的三次写〔设〕

| 写 | 何时 | 写什么 | 等待 |
| --- | --- | --- | --- |
| 检查点 1（请求侧） | `request_sent` 的 Body 读完（EOF、Close 或读错误），并且 forward 还在进行中 | 两个请求阶段的行（streaming）及其 Header；两个请求 Body 的行（初值），按 B.5 在这里定下的合并结果；请求侧全部拥有块；v2 的残缺 Header 块 | 否 |
| 检查点 2（响应侧） | `response_sent` 阶段开始，也就是响应头已经转发给客户端的那一刻（`observedResponseWriter.start`）；并且 `response_received` 已存在，forward 还在进行中 | 两个响应阶段的行（streaming）及其 Header；检查点 1 没有写到的请求侧内容；v2 的残缺 Header 块 | 否 |
| `CommitAudit` | `Finish` | 其余全部，把各行更新到终值，然后终结和签名 | 是 |

几点说明：

- 维护者说的是“响应头到达时”。触发点取 `response_sent` 开始而不是 `WrapResponseReceived`，是为了让两个响应阶段的行和 Header 落在同一个检查点里。`ReverseProxy` 在 `ModifyResponse` 之后先拷贝响应头，再 `WriteHeader`〔推，按标准库的流程〕，两者相差只有几微秒。
- 触发条件都要求 forward 还在进行中，所以下面几种请求的 `Finish` 紧随其后，跳过检查点，只提交一次：被拒绝的请求（没有 `request_sent`）、上游不可达的请求（错误 JSON 没有 `response_received`）、已经取消的请求。
- 请求没有 Body（例如 GET）时，检查点 1 不会触发，请求阶段的行和 Header 由检查点 2 带上。
- 上游可能在读完请求 Body 之前就回了响应头。这时检查点 2 先发生，它带上请求侧到那时为止已经封好的块（下一条）；请求 Body 之后读完时，检查点 1 仍然触发，写剩下的部分。
- 检查点只写“封好的块”：已满 1 MiB 的块，或者 Body 已经结束时的尾块，也就是 legacy 到那一刻已经 flush 的块，所以块边界与 legacy 相同。

检查点写的是自上一次写之后新增的内容。会话为每个阶段记住：行是否已写、Header 组（v1）或块版本（v2）是否已写、Body 行是否已写、块写到哪个 seq。没有新增内容的检查点不发出。

### B.2 输入类型〔设〕

放在 `internal/storage/types.go`，两个存储共用：

```go
// AuditCheckpoint 是在途请求的一次不等待的写。它只插入还没写过的行，
// 形态与 legacy 在途时已提交的行相同（B.4），从不写终值。
type AuditCheckpoint struct {
    AuditID        string
    CaptureVersion int
    Stages         []HTTPStage   // 新阶段：State=streaming，EndedAtNS=nil，状态码与长度取阶段开始时的值
    Headers        []HTTPHeader  // 仅 v1：新增的 (stage, kind) 组
    HeaderBlock    *HeaderBlock  // 仅 v2：到此为止的整块，覆盖写
    Bodies         []BodyStream  // 新 Body：初值（长度 0、无哈希、streaming、pending）；SourceStage 见 B.5
    Chunks         ChunkSource   // 新封好的拥有块
}

// AuditCommit 是 Finish 时的终结写。起始行已由 BeginAudit 写入。
type AuditCommit struct {
    Finish         AuditFinish
    CaptureVersion int           // 必须等于起始行上的值
    Stages         []StageCommit // 全部到达的阶段，按 stageOrder 排列
    Headers        []HTTPHeader  // 仅 v1：检查点没有写过的组（主要是响应 trailer）
    HeaderBlock    *HeaderBlock  // 仅 v2：完整的块；与最后一次检查点相同时为 nil
    Chunks         ChunkSource   // 检查点没有写过的拥有块
    DedupInDB      [2]bool       // 两对阶段各一个：在内存里定不下来时，沿用写库后合并（B.5）
    FinalAttempt   bool          // 最后一次重试（B.8）
    PayloadBytes   int64
}

type StageCommit struct {
    Stage           HTTPStage   // 终值
    StageWritten    bool        // 检查点已插入该阶段行：终结时 UPDATE，否则 INSERT
    ContentType     *string     // 仅 v2，见 C.6
    ContentEncoding *string
    Body            *BodyStream // 终值；合并的一方已是合并后的形态
    BodyWritten     bool        // 检查点已插入 Body 行
    Timeline        *StreamTimeline
}

type HeaderBlock struct {
    Compression     string
    PlaintextLength int64
    DataEnc         []byte
}

// ChunkSource 可以重复遍历；每一项要么是内存里的密文，要么是暂存文件中的位置（F.4）。
type ChunkSource interface {
    Each(visit func(BodyChunk) error) error
}
```

`AuditRecord` 增加 `CaptureVersion int` 和 `UserAgentEnc []byte`，由 `BeginAudit` 写入（C.5）。legacy 路径两者都留零值：前者取列默认值 1，后者为 NULL。

`audit.Store`（`internal/audit/manager.go`）增加两个方法：

```go
Checkpoint(context.Context, storage.AuditCheckpoint) error                     // 异步
CommitAudit(context.Context, storage.AuditCommit) (storage.AuditFinish, error) // 同步
```

writer 增加两种操作：`writeCheckpoint` 和 `writeCommitAudit`。writer 队列是 FIFO，同一 audit 的检查点总是在它的 `CommitAudit` 之前执行〔核：单 writer 按入队顺序处理，`runWriter`〕。

### B.3 检查点在一个 savepoint 里写什么〔设〕

1. `SELECT ended_at_ns FROM audit_records WHERE audit_id=$1`。已终结时什么都不写，正常情况下不会出现。
2. 多行 `INSERT INTO http_stages`，写 streaming 初值。
3. v1：多行 `INSERT INTO http_headers`。v2：`INSERT INTO http_header_blocks … ON CONFLICT (audit_id) DO UPDATE` 覆盖写。
4. 多行 `INSERT INTO body_streams`，写初值。
5. `body_chunks` 多行 INSERT，从 `ChunkSource` 分批取。

批量上限沿用 `graph_writer.go` 的 `forEachInsertBatch`：每条语句至多 400 行、行数据约 4 MiB（`graphHashQueryBatch`、`objectInsertBatchBytes`）〔核〕。`body_chunks` 有 9 列，400 行是 3,600 个绑定参数，远低于协议上限 65,535，实际由 4 MiB 限住。

这些插入用的就是 legacy 的 `insertStage`、`insertHeaders`、`insertBody`、`insertChunk` 的列和取值〔设：抽成多行版本，语义不变〕，所以写出的行与 legacy 在同一时刻已提交的行同形。

### B.4 两次检查点之间的行，与 `RecoverInterruptedAudits` 的关系

legacy 在途时已提交的行〔核〕：

- **阶段行：** `insertStage` 写 `state='streaming'`、`ended_at_ns` 为 NULL，状态码和长度取阶段开始时的值。
- **Body 行：** `insertBody` 写初值。初值是：`observed_length=0`、`stored_length=0`、`sha256` 为 NULL、`hash_complete=0`、`eof_seen=0`、`state='streaming'`、`retention_state='pending'`、`chunk_count=0`、`stream_event_count=0`、`stream_timeline_complete=1`、`source_stage` 为自身。其中 `stream_timeline_complete=1` 来自 `BodyStream.Defaults`：没有事件时取 true。
- **块：** 从 seq 0 起连续。

`FinishStage` 之前，这些行一直保持初值。

检查点写出的行与此相同，只有一处不同：合并了的 `request_sent`，其 Body 行的 `source_stage` 写成 `request_for_newapi_received_from_nginx`，而且没有自己的块。

`recoverInterruptedAudits` 处理这样的行，需要的逻辑都已存在〔核：`recovery.go`〕：

- 它的块聚合按 `lengths.stage = body_streams.source_stage` 关联，所以合并的一方从来源阶段的块得到 `stored_length`、`observed_length` 和 `chunk_count`，这与 legacy 合并后的语义一致；
- 它只改 `state = 'streaming'` 且 audit 未终结的行，清掉 SHA-256 和 EOF，置 partial、`process_exit`、raw `full`，然后签名；
- 对已标 failed 的 audit，它先调 `finalizeIncompleteCapture`，后者同样按 `source_stage` 聚合〔核〕。

所以 `RecoverInterruptedAudits` 不需要新逻辑。

外键也都满足：`body_streams(audit_id, source_stage)` 引用 `http_stages`，而来源阶段的行由同一个检查点插入〔核：`001_init.sql`〕。

### B.5 成对阶段的判定

现有的合并条件见 `writer.go` 的 `deduplicateEquivalentBodyPair`，对两对阶段各判一次：(request_received, request_sent) 和 (response_received, response_sent)〔核〕。只在已存 `capture_status` 不是 failed 时判；partial 的 audit 也判，因为条件只看 Body 本身。下面八条全部成立才合并：

| # | 条件 | 内存里的对应 |
| --- | --- | --- |
| 1 | 两个阶段都有 `body_streams` 行 | 两个阶段都有 `stage.body` |
| 2 | 各自的 `source_stage` 等于自身 | 恒成立：`ensureBodyLocked` 令 `sourceStage = stage.name` |
| 3 | 两者都是 `state = complete` | 用 `finishStageLocked` 的规则算出：没有 fault、`eofSeen`、`storedLength == observedLength` |
| 4 | 两者 `hash_complete = 1`、`eof_seen = 1` | `body.hashComplete && body.eofSeen` |
| 5 | 各自 `stored_length = observed_length` | 来源阶段：保留的字节（内存加暂存）没有因耗尽而截断；重复阶段：见下文的“借用前缀” |
| 6 | 两者 `observed_length` 相等，`sha256` 长 32 字节且相等 | 同一个比较 |
| 7 | 各自的块数和长度之和等于 `chunk_count` 和 `stored_length` | 恒成立，块与计数同源 |
| 8 | 已存 `capture_status` 不是 failed | 见 B.8：检查点失败会使它成为 failed，这时与 legacy 一样不合并 |

合并后，重复阶段的行取来源阶段的 `source_stage`、`stored_length`、`chunk_count`、`stream_event_count` 和 `stream_timeline_complete`，其余列保留自己的值〔核〕。

**请求对，在检查点 1 判定。** 检查点 1 触发时 `request_sent` 已经读完。

- 正常情况下 `request_received` 先读完：两者同步读，入站先于出站；有 body 拦截器预读时，入站更早读完〔核：`body.go`，模块 03 §5〕。
- 两者都满足上表时就合并：检查点 1 把 `request_sent` 的 Body 行写成 `source_stage = request_received`，不写它的块。
- `request_received` 还没读完时（不应出现，但类型上不排除），不在内存里判定：检查点 1 写两份块，`CommitAudit` 置 `DedupInDB[0] = true`，由现有的 `deduplicateEquivalentBodyPair` 在终结时按 legacy 的方式合并。
- 检查点 1 之后，请求 Body 还可能被标记故障，例如 Close 返回错误时的 `body_close_error`（`closeReadBody`）〔核〕。所以 `Finish` 时按终值再判一次：
  - 仍然满足：`CommitAudit` 把重复阶段的 Body 行更新为合并后的终值。
  - 不再满足：`CommitAudit` 把它的 `source_stage` 改回自身，并插入它自己的块。块由请求明文重新封成，AAD 绑定的是该阶段自己的名称，所以来源阶段的密文不能复用。为了保证明文还在，检查点 1 合并了的请求，其明文在 `Finish` 之前不丢弃；内存紧张时可以落暂存，但不丢（F.2）。

**响应对，在 `Finish` 判定。** 检查点不写响应 Body，内存做法沿用初稿：

- 来源阶段 S 照常保留字节。
- 重复阶段 D 不复制字节，只维护“已比对相等的前缀长度”。
- 出现第一个不相等的字节（偏移 d）时，D 转为“自持”：从 d 起自己保留字节，前缀 [0, d) 向 S 借用。
- D 观察到超出 S 已观察长度的字节时，把超出部分放进前瞻缓冲，等 S 追上再比；缓冲超出单阶段预算时，D 转为自持。
- S 释放一块明文的条件是：这一块已经封好，并且 D 已比对过它的末尾，或者 D 已经自持、已经结束。D 通常只落后一次 Read，`ReverseProxy` 的拷贝缓冲是 32 KiB（`proxy.go` 的 `newBufferPool(32 << 10)`）〔核〕。
- 不合并时，D 的块由借用的前缀加上自持的字节切出，块边界按 D 自己的偏移每 1 MiB 一块。每块的 `observed_at_ns` 取 D 观察到该块第一个字节的时刻（legacy 的 `pendingAtNS`）。

块边界：legacy 只在攒满 1 MiB 时，以及 EOF、Close、Finish 时强制 flush（`observeBodyLocked`、`flushBodyLocked`）〔核〕。按同样的规则切块，块行就逐行相同。全局预算压力下提前落暂存时，块可能不足 1 MiB（F.2），这是合理差异。

### B.6 `CommitAudit` 在一个 savepoint 里写什么〔设〕

`applyWrite` 对 `writeCommitAudit` 做与 `writeFinishAudit` 相同的前置检查：未标记的恢复条目，以及恢复溢出。然后依次：

1. `SELECT ended_at_ns, capture_version, capture_status FROM audit_records WHERE audit_id=$1 FOR UPDATE`。
   - 已终结：调 `loadFinishedOutcome`，不写任何行，返回已提交的终态。重试遇到一次结果不确定的提交时就会走到这里。
   - 版本不符：返回本地错误。
2. 对每个阶段：
   - `StageWritten` 时，调现有的 `finishStage(transaction, StageFinish)`，它会更新阶段行，有 Body 时也更新 Body 行，并插入时间线。保留 `capture_headers_failed`、`capture_storage_failed` 的 CASE 也随之沿用；
   - 否则插入终值行。
   - 已存状态为 failed 时，检查点留下的缺行会让 `finishStage` 碰到 0 行。这时跳过该部件，不报错，由第 6 步的 `finalizeIncompleteCapture` 对账。已存状态不是 failed 却碰到 0 行，属于不一致，返回本地错误。
3. 检查点 1 合并、终结时不再合并的请求对：`UPDATE body_streams SET source_stage = stage`，并插入重复阶段自己的块（B.5）。
4. v1：插入剩下的 Header 组，主要是响应 trailer。v2：`HeaderBlock` 不为 nil 时覆盖写完整的块。
5. 插入剩下的块，即响应侧的块和暂存中的块。
6. 调现有的 `finishAudit(transaction, &commit.Finish, signer, dedupInDB)`。两对中在内存里定下的跳过合并，`DedupInDB` 为 true 的照旧在库里合并。之后的 `finalizeIncompleteCapture`、终态 UPDATE、异常时设 raw `full`、按 `capture_version` 分派的摘要（D.3）、`capture_finalized` 事件，都与现在相同。

### B.7 崩溃时留下的证据：legacy 与丁

以一条流式请求为例。检查点和 legacy 的异步操作一样，入队后几毫秒内提交，下表忽略这段时间差。

| 崩溃时刻 | legacy（A.4）〔核〕 | 丁〔设〕 | 差异 |
| --- | --- | --- | --- |
| 拦截器执行中，包括 body 拦截器预读 | 起始行；`request_received` 的行和 Header；预读超过 1 MiB 时还有已满的块 | 起始行和 `user_agent_enc`（C.5） | 入站阶段行、Header 和块都没有。拦截器通常很快，预读有上限 |
| 请求 Body 正在上传 | 起始行；两个请求阶段的行和 Header；两个请求阶段各自已满 1 MiB 的块 | 起始行和 `user_agent_enc`。请求 Body 超过 8 MiB 时，落暂存那一刻起会有一个检查点（F.3）：阶段行、Header 和 Body 行进库，超出预算的块进暂存，启动时导入 | 不足 8 MiB 的请求 Body 什么都不留。这是维护者接受的差异。另外，请求阶段的行和 Header 在这段时间里也没有：决定 1 的触发点在请求 Body 读完时 |
| 请求读完，响应头还没到 | 以上全部；加上两个请求阶段的尾块和请求 trailer | 检查点 1：两个请求阶段的行和 Header（v2 为残缺块），请求侧全部块；合并时只有来源阶段的块 | 合并了的 `request_sent` 没有自己的块，`source_stage` 指向来源阶段。字节已按长度和 SHA-256 证明相同 |
| 响应流到一半 | 以上全部；加上两个响应阶段的行和 Header；两个响应阶段各自已满 1 MiB 的块 | 检查点 1 和 2；响应 Body 只有超出 8 MiB 后落了暂存的块，启动时导入 | 响应 Body 最后不足 8 MiB 的部分没有（legacy 只丢最后不足 1 MiB 的部分）。SSE 响应体通常远小于 1 MiB（附录 A.2：`body_chunks` 的 31 GB 里 28.4 GB 是请求体），所以实际影响小 |
| `Finish` 提交之后 | 完整 | 完整 | 无 |

最后一列里有三项是维护者在决定 4 里没有提到的，记录在这里：

1. 上传期间请求阶段的行和 Header 没有；
2. 拦截器执行期间入站阶段的行和 Header 没有；
3. 响应 Body 最多丢 8 MiB，legacy 最多丢 1 MiB。

它们都不需要新机制：检查点的触发点就是决定 1 规定的那两个时刻。要消除它们，就得在阶段开始时和每满 1 MiB 时再加检查点，那会回到接近 legacy 的写法。本文按决定实施，阶段小结里报告这三项（K.1）。

### B.8 失败〔设〕

检查点失败按 legacy 中被它取代的那些操作的失败方式处理，只有队列满例外。

| 失败 | legacy 的同一批早期写失败〔核〕 | 丁 |
| --- | --- | --- |
| 检查点入队时队列满 | `StartStage` 被拒，阶段不持久、不写 Header（`start_stage_failed`）；`AddChunk` 被拒，块丢失（`add_chunk_failed`）。证据少了，记 gap | 会话同步知道入队失败，数据都还在内存里：把这个检查点的内容并入下一次写，即下一个检查点或 `CommitAudit`。证据不少，不记 gap，只记一条稳定日志 `capture_checkpoint_deferred` |
| 检查点的可隔离失败（23xxx 等） | 只回滚那一个操作；`markCaptureWriteFailed` 把 audit 标为 `capture_write_failed`，Header 失败的阶段标 `capture_headers_failed`；后续终结跳过合并，由 `finalizeIncompleteCapture` 对账 | 回滚整个检查点。`markCaptureWriteFailed` 增加 `writeCheckpoint` 分支，与 legacy 一样把 audit 标为 failed。检查点里的阶段行已随回滚消失，所以针对阶段的更新落空。`CommitAudit` 看到 failed，跳过缺失的部件（B.6 第 2 步），以 failed 终结。不重发失败检查点的内容，与 legacy 的结果一致：那部分证据缺失，记录如实标为 failed |
| 检查点所在批次存储级失败 | 每个操作 `rememberFailedWrite`，恢复时补标记 | `rememberFailedWrite` 增加 `writeCheckpoint` 分支：按其中每个阶段记 `affected`；有 Header 时记 `headers`，有块时记 `chunk` 和观察边界，与 legacy 的 `StartStage`、`AddHeaders`、`AddChunk` 合起来记的相同。`CommitAudit` 的前置检查先补写这些标记（`recoverCaptureEntry`），再按 failed 终结 |
| `CommitAudit` 失败 | `FinishAudit` 失败：会话以 partial、`audit_finalize_failed` 生成完成日志；`rememberFailedWrite` 记下终态，恢复时以已存状态终结 | 按下文有限次重试；仍失败时，走 `FinishAudit` 失败的同一路径 |

**`CommitAudit` 的重试。**

重试的错误：

- 入队时返回的 `ErrQueueFull`；
- 批次级失败：`commitBatch` 返回错误，整批回滚。runWriter 给这类 ack 包上新的哨兵 `storage.ErrWriteBatchFailed`，让会话能把它与操作级结果分开。一次提交结果不确定（COMMIT 报错）也属于这一类；重试是安全的，因为 B.6 第 1 步遇到已终结的行只读回。

不重试的错误，它们重来一次会以同样的方式失败：

- 操作级结果：约束冲突（23xxx）、`localWriteError`、对象完整性错误；
- `ErrRecoveryOverflow`；
- `ErrClosed`（进程正在关闭）；
- 输入校验错误。

其他参数：

- **次数：** 运行参数 `commit_retries`（H.3），默认 3，范围 0 到 5。会话在第一次失败时读一次这个原子值，正常路径不读。
- **间隔：** 第 k 次重试之前等 `min(100 ms × 2^(k-1), 1 s)`。默认 3 次时分别等 100、200、400 ms，处理函数最多多等 0.7 秒，另加各次尝试本身的时间；上限 5 次时最多多等 2.5 秒。等待期间不持有会话锁。
- **与 writer 恢复表的配合：** 重试期间，writer 不能自己去终结这条 audit，否则重试只能读回 failed。
  - 只有 `FinalAttempt = true` 的那次，批次失败或队列满时才调 `rememberFailedWrite` 记终态；
  - 可隔离的失败不会被重试，所以无论是第几次，writer 都立刻记终态，并在同一事务里调 `markCaptureWriteFailed`（`writeCommitAudit` 分支：把 audit 标 `capture_write_failed`）。
- **最终失败：** 与现在 `FinishAudit` 失败相同。会话以 `capture_status=partial`、`audit_finalize_failed` 生成完成日志和 `TerminalSummary`；恢复（`recoverCaptureEntry`）把 audit 标为 failed 并终结。检查点已经写进去的行由 `finalizeIncompleteCapture` 收尾为 partial，保留为 raw `full`。所以最终失败时，检查点写进去的请求侧证据仍在库里；legacy 在同样情形下保留的是全部已提交的异步操作。
- **不交给终结器：** 终态没有提交，交接（G.2）不发生；之后由 pending 扫描按现有路径解析。

### B.9 一条典型流式请求在丁下的操作数

前提与 A.2 相同：四个阶段都到达，各阶段 Body 小于 8 MiB，有请求 Body，没有落暂存，两对都合并。

| 来源 | 操作 | 个数 | 同步 |
| --- | --- | --- | --- |
| `Begin` | `BeginAudit` | 1 | 是 |
| 请求读完 | `Checkpoint`（检查点 1） | 1 | 否 |
| 响应头转发 | `Checkpoint`（检查点 2） | 1 | 否 |
| `Finish` | `CommitAudit` | 1 | 是 |
| 终结器 | `ClaimPendingParse`、`SaveParsedAudit` | 2 | 都是 |

采集从 22 个操作降到 4 个，处理函数路径上的同步等待仍是 2 个（`BeginAudit`、`CommitAudit`），与现在相同；解析侧仍是 2 个同步操作。每多一组请求 trailer 不增加操作，trailer 在请求 EOF 时采到，随检查点 1 写出。请求或响应超过 8 MiB 时，每个阶段第一次落暂存多一个检查点（F.3）。

语句数：

- 检查点 1：阶段、Header、Body、块各一条，v2 下 Header 是一次块的 upsert。
- 检查点 2：阶段、Header 各一条。
- `CommitAudit`：4 次 `finishStage`（各一到三条）、一次块 upsert（只在有响应 trailer 时），以及 `finishAudit` 原有的 6 到 10 条。

现在是 22 个操作，每个都有自己的 savepoint、RELEASE 和一到数条语句〔推，按代码数出〕。

与“终结时一次提交”相比，阶段行和请求侧 Body 行先插入、后更新，与 legacy 相同，所以 `audit_records` 以外的 UPDATE 次数没有减少。省掉的是：16 个异步操作及其 savepoint；成对阶段先写后删的那一份块和 Body 行；响应侧的 `StartStage`、`StartBody`。

### B.10 “与现在相同的行”

同一请求、同一时钟序列下，逐表比较终结之后的行。“相同”指非密文列逐字节相同；密文列各自用随机 nonce，比较的是解密后的明文、AAD 和长度。

| 表 | 列 | unified 与 legacy |
| --- | --- | --- |
| `audit_records` | 现有全部列 | 相同。legacy 特有的 `capture_write_failed`、`audit_finalize_failed` 只在 B.8 的失败路径出现 |
| `audit_records` | `capture_version`、`user_agent_enc`（新增） | legacy：1 和 NULL；v2：2 和 C.5 的编码 |
| `http_stages` | 现有全部列 | 相同。legacy 因入队失败才有的错误码（`start_stage_failed`、`add_headers_failed`、`start_body_failed`、`add_chunk_failed`）在 unified 下不出现：入队失败被并入下一次写 |
| `http_stages` | `content_type`、`content_encoding`（新增） | legacy：NULL；v2：见 C.6 |
| `http_headers` | 全部 | v1：除 `value_enc` 的 nonce 外相同；v2：没有行 |
| `http_header_blocks`（新增） | 全部 | 只有 v2 才有 |
| `body_streams` | 全部 | 相同，包括合并后的形态和 `retention_state` |
| `body_chunks` | `seq`、`offset`、`plaintext_length`、`compression`、`encoded_length`、`observed_at_ns` | 相同，前提是同一个编码器、同一个 Content-Type 和同样的块边界。`encoded_length` 随 Go 工具链可能变化，这是已知的（模块 18 §5）。全局预算压力下的边界见 B.5 |
| `body_chunks` | `data_enc` | 明文相同，nonce 不同 |
| `stream_timelines` | 全部 | 相同，`timeline_enc` 的 nonce 不同 |
| `integrity_events` | `capture_finalized` | `payload_digest` 不同，因为它覆盖密文哈希，v2 的结构也不同；MAC 随之不同。事件类型、时间、顺序相同 |
| `audit_gaps` | 全部 | 写失败类的 gap 只在 legacy 出现；预算耗尽的 gap 只在 unified 出现（F.6） |
| `parsed_results`、轮次图、对象 | 全部 | 相同，由 G 节保证：同一个解析函数、同一份明文 |

legacy 里合并的那一份块是先写后删的，unified 不写。所以 `pg_stat_user_tables` 上 `body_chunks` 的插入和删除计数都会下降。

### B.11 某个阶段没有到达时

与现在一样，不写该阶段的任何行（模块 03 §4）。v2 的 Header 块里也没有该阶段的段（C.3）。

---

## C. Header 块（已批准）

### C.1 现状

**采集**〔核〕：

- 阶段开始时，`startStage` → `addHeadersLocked(stage, "header", headers)`。
- 三个读阶段在 EOF 或 Close 时由 `observedReadCloser.captureTrailers` 写 trailer；`response_sent` 的 trailer 由 `observedResponseWriter.CaptureTrailers` 在 `Finish` 之前写。
- `addHeadersLocked` 把 map 的键按 `sort.Strings`（字节序）排序，对每个键取 `headers.Values(name)`，每个值单独加密。AAD 是 `security.AAD(audit_id, "header", stage, kind, name, strconv.Itoa(index))`。
- 一组 Header 是一个 `AddHeaders` 操作，存进 `http_headers`。主键是 `(audit_id, stage, kind, name, value_index)`，`name` 的排序规则为 `"C"`（`migrations/001_init.sql`）。

名称是“收到的 map 键”。`net/http` 解析出来的入站请求头和上游响应头都是规范形式；`ReverseProxy` 用 `Header.Add` 拷贝，也是规范形式。

这里有一个现存的怪癖：`http.Header.Values(k)` 会先把 k 规范化再去查。所以如果 map 里有非规范的键，那个键查到的是规范键的值：只有 `x-foo` 时，它的值一行都不写；`x-foo` 和 `X-Foo` 同时存在时，`X-Foo` 的值会以两个名称各写一遍。

- 这一点〔核〕于本机 Go 1.27.3 的标准库：`net/http.Header.Values` 调 `textproto.MIMEHeader.Values`，后者返回 `h[CanonicalMIMEHeaderKey(key)]`。仓库里没有对应的测试。
- 审计路由上，这种键只可能出现在代理自己写的响应头里，目前代码没有这样写〔推〕。

**读取方**〔核〕：

| 读取方 | 代码 | 读什么 |
| --- | --- | --- |
| 管理端详情 | `internal/query/service.go` 的 `Get` → `postgres/query_reader.go` 的 `readHeaderEvidence`（按阶段顺序、`kind`、`name`、`value_index` 排序） | 全部 Header，逐值解密；长度不符时返回 `ErrIntegrity` |
| Agent 门面 | `internal/web/agent_requests.go` 的 `agentHeadersOf`（用 `agentapi.MaskValue` 掩码凭据）、`inboundUserAgent`、Header 导出 | 都取自 `query.Detail.Headers` |
| 列表的 User-Agent | `query/service.go` 的 `List`、`listWithHeaderFilters` → `readUserAgent` → `QueryRequestHeaderEvidence` | 每行查询一次（N+1）。显示第一个值；任一值包含子串（不区分大小写）就算匹配；没有 UA 时不匹配 |
| parser 的 allowlist | `parser/evidence.go` 的 `loadRequestHeaders` → `LoadParserRequestHeaders`，在 SQL 里按 `lower(name) IN (...)` 过滤 | 只解密名单内的入站 Header，供洞察和项目标识使用（`parser/project.go`、`parser/backfill.go`） |
| parser 的内容头 | `LoadParserStage` 读该阶段 `content-type`、`content-encoding` 的密文行；`loadBody` → `decryptContentHeaders` 解密，各取第一个非空值 | 两个值 |
| 回填判断 | `backfillInput`、`responseReleased` 调 `LoadParserStage`，只看 `retention_state` | 会读出内容头的密文，但不解密 |
| 测试快照 | `postgres/reader.go` 的 `Snapshot` | 全部密文 |
| 离线导入 | `internal/storage/migrate/verify.go` 的 `verifyEncrypted` 中的 `http_headers` 分支 | 逐值解密校验。源只能是 SQLite |
| 完整性 | `postgres/integrity.go` 的 `capturePayloadDigest` | 每行的元数据和密文哈希（D.1） |

### C.2 存放位置

块放在独立表 `http_header_blocks` 里，`user_agent_enc` 放在 `audit_records` 上。理由如下：

- 块压缩加密后约 1 到 3 KB〔推〕，而 `audit_records` 每行平均被更新约 4 次，没有一次是 HOT 更新（附录 B.2）。块放在行内时，每次更新都要把它再写一遍 WAL。块放进 TOAST 时，行仍然变宽，列表按索引回表要读的页也随之变多。
- 独立表只写一次，到期时随 `ON DELETE CASCADE` 一起删除。

在丁下，块在检查点会被覆盖写两次，见 C.8。

### C.3 明文编码〔设〕

```
block        = magic version stage_section*
magic        = 0x4C 0x4C 0x48 0x42                 ; "LLHB"
version      = 0x01
stage_section = stage_code kind_section kind_section ; 先 header，后 trailer
stage_code   = 1 字节：1 request_received，2 request_sent，3 response_received，4 response_sent
kind_section = u32be(name_count) name_entry*
name_entry   = u32be(len(name)) name u32be(value_count) value*
value        = u32be(len(bytes)) bytes
```

规则：

- **哪些阶段有段。** 只有已写入的阶段有段，按 stage_code 严格递增。没有到达的阶段没有段。
- **空段。** 到达了但没有 Header 的阶段，两个 `name_count` 都是 0。没有 trailer 时，trailer 段的 `name_count` 是 0。
- **名称。** 就是现在 `http_headers.name` 会存的值：map 键原样。同一 kind 内按字节序严格递增，不重复。
- **值。** 每个名称的值按 `value_index` 顺序排列，`value_count ≥ 1`。编码复用 `addHeadersLocked` 的循环，也就是 `sort.Strings` 加 `headers.Values(name)`，C.1 的怪癖原样保留。
- **解码。** 逐条校验以上规则，以及长度不越界、没有尾随字节；任何一条不满足都按完整性错误处理。
- **上限。** `plaintext_length` 不超过 64 MiB。

“展开”成扁平列表时，顺序是：阶段顺序；同一阶段内 header 在 trailer 之前；然后按名称的字节序；最后按 `value_index`。这正是 `readHeaderEvidence` 的 `ORDER BY` 在 `"C"` 排序规则下的顺序〔核〕，`ValueLength` 取 `len(value)`。

Header 在阶段开始的那一刻深拷贝。原因是 `ReverseProxy` 之后还会往同一个响应头 map 里补 trailer 的键；legacy 在阶段开始时当场加密，等于当场做了快照〔核：`startStage`〕。

### C.4 压缩与加密〔设〕

- **压缩：** `bodycodec.Encode(plaintext, "application/x-llmapi-header-block")`。`LLHB` 不是已知的压缩魔数，所以 128 字节以上、压缩后能省 32 字节以上时用 gzip（`internal/bodycodec/codec.go`）〔核〕。
- **加密：** AES-256-GCM，AAD 为 `security.AAD(audit_id, "header_block_v1", compression)`。
- **存储：** 存 `compression`、`plaintext_length` 和 `block_enc` 三列。读取时依次认证解密、用 `bodycodec.Decode(…, plaintext_length)` 解压并核对长度，再按 C.3 严格解码。

### C.5 `user_agent_enc`〔设〕

- **值的来源：** `request_received` 阶段、kind 为 header、`strings.EqualFold(name, "user-agent")` 的所有键，按名称的字节序取，每个键内按 `Values` 的顺序。
- **明文：** `0x01 (u32be(len) bytes)+`，至少一个值。
- **缺失：** Header 缺失时为 NULL。不压缩。
- **AAD：** `security.AAD(audit_id, "user_agent_v1")`。
- **写入时机：** `BeginAudit`。在途请求和崩溃后恢复的记录在列表里也有 UA。
- **读取：** `ListAudits` 的 SELECT 增加 `a.capture_version, a.user_agent_enc`。v2 行在内存里解密，语义同 `readUserAgent`〔核〕；v1 行照旧逐行调 `QueryRequestHeaderEvidence`。分派一律按 `capture_version`。

### C.6 parser 需要、又不必解密块的事实〔设〕

`http_stages` 增加 `content_type` 和 `content_encoding` 两列，都是 `TEXT COLLATE "C"`，可以为 NULL，带 `CHECK (<> '')`。

- **取值规则：** 复刻 `decryptContentHeaders` 的规则〔核〕：取该阶段 kind 为 header、名称小写后等于目标名的第一个非空值；没有就是 NULL。
- **写入：** 两列随阶段行一起写入，在检查点里就写，所以 metadata 记录的回填扫描在 v2 下从不解密块。
- **`LoadParserStage`：** v2 行不再查询 Header，直接读这两列；v1 行照旧。
- **文档：** 同步更新模块 09 §8 和模块 23。

### C.7 各读取方的新旧两条路

新增包 `internal/headerblock`，只依赖 `security`、`bodycodec` 和标准库：

```go
func Encode(stages []Stage) ([]byte, error)
func Decode(plaintext []byte) ([]Stage, error)
func Seal(c security.Cipher, auditID string, plaintext []byte) (compression string, length int64, enc []byte, err error)
func Open(c security.Cipher, auditID, compression string, length int64, enc []byte) ([]byte, error)
func EncodeUserAgent(values []string) []byte
func OpenUserAgent(c security.Cipher, auditID string, enc []byte) ([]string, error)
// Expand 是唯一的读取入口，按 capture_version 分派，输出 C.3 的扁平顺序。
func Expand(c security.Cipher, auditID string, src Source) ([]Value, error)
```

`storage` 增加 `HeaderSource{CaptureVersion int; Rows []HeaderEvidence; Block *HeaderBlockEvidence; StageSet []string}`。

| 读取方 | 改动 |
| --- | --- |
| 详情 | `queryAuditDetail` 返回 `HeaderSource`；`query.Service.Get` 改调 `headerblock.Expand`。`Detail.Headers` 不变，web、Agent 门面、导出和掩码都不用改 |
| 列表 | C.5 |
| parser allowlist | 新增存储方法 `LoadParserHeaderSource`。v1 照旧在 SQL 里过滤；v2 在进程内解密整块，在内存里过滤，再清掉其余的值（决定 2，写进模块 09 §8） |
| parser 内容头 | C.6 |
| `Snapshot` | 增加 `HeaderBlock` 字段 |
| 离线导入 | 不变 |
| 完整性 | D.3 |

### C.8 检查点上的残缺块〔设〕

v2 下，凡是插入阶段行的写（检查点 1、检查点 2、`CommitAudit`），都在同一个操作里覆盖写整块，块里含到那时为止已写入的全部阶段。由此有一个不变式：**块里有段的阶段集合，等于 `http_stages` 里该 audit 的阶段集合。** 这里说的“阶段集合”是一回事，不是说块里的内容是完整的。

各个时刻的块：

| 时刻 | 块里的内容 |
| --- | --- |
| 检查点 1 之后 | 两个请求阶段的 header 段，以及 trailer 段（请求 trailer 在 EOF 时已经采到） |
| 检查点 2 之后 | 再加上两个响应阶段的 header 段；它们的 trailer 段还是空的 |
| `CommitAudit` 之后 | 完整：加上响应 trailer，以及未经检查点、直接终结的阶段。和检查点 2 写的块相同（没有响应 trailer）时不重写，`HeaderBlock` 为 nil |

`Expand` 读取 v2 时校验这个不变式：块里的阶段集合与 `HeaderSource.StageSet` 不等，就按完整性错误处理。

崩溃或终结失败的记录，留下的是最后一次成功的检查点写出的块，这个块只缺 trailer，或者缺之后才到达的阶段。读取方照常展示；阶段行为 partial、`process_exit` 或 failed，本身就说明了它是残缺的。

---

## D. `capture_version` 与 `capturePayloadDigest` v2（已批准）

### D.1 v1 的确切字节序列〔核：`postgres/integrity.go` 的 `capturePayloadDigest`、`digestEncoder`〕

先定义几个编码记号：

- `F(x) = uint64be(len(x)) || x`
- `I(v) = F(uint64be(v))`
- `NI(v)`：NULL 时为 `F(nil)`，否则为 `I(v)`
- `NT(s)`：NULL 时为 `F(nil)`，否则为 `F(s)`
- `CD(d) = F(d)`，其中 d 是数据库算出的 `CASE WHEN octet_length(col) > 0 THEN sha256(col) END`

摘要是 `SHA-256` 作用在下面这个序列上：

```
"llmapi-logger/capture-payload/v1\x00"            ; 原样写入，没有长度前缀
F(audit_id)
I(started_at_ns) I(ended_at_ns)
F(route_id) F(protocol) F(parser_name) F(method) F(path) F(mode) F(forward_status) F(capture_status)
CD(sha256(request_uri_enc))
NI(status_code) NI(ttft_ns) NT(blocked_by) NT(block_code) NT(error_code) NT(newapi_request_id)
对 http_stages 的每一行，按阶段顺序：
  F("stage") F(stage) F(state) F(proto) F(method) F(host)
  NI(status_code) NI(content_length) I(started_at_ns) NI(ended_at_ns) NT(error_code)
对 http_headers 的每一行，按 阶段顺序, kind, name, value_index（"C" 排序规则）：
  F("header") F(stage) F(kind) F(name) I(value_index) I(value_length) CD(sha256(value_enc))
对 body_streams 的每一行，按阶段顺序：
  F("body") F(stage) F(source_stage) I(observed_length) F(sha256 或 nil)
  I(hash_complete) I(eof_seen) F(state) NI(first_observed_at_ns) NI(last_observed_at_ns) NT(error_code)
```

几处细节〔核〕：

- `ended_at_ns` 以非空类型扫描，所以只对已终结的 audit 求值。
- body 行的 `sha256` 直接用 `field` 写入，不经过 `CASE`。
- 在 `F` 编码下，NULL 文本与 `''` 无法区分。

v1 不覆盖下面这些：

- `body_streams` 的 `stored_length`、`chunk_count`、`retention_state`、`stream_event_count`、`stream_timeline_complete`；
- `body_chunks` 和 `stream_timelines` 两张表；
- `audit_records` 的 `schema_generation`、`parse_status`、`caller_*`、`api_key_fpr`、`parse_save_failures`、`parse_next_at_ns`。

### D.2 v2 的确切字节序列〔设，已批准〕

```
"llmapi-logger/capture-payload/v2\x00"
F(audit_id)
I(started_at_ns) I(ended_at_ns)
F(route_id) F(protocol) F(parser_name) F(method) F(path) F(mode) F(forward_status) F(capture_status)
CD(sha256(request_uri_enc))
NI(status_code) NI(ttft_ns) NT(blocked_by) NT(block_code) NT(error_code) NT(newapi_request_id)
CD(sha256(user_agent_enc))
对 http_stages 的每一行，按阶段顺序：
  F("stage") F(stage) F(state) F(proto) F(method) F(host)
  NI(status_code) NI(content_length) I(started_at_ns) NI(ended_at_ns) NT(error_code)
  NT(content_type) NT(content_encoding)
F("header_block")
  NT(compression) NI(plaintext_length) CD(sha256(block_enc))   ; 没有块时，三项都写 F(nil)
对 body_streams 的每一行，按阶段顺序：                          ; 与 v1 相同
  F("body") F(stage) F(source_stage) I(observed_length) F(sha256 或 nil)
  I(hash_complete) I(eof_seen) F(state) NI(first_observed_at_ns) NI(last_observed_at_ns) NT(error_code)
```

几点说明：

- 新增的三个哈希都在数据库里求，与第 1 阶段一致；块的哈希用 `LEFT JOIN http_header_blocks` 取得。
- 新增的两列有 `<> ''` 约束，所以不会出现 NULL 与 `''` 混淆的问题。
- `capture_version` 本身不作为一个字段写入：版本已经由域字符串绑定。

### D.3 校验怎么选版本

新增 `capturePayloadDigestFor(ctx, tx, auditID, schema)`：

1. `schema=live` 时读 `capture_version`。
2. 按版本分派：1 调现有的 `capturePayloadDigest`，一个字节都不改；2 调 `capturePayloadDigestV2`；其他值返回错误，载荷校验 sticky 失败。
3. 写入方（`finishAudit`、`recoverInterruptedAudits`）和校验方（`integrityPayloadDigest`）都走这个函数。

篡改 `capture_version`，无论 1 改 2、2 改 1，还是改成别的值，都会让载荷校验失败。两个域字符串的前 31 个字节相同，第 32 个字节分别是 `1` 和 `2`，所以两段 SHA-256 的输入从第 32 个字节起就不同。事件里的摘要受 HMAC 保护，没有密钥无法重签。

`capture_version` 有 `CHECK (capture_version IN (1, 2))` 约束。它在 `BeginAudit` 时写定，之后不再改变；`CommitAudit` 会核对它与输入一致。

离线导入的目标只有 001 基线，没有 `capture_version` 这一列〔核：`migrate/importer.go` 的 `Run`，`postgres/integrity.go` 的 `VerifyImportIntegrity`〕。所以 `verifyIntegrityPayloadsTransaction` 增加 `schema` 参数，`VerifyImportIntegrity` 传 `schema=baseline`，直接取 1。加一个测试：导入 SQLite 夹具，然后首次启动（应用迁移 006 和 007），全部行仍按 v1 通过校验。

### D.4 摘要何时计算，是否覆盖残缺块〔设〕

摘要只在终结时计算一次，从不在检查点计算。

| 终结方式 | 代码 | 当时库里的块 |
| --- | --- | --- |
| 正常终结 | `CommitAudit` 第 6 步，经 `finishAudit` | 完整的块 |
| 崩溃后的启动恢复 | `recoverInterruptedAudits` | 最后一次成功的检查点写出的残缺块；没有任何检查点时没有块 |
| 终结失败后的 writer 恢复 | `recoverCaptureEntry` → `finishAudit` | 同上 |

所以摘要**会**覆盖残缺块，但只覆盖终结之前不能再完整的记录。这类记录的阶段状态和错误码已经说明它不完整；C.8 的不变式保证块与阶段行一致。

终结之后块不再改变：`CommitAudit` 和 `finishAudit` 遇到已终结的行只读回，检查点也一样（B.3 第 1 步）。所以签过名的块是稳定的。

---

## E. 库表

### E.1 迁移 007〔设〕

新文件 `internal/storage/postgres/migrations/007_header_block.sql`。`derivedMigrations` 加 `{7, …}`，`latestSchemaVersion` 改为 7（`postgres/migrate.go`）〔核：`0faae0a` 上是 5；迁移 006 是随后加的 `turns` 索引〕。

```sql
ALTER TABLE audit_records
    ADD COLUMN capture_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN user_agent_enc BYTEA;
ALTER TABLE audit_records
    ADD CONSTRAINT audit_records_capture_version_check
    CHECK (capture_version IN (1, 2)) NOT VALID;
ALTER TABLE http_stages
    ADD COLUMN content_type TEXT COLLATE "C" CHECK (content_type <> ''),
    ADD COLUMN content_encoding TEXT COLLATE "C" CHECK (content_encoding <> '');
CREATE TABLE http_header_blocks (
    audit_id TEXT COLLATE "C" PRIMARY KEY
        REFERENCES audit_records(audit_id) ON DELETE CASCADE,
    compression TEXT COLLATE "C" NOT NULL CHECK (compression IN ('none', 'gzip')),
    plaintext_length BIGINT NOT NULL CHECK (plaintext_length >= 0),
    block_enc BYTEA NOT NULL
);
-- H.3 的运行参数分区
ALTER TABLE runtime_settings DROP CONSTRAINT runtime_settings_section_check;
ALTER TABLE runtime_settings ADD CONSTRAINT runtime_settings_section_check
    CHECK (section IN ('session_analysis', 'org_reports', 'audit_capture'));
```

- **不回填，不重写。** PostgreSQL 11 起，带常量默认值的 `ADD COLUMN` 只改目录〔推：依据 PostgreSQL 文档，本项目的库上没有实测。实现时在测试库上量迁移耗时，并确认 `pg_class.relfilenode` 不变〕。
- **锁。** 每条 `ALTER TABLE` 都短暂持有 `ACCESS EXCLUSIVE`，受 5 秒 `lock_timeout` 约束（`open.go`），与迁移 005 相同。
- **`capture_version` 的 CHECK** 用 `NOT VALID`，不扫描旧行。新列上的 CHECK 是否会扫描表没有实测〔推〕；会扫描的话也改成 `NOT VALID`。
- **`runtime_settings` 的约束名。** 它是列上的内联 CHECK，约束名 `runtime_settings_section_check` 是 PostgreSQL 的默认命名〔推：`003_session_analysis.sql` 没有显式命名，实现时先查 `pg_constraint` 确认〕。这张表最多两三行，`ADD CONSTRAINT` 的验证扫描可以忽略。
- **`schema_generation`** 不变，仍是 2。
- **写入代码：** `insertAudit` 增加两列；`validateAuditRecord` 校验 `CaptureVersion ∈ {0, 1, 2}`，0 当作 1。

### E.2 回滚

`doc/deployment/postgresql-migration.md` 新增一节“回滚到 schema 版本 6”。在没有任何 v2 写入、也没有保存过 `audit_capture` 设置的前提下执行：

```sql
-- 仅在回滚到不含迁移 007 的版本时执行。先停止新版本，并做好数据库与 audit.key 的联合备份
BEGIN;
DELETE FROM runtime_settings WHERE section = 'audit_capture';
ALTER TABLE runtime_settings DROP CONSTRAINT runtime_settings_section_check;
ALTER TABLE runtime_settings ADD CONSTRAINT runtime_settings_section_check
    CHECK (section IN ('session_analysis', 'org_reports'));
DROP TABLE http_header_blocks;
ALTER TABLE http_stages DROP COLUMN content_type, DROP COLUMN content_encoding;
ALTER TABLE audit_records DROP COLUMN user_agent_enc, DROP COLUMN capture_version;
DELETE FROM schema_migrations WHERE version = 7;
COMMIT;
```

已经有 v2 行时，没有只用 SQL 就能让旧版本保持健康的办法：

- 旧版本会按 v1 重算 v2 行的摘要，结果不等，载荷校验 sticky 失败；
- v2 行也没有 Header 行可供展示；
- 直接 `DELETE` 这些行会被 `turns.parent_turn_id ON DELETE RESTRICT` 挡住〔核〕。

所以按“先扩展、后启用”发布（K.12）：

1. 先发一个带迁移 007 和 v2 读取、`write_path` 默认为 `legacy` 的版本；
2. 再切到 `unified`。

想退回旧写法时，切回 `audit.write_path: legacy` 即可，v2 行照常可读。

旧版本的配置加载用 `KnownFields(true)`（`internal/config/load.go`）〔核〕，遇到新的 `audit:` 段会拒绝启动。回滚前要先删掉这一段。

### E.3 离线导入

- `tables.go` 的白名单和 `importer.go` 的 `known` 表集合都不用改〔核〕。导入目标只有 001 基线，导入的行得到 `capture_version=1`。
- `VerifyImportIntegrity` 按 D.3 传 `schema=baseline`。
- `cmd/audit-import` 不用改。方案里提到的 `cmd/audit-stage` 不在这个工作树里；它将来合入时，白名单要按 007 更新。
- SQLite 不加迁移（H.2），所以导入器对源“版本 12、共 10 个迁移”的检查不受影响。

---

## F. 内存预算与本地暂存

### F.1 配置〔设〕

现在的配置没有 `audit:` 段：审计模式是顶层的 `mode`，密钥是顶层的 `key_path`（`internal/config/types.go`）〔核〕。新增：

```yaml
audit:
  write_path: legacy          # legacy | unified，默认 legacy
  commit_retries: 3           # CommitAudit 的重试次数（H.3），0 到 5；管理界面保存的值优先
  memory:
    stage_bytes: 8388608      # 每个阶段在内存里保留的明文上限，默认 8 MiB（决定 4）
    global_bytes: 268435456   # 全进程上限，默认 256 MiB
  staging:
    dir: ""                   # unified 必填；legacy 下配置了也只做启动导入
    max_bytes: 4294967296     # 默认 4 GiB
```

`config.Validate` 的校验：

- `write_path` 只能是 `legacy` 或 `unified`。
- `unified` 必须配置 `staging.dir`。
- `commit_retries` 在 0 到 5 之间。
- `stage_bytes` 不小于 1 MiB，且不大于 `global_bytes`。下限取 1 MiB 是为了让落暂存的块总是整块（F.4）。
- `staging.dir` 必须是绝对路径，不能与 `key_path` 所在的目录相同、包含它或被它包含（与 5.7 第 4 点同理）。

启动时检查暂存目录：

- 不存在就以 0700 创建；
- 已存在时，在 Unix 上要求属主是当前用户，权限不含组和其他用户；
- 要能在里面创建并删除一个探针文件。

不满足时的处理：available 模式退回 legacy 并告警；strict 模式下审计不可用，准入回 503，与密钥不可用的处理相同（K.10）。Windows 上靠目录 ACL 控制访问，不检查权限位。

### F.2 什么计入预算〔设〕

预算是一个原子计数器，按明文字节计。

| 计入 | 何时释放 |
| --- | --- |
| 各阶段在内存里、尚未落暂存的明文，包括比对窗口和前瞻缓冲（B.5） | 落暂存之后；或者交给终结器之后，改由终结器那一项计入 |
| 检查点和 `CommitAudit` 中仍在内存里的块密文 | 该 audit 的 `CommitAudit` 得到应答之后。检查点不等待，在它之后提交的 `CommitAudit` 应答时，它必然已经处理过 |
| 交给终结器、排队等待解析的明文 | 解析完成或放弃之后（G.2） |

`Finish` 不会因为预算拒绝提交。超出预算时：

1. 先放弃给终结器的明文，改为只交 ID（G.2）；
2. 其他会话新到的字节立即落暂存。

检查点 1 合并了的请求，其明文在 `Finish` 之前只会落暂存，不会被丢弃（B.5）。检查点 1 之后，请求明文已经不再是唯一的证据，只是留给解析用的缓存；内存紧张时，可以在 `Finish` 交接时放弃它，改由终结器从库里读回。

所以 `global_bytes` 是软上限：同时在提交中的请求的密文之和可能让它暂时超出。

### F.3 8 MiB 在丁下意味着什么

| 内容 | 是否到达暂存 |
| --- | --- |
| 请求 Body 小于等于 8 MiB | 不到达。读完时随检查点 1 进库 |
| 请求 Body 大于 8 MiB | 上传期间超出预算的整块进暂存；第一次落暂存时排一个检查点，写入阶段行、Header 和 Body 行，所以 Header 也会进库（满足 5.10 第 3 点）。检查点 1 再把暂存的块和内存里的块一起写进库 |
| 响应 Body 小于等于 8 MiB | 不到达。`Finish` 时随 `CommitAudit` 进库 |
| 响应 Body 大于 8 MiB | 超出部分进暂存，`Finish` 时由 `CommitAudit` 从暂存读出写入；第一次落暂存时同样排一个检查点，写入 Body 行 |
| 全局预算紧张 | 任何阶段都可能提前落暂存 |

按附录 A.1，部署的平均请求体约 1.1 MB；按附录 B.1，heavy 档约 1 MB。这两类流量在 8 MiB 下基本不会碰到暂存〔推〕。

维护者接受的耐久性差异：一条 1 到 8 MiB 的请求 Body，在仍在上传时进程退出，什么也不留下；legacy 会留下其中已满的 1 MiB 块。B.7 另外列出了丁的另三项差异。

### F.4 暂存文件格式〔设〕

每条 audit 一个文件，路径为 `<dir>/<audit_id>.stg`，以 `O_CREATE|O_EXCL|O_WRONLY` 和 0600 创建。第一次写入后，对目录做一次 fsync。

文件里只有块：

```
file   = header record*
header = "LLSTG\x00\x02\x00" u32be(len(audit_id)) audit_id
record = u32be(body_len) u32be(crc32c(body)) body
body   = stage_code(1) seq(u64be) offset(u64be) plaintext_length(u32be)
         encoded_length(u32be) observed_at_ns(u64be) compression(1) data_enc
```

- `data_enc` 就是现有格式：`bodycodec.Encode` 之后 AES-GCM，AAD 为 `(audit_id, "body_chunk_v2", stage, seq, compression)`，与 `flushBodyLocked` 产生的逐字节相同〔核〕。所以暂存的块可以原样插入 `body_chunks`，不用重新加密。
- CRC 只用来发现写了一半的尾部记录；真实性靠 AEAD。
- 初稿里的阶段记录、Header 记录和终态记录都删掉了：阶段行和 Header 由落暂存时的检查点写进库（F.3），终态不再落暂存（决定 3）。

块索引里的每一项，要么是内存密文，要么是文件中的位置；`ChunkSource` 按索引产出，可以重复遍历。读文件失败时，`Each` 返回本地错误，`CommitAudit` 按 B.8 处理：不重试，以 failed 终结，缺块由 `finalizeIncompleteCapture` 标记。

### F.5 写盘与 fsync〔设〕

- 压缩加密照旧在会话锁内同步完成，和 legacy 的 flush 时机、代价相同。
- 写文件和 fsync 交给一个进程级的暂存 writer goroutine。入队不阻塞，队列计入全局预算。
- writer 每批最多攒 5 ms，写完后对本批涉及的每个文件 `fdatasync` 一次。
- 磁盘慢时，积压表现为预算被占满，最后耗尽（F.6），转发不受阻塞。
- `CommitAudit` 得到应答之后，暂存 writer 丢弃该会话仍在队列里的记录，然后删除文件。

决定 4 之后，这是罕见路径，代价只由超过 8 MiB 的 Body 承担。

### F.6 耗尽〔设〕

全局预算已满，而暂存也满了（`max_bytes` 或 ENOSPC），或者写暂存出错时，该阶段：

- 不再保留后续字节，只继续计算哈希、长度、时间和 SSE；
- 标 `body.faulted`，错误码 `capture_budget_exhausted`；写暂存出错时为 `staging_write_failed`；
- 阶段 partial，置 `captureFault`，raw 为 `full`。

available 模式记一次 `queue_full` gap，因为 `audit_gaps.reason` 有 CHECK 约束〔核〕；真实原因由阶段上的错误码给出。两种模式下转发都照常继续。

### F.7 启动导入〔设〕

启动顺序：`EnableIntegrity` → 暂存导入 → `RecoverInterruptedAudits` → 构造 Manager（`internal/app/app.go`）。只要配置了 `staging.dir` 就导入，不论当前的 `write_path` 是什么。

导入由 `internal/audit/staging` 完成，它持有 cipher；writer 新增一个操作 `RestoreStagedChunks`。对每个文件：

| 情形 | 处理 |
| --- | --- |
| audit 已终结 | 只删文件（提交之后、删除之前崩溃） |
| audit 不存在 | 改名为 `.orphan` |
| 对应的 Body 行不存在（落暂存时的检查点失败了） | 改名为 `.orphan`，记日志 |
| 正常 | 按 CRC、AEAD、seq 和 offset 的连续性校验，插入库里还没有的块，然后删除文件 |
| 尾部记录不完整 | 视为崩溃点，丢弃 |
| 中间记录校验失败 | 导入它之前的部分，文件改名为 `.corrupt` |

之后运行的 `RecoverInterruptedAudits` 按现有逻辑处理这些 audit（B.4）。导入是幂等的：已有的 seq 跳过。

### F.8 部署〔核 compose 与 Dockerfile，其余〔设〕〕

`audit-proxy` 的根文件系统是 `read_only: true`；可写的只有 `audit-data:/data` 和 `/tmp`。`/data` 里放着密钥，`/tmp` 是 64 MB 的 tmpfs（`rw,noexec,nosuid`）；进程以 `USER 65532:65532` 运行。

暂存不能放在这几处：

- 根文件系统只读。
- `/tmp` 太小，属于内存文件系统，而且重启后清空。
- `/data` 与密钥同卷，违反 F.1 的约束。

所以新增一个命名卷 `audit-staging:/staging`，配置写 `audit.staging.dir: /staging`。Dockerfile 预建 `/staging`，chown 给 65532，权限 0700。两个示例配置都加一段注释掉的 `audit:`。

部署说明写明三点：

- 这个卷要放在与数据库同样可靠的盘上；
- 不能用 tmpfs；
- 切回 legacy 之后，暂存目录要保留到它变空为止。

---

## G. 解析不读回

### G.1 谁来解析〔设〕

终结器就是现有的解析 worker goroutine，再加一个输入：`parser.Worker.Submit(job FinalizeJob) bool` 把作业放进一个有界 FIFO，由 `run` 循环处理。

理由是 `backfillMark`、`backfillRetry`、`projectRetry`、`pendingReleases` 和 `analyze` → `backfillLater`/`backfillUnsure` 都标明只由 parser goroutine 访问〔核：`parser/worker.go`〕。另起一个 goroutine 会破坏回填水位的不变式：每条保存为 ok 或 partial 的解析，都会走到 `analyze`。

作业的处理与 `Worker.process` 相同，只有两处不同：

- 不调 `LoadParserAudit`；
- `loadInput` 换成从内存构造（G.3）。

`ClaimPendingParse` 保留，因为 `saveParsedAudit` 只更新 `parse_status = 'processing'` 且恰好一行的记录（`graph_writer.go`）〔核〕。

### G.2 交接、内存与回退〔设〕

在 `Session.finish` 里，`CommitAudit` 成功之后：

1. **何时交明文。** 下面四个条件同时满足时，把明文交给终结器：提交成功、返回的终态没有被降级、解析状态为 pending、全局预算容得下。否则只交一个 ID 作业。“没有降级”是为了保证解析的就是落库的证据：例如检查点失败使 capture 变为 failed 时，就改走库里的路径。
2. **FIFO。** 容量 4,096 个作业。ID 作业和带明文的作业在同一个 FIFO 里排队；ID 作业走现在的 `loadInput`，从库里读。
3. **FIFO 满。** 不交作业，记录留在 pending，由 30 秒一次的扫描接手。
4. **panic。** 给 `process` 加 recover：panic 时调 `releaseProcessing`，记稳定错误码。`NormalizeAudit` 和 `PrepareWithLookup` 现在没有 recover〔核：`prepareTurn` 直接调用〕。
5. **超时。** 作业截止时间 2 分钟。到期时，如果 `SaveParsedAudit` 还没有提交，就显式调 `releaseProcessing`：失败次数加一并退避，第 5 次后记终态错误 `parsed_result_save_failed`（`parser_writer.go`）〔核〕。如果 `SaveParsedAudit` 已经提交、只是应答被取消，就按现在的逻辑走 `backfillUnsure`。
6. **回退时的保留状态。** 第二步里提交先于解析，raw 已经以 `pending` 状态落库。所以终结器失败后，记录保持 pending，由现有的 worker 读库解析，不预先标 `full`（K.19）。

处理函数只等 `CommitAudit`，不等解析。

### G.3 从内存构造 `Input`〔设〕

| `Input` 字段 | 现在（`parser/evidence.go`）〔核〕 | 内存来源 |
| --- | --- | --- |
| `Present` | 阶段行和 Body 行都存在 | 该阶段有 `stage.body` |
| `ContentType`、`ContentEncoding` | `decryptContentHeaders` | C.6 的规则，作用于内存里的快照 |
| `Data`、`Complete` | `readRawBody` 后接 `decodeContent` | 把 `readRawBody` 拆成“从块序列组装”的公共函数；块序列来自内存段和暂存读回，所有核对照旧 |
| `StatusCode` | `response_received` 阶段行 | `stage.statusCode` |
| `Headers`（allowlist） | `LoadParserRequestHeaders` | 内存里的 `request_received` 快照，按同样的规则过滤、排序 |

`prepareNormalizedTurn` 里的 `CreatedAtNS` 取 `worker.now()`，仍是解析时刻〔核〕。

### G.4 父轮次推断的顺序

只有一个 goroutine、一个 FIFO，ID 作业也在其中。所以除了 FIFO 满时退到扫描以外，解析顺序就是 `Submit` 的顺序，也就是各请求 `CommitAudit` 应答的顺序，与现在 `Notify` 的保证相同。

退到扫描的记录，可能被交接顺序在它之后的记录超过。现在也有这个问题，而且更容易触发：现在的队列容量是 100。

### G.5 附录 B.2 的队列容量问题

unified 的 FIFO 有 4,096 个位置，又有 ID 作业兜底，突发流量不再落到 30 秒一次的扫描上。所以做 A/B 时，工作负载必须让 legacy 的待解析积压保持在 100 以内（I.6）。否则 unified 显得更快，是因为排队方式不同，而不是写入路径的差别。

---

## H. 开关、第二个存储与重试设置

### H.1 `audit.write_path` 选什么〔设〕

| 层 | legacy | unified |
| --- | --- | --- |
| `internal/app` | 现状 | 把 `WritePath`、预算、暂存和重试设置传给 `audit.NewManager(…, Options)`；构造 `staging`；注册 `parserWorker.Submit`；构造 H.3 的设置服务 |
| `internal/audit` | `Session` 现有的 Store 调用 | 阶段开始时只记在内存里并做快照；Body 走 unified 保留器；在 B.1 的两个时刻发检查点；`finish` 时构造 `AuditCommit`，并按 B.8 重试 |
| `internal/proxy` | 不变 | 不变 |
| 存储 | 现有操作 | `Checkpoint`、`CommitAudit`、`RestoreStagedChunks` |
| parser | `Notify` | `Submit` |

Body 采集拆成两层：

- 观察层两条路径共用：哈希、长度、时间、SSE、终止事件探针、写失败标志。
- 保留层是一个接口：`legacyRetainer` 就是现在的“攒 1 MiB 再 `AddChunk`”；`unifiedRetainer` 负责内存段、封块、落暂存和比对窗口。

`finishStageLocked` 的判定逻辑两条路径只有一份。

### H.2 SQLite〔设〕

`internal/storage/sqlite` 实现 v1 形态的 `Checkpoint`、`CommitAudit` 和 `RestoreStagedChunks`：每个都在一个 savepoint 里组合它现有的 `insertStage`、`insertHeaders`、`insertBody`、`insertChunk`、`finishStage` 和带 `dedupInDB` 参数的 `finishAudit`。

- 不加 SQLite 迁移，所以 SQLite 永远只写 v1。
- 会话通过 `interface{ SupportsHeaderBlock() bool }` 决定写 v1 还是 v2。

这样，unified 的采集、检查点、合并、暂存和终结器，都在 SQLite 上的主机测试里覆盖。依赖 PostgreSQL 的测试在没有 DSN 时跳过，验收报告要写明哪些在真实库上跑过。

接口变化牵连的实现〔核〕：

- **SQLite 存储：** `parser_reader.go`、`query_reader.go`、`reader.go` 按 v1 返回新的字段。
- **测试里的假存储：** `internal/parser/worker_test.go` 的 `fakeStore`、`internal/parser/project_test.go` 的 `projectBackfillStore`、`internal/query/service_test.go` 的 `fakeStore`。
- **嵌入接口的测试存储：** `internal/audit/body_buffer_test.go` 的 `bufferStore` 和 `failingFinalizeStore` 嵌入了 `audit.Store` 接口，编译不受影响；unified 用例要另外拦截 `Checkpoint` 和 `CommitAudit`。
- **流结束顺序测试：** `internal/proxy/stream_end_order_test.go` 的 `blockingFinishStore` 嵌入 `*sqlite.Store`，要覆盖 `CommitAudit`；检查点不能被挡住。

### H.3 运行参数：`CommitAudit` 的重试次数〔设，按现有模式〕

现有模式〔核〕：

- **存储。** 表 `runtime_settings`（`003_session_analysis.sql`）每个分区一行，`settings` 列放明文 JSON。读写方法是 `postgres/runtime_settings.go` 的 `LoadRuntimeSettings`、`SaveRuntimeSettings`、`DeleteRuntimeSettings`。写走 `submitPolicySync`：一旦入队，就等到确定的提交或回滚。分区名常量在 `internal/storage/runtime_settings.go`，合法分区由 `validSettingsSection` 判定。SQLite 的实现是空的：读返回 `ErrNoRows`，写返回错误（`sqlite/session_analysis.go`）。
- **服务。** 以 `internal/orgreport/runtime_settings.go` 为例：
  - 配置文件是底；保存的分区覆盖其中可编辑的字段。
  - 启动时由 `loadSavedSettings` 读一次。读不到或不再合法时告警，并按配置文件运行。
  - 生效的值放在原子指针里（`service.settings.Store`）。
  - 写的流程：先校验；在 `settingsMu` 下保存；用时钟戳作版本，且保证严格递增；保存后立即替换生效值。
  - 删除分区就是回到配置文件的值。
  - 存储读失败时，读请求按配置文件回答，写请求一律拒绝（`ErrSettingsUnavailable`）。
  - `SettingsView` 带 `source`（`file` 或 `saved`）、`updated_ns`、`settings`，以及 `file`（配置文件的值，即重置后会回到的值）。
- **Web。** `internal/web/settings_api.go` 提供 `GET`、`PUT`、`DELETE /api/v1/settings/org-reports`，在 `internal/web/handler.go` 里注册，只对管理员开放。校验失败回 400 `invalid_settings`，消息写明字段和范围。
- **前端。** `internal/web/frontend/src/app.tsx` 的 `settingsSections` 列出“系统配置”菜单的各个分区；表单组件在 `components/settings/`；接口在 `api.ts`；类型在 `lib/settings/types.ts`。
- **路由表。** `internal/agentapi/routes.go` 的注释写明：每条管理路由，要么映射到门面，要么列在 `WebRouteExceptions` 里；`internal/web` 有测试扫描路由。

新设置：

| 项 | 值 |
| --- | --- |
| 配置文件 | `audit.commit_retries`，默认 3 |
| 分区 | `audit_capture`（`storage.SettingsAuditCapture`）；`validSettingsSection` 和迁移 007 的 CHECK 都要加上 |
| 可编辑字段 | `{"commit_retries": n}`，整数 0 到 5；超出范围时回 400，消息为 `audit.commit_retries must be between 0 and 5` |
| 服务 | 新文件 `internal/audit/settings.go`：`CaptureSettings`，提供 `Get`、`Update`、`Reset`，结构照搬 orgreport（`SettingsView`、`settingsMu`、版本戳、`ErrInvalidSettings`、`ErrSettingsUnavailable`） |
| 热路径 | 生效值是 `audit.Manager` 上的一个 `atomic.Int32`。设置服务在启动、保存和重置时调 `manager.SetCommitRetries`。会话只在 `CommitAudit` 第一次失败时读一次，所以每条请求都没有数据库读 |
| 审计不可用时 | Manager 是 `NewUnavailable` 时没有会话在用这个值；页面照常读写，写进库的值下次启动生效。存储本身打不开时，按 `ErrSettingsUnavailable` 的规则拒绝写 |
| Web | `/api/v1/settings/audit-capture` 的 `GET`、`PUT`、`DELETE`，加在 `settings_api.go` 和 `handler.go` 里，只对管理员开放 |
| 路由表 | 列入 `WebRouteExceptions`，理由“采集写入的运行参数，只在管理界面修改”，不扩大 Agent 门面的合同 |
| 前端 | `settingsSections` 增加一项：`{ id: "capture", label: "审计写入", hint: "终结提交失败时的重试" }`，总是显示。新表单 `components/settings/capture-settings-form.tsx`，显示生效值、来源和配置文件的值，可以保存或重置；说明文字写明只在 `unified` 下生效、每次重试的间隔以及最多多等多久。`api.ts` 增加三个方法，`lib/settings/types.ts` 增加类型 |
| legacy | 不使用这个值：`FinishAudit` 的失败路径不变 |

---

## I. 测试与验收

### I.1 等价测试（legacy 对 unified）

- **夹具：** `internal/protofixture` 的四类协议，流式和非流式都要有。覆盖多轮与分支、工具与多模态、未知事件、断流与取消、错误响应、上游不可达、拦截器拒绝、没有请求 Body 的请求、上游在读完请求之前就回响应、超过 1 MiB 和超过 8 MiB 的 Body、trailer。
- **时钟：** `Manager.now` 和 `Worker.now` 注入同一个确定的计数器时钟。unified 调用 `now()` 的次数和顺序必须与 legacy 相同。
- **比对：**
  - 客户端看到的字节和 A.5 的三个事件；
  - 终结后的各表行，按 B.10 逐列比较；
  - v2 的 Header 与 v1 比较 `headerblock.Expand` 的结果；
  - `Detail` 的 JSON；
  - Agent 门面的各类导出；
  - raw 下载、重建导出、解析结果、轮次图和完整性链。
- **在哪里跑：** SQLite 上跑 v1，PostgreSQL 上跑 v2。

### I.2 崩溃时的证据

在 B.7 表中每个崩溃时刻注入崩溃：用测试存储挡住后续写入并丢弃进程状态，然后重启，运行暂存导入和 `RecoverInterruptedAudits`。

对每个时刻断言：

- 留下的行与 B.7“丁”一列一致；
- 恢复之后的形态与 legacy 在同一时刻崩溃、恢复后的形态相同，只有 B.7 最后一列列出的差异；
- 链和载荷校验通过，v2 下覆盖的是残缺块（D.4）。

### I.3 故障注入

沿用模块 14 §4 的手段：只读事务、触发器抛出指定的 SQLSTATE、延迟外键、容量为 1 的队列。

| 用例 | 期望 |
| --- | --- |
| 检查点入队时队列满 | 内容并入下一次写，终结后的行与没有故障时相同，不记 gap |
| 检查点被触发器拒绝（`BEFORE INSERT ON http_headers`、`body_chunks`、`http_stages`、`body_streams`） | audit 为 failed，该检查点的行缺失，由 `finalizeIncompleteCapture` 收尾；与 legacy 下同一触发器的结果对照，差异只在于粒度：丁整个检查点缺失，legacy 只缺那一个操作 |
| `capture_failure_test.go` 的 `BEFORE UPDATE OF state ON body_streams` 用例 | 检查点写过的 Body 行，终结时用 `finishStage` 的 UPDATE，触发器会触发：`CommitAudit` 可隔离失败，不重试，以 failed 终结。没经过检查点的 Body 行是直接插入终值的，要另外装 INSERT 版本的触发器 |
| `CommitAudit` 批次失败一次后恢复（打开只读事务，下一次尝试前关掉） | 重试成功；行与没有故障时相同；完成日志为 complete |
| `CommitAudit` 批次持续失败 | 重试 `commit_retries` 次，间隔符合 B.8；之后以 partial 和 `audit_finalize_failed` 生成日志，恢复后为 failed，检查点写入的行仍在 |
| `CommitAudit` 约束失败 | 不重试，立即失败 |
| `commit_retries = 0` | 只尝试一次 |
| 提交结果不确定（模拟 COMMIT 报错但实际已提交） | 重试读回已提交的终态，不重复签名 |
| 暂存写满、ENOSPC、全局预算耗尽 | `capture_budget_exhausted`，阶段 partial，raw `full`，记 gap，转发字节不变 |
| 暂存文件损坏：尾部截断、中间 AEAD 失败、CRC 错、错误的 `audit_id` | 按 F.7 处理 |
| 终结器 panic，或超时 | 显式 release；之后 worker 读库完成；进程不退出 |
| 提交之后、解析之前崩溃 | 重启后暂存文件被删除，由 pending 扫描完成解析 |
| 以 unified 运行之后切回 legacy 启动 | 暂存照常导入 |

### I.4 流结束顺序

`stream_end_order_test.go` 在两条路径下各跑一遍；unified 下挡住的是 `CommitAudit`。A.5 的表要逐格相同。另外两项断言：检查点不被挡住；`CommitAudit` 返回之前，“请求完成”日志不出现。

### I.5 旧行与旧事件

- 迁移 006 状态的库升级到 007 之后，链和载荷校验全部通过；
- v1 和 v2 共存时校验也全部通过；
- 篡改测试：`capture_version`、`user_agent_enc`、块密文、`content_type`、删掉块的行、块的阶段集合与阶段行不一致，每一种都要被发现；
- D.2 固定一个测试向量；
- 离线导入之后首次启动，全部行通过校验。

### I.6 顺序测试与 A/B

**顺序测试：** 同一会话的两轮紧挨着结束时，后一轮挂在前一轮下面。三种情形都要测：两轮都交了明文；前一轮只交了 ID 作业；前一轮退到扫描。

**A/B：** `cmd/audit-bench run` 增加 `--write-path`、`--staging-dir`、`--stage-bytes` 三个参数。结果里要有：暂存写入的字节数和 fsync 次数、每条 audit 的操作数和提交数、各表的插入与删除行数、WAL、进程内存峰值、首字节延迟、流结束延迟（含 `Finish` 前封块的时间）、结束到可查询的延迟、详情和导出的 p95。工作负载要让 legacy 的待解析积压保持在 100 以内。第一步与第二步各自对照一次。

### I.7 设置

- 服务的单元测试照搬 `orgreport/runtime_settings_test.go` 的用例：来源、重置、不合法的保存值被忽略、存储读失败时拒绝写、版本单调递增。
- `internal/web/settings_api_test.go` 加三个方法和 400 的消息。
- 路由表测试要通过。
- 前端：`system-settings.test.tsx` 加这个分区。
- 一个端到端用例：保存 0 之后，批次失败只尝试一次，不需要重启进程。

---

## J. 工作拆分

### J.1 提交顺序（每个提交都能单独验证）

| # | 提交 | 验证 |
| --- | --- | --- |
| 1 | `storage` 类型：`AuditCheckpoint`、`AuditCommit`、`HeaderSource`、`ErrWriteBatchFailed`、`SettingsAuditCapture`，以及 `AuditRecord` 的新字段和校验 | 编译，单元测试 |
| 2 | `internal/headerblock`：编码、解码、密封、`Expand`、UA 编码，以及测试向量 | 纯单元测试 |
| 3 | PostgreSQL 和 SQLite 的 `Checkpoint`、`CommitAudit`（v1），包括多行插入、`finishStage` 复用、`dedupInDB`、已终结时幂等、`ErrWriteBatchFailed`，以及 `markCaptureWriteFailed` 和 `rememberFailedWrite` 的新分支 | “检查点加终结”与 legacy 的操作序列写出相同的行；失败矩阵（I.3 前三行） |
| 4 | `internal/audit`：unified 保留器、两个检查点、请求对在检查点 1 的合并、`finish` 构造 `AuditCommit`、重试（先用配置文件的值）、`audit.write_path` 和 `audit.memory` 配置；超出预算即耗尽，暂存留到第 5 步 | SQLite 上的 I.1、I.2（不含暂存）、I.4 |
| 5 | 暂存：文件格式、writer goroutine、读回、落暂存时的检查点、`RestoreStagedChunks` 和启动导入；暂存目录的配置、compose 卷、Dockerfile | I.3 中的暂存用例 |
| 6 | 迁移 007、`capture_version`、摘要 v2、块的写入与残缺块不变式、`BeginAudit` 写 UA、各读取方的 v2 路径、`LoadParserStage` 的两列 | PostgreSQL 上的 I.1、I.2、I.5 |
| 7 | 终结器：`Worker.Submit`、内存构造的 `Input`、拆出 `readRawBody` 的公共组装、recover 和超时 | I.6 的顺序测试、G.3 的等价、回填水位测试 |
| 8 | 重试设置：服务、Web 路由、路由表例外、前端表单、启动时加载 | I.7 |
| 9 | `audit-bench` 参数与 A/B；文档：模块 03、04、09（含 parser 解密整块）、10、13、14、18、23，部署回滚，方案附录 D | A/B 报告 |

第 3 步合入时 legacy 完全不变。第 4 步之后，`unified` 可以在 SQLite 和 PostgreSQL（v1）上跑；第 6 步把 PostgreSQL 切到 v2。第 8 步只依赖第 1、4 步，可以与第 5 到 7 步并行。

### J.2 并行拆分与文件归属

| 部分 | 拥有的文件 | 依赖 |
| --- | --- | --- |
| P-types | `internal/storage/{types.go, query_types.go, parser_types.go, runtime_settings.go}` | 最先做 |
| P-hb | `internal/headerblock/*`（新） | P-types 的形状（可以先约定） |
| P-pg | `internal/storage/postgres/{writer.go, checkpoint_writer.go(新), commit_writer.go(新), write_recovery.go, recovery.go, integrity.go, migrate.go, migrations/007_header_block.sql, parser_reader.go, query_reader.go, reader.go, types.go, runtime_settings.go}` 及其测试 | P-types、P-hb |
| P-sqlite | `internal/storage/sqlite/{writer.go, checkpoint_writer.go(新), commit_writer.go(新), parser_reader.go, query_reader.go, reader.go}` 及其测试 | P-types |
| P-audit | `internal/audit/{session.go, body.go, manager.go, retain.go(新), checkpoint.go(新), commit.go(新)}` 及其测试，`internal/proxy/*_test.go` | P-types、P-hb；暂存接口与 P-stage 约定 |
| P-stage | `internal/audit/staging/*`（新） | P-types |
| P-parser | `internal/parser/{worker.go, evidence.go, backfill.go, project.go, finalize.go(新), types.go}` 及其测试（包括其中的假存储） | P-types、P-hb |
| P-query | `internal/query/service.go` 及其测试（包括假存储） | P-types、P-hb |
| P-settings | `internal/audit/settings.go`（新）及其测试，`internal/web/{settings_api.go, handler.go}` 及其测试，`internal/agentapi/routes.go`，`internal/web/frontend/src/{app.tsx, api.ts, lib/settings/types.ts, components/settings/capture-settings-form.tsx(新), components/settings/system-settings.test.tsx}` | P-types；与 P-audit 约定 `SetCommitRetries` |
| P-cfg | `internal/config/*`、`internal/app/*`、`compose.yaml`、`Dockerfile`、`configs/*.yaml`、`doc/deployment/*` | 各接口确定之后 |
| P-bench | `internal/auditbench/*`、`cmd/audit-bench/*` | P-cfg |
| P-migrate | `internal/storage/migrate/*_test.go` | P-pg |

`internal/audit/settings.go` 归 P-settings，`manager.go` 归 P-audit，两者只通过 `SetCommitRetries` 这一个方法交互。模块文档由第 9 步统一修改，避免多方同时改同一份文档。

---

## K. 实施时按推荐做的小选择

下面这些不再等维护者决定。实施者按推荐做，阶段结束时在小结里逐项报告。

1. **丁的三项残余差异（B.7）：** 上传期间请求阶段的行和 Header 没有；拦截器执行期间入站阶段的行和 Header 没有；响应 Body 最多丢 8 MiB。
   - 审阅时的修正：前两项用一处改动收窄，不加检查点，也不加写操作。unified 下 `BeginAudit` 本来就同步提交起始行和 `user_agent_enc`，让它在同一个操作里把入站阶段（`request_received`）的行和 Header 也写进去：v1 是逐值的行，v2 是只含这一个阶段的残缺块，之后的检查点照常覆盖写。这样拦截器执行期间和上传期间崩溃，库里都有入站阶段的行和全部入站 Header，与 legacy 相同；仍然缺的只有 `request_sent` 的行和 Header（它与入站 Header 几乎逐条相同）以及不足 8 MiB 的请求 Body。代价是 `BeginAudit` 多一到两条插入，入站 Header 的密封从阶段开始挪到 `BeginAudit` 之前。
   - 第三项是 8 MiB 预算的直接后果，按决定 4 接受。
   - 三项都在阶段小结里报告。
2. **检查点 2 的触发点：** 取 `response_sent` 开始，不取 `WrapResponseReceived`，这样两个响应阶段的行和 Header 落在同一次写里（B.1）。
3. **请求对的合并：** 在检查点 1 判定，`Finish` 时再核对一次；不再满足时把 `source_stage` 改回自身，并补写重复阶段的块；合并了的请求在 `Finish` 之前保留明文，内存不够时落暂存（B.5）。
4. **检查点入队时队列满：** 内容并入下一次写，不记 gap（B.8）。
5. **检查点的可隔离失败：** 与 legacy 一样把 audit 标为 failed，不重发（B.8）。
6. **`content_type`、`content_encoding`：** 放在 `http_stages`，存 parser 实际选用的值，不设长度上限，进摘要 v2（C.6）。
7. **残缺块：** 每次写阶段行时，在同一操作里覆盖写整块；读取时校验块的阶段集合与阶段行一致；`CommitAudit` 中块没有变化时不重写（C.8）。
8. **`user_agent_enc`：** 在 `BeginAudit` 时写入（C.5）。
9. **耗尽时的 gap：** 复用 `queue_full`，阶段上的错误码为 `capture_budget_exhausted`（F.6）。
10. **暂存目录不可用：** available 退回 legacy 并告警；strict 回 503（F.1）。
11. **暂存的 fsync：** 后台组提交，每批 5 ms（F.5）。
12. **发布：** 先发带读取能力、默认 `legacy` 的版本，再启用 `unified`（E.2）。
13. **终结器：** 保留 `ClaimPendingParse`（G.1）。
14. **`Worker.process`：** 加 recover；超时显式 release，计入 5 次失败的上限。对 legacy 同样生效（G.2）。
15. **`http.Header.Values` 的怪癖：** 原样保留，另开 issue（C.1）。
16. **大提交：** `PayloadBytes` 超过 16 MiB 的 `CommitAudit`、检查点走 `alone()`；批次累计到 32 MiB 就截断。数值由 A/B 调整。
17. **附录 B.2 的扫描节奏：** 不在本阶段处理；A/B 时控制 legacy 的积压。
18. **SQLite：** 只做 v1，不加迁移（H.2）。
19. **回退时的保留状态：** 终结器失败时，记录保持 `pending`，由 worker 读库解析，不预先标 `full`。任务原文写的是标 `full`，那是针对第三步写的（G.2 第 6 条）。
20. **重试设置：** 范围 0 到 5；间隔 100 ms 起翻倍，上限 1 s；路由列入 `WebRouteExceptions`，不进 Agent 门面；legacy 不使用这个值（H.3、B.8）。
21. **重试的错误分类：** 只重试队列满和批次级失败（包括结果不确定的提交），其他一律不重试（B.8）。

---

## 附：残余风险

1. **CPU 的位置变了。** `Finish` 之前要压缩加密响应侧保留的 Body；请求侧已经在检查点 1 封好了，时机与 legacy 的尾块相同。分块响应和 HTTP/2 响应的结束会相应推后，但两对都合并时，封块的总量大约只有 legacy 的一半。净效果要看 A/B。
2. **writer 事务里有本地文件读。** 暂存的块在 writer 事务里读文件（F.4），只发生在超过 8 MiB 的 Body 上。
3. **v2 写入之后没有只用 SQL 的回滚办法**（E.2）。
4. **parser 在进程内解密整块。** 这是维护者接受的明文边界改变（决定 2），要写进模块 09。
5. **最终失败时比 legacy 多丢一些。** `CommitAudit` 最终失败时，响应侧证据没有进库；legacy 在同样的故障下，至少有已提交的那些异步块。重试缩小了这个窗口，但没有消除。

---

## 实施记录

下面是代码与正文不同、或正文没有写到的地方，取自代码和各提交的说明（第 3 阶段的全部提交，`0faae0a` 之后）。每条给出正文的位置和代码的位置。

### R.1 会话

1. **重试次数在第一次尝试之前读。** B.8、H.3 写的是“第一次失败时读一次”。`commitWithRetries` 在第一次尝试之前读 `Manager.CommitRetries()`，这样即使次数为 0，那一次尝试也能带上 `FinalAttempt`；正常路径多一次原子读。改动对之后开始的提交生效。
2. **没有前瞻缓冲。** B.5 写重复阶段读到来源前面时把超出部分放进前瞻缓冲。`unifiedRetainer.retain` 里，重复阶段遇到来源还没保留到的字节就从那里起自己保留，前缀照旧借用。按代理的读写顺序，来源总是先读到，这种情形不常见。
3. **来源可能越过预算一次读。** F.2 没有写：来源阶段的块在重复阶段比对过之前不能落暂存，`reserveRetainedLocked` 把这一次读的字节越过单阶段和全局预算照收，而不是结束保留。
4. **短块只在全局预算吃紧时出现。** F.1 说 `stage_bytes` 的下限 1 MiB 保证落暂存的块总是整块。实际上单阶段预算总是先让已关闭的整块落暂存，只有全局预算吃紧、阶段只剩正在攒的块时，`stageOneChunkLocked` 才提前结束它。
5. **落暂存时的检查点只写行。** F.3 写“写入阶段行、Header 和 Body 行”。`spillCheckpointLocked` 只写到此为止的阶段行和 Header，以及落暂存那个阶段自己的 Body 行，不写块、不写其他 Body 行，所以来源阶段落暂存本身不妨碍请求对在检查点 1 合并（重复阶段自己也落暂存时除外，见第 11 条）；没能入队时下次落暂存再试。
6. **失败 capture 上的合并。** B.5 表的第 8 条写检查点失败使 audit 成为 failed 时“与 legacy 一样不合并”。会话不知道库里的失败标记：在检查点 1 合并的请求对和在 `Finish` 时内存里合并的响应对，在最终 failed 的 audit 里也以指向来源的形态存储（模块 03 §13.3）。legacy 在这种情况下两份 raw 都保留。
7. **起始行没有入站阶段。** K.1 的修正让 `BeginAudit` 带上入站阶段，正文没有写它被拒绝时怎样。实现：阶段行和 Header 各在一个嵌套 SAVEPOINT 里，被可隔离的错误拒绝时只回滚那一部分，起始行保留并标 failed；阶段行被拒绝时 `BeginAudit` 在批次提交后返回 `storage.ErrInboundStageNotStored`，会话按 legacy 的 `StartStage` 失败处理，请求对不在内存里合并（模块 03 §13.9）。
8. **交接的条件更严。** G.2 第 1 条之外，还要求起始行带着入站阶段、没有任何块落过暂存，以及两个接收阶段的块全部完整留在内存里、与提交的长度和块数相符。“全局预算容得下”是只检查不另占（`handover.go` 的 `jobLocked`）。
9. **落了暂存的内容只交 id。** F.2、G.2 设想终结器可以读回暂存的明文。`evidenceLocked` 遇到落过暂存的块就只交 id 作业，由 worker 读库；接口留了位置（`internal/audit/handover.go` 的注释）。
10. **版本 2 的块封不出来时。** 检查点不发出，记 `capture_checkpoint_deferred`；`CommitAudit` 在发送前就失败、不重试，按最终失败处理，启动恢复以检查点写过的块终结。正文没有写。
11. **应用里请求 Body 超过预算时，请求对不在内存里合并。** B.5 设想两个请求阶段交替读取（重复阶段最多落后一次读），第 2、3 条写的也是这种顺序。这只在没有预读 Body 的拦截器时成立。应用给每条路由加上 `uaguard` 和 `contentpolicy` 两个全局拦截器，它们总是声明需要 Body，框架先把请求 Body 读到末尾再回放，所以 `request_received` 在 `request_sent` 出现之前就读完了。请求 Body 不超过 `stage_bytes` 时没有区别。超过时：来源阶段在预读中把块落了暂存（这时还没有重复阶段，不受“比对过才能落”的限制）；重复阶段从偏移 0 起比对不到已落暂存的块，转为自持，自己也落暂存，它的落暂存检查点写出指向自身的 Body 行；检查点 1 于是写两份块，`CommitAudit` 置 `DedupInDB`，由库内合并删掉重复阶段的块。终态的行与内存合并的相同，以 failed 终结的 audit 两份都保留（库内合并不对它执行，与 legacy 相同）。代价见 R.7 的 1 MiB 预算一栏：WAL 接近 legacy。B.7 表的“请求 Body 正在上传”一行也是按交替读取写的：应用里上传发生在拦截器预读期间，之后是把缓冲的 Body 发给上游的一段，检查点 1 要等 `request_sent` 的 Body 结束才发出，这一段里 unified 没有预算以内的请求 Body，legacy 已有完整的入站 Body（模块 03 §13.7）。这一条是 A/B 之后查出来的：逐操作的跟踪是在 `internal/proxy` 的代理加一个读 Body 的测试拦截器上做的（SQLite 与 PostgreSQL 各一遍，临时插桩，已移除）；完整应用上只确认了每条请求两条暂存记录、借用在偏移 0 停止，与压测量到的行数相符。没有提交固定这一行为的测试。代码没有改，因为每一种改法都会改变崩溃时留下的行，对 failed 的 audit 还会改变终态里存几份，要由维护者决定：
    - 与暂存的来源块比对：`matching` 把落了暂存的块读回解密再比（一次读盘和解密，在转发路径上、会话锁内，每个暂存块一次）。
    - 按块比对摘要：来源落暂存时记下每块的 SHA-256，重复阶段至多自持一块，摘要相同就放掉改为借用。
    - 保持现状：默认预算 8 MiB 之下只有更大的请求 Body 受影响。

    不可取的两种：来源已经读完就不比对直接借用（上传被截断或被改写时会存下没人核对过的 `request_sent`）；让来源越过预算等重复阶段出现（预读上限是 512 MiB）。

### R.2 存储与读取

1. **失败 capture 上的检查点过滤。** B.3 没有写：检查点碰到已标 failed 的 audit 时，只写有父行的部分（Header 要有阶段行，Body 要有自己和来源的阶段行，块要有 Body 行），与 B.6 第 2 步对提交的处理相同；块照样整块写（`applyCheckpoint`、`loadPresentRows`）。之前一个缺失的入站阶段行会让整个检查点因外键失败而丢失。
2. **阶段集合检查的例外。** C.7、C.8 写块的阶段集合与阶段行不等一律按完整性错误。写失败时会话并不知道，两者可能对不上；`headerblock.Expand` 对已存 `capture_status = failed` 和 `forward_status = interrupted` 的 audit 放宽这一条，其余 audit 不变（模块 09 §8）。被拒绝的入站块会留下有阶段行、没有块的 failed audit。
3. **块来源读失败是本地错误。** PostgreSQL 起初把读暂存块失败当作整批失败；`insertChunkRows` 改为本地错误，只回滚那一个操作，与 SQLite 一致（F.4 本来就这么要求）。失败记账取块边界用 `EachMetadata`，不在锁下读文件。
4. **`RestoreStagedChunks` 总是独占一个事务**，它报告已有的、借用的（合并了的重复阶段）、没有 Body 行的和接不上的阶段，规则在 `storage.StagedRestorePlan`，两个存储共用。
5. **迁移 007 的三个 CHECK 都是 `NOT VALID`。** E.1 只把 `capture_version` 的那个写成 `NOT VALID`；随 `ADD COLUMN` 一起写的 CHECK 会扫全表，所以两个内容列的也单独以 `NOT VALID` 添加（模块 04 §3.9）。
6. **版本 2 提交的批次失败记账。** 存储打不开旧块，不知道少了哪些 Trailer，所以带新块的提交丢在失败批次里时，先前写过的阶段都记为 Header 丢失。
7. **语句数。** B.9 是按代码数的估计。`TestStagedWriteStatementCounts` 在提交 `6a3d5c5` 时以版本 1 量得：一条典型流式请求 legacy 22 个操作、105 条语句，unified 4 个操作、38 条语句（含 SAVEPOINT 与 RELEASE，不含 BEGIN 与 COMMIT）。之后入站阶段改用嵌套 SAVEPOINT、PostgreSQL 改写版本 2，这个测试的数字没有重新记录，它只断言操作数和 unified 更少。A/B（R.7）在 PostgreSQL、版本 2 上经协议转发量得：每条 audit 的 writer 操作 legacy 27.0 个、unified 9.0 个，差 18 个，与 22 对 4 相符；剩下约 5 个是采集之外的写（解析、身份回填、分析），两条路径都有，没有逐个核对。

### R.3 暂存

1. **文件格式与 F.4 相同**，只有文件头和块记录；CRC 是 CRC-32C（Castagnoli）。F.5 写的 `fdatasync` 实际是 `File.Sync`（fsync），新建文件的那一批写完后 fsync 一次目录。待写队列另有 4096 条的上限，满了按耗尽处理。
2. **导入的情形比 F.7 多。** 文件读不出来时导入中止并返回错误，审计不可用（否则恢复会终结这些 audit，下次启动把完好的文件当已终结删掉）；导入时存储报错同样使审计在两种模式下都不可用；文件头指向别的 audit、块与库里的接不上时改名为 `.corrupt`；合并了的重复阶段的块不插入。扫描允许一个阶段的暂存块跳过检查点已写并释放的那些（上游先回响应时会这样），由存储核对文件接着库里的块。
3. **构造提交之后不再落暂存**，迟到的读按耗尽处理（`capture_budget_exhausted`），以免会话释放暂存之后又建出文件。
4. **legacy 下暂存目录不可用只记告警**，不影响启动；配置了目录且可用时，不论写入路径都导入。
5. **`max_bytes` 必须为正**，是新增的配置校验；它计入目录里的全部普通文件，包括导入改名保留的文件。
6. **日志码。** 暂存 writer 写失败的日志与被拒绝的阶段用同一个错误码：目录或磁盘满为 `capture_budget_exhausted`，其他写错误为 `staging_write_failed`（F.6）。删除、改名暂存文件失败和审计管理器构造失败的日志只带稳定的 `reason` 码，不带错误原文（模块 13 §2.1）。
7. **最终失败的提交，其暂存块由 writer 恢复写入。** F.5 只写了提交得到确认后删文件。提交交给 writer 之后最终失败时，存储在恢复表里记下对暂存块的引用（文件位置，`storage.StagedChunkHolder`）；恢复在把 audit 以 failed 终结的同一个事务里先插入这些块，再由 `finalizeIncompleteCapture` 收尾，提交后删文件。写入的是 `body_chunks` 的行，`body_streams` 的 `stored_length`、`chunk_count` 由随后的 `finalizeIncompleteCapture` 按块求出，都在签名之前；不改动任何已终结的 audit。启动导入遇到已终结、库里却缺文件中块的 audit 时，不写库，文件改名为 `.orphan`。两种顺序（进程活着时恢复，或先停下再由启动导入）写出的块相同；终态不同，分别是 failed 和 interrupted，与 legacy 在同样两种情况下的区别相同。

### R.4 parser

1. **recover 只包 normalization 和轮次准备。** `Parse` 原本就有 recover（`parser_panic`）；新增的 `prepareSafely` 包住 `NormalizeAudit` 和 `PrepareWithLookup`，panic 记 `normalize_panic` 并 release，计一次失败。
2. **期限的范围。** 2 分钟从读审计行、claim 开始到保存为止，保存之后的分析不受约束；对 `Notify`、扫描和 `Submit` 的作业都生效。claim 的等待到期时同样显式 release。
3. **队列上限。** `Notify` 的 100 比较的是整个队列的长度，不只是 `Notify` 进来的作业，所以队列里有 100 个 `Submit` 作业时扫描和 `Notify` 也被拒绝。

### R.5 设置

1. **`write_path` 是实际使用的路径。** H.3 写设置视图显示配置文件的值。`assembleCaptureSettings` 传的是 `Manager.WritePath()`：管理器不可用或退回 legacy 时为 `legacy`。
2. **审计存储打不开时不能保存。** H.3 写 Manager 是 `NewUnavailable` 时页面照常读写。实际上这时存储已关闭或没有打开，服务没有存储：读按配置文件回答，写一律 `503 settings_unavailable`。
3. **`PUT` 拒绝缺字段。** 0 是合法值，缺字段或 `null` 按 400 拒绝，不取默认。

### R.6 已知限制

正文没有写、实施时确认的限制，模块 03 §13.5、§13.7 有详细说明：

1. 检查点丢在失败批次里的 audit，即使重试的提交成功也以 failed 终结：`CommitAudit` 先写恢复表里的失败标记。快请求的检查点常与提交同批，故障期间发出的检查点也是这样。
2. 提交交给 writer 之后最终失败时，会话仍在内存里的部分（每个阶段最多 `stage_bytes`）丢失，`response_sent` 没有 Body 行；暂存的块由 writer 恢复在终结前写入（R.3 第 7 条）。legacy 在同样故障下保留除失败批次以外的全部异步写。
3. 随 Body 结束到达的上游响应 Trailer 只由 `CommitAudit` 写；进程在 `Finish` 之前退出时没有，legacy 在 EOF 时已异步写出。
4. 响应大时 `Finish` 在 unified 下更慢：响应侧的块在这时才压缩加密。响应小时反而更快（R.7）。
5. 设置页在审计存储打不开时只能读（R.5 第 2 条）。
6. `cmd/audit-bench` 的 `--write-path`、`--staging-dir`、`--stage-bytes`（I.6）是在会话、存储和暂存都完成之后才加的，另有 `--count-statements`（模块 14 §9.5）；R.7 的 A/B 用的是加上它们之后的同一个二进制。

### R.7 实测

同一个二进制（提交 `b807047` 构建，之后的提交只改测试、注释和文档）分别以 `--write-path legacy` 和 `unified` 跑 `cmd/audit-bench run`（模块 14 §9.5）。合成流量，本机容器里的 PostgreSQL 18.6，默认参数，数据在磁盘卷上，每次运行一个新 schema，种子相同。数字不是生产数据，只用来比较两条路径。

三档负载：

- heavy：40 个会话各 6 轮，并发 2，请求 Body 约 0.97 MB，响应 30–130 kB，273 条 audit；
- 2 MB：同 heavy，每项字节数加倍（`--item-bytes 9200`），请求 Body 约 1.87 MB，276 条 audit。unified 跑两次：默认预算 8 MiB，和 `--stage-bytes 1048576`（每个请求都落暂存）；
- small：200 个会话各 5 轮，并发 4，1,171 条 audit。

每档各跑两遍：一遍经协议转发统计语句（取操作数、语句数），一遍不转发（取延迟）。两遍的 WAL 相差不到 2%（2 MB 档不到 8%），下表的 WAL 取转发那一遍。待解析积压的最大值：heavy 2，small 4–5，2 MB 档 legacy 15–20、unified 8 MiB 3–6、unified 1 MiB 13–18，都在 100 以内。

**两条路径存下的东西相同。** 每一档里，两条路径的轮次数、会话数、`content_objects`、`turn_context_ops`、`turn_response_items`、`integrity_events`、`parsed_results` 的行数，`capture_status`、`parse_status` 和 `retention_state` 的分布都逐项相等；解析状态与夹具预期不符的为 0；暂存目录在每次运行之后是空的。

每条 audit 的写入（legacy → unified）：

| 指标 | heavy | small | 2 MB，8 MiB 预算 | 2 MB，1 MiB 预算 |
| --- | --- | --- | --- | --- |
| writer 操作（个） | 27.02 → 9.02 | 27.01 → 9.00 | 29.08 → 9.03 | 29.08 → 11.08 |
| writer 提交（次） | 7.68 → 6.65 | 4.58 → 4.68 | 8.21 → 6.53 | 8.21 → 8.69 |
| writer 语句（条） | 313.8 → 232.2 | 214.2 → 134.8 | 319.8 → 230.7 | 319.8 → 249.2 |
| 只读连接的语句（条） | 41.8 → 18.8 | 34.6 → 11.6 | 41.8 → 18.7 | 41.8 → 40.8 |
| writer 连接的 WAL（kB） | 1033.2 → 597.3 | 56.1 → 36.5 | 1926.4 → 1068.8 | 1926.4 → 1896.1 |
| 整库 WAL（kB） | 1059.2 → 612.7 | 58.2 → 38.7 | 2305.2 → 1092.8 | 2305.2 → 1966.0 |
| WAL 记录（条） | 2271 → 1461 | 311 → 223 | 3783 → 2216 | 3783 → 3620 |
| `body_chunks` 插入 / 删除（行） | 4.00 / 3.81 → 2.03 / 1.83 | 4.00 / 3.80 → 2.02 / 1.82 | 6.00 / 5.76 → 3.03 / 2.78 | 6.00 / 5.76 → 5.03 / 4.78 |
| `body_streams` 更新（行） | 10.41 → 6.44 | 10.43 → 6.45 | 10.42 → 6.45 | 10.42 → 7.45 |
| Header | 33.6 行 → 1 个块 | 33.7 行 → 1 个块 | 33.7 行 → 1 个块 | 33.7 行 → 1 个块 |
| 暂存写入（kB）/ 记录（条） | 0 | 0 | 0 | 801.9 / 2.00 |

- writer 操作少 18 个，与采集从 22 个操作变成 4 个相符（R.2 第 7 条）。提交次数变化不大：writer 本来就把相邻的操作攒成一批提交。
- WAL 少 35%（small）到 45%（2 MB，8 MiB 预算）。少掉的主要是重复阶段先写后删的那一份块，和每条 audit 三十多行 Header。
- 运行结束时 Header 占的空间：heavy 档 `http_headers` 3.3 MB（9,183 行）对 `http_header_blocks` 0.25 MB（273 行）；small 档 14.2 MB（39,439 行）对 0.96 MB（1,171 行）。`http_stages` 因为多了两个内容列和 `user_agent_enc`，0.35 → 0.41 MB、1.45 → 1.60 MB。
- 只读连接的语句每条 audit 少 23 条，是解析不再读回证据。1 MiB 预算一栏没有少，因为落过暂存的 audit 只交 id，由 worker 读库（R.1 第 9 条）。
- 1 MiB 预算一栏的 WAL 接近 legacy，原因是 R.1 第 11 条：应用里请求 Body 总是先读完，超过预算的请求对改由库内合并，两份块都写了一遍。暂存每条 audit 写 2 条记录（两个请求阶段各一块）、802 kB，每条记录一次 fsync，每个文件一次目录 fsync（552 条记录、552 次文件 fsync、256–274 次目录 fsync）。

延迟（不转发的那一遍，p50 / p95，毫秒，legacy → unified）：

| 指标 | heavy | small | 2 MB，8 MiB 预算 | 2 MB，1 MiB 预算 |
| --- | --- | --- | --- | --- |
| 首字节 | 423.4 / 434.7 → 418.7 / 423.8 | 312.4 / 320.4 → 312.8 / 316.7 | 442.2 / 483.8 → 426.1 / 473.9 | 442.2 / 483.8 → 441.6 / 472.8 |
| 响应结束 | 443.1 / 468.9 → 433.2 / 466.8 | 333.4 / 361.3 → 326.2 / 342.0 | 470.8 / 541.7 → 445.6 / 511.0 | 470.8 / 541.7 → 463.4 / 529.0 |
| 处理函数在 `Finish` 里 | 18.2 / 39.8 → 13.3 / 29.4 | 20.5 / 46.4 → 13.8 / 25.8 | 23.4 / 83.3 → 17.0 / 70.7 | 23.4 / 83.3 → 18.5 / 66.9 |
| 结束到可查询 | 185.7 / 323.6 → 170.3 / 270.3 | 117.6 / 242.9 → 92.6 / 184.9 | 876.6 / 3764.8 → 363.7 / 689.8 | 876.6 / 3764.8 → 1171.3 / 3279.5 |
| 详情 | 43.0 / 49.1 → 42.9 / 47.9 | 4.0 / 5.7 → 4.3 / 5.9 | 65.6 / 72.6 → 65.5 / 75.7 | 65.6 / 72.6 → 66.1 / 74.3 |
| 导出请求 | 42.0 / 47.6 → 42.1 / 46.9 | 4.0 / 5.8 → 4.3 / 6.1 | 63.6 / 72.8 → 65.7 / 73.5 | 63.6 / 72.8 → 66.5 / 72.5 |
| 导出响应 | 40.2 / 45.2 → 41.3 / 45.4 | 3.9 / 5.4 → 4.2 / 5.7 | 59.6 / 64.8 → 61.9 / 69.8 | 59.6 / 64.8 → 61.4 / 67.7 |

- 首字节的上游延迟设的是 400 ms（small 300 ms），其余才是代理和审计的开销。响应结束提前 7–25 ms，`Finish` 短 5–7 ms：这几档的响应都小，终结只有一个 writer 操作的好处大于在 `Finish` 时封块的代价。
- 结束到可查询在 2 MB 档差别最大：legacy 的解析要把 2 MB 的请求读回来，积压到 15–20 条；unified 8 MiB 预算下用会话交来的明文。1 MiB 预算下每条 audit 都读库，没有改善，p50 还更慢。
- 读取（详情、导出）没有可分辨的差别，都在两遍运行之间的波动以内。版本 2 的详情要解一个 Header 块，没有量出代价。

进程内存峰值（应用、fake upstream 和负载驱动在同一个进程里；Go 运行时总量，MB，两遍取大）：heavy 77.0 → 80.9，small 43.8 → 43.6，2 MB 档 118.7 → 148.8（8 MiB 预算）、127.5（1 MiB 预算）。并发只有 2 和 4，全局预算 256 MiB 没有碰到。

与第 2 阶段末尾的对照（`0faae0a`，只有 legacy，同样的 heavy 和 small 负载）：每条 audit 的 WAL 1059.1 → 1059.2 kB、58.1 → 58.2 kB，结束到可查询的 p95 0.31 → 0.32 s、0.25 → 0.24 s。第 3 阶段没有改变 legacy 路径的写入量。

大响应（`internal/audit` 的 `TestMeasureFinish`、`TestMeasureStaging`，SQLite，单条流式响应，三次取中位数）：

| 响应 | `Finish`，legacy → unified | 暂存 |
| --- | --- | --- |
| 1 MiB | 8.2 → 11.9 ms | 无 |
| 8 MiB | 26.4 → 37.8 ms | 无 |
| 16 MiB | 15.6 → 67.6 ms | 9 条记录，1.9 MiB，9 次文件 fsync，1 次目录 fsync |
| 64 MiB | 24.2 → 152.5 ms | 57 条记录，12.3 MiB，56 次文件 fsync，1 次目录 fsync |

响应越大，unified 的 `Finish` 越慢：响应侧的块在这时才压缩加密。这两个测试里堆的峰值（64 MiB 时 legacy 303 MiB、unified 233 MiB，高出基线的部分）包含测试自己持有的整个响应，只能看相对大小。

没有量的：

- 真实流量。请求大小、协议比例和异常比例都来自合成夹具。
- 并发高到全局预算吃紧的情形；暂存目录所在磁盘与数据库同盘时的 fsync 争用（这里两者是同一台机器上的两个卷）。
- 响应落暂存时通过真实代理和 PostgreSQL 的延迟（上表的大响应只在 SQLite 上量过）。
- 2 MB 档 legacy 的积压到过 20，说明这一档的到达速率已经接近解析的吞吐，它的“结束到可查询”更多反映解析排队，不只是写入路径。

方案 4.2 的第三步（规范化先于提交：解析在提交之前完成，一个事务写完采集与轮次图，见方案 4.2 与 5.1）以这次 A/B 为前提，本阶段没有做，仍待决定。

更正：这里早先把第三步写成“删去 legacy 路径、把 unified 设为默认”，是错的，那是另一件事。A/B 之后维护者决定只保留 unified 这一条写入路径；删去 legacy 路径在下一个分支上实施，与第三步无关，见 R.8。

### R.8 删去 legacy 写入路径

A/B（R.7）之后维护者决定只保留 unified。这一节记录删了什么、留了什么、证据怎样保住，以及因此改变的测试断言。正文 F.1、H.1 的开关与退回 legacy 是历史，不再改写。

**删去的。**

- `internal/audit`：会话里只为 legacy 存在的分支（会话自己逐操作调用 `StartStage`、`AddHeaders`、`StartBody`、`AddChunk`、`FinishStage`、`FinishAuditWithResult` 的地方，`finish` 的 legacy 实现），`legacyRetainer` 与保留层接口，`bodyCapture` 里只给它用的字段，`Options.WritePath`、`WritePathLegacy`/`WritePathUnified` 常量和 `Manager.WritePath`。`audit.Store` 收窄为 `Healthy`、`BeginAudit`、`Checkpoint`、`CommitAudit`、`InsertAuditGaps`：没有会话再发出逐操作写，由编译器保证。`audit.NewManager` 构造的就是 unified 管理器。
- `internal/config`：`audit.write_path` 不再选择任何东西，省略或写 `unified` 照常；写 `legacy` 时校验失败，错误说明 legacy 写入路径已在这个版本删去，不悄悄忽略。
- `internal/app`：开关和 available 模式退回 legacy 的做法（`audit staging unavailable, using the legacy write path`），以及 legacy 下暂存不可用时的 `audit staging directory unusable, nothing imported`；交接总是装 `parser.Worker.Submit`。
- 设置页上的写入路径说明和 legacy 提示。
- `cmd/audit-bench` 的 legacy 运行：`--write-path` 只接受 `unified`（也是默认），写 `legacy` 时拒绝并提示用提交 `b807047` 构建的二进制。

**留下的，以及为什么。**

- 存储的逐操作写和 SQL（PostgreSQL、SQLite 的 `insertStage`、`insertHeaders`、`insertBody`、`insertChunk`、`finishStage`、`finishAudit` 与导出的 `StartStage` 等）：SQLite 的 `Checkpoint`、`CommitAudit` 由它们组成，版本 1 夹具、离线导入的测试和存储层等价测试（`TestStagedWriteMatchesLegacyRows`、`TestUnifiedWriteMatchesLegacyRows`）用它们。
- `RecoverInterruptedAudits` 与 writer 的采集恢复：上一个版本以 legacy 路径留下、未终结的 audit（采集版本 1）要在新版本第一次启动时终结。新增 `internal/app` 的 `TestFirstStartRecoversAnAuditTheLegacyPathLeftOpen`：用存储的逐操作写造出 legacy 在响应流到一半时已提交的行（A.4 第三行），在 SQLite 和 PostgreSQL 上各启动一次应用，audit 恢复为 interrupted/partial、raw `full`，存储长度等于已提交的块，载荷校验通过，请求 raw 和详情 Header 读得回来，新会话照常准入。
- 库内成对合并（`deduplicateEquivalentBodyPair`、`DedupInDB`）、`parser.Worker.Notify` 和 pending 扫描：unified 仍在用。
- 采集版本 1 的读取和校验（query、parser、完整性、`headerblock.Expand`）：旧数据照常可读、可校验，不重写任何已有的行。
- 设置接口的 `write_path` 字段，总是 `unified`，接口形状不变；`unifiedWriteSupport` 检查（存储可以声明不能承担这条写入路径），日志码 `unified_unsupported` 沿用。

**暂存目录必填。** 维护者的决定：`audit.staging.dir` 在两种模式下都必填（配置校验拒绝空值，仍要求绝对路径、与密钥目录分开）。启动时目录配置了却不可用（或没有配置），两种模式下审计都不可用，与此前 strict 的处理相同：关闭存储，记一条 `audit staging unavailable`（`error_category=staging_unavailable` 和原有的 `reason` 码，不带路径和错误原文），以 `audit.NewUnavailable` 运行；available 模式不审计照常转发，strict 模式拒绝。不提供不带暂存运行的降级方式，以前 available 模式退回 legacy 的做法已经没有了。这个判断在导入和 `RecoverInterruptedAudits` 之前：目录不可用就像暂存文件全都读不出来：此时恢复会把带着暂存块中断的 audit 不带这些块就终结（与导入读不出文件时中止的理由相同，第 3 阶段设计 R.3 第 2 条）；维护者的决定是目录不可用时整个审计不可用。于是不恢复、不终结任何记录，存储关闭，中断的 audit 原样保持未终结，暂存文件不动；目录修好、重启之后按正常顺序（验证完整性链 → 导入暂存 → 恢复），暂存块导入这些仍未终结的 audit。`TestUnusableStagingLeavesInterruptedAuditsOpen`（及 PostgreSQL 版）固定这一点。

**证据怎样保住。** 会话层的等价测试原来让同一流量走两条路径再比行，是 unified 存下的与 legacy 相同的证明。删代码之前先把 legacy 一侧冻结成金文件（`internal/legacyoracle`，各包 `testdata/legacy-oracle`），选它而不是在测试代码里留一份 legacy 会话：会话分布在 `internal/proxy`、`internal/storage/postgres`、`tests/integration` 等包里，测试专用的 legacy 实现进不去这些包，要留就得留一整份会话。

- 生成：oracle 提交 `5fcb4c0` 的非测试代码就是 `ce4e976`；每个测试在那里同时跑 legacy 和 unified，legacy 的值按 `LLMAPI_WRITE_LEGACY_ORACLE` 写进文件，不写时与文件比对，unified 与文件比。之后的提交去掉 legacy 一侧，只拿 unified 比文件。代码已删，文件不能再生成。
- 规范化：SQLite 上 audit id 来自带种子的随机源，采集时间来自计数时钟，clock 读取次数也冻结；密文按自己行的 AAD 打开，记为明文长度和 SHA-256，其他密文记长度，parser 自己时钟盖的列遮掉。PostgreSQL 上 audit id 和时间不进比较（`normalizeSessionDump`、`storedShape`），两次运行必然不同的 Header 值（请求 id、夹具交换 id、`Date`）去掉或只记长度。长文本（查询视图、导出、Agent 门面输出）记为长度、SHA-256 和开头一段。超过 1 MiB 的文件 gzip 压缩。
- 复核：生成之后各重跑一遍，legacy 与 unified 都与文件一致：SQLite 的在 Windows 和 Linux 上各一遍，PostgreSQL 的在容器里一遍；文件里没有路径、用户名和端口。
- 覆盖：`internal/proxy` 的端到端、暂存和故障测试，`internal/audit` 的分歧与暂存测试，`internal/storage/postgres` 的会话测试和 harness 的 legacy 模型（`TestHarnessLegacyModelMatchesSession`，冻结真实 legacy 会话的操作流），`tests/integration` 的版本 2 与写入路径测试。

**改变的断言。** 没有发现正文与 R.1 到 R.6 解释不了的行为差别：每一处都由 B.8、R.6 或维护者的暂存决定说明。

| 测试 | 以前断言 | 现在断言 | 原因 |
| --- | --- | --- | --- |
| `internal/proxy` `TestAsyncCaptureFailuresMatchCompletionLogAndAllowRetainedRaw` → `TestCaptureWriteFailuresEndTheAuditFailed` | legacy 下可隔离的写失败只回滚那一个操作；完成日志等于已存终态（failed/`capture_write_failed`）；其余块保留，raw 除丢的块外可读；SSE 时间线保持完整；“stage enqueue”（`FinishStage` 队列满）为 partial/`audit_finalize_failed` | 被拒绝的检查点整个回滚，请求侧的行一起没有（B.8 第 2 行）：检查点 1 里被拒的一行就让整个请求侧缺失，这是这些测试固定下来的最大差别；被拒绝的提交立即最终失败：完成日志 partial/`audit_finalize_failed`，之后 writer 恢复以 failed/`capture_write_failed` 终结，响应 Body 和时间线没有（B.8 第 4 行、R.6 第 2 条）。逐项断言：入站 Header 被拒时只有入站阶段为 partial/`capture_headers_failed`，响应两阶段和合并的响应对为 complete；提交被拒时所有阶段和留下的 Body 为 partial/`capture_write_failed`、hash 与 EOF 未确认；留下的 Body 存储长度等于观察长度、块数等于块行；缺失的一侧读作不存在；载荷校验通过。十个情形保留九个，只去掉“stage enqueue”（不再有 `FinishStage`） | B.8、R.6 第 2 条、模块 03 §13.5 |
| `internal/proxy` `TestCollectorQueueRejectionKeepsCollectorFaultLabels` | `StartBody`/`AddChunk` 入队被拒是采集器故障 | 删去，只测 legacy 机制；unified 的入队被拒由 `TestCheckpointQueueFullIsFoldedIntoTheNextWrite`、`TestCommitAuditRetries` 覆盖 | 只属于 legacy |
| `internal/audit` `TestManagerOptionsDefaultToLegacy` → `TestNewManagerWritesThroughTheUnifiedPath` | `NewManager` 是 legacy | 起始行带入站阶段、一次提交、没有逐操作写 | 只剩一条路径 |
| `internal/audit` `TestManagerRefusesUnifiedOnAStoreThatCannotServeIt` → `TestManagerRefusesAStoreThatCannotServeTheWritePath`；`TestManagerOptionsValidation` | 这样的存储 legacy 可以用；未知写入路径被拒 | 只断言拒绝；未知写入路径一项去掉（选项没有了） | 只属于 legacy |
| `internal/audit` `TestBodyBufferLazyBoundedAndReleased`、`TestBodyBufferForceReleasesEmptyAndFaulted` | legacy 保留层的暂存缓冲 | 删去，改为 `TestBodyChunksFollowTheGridAndAreReleased`（块网格、Finish 后释放） | 只属于 legacy |
| `internal/audit` `TestBodyEncoderReleasedOnFinish`、`TestBodyEncoderConcurrentStages`；`TestBodyEncoderReleasedAfterDeferredFlushAndFailedFinish` → `TestBodyEncoderReleasedAfterFailedFinish`；两个基准 | 在 legacy 会话上；未满的块在失败的 `FinishStage` 之前由 `AddChunk` 写出 | 在 unified 会话上；未满的块封进失败的提交 | 写库方式不同 |
| `internal/proxy` `TestMemoryBudgetExhaustion` | 断言不变 | 断言不变，明说管理器没有暂存（以前靠 nil 默认） | 测试管理器一律带暂存 |
| 各等价测试（`internal/proxy` 端到端、暂存、故障；`internal/audit` 分歧与暂存；`internal/storage/postgres` 会话；`tests/integration` 版本 2 与写入路径） | 与并排的 legacy 运行比 | 与 legacy oracle 比，比较项不变；去掉只关于 legacy 一侧的断言：legacy 解析读回块、legacy 的完整性校验、legacy 的版本 1 列检查、版本 2 测试里 legacy Header 字节的测量日志、入站阶段测试里 legacy 的完成日志检查。`sendAgainstOracle` 另比响应头和 Trailer，比以前严 | legacy 已删 |
| `internal/proxy` stream_end_order 各测试 | 两条路径各一遍 | legacy 子测试去掉，表照旧在 unified 上断言 | 只剩一条路径 |
| `internal/storage/postgres` `TestHarnessLegacyModelMatchesSession` | 与真实 legacy 会话比 | 与冻结的操作流比 | legacy 已删 |
| `internal/app` `TestUnifiedWritePathHandsCommittedAuditsToTheParser` → `TestCommittedAuditsAreHandedToTheParser` | legacy 子测试断言不交接 | 去掉 | 只属于 legacy |
| `internal/app` `TestFailedFinalCommitKeepsStagedChunks` | 两条路径同一故障下的终态 | 去掉 legacy 运行，它到过的终态在 unified 上断言 | 只剩一条路径 |
| `internal/app` `TestUnusableStagingDirectory` → `TestUnusableStagingDirectoryMakesTheAuditUnavailable` | available 退回 legacy、保持健康 | 两种模式下审计都不可用；没有配置、不是目录、在文件下面、对他人开放（仅 Unix）；断言日志行和什么都没采集 | 维护者的暂存决定 |
| `internal/app` `TestLegacyStartImportsWhatUnifiedStaged`（含 PostgreSQL） → `TestStartImportsWhatThePreviousRunStaged` | legacy 启动、没有 stager | 启动带 stager；恢复的断言不变 | 只剩一条路径 |
| `internal/app` `TestCaptureSettingsWithTheUnavailableManager` | `write_path` 为 `legacy` | `unified` | 字段总是 unified |
| `tests/integration` `TestAuditPersistsFourEncryptedBodyStages` | Header 和 Trailer 读版本 1 的 `http_headers` 行（默认走 legacy） | 经 `headerblock.Expand` 读版本 2 的块，并要求没有逐值行 | PostgreSQL 上写版本 2（C、D） |
| `tests/integration` `TestUnifiedParseDoesNotReadBackOnPostgreSQL` | 与 legacy 比读回次数和延迟 | 去掉 legacy 运行 | 只属于 legacy |
| `internal/config` `TestAuditDefaultsToLegacy` → `TestAuditDefaults`；`TestValidateAudit`；新增 `TestLoadAuditRefusesTheRemovedLegacyWritePath`、`TestLoadAuditRequiresTheStagingDirectory`；`TestExampleConfigsLoad` | 默认 legacy；只有 unified 要求暂存目录 | 默认 unified；两种模式都要求暂存目录；`legacy` 被拒；Windows 上把示例的 Unix 暂存路径换成本机绝对路径 | 配置变更 |
| `TestMeasureFinish`、`TestMeasureStaging` | 两条路径各量一遍 | 去掉 legacy 一侧，数字见 R.7 | 只剩一条路径 |
| `internal/proxy` 端到端 | 数 unified 存储上的逐操作写（`legacyOps`）为 0 | 去掉：`audit.Store` 已没有这些方法，由编译器保证 | 接口收窄 |

**已定：检查挪到恢复之前。** 本节起初把“暂存目录不可用时启动仍先跑 `RecoverInterruptedAudits`”列为待定（那样带着暂存块中断的 audit 会不带这些块就终结，目录修好后导入把文件改名为 `.orphan`）。维护者决定把检查挪到恢复之前，理由与 R.3 第 2 条相同，做法见上面“暂存目录必填”一段。

### R.9 偶发的未终结或未解析

**看到的。** unified 成为唯一写入路径之后，整包运行偶尔有一条 audit 在几秒内没有终结或没有解析，单独重跑总是通过，各一次：`internal/parser` `TestInputFromHandedOverEvidenceEqualsTheStoredInput/postgres`（“no job was handed over”）；`internal/app` `TestPostgresArchiveDiskFullPublishesNothing`（6 条 audit 30 秒后只有 5 条终态）；`tests/integration` `TestAgentJourneyPaging`（9 条里 1 条 open）；`internal/proxy` `TestCaptureWriteFailuresEndTheAuditFailed`（SQLite，主机上与编译并行时）；另有 `internal/app` `TestFailedFinalCommitKeepsStagedChunks` 与 `internal/web` `TestWebRegenerateIsNotDelayedByAWriteToAnotherWeek` 各一次。

**复现。** 临时插桩（已移除，没有提交）把 writer 批次失败、操作级失败、队列满、恢复终结、提交的每次失败和降级、检查点推迟、交接被拒、parser 的 claim/读取/保存失败打到标准错误，在 PostgreSQL 容器里同时最多跑三个测试二进制：`internal/parser` 36 遍、`internal/app` 12 遍、`tests/integration` 7 遍。`internal/parser` 失败一次，正是上面那条：

- 检查点 2 被 `ValidateAuditCheckpoint` 拒绝（`capture version 2 checkpoint inserting stages requires a header block`），会话记 `capture_checkpoint_deferred`；
- `CommitAudit` 在发送前被 `ValidateAuditCommit` 以同一原因拒绝（不重试，耗时 2 µs），会话以 partial、`audit_finalize_failed` 结束，不交接。

其余失败事件全部来自测试注入的故障；没有出现未注入的批次失败、队列满或恢复终结，PostgreSQL 日志里也没有死锁、锁超时或语句超时。所以“提交批次失败、由 5 秒一次的恢复以 failed 终结、再等 30 秒的 pending 扫描”这一假设不成立。

**原因。** `blockShape.with`（`internal/audit/header_block.go`）用会话的 `stageOrder` 计算位，它从 1 开始编号，而范围检查是 0 到 3，于是 `response_sent` 从不进入形状（C.8 的“与上次写的块相同就不带块”）。只有 `response_sent` 变化的写因此不带块：

- 上游在 `request_sent` 的 Body 被看到结束（EOF 或 Close）之前就回了响应头时，检查点 1 已带上 `response_received`，检查点 2 只插入 `response_sent`；它和随后的提交都插入了阶段却没有块，被存储拒绝。提交在发送前失败，恢复表里没有记录，audit 一直不终结（`ended_at_ns` 为空、不解析），直到下次启动由 `RecoverInterruptedAudits` 收尾（R.1 第 10 条的路径）。这个先后取决于 Transport 何时读到请求 Body 的结束，负载下才偶尔出现。
- 响应写出方在检查点 2 之后捕获的 `response_sent` Trailer 不改变形状，提交不带块，存下的块里没有这些 Trailer，audit 却以 complete 终结。

SQLite 写版本 1，没有块，不受影响；`internal/proxy` 那一次（SQLite）不是这个原因，在主机上与容器里的测试并行循环 12 遍没有复现，见下。

**改了什么。** 提交 `98863ba`：形状改用 `storage.StageOrder`（0 到 3）。形状只在内存里；没有碰到上面两种先后的 audit，每次写带不带块与之前相同，存下的行不变。新增 `TestHeaderBlockCoversTheResponseSentStage`（会话测试，桩存储按两个存储的规则校验）：上游先回响应时两个检查点和提交都合法、检查点 2 带四个阶段的块；`response_sent` 有 Trailer 时提交带上含它们的块。修复前两个子测试都失败。修复后 `internal/parser` 在同样条件下 40 遍、`tests/integration` 4 遍，没有失败，也没有任何检查点推迟。

**生产上的影响。** PostgreSQL 部署里，上游响应头先于请求 Body 的结束被观察到的请求，会以一条未终结的 audit 留到下次启动，期间不解析，启动时由 `RecoverInterruptedAudits` 收尾；带下游 Trailer 的响应丢了 `response_sent` 的 Trailer。客户端收到的响应不受影响。

**没有解决的。** `internal/proxy` `TestCaptureWriteFailuresEndTheAuditFailed`、`TestFailedFinalCommitKeepsStagedChunks` 和 `internal/web` 那一次没有复现，原因未定。一个可能：同一个“上游先回”的先后会让检查点 1 带上 `response_received`，故障注入用例对哪一次写带哪些行的断言（例如“header insert”的 3 个阶段）就不再成立。提交 `a96c20a` 把 archive harness 的等待放宽到 90 秒，说明里的原因（交接在负载下被错过）不对：那条 audit 根本没有终结，等多久都一样；修复之后 30 秒也够，是否改回由维护者决定。
