# Issue #59 第 3 阶段详细设计：终结时一次提交、单一 Header 块、解析不读回

状态：草案，待维护者审阅，**尚未实施**。基于提交 `0faae0a`（分支 `claude/issue-59-stage3-ca432f`）。迁移编号按 007 写：006 已经给了 `turns (created_at_ns, turn_id)` 索引。本阶段对应方案 `doc/design/issue-59-unified-write-cold-archive.md` 第 6 节的 P2：4.2 的第一步和第二步、决策 5.10、`audit.write_path` 开关。4.2 第三步不在范围内。

## 0. 实施前必须先定的四件事

正文 K 节列了十九项待定。其中四项不是“给个默认值就能做”的：一项推翻了此前对维护者说过的话，三项的推荐做法与已有决策的用意相抵。它们定下来之前，除了不带调用方的 `CommitAudit`（J.1 第 1、3 步）以外，本阶段的代码都不动。

### 0.1 在途请求崩溃时留下的证据（A.4、F.8）

此前的说法是“单请求每阶段预算取 1 MiB，与现在的写库阈值相同，所以在途请求崩溃时留下的证据不比现在少”。**这句话只对超过 1 MiB 的那部分 Body 成立。** 现在阶段行和 Header 在阶段开始后几毫秒内就提交了，请求 Body 在读完时提交；按 4.2 第一步的写法，这些都要等到 `Finish`。一条请求体不到 1 MiB、响应流到一半时崩溃的请求：

| | 现在 | 4.2 第一步原样实现 |
| --- | --- | --- |
| 起始行 | 有 | 有 |
| 已到达的阶段行与 Header | 有 | 没有 |
| 请求 Body | 有，可下载 | 没有 |
| 响应 Body | 只有满 1 MiB 的块 | 没有（超出预算的部分在暂存里） |

方案 3.2 第 4 条要求崩溃耐久性的任何变化都是明确的决定。“前两步不改变耐久性”对已完成的请求成立，对在途请求不成立。四种处理方式：

| 选项 | 做法 | 代价 |
| --- | --- | --- |
| 甲 | 接受，并写进模块 03 和方案 3.2 | 长流中途崩溃后，请求 raw 和 Header 都没有，只剩起始行和 User-Agent |
| 乙 | 请求在途超过 T 秒（设计稿建议 10 秒）时，把已有的部分写进本地暂存 | LLM 流式请求超过 10 秒的很常见，这等于让相当一部分请求都写一次本地盘，接近 5.1 否决的做法 |
| 丙 | 每条请求在请求 Body 读完时把请求侧写进本地暂存 | 每条请求一次本地写盘，就是 5.1 否决的做法 |
| 丁 | 阶段性提交到数据库：请求 Body 读完时、响应头到达时，各排一个不等待的写操作，把到那时为止的阶段行、Header 和请求 Body 提交；`Finish` 时再提交其余并等待 | 每条请求多两个异步写操作（现在约二十个）；Header 块要先写一份残缺的、终结时再更新一次；崩溃时留下的证据与现在基本相同，不需要本地盘 |

审阅意见倾向丁：它不引入第二处持久化，也不让耐久性倒退，与 5.1“耐久性不倒退、不为每条请求落本地盘”的用意一致。它和“终结时一次提交”的字面不同（变成最多三次，其中只有最后一次被等待），所以要由维护者定。

### 0.2 Header 块与 parser 的明文边界（C.7、K.7）

设计稿让 parser 在读白名单 Header 时解密整块再过滤。现在白名单之外的 Header（包括 `Authorization`、`x-api-key`）在 parser 进程里从不解密，5.10 第 2、3 点正是为了守住这条边界。整块解密意味着洞察、项目标识和它们的回填每处理一条记录，都会把凭据解密到内存里一次。

可行的替代：把块拆成两段密文，一段是凭据项的值（判定沿用 `agentapi.IsCredential`），一段是其余全部内容，其中凭据项只留名称、次序和长度。parser 和回填只开后一段；详情页两段都开。两段都进摘要 v2。P3 的归档按 5.5 本来就不保留凭据值，届时只需要后一段加上由前一段算出的指纹。代价是块的格式和摘要多一项。

这改的是 C.3、C.4、D.2 的格式，属于完整性格式，要维护者定：整块一段（简单，边界变宽），还是两段（边界不变，格式多一项）。

### 0.3 `CommitAudit` 失败时怎么办（B.5、K.3）

设计稿推荐把失败的整条提交密封进本地暂存，等数据库恢复后重放。这是第二套重放语义：5.1 否决乙时的理由之一，就是不愿意同时维护“在途溢出的残缺证据”和“已 `Finish` 的完整终态”两套重放。

更简单的做法没有被设计稿比较：`Finish` 本来就同步等待提交，失败时会话手里仍然有全部数据，可以在处理函数返回之前有限次重试（带总时限）；仍然失败就按现在的失败路径以 failed 终结，证据丢失范围写进文档。它不需要落盘，也不产生重放。代价是数据库故障期间这些请求的处理函数多等一个时限。

### 0.4 预算默认值与真实负载（F.4、K.2）

附录 A.1 的部署平均请求体约 1.1 MB。按每阶段 1 MiB 的预算，这类请求大多会有第一个整块落暂存。也就是说，按已经选定的“超预算落本地暂存”，在这种负载上大部分请求都会写本地盘。选定暂存时这一点还不知道。

处理方式取决于 0.1：选丁的话，请求 Body 在读完时就进了数据库，内存里那份只是留给解析用的，预算可以放宽而不影响崩溃证据；选甲或乙的话，预算越大崩溃时丢得越多。建议 0.1 定了之后，用同一个二进制在 `legacy` 与 `unified` 之间做 A/B，预算取 1 MiB 和 8 MiB 两档，再定默认值。

### 0.5 只需要点头的两项

Header 块的存放与编码（C.2 到 C.4，受 0.2 影响）和摘要 v2 的字节序列（D.2）按 5.10 设计，审阅没有发现问题，需要维护者确认后才能写代码。其余各项（K.6、K.8 到 K.19）的推荐做法都不改变证据语义的方向，实施时照做并在阶段小结里列出。

---

记号：

- 〔核〕：作者读代码直接核对过（提交 `0faae0a`），给出文件与函数。
- 〔推〕：推断，没有测试或实测证实。
- 〔设〕：本文提出的设计。
- **【需维护者】**：涉及证据语义或完整性格式，动手前必须由维护者批准。

文中路径都相对仓库根目录。

---

## A. 现在的采集路径

### A.1 一条请求经过的代码

按时间顺序。“异步”指 `submitAsync`：入队即返回，不等提交；“同步”指 `submitSync`：等所在批次提交后的 ack（`internal/storage/postgres/writer.go`）〔核〕。

| 时刻 | 代码 | 写入操作 | 等待 |
| --- | --- | --- | --- |
| 路由命中后 | `internal/proxy/proxy.go` `handler.ServeHTTP` → `beginAudit` → `internal/audit/manager.go` `Manager.Begin` | 生成 id，Request-URI 用 AAD `(audit_id, "request_uri")` 加密，算 `api_key_fpr`，`BeginAudit` | 同步 |
| 同上 | `Manager.Begin` → `Session.WrapRequestReceived` → `startStage` | `StartStage(request_received)`；`addHeadersLocked` 逐值加密后一次 `AddHeaders` | 异步 |
| 紧接着 | `proxy.go` 注册 `defer session.Finish()`，早于拦截器 | — | — |
| 拦截器 | `h.engine.Evaluate`；拒绝时 `MarkRejected`、`closeRequestBody`、`writeJSON`。拒绝路径的 ResponseWriter 没有被包装，所以没有 `response_sent` 阶段 | — | — |
| 放行 | `WrapResponseWriter`，`defer observedResponse.CaptureTrailers()`，然后 `reverseProxy.ServeHTTP` | — | — |
| Rewrite | `newReverseProxy` 的 `Rewrite`：Accept-Encoding 改 identity，`WrapRequestSent` → `startStage(request_sent)` | `StartStage`、`AddHeaders` | 异步 |
| Transport 读出站 Body | 出站 Body 包着入站的 observed reader，所以每次 Read 先 `observeRead(request_received)`，再 `observeRead(request_sent)`（`internal/audit/body.go` `observedReadCloser.Read`） | 首次观察时 `ensureBodyLocked` → `StartBody`；`observeBodyLocked` 攒满 1 MiB 时 `flushBodyLocked` → `AddChunk` | 异步 |
| 请求 Body EOF | `observeRead` 收到 `io.EOF`：`flushBodyLocked(force=true)` 写尾块，`eofSeen`/`hashComplete`；`captureTrailers` → `AddHeaders(trailer)` | `AddChunk`、`AddHeaders` | 异步 |
| 响应头到达 | `ModifyResponse` → `WrapResponseReceived`：读 `X-Oneapi-Request-Id`，`startStage(response_received)` | `StartStage`、`AddHeaders` | 异步 |
| 响应 Body | 拷贝循环读 upstream（`observeRead(response_received)`，SSE 事件与终止事件探针只在这一阶段），写 `observedResponseWriter.Write` → 首次写时 `start` → `startStage(response_sent)`，然后 `observeWrite` | 每个阶段 `StartBody`，每 1 MiB 一个 `AddChunk` | 异步 |
| 响应 EOF | 同请求 EOF：尾块、trailer | `AddChunk`、`AddHeaders` | 异步 |
| 处理函数返回 | defer 逆序执行：`CaptureTrailers`（`response_sent` 的 trailer），然后 `session.Finish` | `AddHeaders` | 异步 |
| `Finish` | `internal/audit/session.go` `finish`：定 forward status；按阶段顺序 `finishStageLocked`（强制 flush、`response_sent` 逻辑 EOF、封存时间线、成对 `body_stage_mismatch` 检查）；逐个 `FinishStage`；`FinishAuditWithResult` | `FinishStage`×n 异步，`FinishAudit` 同步 | 等终结批次提交，无超时 |
| 提交之后 | 解析状态为 pending 时 `notify`（`parser.Worker.Notify`，队列满则放弃），有 request id 时 `callerNotify`；生成 `TerminalSummary` | — | — |
| 最后 | `proxy.go` 最外层 defer 写“请求完成”日志 | — | — |

以上全部〔核〕。

`finishAudit`（`internal/storage/postgres/writer.go`）在一个 savepoint 里依次做〔核〕：

1. `ended_at_ns` 已有值时只读回已提交的终态（`loadFinishedOutcome`），不再改任何东西。
2. 已存的 `capture_status = 'failed'` 时沿用 failed，跳过成对合并；否则 `deduplicateEquivalentBodyStages`。
3. `CaptureStatus != complete` 时 `finalizeIncompleteCapture`：按已提交的块修正长度和计数，把 streaming 的阶段和 Body 收尾为 partial。
4. 更新 `audit_records` 终态和调用者状态。
5. 结果异常时（非 completed、非 complete、无状态码或不在 2xx/3xx、skipped），把全部 `body_streams.retention_state` 设为 `full`。
6. `capturePayloadDigest` 加 `appendIntegrityEvent(capture_finalized)`。

`applyWrite` 处理 `writeFinishAudit` 时，先对该 audit 未写标记的恢复条目执行 `recoverCaptureEntry`，再检查恢复溢出〔核〕。

### A.2 一条典型流式请求的操作数和提交数

前提：四个阶段都到达，各阶段 Body 小于 1 MiB，没有 trailer。

| 来源 | 操作 | 个数 | 同步 |
| --- | --- | --- | --- |
| `Begin` | `BeginAudit` | 1 | 是 |
| 每个阶段 | `StartStage`、`AddHeaders`、`StartBody`、`AddChunk` | 4×4 = 16 | 否 |
| `Finish` | `FinishStage`×4、`FinishAudit` | 5 | `FinishAudit` 是 |
| 解析 worker | `ClaimPendingParse`、`SaveParsedAudit` | 2 | 都是 |

采集共 22 个操作，与方案 2.2 的估计一致〔核，按代码数出〕。每多 1 MiB，该阶段多 1 个 `AddChunk`；每组 trailer 多 1 个 `AddHeaders`。之后还有洞察的 `SaveAnalysis` 和项目标识的写入。

每个操作一个 `SAVEPOINT writer_operation`。批次最多 64 个操作或等 5 ms（`types.go` 的 `writerBatchSize`，`open.go` 的 `writerBatchDelay`）〔核〕。所以提交数取决于并发和时序，不能从代码推出。附录 B.2 实测为每条 audit 27.74（heavy）和 17.76（small），其中含读连接的只读语句。

### A.3 各种失败怎么处理

| 情形 | 代码 | 结果〔核〕 |
| --- | --- | --- |
| 队列满 | `submitAsync` 不阻塞，直接返回 `ErrQueueFull`；如果是 `FinishAudit`，先 `rememberFailedWrite` | `StartStage` 失败：阶段 `faulted`、`start_stage_failed`、不持久、不写 Header；`StartBody` 失败：`start_body_failed`；`AddChunk` 失败：`add_chunk_failed`，`storedLength` 不增加；`AddHeaders` 失败：`add_headers_failed`；`FinishStage` 失败：`captureStatus=partial`、`audit_finalize_failed`。available 模式记 gap（`queue_full`），但一个会话最多记一次，不论失败几次、哪一种（`recordGapReasonLocked` 的 `gapRecorded`） |
| 可隔离的写失败（SQLSTATE 23xxx、本地校验错误等，`canIsolateWriteError`） | `commitBatch` 回滚到该操作的 savepoint，然后 `markCaptureWriteFailed` | audit 标 `capture_status='failed'`、`capture_write_failed`；Header 失败的阶段标 `capture_headers_failed`；缺块时 Body 标 `capture_chunk_missing`。同批其他操作照常 |
| 存储级失败 | 整批回滚，每个操作 `rememberFailedWrite`，writer 置不健康 | `recoverCaptureWrites` 每 5 秒处理至多 16 个 audit，补记失败标记，并在队列屏障之后补写终态。恢复表上限 1024，满了锁定溢出，拒绝新的准入 |
| strict 与 available | `proxy.go` `beginAudit` | 区别只在 `BeginAudit`：strict 失败回 503，available 失败照常转发、不建 audit。会话里的 gap 只在 available 模式记（`newSession` 只在 `ModeAvailable` 时设 `session.gaps`）。`BeginAudit` 之后的写失败在两种模式下都只降级证据 |
| 客户端取消 | `MarkClientCancelled`、`markFailure`、`observeWrite` 和 `observeRead` 里对 `request.Err()` 的判断 | `client_cancelled`，`captureFault`；终止事件之后的断开按 completed 处理（`responseLogicallyCompleteLocked`） |
| 上游中断 | `observeRead(response_received)` 读错误 | `body_read_error`，`newapi_error`/`upstream_body_read_error`；上游不可达时 `ErrorHandler` 自己写 502/504 JSON |
| 进程退出 | 下次启动时 `internal/app/app.go` 在 `EnableIntegrity` 之后调 `RecoverInterruptedAudits`（`internal/storage/postgres/recovery.go`） | `ended_at_ns IS NULL` 的 audit 改为 `interrupted`；streaming 的阶段和 Body 改为 partial、`process_exit`；按已提交的块修长度，raw 一律 `full`；每条签一个 `capture_finalized`；插一条聚合的 `process_exit` gap |

恢复里有一个现成限制：`recoverInterruptedAudits` 的块聚合 CTE 不带 audit 过滤，对整张 `body_chunks` 做 `GROUP BY`（`recovery.go`）〔核〕。方案 2.2 已记录，本阶段不改。

### A.4 崩溃时库里有什么

这一节决定 F 节里最重要的一个取舍。

以一条流式请求为例：请求 Body 小于 1 MiB，进程在响应流到一半时崩溃。

| 证据 | legacy：崩溃时已提交 | 依据 |
| --- | --- | --- |
| audit 起始行 | 有 | `BeginAudit` 同步 |
| 已到达的阶段行（streaming 状态） | 有，入队后几毫秒内提交 | `startStage` 立即 `StartStage` |
| 已到达阶段的全部 Header | 有 | `startStage` 立即 `AddHeaders` |
| 请求 Body，两个请求阶段各一份 | 有 | 请求 EOF 时 `flushBodyLocked(force=true)` |
| 请求 trailer | 有 | EOF 时 `captureTrailers` |
| 响应 Body | 只有已经满 1 MiB 的块 | `observeBodyLocked` |

以上〔核〕。恢复之后，这条记录是 `interrupted`、`partial`，四个阶段都在，请求 raw 完整可下载。

`unified` 第一步按 4.2 的写法，只在 `Finish` 时提交一次。同一时刻崩溃时库里只有 audit 起始行；没有超出预算、因而没有落暂存的内容全部丢失〔推，按 4.2 的描述推出〕。维护者定默认值时说“单请求预算等于现在的 flush 阈值，保证请求中途崩溃留下的证据不少于现在”。这个前提只对超过 1 MiB 的那部分 Body 成立；对 Header、阶段行和小于 1 MiB、已经读完的请求 Body 不成立。处理方式见 F.8，**【需维护者】**。

### A.5 流结束时刻与终结提交的先后

`internal/proxy/stream_end_order_test.go` 用一个包装 `*sqlite.Store` 的 `blockingFinishStore` 挡住 `FinishAuditWithResult`〔核〕。它固定了方案 2.2 那张表：HTTP/1.1 分块和 HTTP/2 的响应结束晚于终结提交；带 `Content-Length` 的 HTTP/1.1 在终结提交之前就结束；代理自己生成的错误 JSON 连状态行都晚于终结提交。

### A.6 本阶段不能改变的东西

1. 转发字节和转发时序。只有“终结提交”的内容变了，它挡住处理函数返回这件事不变，所以 A.5 那张表在 `unified` 下必须逐格相同。
2. `BeginAudit` 在两种模式下都同步（5.6）。strict 只在准入时生效。
3. defer 的顺序：先 `CaptureTrailers`，然后 `Finish`（等提交），最后写完成日志。完成日志和 `TerminalSummary` 取的是已提交的终态。
4. 四个阶段独立采集：各自的长度、SHA-256、时间、状态和错误码；`body_stage_mismatch` 的判定；终止事件之后断开算完成的规则；gap 的语义。
5. 成对合并的条件和合并后的行形态（B.3）。
6. 异常结果的 raw 保留为 `full`；`DecideRawRetention` 的按侧规则不动。
7. 旧行和旧事件照常读取和校验，不重写任何已有的行。

---

## B. `CommitAudit`

### B.1 输入类型〔设〕

放在 `internal/storage/types.go`，两个存储共用：

```go
// AuditCommit 是 unified 路径在 Finish 时提交的全部采集结果。
// 审计起始行已由 BeginAudit 写入；CommitAudit 只更新它，不插入。
type AuditCommit struct {
    Finish         AuditFinish   // 终态，语义同 FinishAudit
    CaptureVersion int           // 1：逐值 Header 行；2：单一 Header 块。必须等于起始行上的值
    Stages         []StageCommit // 只含实际到达的阶段，按 stageOrder 排列
    Headers        []HTTPHeader  // 仅 v1：逐值密文，AAD 与现在相同
    HeaderBlock    *HeaderBlock  // 仅 v2；没有任何阶段时为 nil
    Chunks         ChunkSource   // 拥有块，按 (stage 顺序, seq) 产出
    PayloadBytes   int64         // 块密文与 Header 密文的总字节，用于批次与 alone 判定
}

type StageCommit struct {
    Stage           HTTPStage      // 终值：State、EndedAtNS、ErrorCode、StatusCode、ContentLength
    ContentType     *string        // 仅 v2，见 C.6
    ContentEncoding *string        // 仅 v2
    Body            *BodyStream    // 终值；SourceStage 已按 B.3 在内存里判定；RetentionState=pending
    Timeline        *StreamTimeline
}

type HeaderBlock struct {
    Compression     string // none | gzip
    PlaintextLength int64
    DataEnc         []byte
}

// ChunkSource 让 writer 按语句大小分批取块：内存里的块直接给出，
// 落了暂存的块从本地文件按需读出，进程不必一次装下整个 Body 的密文。
type ChunkSource interface {
    Each(visit func(BodyChunk) error) error
}
```

`ChunkSource` 的约定：

- **可以重复遍历。** 每次 `Each` 都从头产出，降级重放（B.5）要遍历第二遍。会话在 `CommitAudit` 应答之前不释放它引用的内存密文。
- **每一项来自块索引。** 一块要么是内存里的密文：尚未落暂存的段在 `Finish` 时封好，以及已封好但仍在暂存 writer 队列里的块；要么是暂存文件里的位置（已写盘）。所以 `Finish` 不必等暂存 writer 写完。会话把自己标为“已提交”之后，暂存 writer 丢弃该会话仍在队列里的记录，提交后删除文件，不会再被写回来。
- **读暂存失败时**，`Each` 返回一个本地错误（`localWriteError`，可隔离），触发 B.5 的降级重放。重放时块逐行插入，读不出的那一块跳过，按现在 `AddChunk` 失败的语义处理：seq 出现缺口，`finalizeIncompleteCapture` 标 `capture_chunk_missing`。
- **在 writer 事务里读本地文件。** 读的是本地文件，与 PostgreSQL 的语句超时相比很快；但它确实把文件 IO 放进了唯一 writer 的事务里。A/B 要看这一项。

`AuditRecord` 增加 `CaptureVersion int` 和 `UserAgentEnc []byte`，由 `BeginAudit` 写入（C.5）。legacy 路径两者都留零值：前者取列默认值 1，后者为 NULL。

存储接口在 `internal/audit/manager.go` 的 `Store` 里增加：

```go
CommitAudit(context.Context, storage.AuditCommit) (storage.AuditFinish, error)
```

返回值与 `FinishAuditWithResult` 相同：外层事务提交之后的实际终态。

### B.2 一个 savepoint 里写什么〔设〕

`writeCommitAudit` 是新的 writer 操作，在 `applyWrite` 里与 `writeFinishAudit` 共用前置检查：恢复条目的标记和恢复溢出。执行顺序：

1. `SELECT ended_at_ns, capture_version, capture_status FROM audit_records WHERE audit_id=$1 FOR UPDATE`。
   - 已终结：调 `loadFinishedOutcome`，不插入任何行，返回已提交的终态。这对应提交结果不确定之后的重试，以及暂存重放（F.7）。
   - `capture_version` 与输入不符：本地错误，不写。
2. 多行 `INSERT INTO http_stages`：最多 4 行，写终值。v2 带 `content_type`、`content_encoding`。
3. v1：多行 `INSERT INTO http_headers`。v2：`INSERT INTO http_header_blocks` 一行。
4. 多行 `INSERT INTO body_streams`：写终值，合并过的阶段直接写合并后的形态。
5. `body_chunks` 多行 INSERT，从 `ChunkSource` 分批取。
6. `stream_timelines` 多行 INSERT。
7. 调现有的 `finishAudit(transaction, &commit.Finish, signer)`，并加一个参数 `skipDedup=true`。

这样第 7 步完全复用现有终结逻辑：

- 已存状态不是 failed。
- 合并已经在内存里做过。就算不跳过，`readBodyDedupState` 读到重复阶段的 `source_stage` 已不等于自身，也会直接返回，结果一样。
- `finalizeIncompleteCapture` 在 capture 非 complete 时照常运行。对 unified 写入的行它没有可修的东西，因为行和块在同一操作里写出、彼此自洽；出于对等起见仍然运行。
- 终态 UPDATE、异常 raw 设 `full`、按 `capture_version` 分派的摘要（D.3）、`capture_finalized` 事件，都与现在相同。

批量上限沿用 `graph_writer.go` 的 `forEachInsertBatch`：每条语句最多 400 行、行数据约 4 MiB（`graphHashQueryBatch`、`objectInsertBatchBytes`）〔核〕。

- `body_chunks` 9 列 × 400 行 = 3,600 个绑定参数，远低于协议上限 65,535。实际上限由 4 MiB 决定，约 4 个 1 MiB 块一条语句。
- `http_headers` 7 列 × 400 行 = 2,800 个参数，一条请求的 Header 一两条语句就够。
- `http_stages`、`body_streams`、`stream_timelines` 各一条语句。

语句数：v2、各阶段小于 1 MiB、两对都合并时，插入约 5 条，再加 `finishAudit` 原有的 6 到 10 条。现在是 22 个操作，每个都有 savepoint、RELEASE 和一到数条语句〔推，按代码数出〕。

### B.3 成对阶段的判定挪到内存里

现有条件，见 `writer.go` 的 `deduplicateEquivalentBodyPair`，对 (request_received, request_sent) 和 (response_received, response_sent) 两对各判一次〔核〕。只在已存 `capture_status` 不是 failed 时判；partial 的 audit 也判，条件只看 Body 本身。条件是下面全部成立：

| # | 条件 | unified 在内存里的对应 |
| --- | --- | --- |
| 1 | 两个阶段都有 `body_streams` 行 | 两个阶段都有 `stage.body` |
| 2 | 各自的 `source_stage` 等于自身 | 恒成立：`ensureBodyLocked` 置 `sourceStage = stage.name` |
| 3 | 两者 `state = complete` | `finishStageLocked` 算出的 `bodyState`：没有 fault、`eofSeen`、`storedLength == observedLength` |
| 4 | 两者 `hash_complete = 1`、`eof_seen = 1` | `body.hashComplete && body.eofSeen` |
| 5 | 各自 `stored_length = observed_length` | 来源阶段：保留的字节，内存加暂存，没有因耗尽而截断；重复阶段：见下文的“借用前缀” |
| 6 | 两者 `observed_length` 相等，`sha256` 长 32 且相等 | 同一个比较。`finishStageLocked` 已经在不等时标 `body_stage_mismatch` |
| 7 | 各自块的数量和长度之和等于 `chunk_count` 和 `stored_length` | 恒成立：块在内存里生成，与计数同源 |
| 8 | 已存 `capture_status` 不是 failed | unified 在提交前没有异步失败，恒成立 |

合并后重复阶段的行〔核〕：`source_stage`、`stored_length`、`chunk_count`、`stream_event_count`、`stream_timeline_complete` 取来源阶段的值，其余列保留自己的值，重复阶段的块全部删除。`response_sent` 自己的 `stream_event_count` 是 0，因为只有 `response_received` 做 SSE 观察（`ensureBodyLocked` 里的 `body.stream`）；合并后它变成来源阶段的事件数。unified 直接按这个形态写出。

重复阶段在内存里的做法〔设〕：

- 来源阶段 S 照常保留字节。
- 重复阶段 D 不复制字节，只维护“已比对相等的前缀长度”。D 每观察一段，就与 S 同偏移的字节比对。
- 出现第一个不相等的字节（偏移 d）时，D 转为“自持”：此后 D 自己保留从 d 起的字节，前缀 [0, d) 向 S 借用。
- 代码里 S 总是先于 D 观察到同一偏移的字节：出站 Body 包着入站 reader，响应写出的是刚读到的字节。这一点〔核〕于 `body.go`、`proxy.go`，但不是类型系统保证的。如果 D 观察到超出 S 已观察长度的字节，就把超出部分暂存为“前瞻缓冲”，等 S 追上再比对。前瞻缓冲计入预算；超出单阶段预算时 D 转为自持。
- 比对窗口：S 在每个 1 MiB 边界封块、落暂存（F.2），而 D 通常落后一次 Read。所以 S 释放一块明文的条件是“已写入暂存”且“D 已比对过这一块的末尾，或 D 已自持、已结束”。
  - 正常情况下 D 只落后一次 Read（`ReverseProxy` 的拷贝缓冲是 32 KiB，`proxy.go` 的 `newBufferPool(32 << 10)`）〔核〕，窗口很小。
  - 例外是 body 拦截器的有界预读：S 先读到预读上限，D 之后才从回放缓冲读（模块 03 §5）。这时 S 可能已经把前面的块落了暂存、释放了明文，D 需要的字节就从暂存读回、解密后再比对（F.5）。这是慢路径，只在有 body 拦截器的路由上出现。
  - 窗口中尚未释放的明文计入预算。
- `Finish` 时按上表判定。合并：D 没有块。不合并：D 的块由“借用的前缀”加“自持的字节”切出，块边界按 D 自己的偏移每 1 MiB 一块。借用的前缀从 S 的内存段读取，已落暂存的部分从暂存读回。

为了让不合并时的块行与 legacy 相同，D 要记录每个 1 MiB 边界上第一个字节被观察到的时刻，作为该块的 `observed_at_ns`（legacy 的 `pendingAtNS`）。

块边界：legacy 只在攒满 1 MiB 时，以及 EOF、Close、Finish 时强制 flush（`observeBodyLocked`、`flushBodyLocked`）〔核〕。所以一条完整 Body 的块总是若干个整 1 MiB 加一个尾块，unified 按同一规则切块就能逐行相同。唯一例外是全局预算压力下的提前落暂存（F.5），那时块可能不足 1 MiB，属于合理差异。

### B.4 某个阶段没有到达时

和现在一样：不写该阶段的任何行（方案 03 §4：“未调用 NewAPI 时……必须不存在”）。v2 的 Header 块里也没有该阶段的段（C.3）。

### B.5 失败的报告与恢复

一个操作装着整条 audit，失败的代价与现在不同。现在一个操作失败只丢那一个操作的证据，之前已提交的阶段、Header 和块都还在。

| 失败 | 现在 | unified 的提案〔设〕 |
| --- | --- | --- |
| 可隔离错误（23xxx，例如测试里的触发器） | 只回滚那一个操作；`markCaptureWriteFailed` 标记失败 | 第一次整体回滚到 savepoint 之后，在同一事务里“降级重放”，见下文 |
| 存储级错误（整批失败）、`ErrQueueFull` | 每个操作 `rememberFailedWrite`；恢复时补标记，按屏障补写终态；已经提交的部分保留 | 选项见下表 |
| 提交结果不确定（COMMIT 报错） | `finishAudit` 遇到已终结的行直接读回 | 同样：B.2 第 1 步遇到已终结的行不再插入 |

**降级重放**〔设〕：在同一个外层事务里，按 legacy 会提交的操作序列，用 legacy 的 SQL 逐个重放。每个操作包一个嵌套 savepoint，粒度与 legacy 相同：

1. 每个阶段：`insertStage`，写 streaming 初值。
2. 每个阶段每个 kind 的一组 Header：`insertHeaders`。v2 下整块是一个部件。
3. 每个 Body：`insertBody`，写初值。
4. 每个块一行：`insertChunk`。
5. 每个阶段：`finishStage`，即现在的 UPDATE。

失败的部件调现有的 `markCaptureWriteFailed`（按对应的 legacy 操作类型），然后以已存的 failed 状态调 `finishAudit`，由 `finalizeIncompleteCapture` 对账。初值取 `startStage`、`ensureBodyLocked` 当时会写的值：

- 阶段：状态、开始时间、status、content length；
- Body：长度为 0，`pending`。

这些值都在会话里。

和 `internal/proxy/capture_failure_test.go` 的对应关系：

| 用例 | unified 下 |
| --- | --- |
| `BEFORE INSERT ON http_headers`、`BEFORE INSERT ON body_chunks`（首块、中间块、尾块、全部块） | 第一次整体插入就会触发，进入重放，得到与 legacy 相同的行。只适用于 v1 和 SQLite；PostgreSQL v2 不写 `http_headers`，等价的用例是 `http_header_blocks` 上的 INSERT 触发器，结果是整块丢失，比 legacy 只丢一组更多，属于 v2 的合理差异 |
| `BEFORE UPDATE OF state ON body_streams WHEN NEW.state = 'complete'`（阶段终结及其组合） | 第一次整体插入直接写终值，不做 UPDATE，触发器不会触发，结果是 complete，与 legacy 不同。要么改用等价的 INSERT 触发器（`BEFORE INSERT ON body_streams WHEN NEW.state = 'complete'`，这时会触发重放，而重放第 5 步的 UPDATE 会再触发原来的 UPDATE 触发器），要么承认这是触发器写法导致的差异。推荐测试里两种触发器都装上 |
| “stage enqueue”（入队失败） | unified 没有按阶段入队，没有对应用例；由 `CommitAudit` 队列满的用例代替 |

存储级错误和队列满的三个选项：

| 选项 | 做法 | 代价 |
| --- | --- | --- |
| 甲 | 只保留终态元数据：`rememberFailedWrite` 存 `AuditFinish`，恢复时以 failed 终结一条没有阶段的 audit | 这批里每条请求的证据全部丢失；一次瞬时故障最多丢 64 条完整证据。现在同样的故障只丢这批里的那几个操作 |
| 乙 | writer 在恢复表里保留整个 `AuditCommit` 的密文，重试时重放 | 违反模块 04 §5“不会缓存或重放 Header value、Body、密文”的既定原则；内存只能按字节设上限 |
| 丙 | 会话收到错误后，把已密封的整条提交写进本地暂存（F.7 的终态文件），由暂存重放循环在存储恢复后重新提交；写暂存也失败时退回甲 | 失败路径才写盘；需要 writer 对 `CommitAudit` 不自动记终态，否则恢复会先把 audit 以 failed 终结，重放时就只能读回 |

推荐丙，暂存不可用时退回甲。**【需维护者】**：这关系到存储故障期间证据丢失的范围；重放成功时，记录拿到的是原来的终态（例如 complete），而当时的请求完成日志已经写了 `audit_finalize_failed`。现在的恢复也有同样的日志与库不一致（模块 03 §8）。

大提交：一个 `CommitAudit` 可能带几十 MiB 的块。现在一批最多 64 个操作，最坏也能到 64 MiB，所以这不是新问题，但会更集中。提案：

- `PayloadBytes` 超过 16 MiB 的提交走 `alone()`，独占一个事务，失败不连累邻居。
- 收集批次时按字节累计，超过 32 MiB 就截断。

两个数字由 A/B 调整。

现有的写失败恢复路径（`write_recovery.go`）对 unified 写入的 audit 只剩两件事：`CommitAudit` 的终态（选甲时）和 `BeginAudit` 之后的状态修复。`markCaptureWriteFailed` 的各个分支只对 legacy 的操作类型生效，保留不动。

### B.6 “与现在相同的行”是什么意思

同一请求、同一时钟序列下逐表比较。“相同”指非密文列逐字节相同；密文列各自用随机 nonce，所以比较的是解密后的明文、AAD 和长度。两次 legacy 运行之间本来也只有这一处不同。

| 表 | 列 | unified 与 legacy |
| --- | --- | --- |
| `audit_records` | 现有全部列 | 相同。`ended_at_ns` 取 `finish()` 里的同一次 `now()`。legacy 才有的 `capture_status='failed'`、`capture_write_failed`、`audit_finalize_failed` 来自异步写失败，unified 只在 B.5 的失败路径出现 |
| `audit_records` | `capture_version`、`user_agent_enc`（新增） | legacy：1、NULL；unified v2：2、按 C.5 编码 |
| `http_stages` | 现有全部列 | 相同。legacy 的中间态（streaming、`ended_at_ns` 为 NULL）在提交后不可见。`start_stage_failed`、`add_headers_failed`、`start_body_failed`、`add_chunk_failed`、`capture_headers_failed`、`capture_storage_failed` 这些因写失败产生的错误码只在 legacy 出现 |
| `http_stages` | `content_type`、`content_encoding`（新增） | legacy：NULL；v2：C.6 |
| `http_headers` | 全部 | v1：除 `value_enc` 的 nonce 外相同；v2：没有行 |
| `http_header_blocks`（新增） | 全部 | 只有 v2 才有 |
| `body_streams` | 全部 | 相同，包括合并后的形态和 `retention_state` |
| `body_chunks` | `seq`、`offset`、`plaintext_length`、`compression`、`encoded_length` | 相同：同一个编码器、同一个 Content-Type 输入、同样的块边界。`encoded_length` 随 Go 工具链可能变化，这是已知的（模块 18 §5）。全局预算压力下的块边界见 B.3 |
| `body_chunks` | `observed_at_ns` | 语义相同（块第一个字节被观察到的时刻） |
| `body_chunks` | `data_enc` | 明文相同，nonce 不同 |
| `stream_timelines` | 全部 | 相同，`timeline_enc` 的 nonce 不同 |
| `integrity_events` | `capture_finalized` | `payload_digest` 不同：它覆盖密文哈希，v2 的结构也不同；MAC 随之不同。事件类型、时间、顺序相同 |
| `audit_gaps` | 全部 | 写失败类的 gap 只在 legacy 出现；预算耗尽的 gap 只在 unified 出现（F.6） |
| `parsed_results`、turn 图、对象 | 全部 | 由 G 节保证相同：同一个解析函数、同一份明文 |

legacy 里合并的那一份是“先写后删”的，unified 不写。所以 `pg_stat_user_tables` 的插入和删除计数会下降，这是第一步的目的之一。

---

## C. Header 块 **【需维护者：存储位置、明文编码、AAD】**

### C.1 现状

采集〔核〕：

- 阶段开始时 `startStage` → `addHeadersLocked(stage, "header", headers)`。
- 三个读阶段在 EOF 或 Close 时由 `observedReadCloser.captureTrailers` 写 trailer；`response_sent` 的 trailer 由 `observedResponseWriter.CaptureTrailers` 在 `Finish` 之前写。
- `addHeadersLocked` 把 map 的键按 `sort.Strings`（字节序）排序，对每个键取 `headers.Values(name)`。每个值单独加密，AAD 为 `security.AAD(audit_id, "header", stage, kind, name, strconv.Itoa(index))`。一组 Header 一个 `AddHeaders` 操作，存进 `http_headers`，主键 `(audit_id, stage, kind, name, value_index)`，`name` 的排序规则为 `"C"`（`migrations/001_init.sql`）。

名称是“收到的 map 键”。`net/http` 解析出来的入站请求头和上游响应头都是规范形式；`ReverseProxy` 用 `Header.Add` 拷贝，也是规范形式。有一个现存的怪癖：`http.Header.Values(k)` 会先把 k 规范化再查。所以如果 map 里有非规范的键（例如代码直接赋值 `h["x-foo"]`），那个键查到的是规范键 `X-Foo` 的值：

- 只有 `x-foo` 时，它的值一行都不写；
- `x-foo` 和 `X-Foo` 同时存在时，`X-Foo` 的值会以两个名称各写一遍。

这一点〔核〕于本机 Go 1.27.3 标准库：`net/http.Header.Values` 调 `textproto.MIMEHeader.Values`，后者返回 `h[CanonicalMIMEHeaderKey(key)]`。仓库里没有对应测试。审计路由上这种键只可能出现在代理自己写的响应头里，目前代码没有这样写〔推〕。

读取方〔核〕：

| 读取方 | 代码 | 读什么 |
| --- | --- | --- |
| 管理端详情 | `internal/query/service.go` `Get` → `postgres/query_reader.go` `readHeaderEvidence`（`ORDER BY` 阶段顺序、`kind`、`name`、`value_index`） | 全部，逐值解密，长度不符时返回 `ErrIntegrity` |
| Agent 门面 | `internal/web/agent_requests.go` 的 `agentHeadersOf`（`agentapi.MaskValue` 掩码凭据）、`inboundUserAgent`、Header 导出（`agent_requests.go:939`） | 取自 `query.Detail.Headers` |
| 列表的 User-Agent | `query/service.go` 的 `List`、`listWithHeaderFilters` → `readUserAgent` → `QueryRequestHeaderEvidence` | 每行一次查询（N+1）；显示第一个值，任一值包含子串（不分大小写）即匹配，没有 UA 不匹配 |
| parser 的 allowlist | `parser/evidence.go` `loadRequestHeaders` → `LoadParserRequestHeaders`（SQL 按 `lower(name) IN (...)` 过滤） | 只解密名单内的入站 Header，供洞察与项目标识（`parser/project.go`、`parser/backfill.go`） |
| parser 的内容头 | `LoadParserStage` 读该阶段 `content-type`、`content-encoding` 的密文行；`loadBody` → `decryptContentHeaders` 解密，各取第一个非空值 | 两个值 |
| 回填判断 | `backfillInput`、`responseReleased` 调 `LoadParserStage` 只看 `retention_state` | 会读出内容头的密文，但不解密 |
| 测试快照 | `postgres/reader.go` `Snapshot` | 全部密文 |
| 离线导入 | `internal/storage/migrate/verify.go` `verifyEncrypted` 的 `http_headers` 分支 | 逐值解密校验，源只能是 SQLite |
| 完整性 | `postgres/integrity.go` `capturePayloadDigest` | 每行的元数据和密文哈希（D.1） |

### C.2 存放位置

| | `audit_records` 上加一列 | 独立表 `http_header_blocks` |
| --- | --- | --- |
| 大小 | 压缩加密后约 1 到 3 KB〔推，按附录 A.3 每条 52 个值、平均 100 字节估算〕 | 同左 |
| TOAST | 密文不可压缩。行超过约 2 KB 时移出行外，否则留在行内 | 一行，写一次 |
| 后续 UPDATE | `audit_records` 每行平均被更新约 4 次，没有一次是 HOT（附录 B.2）。块留在行内时，每次更新都把它再写一遍 WAL；移出行外时复用 TOAST 指针，但行仍然变宽 | 不受影响 |
| 列表查询 | 行变宽，每页的行变少，按索引回表的页数变多 | 不受影响 |
| HOT | 以后如果把状态列移出索引想要 HOT，行宽是阻碍 | 不受影响 |
| 归档 P3 | 读同一行 | 多读一张表，列覆盖测试多一项 |
| retention | 随行删除 | `ON DELETE CASCADE` |

推荐独立表。`user_agent_enc` 按 5.10 放在 `audit_records` 上：列表每行都要读它，而它通常只有几十字节。

### C.3 明文编码〔设〕

二进制、确定性、可逐字节复现，不用 JSON：Header 值可能含非 UTF-8 字节，`encoding/json` 会把它们替换成 U+FFFD。

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

- 段只出现在实际到达的阶段，按 stage_code 严格递增。没有到达的阶段没有段，与现在“没有行”一致。
- 到达了但没有 Header 的阶段，两个 `name_count` 都是 0。没有 trailer 时，trailer 段的 `name_count` 是 0；“没有观察到 trailer”和“观察到空 trailer”不区分，与现在一样都是没有行。
- 名称就是现在 `http_headers.name` 会存的值：map 键原样，不另做规范化。同一 kind 内按字节序严格递增，不重复。
- 每个名称的值按现在的 `value_index` 顺序排列，`value_count ≥ 1`。编码时复用 `addHeadersLocked` 的同一个循环（`sort.Strings` 加 `headers.Values(name)`），C.1 说的怪癖也原样保留，得到的集合与 v1 的行逐项相同。修不修这个怪癖另议，见 K.15。
- 解码时检查上面每一条，以及长度不越界、没有尾随字节。任何一条不满足都按完整性错误处理。这样一份明文只有一种解码，P3 归档比对时可以直接比字节。
- 上限：`plaintext_length` ≤ 64 MiB。Go 默认请求头上限 1 MB，Transport 默认响应头上限 10 MB〔推，标准库默认值〕。

“展开”成扁平列表时，顺序为 (stage 顺序, header 先于 trailer, name 字节序, value_index)。这正是 `readHeaderEvidence` 的 `ORDER BY` 在 `"C"` 排序规则下的顺序〔核〕，所以 v1 与 v2 交给 `query` 的列表逐项相同，`ValueLength` 取 `len(value)`。

快照时机：Header 必须在阶段开始的那一刻深拷贝。`ReverseProxy` 之后会往同一个响应头 map 里补 trailer（`http.TrailerPrefix` 键）。legacy 当场加密，等于当场快照了〔核于 `startStage`〕。

### C.4 压缩与加密〔设〕

- 压缩：`bodycodec.Encode(plaintext, "application/x-llmapi-header-block")`。这个类型不是 text 或 json，但 `LLHB` 不是已知的压缩魔数，所以 128 字节以上、压缩节省超过 32 字节时用 gzip（`internal/bodycodec/codec.go`）〔核〕。
- 加密：AES-256-GCM，AAD 为 `security.AAD(audit_id, "header_block_v1", compression)`，与 `body_chunk_v2` 和 `stream_timeline_v1` 同一种写法。
- 存储：`compression`、`plaintext_length`、`block_enc`。读取时先认证解密，再用 `bodycodec.Decode(…, plaintext_length)` 解压并核对长度，然后按 C.3 严格解码。

### C.5 `user_agent_enc`〔设〕

- 值的来源：`request_received` 阶段、kind 为 header、`strings.EqualFold(name, "user-agent")` 的所有键，按名称字节序，每个键的值按 `Values` 顺序。现在列表按 `lower(name), value_index` 排序，在只有规范键 `User-Agent` 时两者一致〔核〕；大小写不同的多个键同时出现时，旧排序在相同 `value_index` 上是不确定的，新排序是确定的。
- 明文：`0x01 (u32be(len) bytes)+`，至少一个值。一个空串值编码为 `01 00 00 00 00`。
- Header 缺失时，列为 NULL，不写密文。所以 NULL 与 `""` 有区别，多值顺序保留。
- 不压缩。AAD 为 `security.AAD(audit_id, "user_agent_v1")`。
- 写入时机：`BeginAudit`。入站 Header 在那时已经完整，拦截器在其后运行，不改 Header。好处是进行中的请求和崩溃后恢复的记录在列表里照样有 UA，与现在 Header 几毫秒内提交的效果一致。
- 读取：`ListAudits` 的 SELECT 增加 `a.capture_version, a.user_agent_enc`。
  - `capture_version = 2`：在内存里解密解码，显示第一个值，任一值包含子串即匹配，NULL 不匹配。与现在 `readUserAgent` 的语义相同〔核〕。
  - `capture_version = 1`：照旧逐行调 `QueryRequestHeaderEvidence`。

  所以新行没有了逐行查询，旧行仍然有，随 retention 自然减少。也可以用 `LEFT JOIN LATERAL` 把旧行的 UA 行聚合进同一条查询，代价是要扫描 `bytea[]`，本阶段不做。分派一律按 `capture_version`，不按 `user_agent_enc` 是否为 NULL，因为 NULL 对旧行没有“缺失”的含义。

### C.6 parser 需要、又不必解密块的事实〔设〕

`http_stages` 增加两列：

- `content_type TEXT COLLATE "C" NULL CHECK (content_type <> '')`；
- `content_encoding TEXT COLLATE "C" NULL CHECK (content_encoding <> '')`。

值的规则复刻 `decryptContentHeaders`〔核〕：该阶段 kind 为 header、小写名称等于 `content-type`（或 `content-encoding`）的值，按（名称、`value_index`）排列，取第一个非空值；都为空或没有时为 NULL。parser 用 `""` 和“没有”效果相同，所以 NULL 覆盖两者，列里不存 `""`。

放在 `http_stages` 而不是 `body_streams`：它们是阶段的 Header 事实，没有 Body 的阶段也有。`LoadParserStage` 本来就读 `http_stages` 这一行。两列都进 v2 摘要（D.2）。

`LoadParserStage` 在 v2 行上不查 Header，也不碰块，直接把两列放进新增的 `ParserStage.ContentType`、`ContentEncoding`；v1 行照旧查密文行。所以 metadata 记录的回填扫描从不解密块。

这两列是新的明文列。按 5.10 第 3 点它们属于“非敏感字段”。值来自客户端或上游，长度不设上限；Content-Type 可能带 multipart boundary。同步更新模块 09 §8 和模块 23。

### C.7 各读取方的新旧两条路

新增包 `internal/headerblock`，只依赖 `security`、`bodycodec` 和标准库：

```go
func Encode(stages []Stage) ([]byte, error)                   // C.3
func Decode(plaintext []byte) ([]Stage, error)                // 严格校验
func Seal(c security.Cipher, auditID string, plaintext []byte) (compression string, length int64, enc []byte, err error)
func Open(c security.Cipher, auditID, compression string, length int64, enc []byte) ([]byte, error)
func EncodeUserAgent(values []string) []byte                  // 调用方保证 len>0
func OpenUserAgent(c security.Cipher, auditID string, enc []byte) ([]string, error)
// Expand 是唯一的读取入口：按 capture_version 分派，v1 逐值解密，v2 解密块，
// 输出顺序固定为 C.3 的扁平顺序。
func Expand(c security.Cipher, auditID string, src Source) ([]Value, error)
```

`storage` 增加 `HeaderSource{CaptureVersion int; Rows []HeaderEvidence; Block *HeaderBlockEvidence}`。

| 读取方 | 改动 |
| --- | --- |
| 详情 | `queryAuditDetail` 返回 `HeaderSource`；`query.Service.Get` 改调 `headerblock.Expand`。之后 `Detail.Headers` 不变，web、agent 门面、导出、掩码都不用改 |
| 列表 | C.5 |
| parser allowlist | 新增存储方法 `LoadParserHeaderSource`；v1 照旧在 SQL 里按名称过滤，v2 解密整块后在内存里过滤，再清掉其余的值 |
| parser 内容头 | C.6 |
| `Snapshot` | 增加 `HeaderBlock` 字段 |
| 离线导入 | 不变：源只有 v1 |
| 完整性 | D.3 |

allowlist 读取方式的改变 **【需维护者】**：现在名单之外的 Header（包括 `Authorization`）在 parser 进程里永远不被解密；v2 之后，洞察、项目标识和它们的回填每处理一条记录，都会在进程内短暂解密整块。主密钥本来就在这个进程里，所以威胁模型没有变。但这是模块 09 §8 明文边界的一处改变，要写进文档。另一种做法是在采集时按当前名单另存一份“allowlist 块”，但名单可以随时修改，以后修改的名单对旧行就不生效了，不推荐。

---

## D. `capture_version` 与 `capturePayloadDigest` v2 **【需维护者】**

### D.1 v1 的确切字节序列〔核：`postgres/integrity.go` 的 `capturePayloadDigest`、`digestEncoder`〕

记号：

- `F(x) = uint64be(len(x)) || x`。
- `I(v) = F(uint64be(v))`，即 8 字节长度 `00…08` 加 8 字节值。
- `NI(v)`：NULL 时为 `F(nil)`，即 8 个零字节；否则为 `I(v)`。
- `NT(s)`：NULL 时为 `F(nil)`，否则为 `F(s)`。
- `CD(d)`：`F(d)`，其中 d 是数据库算出的 `CASE WHEN octet_length(col) > 0 THEN sha256(col) END`，NULL 或空密文写成 `F(nil)`。

整体是 `SHA-256` 作用在下面的序列上：

```
"llmapi-logger/capture-payload/v1\x00"            ; 域字符串，原样写入，没有长度前缀
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

几处要注意的细节〔核〕：

- `ended_at_ns` 用非空类型扫描，所以只对已终结的行求值。
- body 行的 `sha256` 直接用 `field`，没有经过 `CASE`。
- 在 `F` 编码下，NULL 文本与 `''` 无法区分。现有代码从不写 `''`，所以这不是现实中的问题。

v1 不覆盖的列：

- `body_streams`：`stored_length`、`chunk_count`、`retention_state`、`stream_event_count`、`stream_timeline_complete`；
- `body_chunks` 和 `stream_timelines`，整张表都不覆盖；
- `audit_records`：`schema_generation`、`parse_status`、全部 `caller_*`、`api_key_fpr`（刻意留在链外，模块 09 §7）、`parse_save_failures`、`parse_next_at_ns`。

前三项由解析之后的 `SaveParsedAudit` 改写（释放 raw 时清零长度和计数），本来就不能进采集摘要；它们由 `semantic_compacted` 和 `reconstruction_failed` 的摘要覆盖。

### D.2 v2 的确切字节序列〔设〕

与 v1 相同的编码器，相同的 `F`、`I`、`NI`、`NT`、`CD`：

```
"llmapi-logger/capture-payload/v2\x00"
F(audit_id)
I(started_at_ns) I(ended_at_ns)
F(route_id) F(protocol) F(parser_name) F(method) F(path) F(mode) F(forward_status) F(capture_status)
CD(sha256(request_uri_enc))
NI(status_code) NI(ttft_ns) NT(blocked_by) NT(block_code) NT(error_code) NT(newapi_request_id)
CD(sha256(user_agent_enc))                                   ; 新增；NULL 写成 F(nil)
对 http_stages 的每一行，按阶段顺序：
  F("stage") F(stage) F(state) F(proto) F(method) F(host)
  NI(status_code) NI(content_length) I(started_at_ns) NI(ended_at_ns) NT(error_code)
  NT(content_type) NT(content_encoding)                       ; 新增
F("header_block")                                             ; 恰好一次，取代全部 "header" 行
  NT(compression) NI(plaintext_length) CD(sha256(block_enc))  ; 没有块时三项都写成 F(nil)
对 body_streams 的每一行，按阶段顺序：                         ; 与 v1 相同
  F("body") F(stage) F(source_stage) I(observed_length) F(sha256 或 nil)
  I(hash_complete) I(eof_seen) F(state) NI(first_observed_at_ns) NI(last_observed_at_ns) NT(error_code)
```

说明：

- 三处新哈希都在数据库里求，与第 1 阶段一致：`CASE WHEN octet_length(col) > 0 THEN sha256(col) END`。块用 `LEFT JOIN http_header_blocks`，没有行时得到 NULL。
- 新的两列文本有 `<> ''` 约束，所以 v2 里不会出现 NULL 与 `''` 的混淆。
- “没有块”只出现在崩溃恢复的行上（F.7），这种行的摘要照常可以算出和校验。
- `capture_version` 不作为字段写入：版本已经由域字符串绑定。写进去也无害，但多余。
- 没有借 v2 扩大覆盖范围，例如块数。理由见 D.1 末段；而且 v2 与 v1 差得越少，复核越容易。

### D.3 校验怎么选版本

新增 `capturePayloadDigestFor(ctx, tx, auditID, schema)`：

1. `SELECT capture_version FROM audit_records WHERE audit_id=$1`（`schema=live` 时）。
2. 1 调现有 `capturePayloadDigest`，一个字节都不改；2 调 `capturePayloadDigestV2`；其他值返回错误，校验失败，载荷校验状态 sticky 置为失败。
3. 写入（`finishAudit`、`recoverInterruptedAudits`）和校验（`integrityPayloadDigest`）都走这一个函数。

篡改 `capture_version` 的后果：

- v2 行被改成 1：v1 函数读 `http_headers`（没有行），结果与事件里的摘要不等。
- v1 行被改成 2：v2 函数读块（没有），结果同样不等。
- 改成其他值：直接报错。

三种情况都使载荷校验失败。旧行不可能被新函数校验通过，反过来也一样：两个域字符串的前 31 个字节相同（`llmapi-logger/capture-payload/v`），第 32 个字节分别是 `1` 和 `2`，所以两段 SHA-256 输入从第 32 个字节起就不同，摘要相等即意味着碰撞。改版本号无法让一条记录换一个函数通过，因为事件里的摘要受 HMAC 保护，攻击者没有密钥就无法重签。

约束：

- `capture_version` 有 `CHECK (capture_version IN (1, 2))`（E.1）。
- 它在 `BeginAudit` 时写定，之后不变；`CommitAudit` 校验输入与行上的值一致。
- 起始行在写入当时就决定了以后用哪个摘要版本，包括崩溃后由 `RecoverInterruptedAudits` 终结的行：v2 行没有块时按 D.2 写 `F(nil)`。

离线导入的目标只有 001 基线（`InitializeImportSchema`），没有 `capture_version` 列，而 `VerifyImportIntegrity` 在同一个事务里对每个 `capture_finalized` 事件重算摘要〔核：`migrate/importer.go` 的 `Run`，`postgres/integrity.go` 的 `VerifyImportIntegrity`〕。第 1 步的 SELECT 在那里会失败。所以：

- `verifyIntegrityPayloadsTransaction` 增加 `schema` 参数。`VerifyImportIntegrity` 传 `schema=baseline`，第 1 步直接取 1。
- SQLite 源只可能有 v1 行，这样做是对的。
- 加一个测试：导入一个 SQLite 夹具，再以 live 模式首次启动（应用 006、007），全部行仍按 v1 通过校验。

---

## E. 库表

### E.1 迁移 007〔设〕

文件 `internal/storage/postgres/migrations/007_header_block.sql`。`derivedMigrations` 加 `{7, …}`，`latestSchemaVersion` 改为 7（`postgres/migrate.go`）〔核：`0faae0a` 上是 5；迁移 006 是随后加的 `turns` 索引，所以这里取 7〕。

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
```

- **不回填，不重写。** PostgreSQL 11 起，常量默认值的 `ADD COLUMN … NOT NULL DEFAULT 1` 只改目录，已有行读出来是 1。可空、无默认值的列同样只改目录。〔推：依据 PostgreSQL 文档的行为，本项目的数据库上没有实测；实现时在测试库上量迁移耗时并确认 `pg_class.relfilenode` 不变。〕
- **锁。** 每条 `ALTER TABLE` 短暂持有 `ACCESS EXCLUSIVE`，受连接的 5 秒 `lock_timeout` 约束（`open.go`），与迁移 005 相同。
  - `capture_version` 的 CHECK 用 `NOT VALID` 加上，不扫描旧行。旧行都是默认值 1，按构造满足；新行和更新照常受约束检查。
  - 新列上的 CHECK 只涉及全为 NULL 的新列〔推：PostgreSQL 对新加列上的 CHECK 是否仍要扫表没有实测，实现时在大表上用 `EXPLAIN`/计时确认；如果要扫，也改成 `NOT VALID`〕。
- **`schema_generation`** 不变，仍是 2。
- `insertAudit` 增加两列；`validateAuditRecord` 校验 `CaptureVersion ∈ {0,1,2}`，0 当作 1。

### E.2 回滚

写进 `doc/deployment/postgresql-migration.md` 新的一节“回滚到 schema 版本 6”，格式与迁移 005、006 那两节相同。

没有任何 unified（v2）写入时：

```sql
-- 仅在回滚到不含迁移 007 的版本时执行，先停止新版本并做好数据库与 audit.key 的联合备份
BEGIN;
DROP TABLE http_header_blocks;
ALTER TABLE http_stages DROP COLUMN content_type, DROP COLUMN content_encoding;
ALTER TABLE audit_records DROP COLUMN user_agent_enc, DROP COLUMN capture_version;
DELETE FROM schema_migrations WHERE version = 7;
COMMIT;
```

`DROP COLUMN` 只改目录。

已经有 v2 行时，没有只用 SQL 就能让旧版本保持健康的办法：

- 旧版本按 v1 重算 v2 行的摘要，必然不等，后台载荷校验会把存储 sticky 置为不健康。
- v2 行没有 `http_headers` 行，旧版本的详情里也没有 Header。
- 直接 `DELETE` 这些 audit 不可行：`turns.parent_turn_id` 是 `ON DELETE RESTRICT`〔核：`001_init.sql`〕，后续轮次挂在它们下面时会失败。只能走 retention 的检查点逻辑。

推荐的做法 **【需维护者】**：按“先扩展、后启用”发布。

1. 先发一个包含迁移 007 和 v2 读取、`write_path` 默认为 `legacy` 的版本。
2. 观察一段时间，再切 `unified`。

一旦写过 v2 行，回滚目标就不能早于第 1 步的版本。想退回旧写法，切回 `audit.write_path: legacy` 即可，v2 行仍然可读。

配置的回滚：`internal/config/load.go` 用 `KnownFields(true)`〔核〕，旧版本遇到新的 `audit:` 段会拒绝启动，回滚前要把这一段删掉。

### E.3 离线导入

- `internal/storage/migrate/tables.go` 的白名单不用改：SQLite schema 12 没有新列，导入目标仍是 001 基线。007 由首次启动时的 `migrate()` 应用，导入的行得到 `capture_version=1`。
- `importer.go` 的 `known` 表集合不用改：目标必须只有基线表，已经应用过 007 的目标会因多出 `http_header_blocks` 被拒为 `target_not_empty`，与 002 到 006 的处理一致。
- `VerifyImportIntegrity` 按 D.3 传 `schema=baseline`。
- `cmd/audit-import` 本身不用改。方案提到的未提交 `cmd/audit-stage` 不在这个工作树里〔核〕；它合入时，白名单要按 007 更新。
- SQLite 不加迁移（H 节），所以导入器对源“版本 12、共 10 个迁移”的检查不受影响。

---

## F. 内存预算与本地暂存

### F.1 配置〔设〕

现在的配置没有 `audit:` 段，审计模式是顶层的 `mode`，密钥是顶层的 `key_path`（`internal/config/types.go`）〔核〕。新增：

```yaml
audit:
  write_path: legacy          # legacy | unified，默认 legacy
  memory:
    stage_bytes: 1048576      # 每个阶段在内存里保留的明文上限，默认 1 MiB（维护者已看过的默认值）
    global_bytes: 268435456   # 全进程，默认 256 MiB（本文提议）
  staging:
    dir: ""                   # unified 必填；legacy 下填了只做启动恢复
    max_bytes: 4294967296     # 暂存目录总量上限，默认 4 GiB（本文提议）
```

`config.Validate` 的规则：

- `write_path` 只能取两个值。
- `unified` 必须配置 `staging.dir`。
- `stage_bytes` ≥ 64 KiB 且 ≤ `global_bytes`。
- `staging.dir` 必须是绝对路径，不能与 `key_path` 所在目录相同、包含它或被它包含。这与 5.7 第 4 点对归档目录的约束一致，P3 还要再加一条：不能与 `archive.dir` 重叠。

启动时检查：目录不存在就以 0700 创建；已存在时在 Unix 上要求属主是当前用户、权限不含组和其他用户；要能创建并删除一个探针文件。不满足时 unified 不可用：available 退回 legacy 并告警，strict 拒绝启动审计（**【需维护者】**，K.10）。Windows 沿用密钥文件的做法，靠目录 ACL，不检查权限位。

### F.2 什么计入预算〔设〕

一个原子计数器，按明文字节计：

| 计入 | 何时释放 |
| --- | --- |
| 各阶段在内存里、尚未落暂存的明文（含重复阶段的前瞻缓冲） | 写入暂存文件之后，或 `Finish` 时交给终结器 |
| 已经封好、排队等暂存 writer 写盘的块的明文长度 | 写盘之后 |
| 交给终结器、排队等解析的明文 | 解析完成或放弃之后（G.2） |
| `Finish` 时为提交封好的块密文（按密文长度计），以及仍在暂存 writer 队列里的密文 | `CommitAudit` 应答之后；落暂存的块写盘之后 |
| 重复阶段比对窗口里 S 尚未释放的明文（B.3） | D 比对过之后 |
| Header 快照 | 不计。每个阶段几 KB，计入只会让统计变复杂 |

`Finish` 时，一条请求会同时持有给终结器的明文和给提交的密文。`Finish` 不因预算拒绝提交：提交的密文照常计入，允许暂时超过 `global_bytes`。超出时有三项处理：

- 先放弃给终结器的明文，改交 ID 作业（G.2），封块一完成就释放；
- 其他会话新到的字节立即落暂存；
- 在 `CommitAudit` 应答、释放密文之前，计数可能高于上限。

所以 `global_bytes` 是软上限，硬上限要再加上同时在提交中的请求的密文之和。writer 队列按个数计（1024），最坏情况下这部分不受字节约束；B.5 的批次字节上限只约束一批，不约束队列。

单阶段预算只限内存里的那部分。超出时把整 1 MiB 的块封好落暂存，内存只留索引：seq、偏移、长度和文件位置。

全局预算满时：

1. 新到的字节立即落暂存，不再等攒满 1 MiB；这时块可能不足 1 MiB（B.3）。
2. 暂存也满或不可写时，进入耗尽（F.6）。

### F.3 暂存文件格式〔设〕

每条 audit 一个文件，`<dir>/<audit_id>.stg`。`audit_id` 是 `apx_` 加小写 Base32，可以安全地作文件名。以 `O_CREATE|O_EXCL|O_WRONLY` 和 0600 创建，第一次写入后对目录做一次 fsync，持久化目录项。

```
file   = header record*
header = "LLSTG\x00\x01\x00" u32be(len(audit_id)) audit_id
record = u32be(body_len) u32be(crc32c(body)) body
body   = type(1 字节) payload
```

| type | payload | 加密 |
| --- | --- | --- |
| 1 阶段开始 | stage_code、`started_at_ns`、proto、method、host、status、`content_length`、两个 content 值 | `security.AAD(audit_id, "staging_stage_v1", stage)` |
| 2 Header 段 | stage_code、kind、该阶段该 kind 的 C.3 段 | `security.AAD(audit_id, "staging_headers_v1", stage, kind)` |
| 3 块 | 明文元数据：stage_code、seq、offset、`plaintext_length`、`encoded_length`、`observed_at_ns`、compression；随后是块密文 | 块密文就是现有格式：`bodycodec.Encode` 之后 AES-GCM，AAD 为 `(audit_id, "body_chunk_v2", stage, seq, compression)`，与 `flushBodyLocked` 逐字节相同 |
| 4 终态（F.7 重放用） | 密封后的整个 `AuditCommit`，块以类型 3 的记录给出 | `security.AAD(audit_id, "staging_commit_v1")` |

- CRC 只用来发现写到一半就崩溃的尾部记录，真实性靠 AEAD。
- 块记录的元数据是明文，但 AAD 绑定了 stage、seq 和 compression。offset 和长度在导入时按 seq 连续、offset 累加、解密后长度一致逐项核对。
- 块密文与 `body_chunks.data_enc` 同格式，导入时原样插入，不重新加密。

为什么一条 audit 一个文件：恢复时直接对应到 audit；清理就是删掉一个文件；不存在多个请求交错写同一个文件的锁问题。

### F.4 写盘、fsync 与它的代价〔设〕

现在 `flushBodyLocked` 在 `session.mu` 里、在转发的 goroutine 上同步压缩加密，再非阻塞入队，从不阻塞在 IO 上〔核〕。暂存保持这一点：

- 压缩加密仍在原处，与 legacy 同时机、同代价。
- 写文件和 fsync 交给一个进程级的暂存 writer goroutine，入队非阻塞，队列按字节有界（计入全局预算）。
- writer 每批最多攒 5 ms，写入各文件，然后对本批涉及的每个文件 `fdatasync` 一次，组提交，与数据库 writer 同构。

这样块从产生到持久的延迟约等于现在 `AddChunk` 到批次提交的延迟，掉电时损失的范围相当。磁盘慢的时候积压在队列里，表现为预算被占满，最终是耗尽（F.6），转发不受阻塞。

代价：附录 A.1 的部署平均请求体约 1.1 MB，附录 B.1 的 heavy 档约 1 MB 和 220 个上下文条目。按默认的单阶段 1 MiB，heavy 流量里大部分请求的 `request_received` 都会有第一个整块落暂存〔推〕。`request_sent` 在合并时不保留字节，所以不会再写一份。所以按维护者看过的默认值，unified 在真实负载上的大部分请求都要多付：

- 一次文件写；
- 一次组 fsync 的份额；
- 终结器读回时的一次解密和解压；
- 提交时一次读回密文。

省掉的是现在两个请求阶段各写一份、事后删掉一份的 WAL，以及解析时的数据库分页读回。孰多孰少要 A/B 才知道。建议 A/B 同时跑 `stage_bytes` = 1 MiB 和 8 MiB 两档，**【需维护者】**定默认值（K.2）。

### F.5 终结器怎么读回

`staging.Reader(auditID)` 按 seq 顺序读该阶段的块记录，逐块校验 CRC、AEAD、长度和 seq/offset 连续，然后 `bodycodec.Decode`。G.3 把内存里的段和读回的段拼成与 `readRawBody` 相同的结果。

### F.6 耗尽〔设〕

全局预算满、暂存写满（`max_bytes`、ENOSPC）或暂存写出错时，该阶段：

- 不再保留后续字节，只继续算哈希、长度、时间和 SSE；
- `body.faulted`，错误码 `capture_budget_exhausted`（暂存写出错时为 `staging_write_failed`）；
- 阶段 partial，`captureFault`，raw `full`。

available 模式记一次 gap，转发照常继续；strict 同样继续转发。这与 legacy 下队列满时块丢失的语义相同：strict 只管准入（模块 03 §8）。

gap 的 `reason` 受 `audit_gaps` 的 CHECK 约束（`001_init.sql`）〔核〕。提议复用 `queue_full`，不改库表；每条记录上的真相由阶段错误码 `capture_budget_exhausted` 给出。另一种做法是迁移 007 顺带放宽 CHECK，加一个 `capture_budget_exhausted` 原因（K.9）。

已经落了暂存的块再写失败时，seq 出现缺口，提交时按现在的 `capture_chunk_missing` 规则标记。

### F.7 启动恢复与暂存重放〔设〕

启动顺序：`EnableIntegrity` → **暂存导入** → `RecoverInterruptedAudits` → 构造 Manager（`internal/app/app.go`）。只要配置了 `staging.dir`，不论当前是不是 `unified`，都做导入：上次以 unified 运行留下的文件，在这次以 legacy 启动时也要导入。

**中途文件**（没有类型 4 的记录）：

导入由 `internal/audit/staging` 完成，它持有 cipher；数据库这边新增一个 writer 操作 `RestoreInFlight`。只有当 audit 行存在且 `ended_at_ns IS NULL` 时才写。写入的内容与 legacy 中途崩溃时已经提交的行形态相同：

- 阶段行为 `streaming`，`ended_at_ns` 为 NULL；
- Body 行为 `streaming`，长度为 0；
- 块原样插入；
- v1 写逐值 Header 行（导入时解密暂存的 Header 段，按 v1 AAD 重新加密）；v2 写一个只含已暂存阶段的“残缺 Header 块”（重新密封）；
- `capture_version` 取行上的值。

紧接着运行的 `RecoverInterruptedAudits` 按现有逻辑处理它们：

- 从块聚合 `stored_length` 和 `chunk_count`；
- 清掉 SHA-256 和 EOF；
- partial、`process_exit`、raw `full`；
- 签名，计入那一条聚合的 `process_exit` gap。

结果与 legacy 下同一时刻崩溃的恢复结果同形，恢复逻辑和摘要都不用另写。导入的 commit 应答之后删除文件。

导入要幂等：

- audit 已终结时直接删文件。这对应提交之后、删文件之前崩溃。
- 阶段行已存在时视为已导入。这对应导入提交之后、恢复之前崩溃。

**终态文件**（有类型 4 的记录，即 B.5 丙写下的）：按记录里的 `AuditCommit` 调 `CommitAudit`，audit 拿到原来的终态。启动时导入，运行中由一个重放循环在存储恢复健康后重试。

**损坏：**

- 尾部记录 CRC 错或不完整：视为崩溃点，丢弃它，只用之前的前缀。
- 中间记录 AEAD 失败：停在那里，导入之前的前缀，把文件改名为 `.corrupt` 留给人工检查，不删除。之后缺失的块由恢复逻辑按 seq 缺口标记。
- 文件里的 audit 在库里不存在（例如 retention 已经删了，或者是另一个库的文件）：改名为 `.orphan`，不导入。

**清理：**

- 正常请求的文件在 `CommitAudit` 成功之后不立刻删除，等终结器读完再删（G.2）。
- 交给终结器的作业只带 ID、不带明文时，提交成功就删除。
- 进程在提交之后、解析之前崩溃时，启动导入看到 audit 已终结，直接删除文件；解析由现有的 pending 扫描完成，读的是库里的 raw。

### F.8 落暂存时保存 Header，以及中途崩溃的证据 **【需维护者】**

5.10 第 3 点要求在落暂存时同步保存已经启动的阶段的 Header。提议：

- 会话第一次创建暂存文件时，补写所有已开始阶段的类型 1 和类型 2 记录。
- 此后每个新阶段开始、每次 trailer 采到，都追加记录。

这只覆盖落了暂存的请求。A.4 的那条请求（请求体小于 1 MiB、响应流到一半）没有暂存文件，崩溃后库里只剩起始行。可选的做法：

| 选项 | 做法 | 代价 |
| --- | --- | --- |
| 甲 | 接受，写进模块 03 §12 和方案 3.2 第 4 条：unified 下，未超出预算的在途请求崩溃时只留起始行和 `user_agent_enc` | 长 SSE 流的崩溃取证变弱：请求 raw 和 Header 都没有了 |
| 乙 | 按时间落暂存：请求在途超过 T 秒（例如 10 秒）时，把请求侧（阶段记录、Header、已读完的请求 Body）和响应侧已有的部分写进暂存 | 只有长请求付一次文件写；复用 F.3 的全部机制，代码量小 |
| 丙 | 每条请求在请求 Body 读完时就把请求侧写进暂存 | 等于对每条请求付一次本地写盘，与 5.1 否决乙时的理由冲突 |

推荐乙，T 可配置，默认 10 秒；T=0 等价于甲。

### F.9 部署上的后果

`compose.yaml` 里 `audit-proxy` 的形态〔核〕：

- `read_only: true`；
- 可写的只有命名卷 `audit-data:/data`（放着 `/data/audit.key`）和 `/tmp`；
- `/tmp` 是 `tmpfs`，选项为 `rw,noexec,nosuid,size=64m`；
- 镜像以 `USER 65532:65532` 运行，`/data` 在镜像里预建并 chown 给 65532（`Dockerfile`）。

暂存不能放在这几处：

- **根文件系统**：只读。
- **`/tmp`**：64 MB 装不下默认的 `max_bytes`。它是内存文件系统，暂存会吃掉进程之外的内存，绕过全局预算。它在容器重启时清空，正好丢掉崩溃恢复要用的文件。
- **`/data`**：可以写，但它是密钥所在的卷。F.1 按 5.7 第 4 点的同一条理由禁止暂存与密钥目录重叠：暂存里是密文，与密钥放在同一个卷里，一次卷备份或拷贝就同时带走了两者。

所以 compose 增加一个命名卷，例如 `audit-staging:/staging`，配置写 `audit.staging.dir: /staging`。Dockerfile 预建 `/staging` 并 chown 给 65532、权限 0700：Docker 第一次挂载空的命名卷时会沿用镜像里该目录的属主和权限，进程不需要 root 就能写。

部署说明还要写清：

- 这个卷要和数据库放在同样可靠的磁盘上，暂存的 fsync 才有意义；
- 不要用 tmpfs；
- 切回 legacy 之后，暂存目录要保留到它变空为止（F.7）。

`configs/audit-proxy.docker.yaml` 和 `configs/audit-proxy.example.yaml` 加注释掉的 `audit:` 段，默认仍是 legacy。

---

## G. 解析不读回

### G.1 谁来解析〔设〕

终结器就是现有的解析 worker goroutine，加一个输入：`parser.Worker` 增加一个 `Submit(job FinalizeJob) bool`，作业进入一个有界 FIFO，由 `run` 循环处理。

理由〔核：`parser/worker.go` 的注释和字段〕：`backfillMark`、`backfillRetry`、`projectRetry`、`pendingReleases` 和 `analyze` → `backfillLater`/`backfillUnsure` 都标明“只由 parser goroutine 访问”。独立的终结器 goroutine 调用它们会产生竞争，回填水位的不变式（每条保存为 ok 或 partial 的解析都会走到 `analyze`，否则报给 `backfillLater`）也就不再成立。放在同一个 goroutine 里，这些都不用改。代价是：回填和扫描运行时，终结作业要等；现在的 `Notify` 也一样等。

`FinalizeJob` 包含 `storage.ParserAudit`（来自已提交的终态）、`Input` 的来源（G.3）和释放预算的回调。处理流程与 `Worker.process` 相同，只有两处不同：不调 `LoadParserAudit`；`loadInput` 换成从内存构造。之后的 `ClaimPendingParse`、`parseSafely`、`normalizeResult`、`prepareTurn`（包括只有请求的轮次）、`persistResult`（`SaveParsedAudit` 仍是独立事务，raw 仍然先写后删）、`analyze` 全部是同一份代码。

保留 `ClaimPendingParse` 有两个理由。首先，`saveParsedAudit` 只更新 `parse_status = 'processing'` 的行，并要求恰好一行（`graph_writer.go`）〔核〕，所以解析之前必须先进入 processing。其次，这是一次条件更新，能挡住 30 秒扫描对同一条 audit 的重复处理。它在终结器上运行，不在处理函数的路径上。另一种做法是 `CommitAudit` 直接写 `processing`，再预留 FIFO 槽位、提交之后填充，可以省一次同步操作，但状态机更复杂，等 A/B 显示有必要再做（K.13）。

### G.2 交接、内存和退化〔设〕

在 `Session.finish` 里，`CommitAudit` 返回之后：

1. 只有以下全部成立时才把明文交给终结器：
   - 提交成功；
   - 返回的终态与提交时一致，没有被降级；
   - 解析状态为 pending；
   - 全局预算还容得下交接。

   否则只交一个不带明文的 ID 作业。“提交没有降级”保证解析用的就是落库的证据。
2. 作业 FIFO 按个数设上限，提议 4,096。ID 作业和带明文的作业在同一个 FIFO 里，所以顺序就是交接顺序。ID 作业走现在的 `loadInput`，从库里读回。
3. FIFO 也满时，不交作业，记录留在 pending，由 30 秒扫描接手。这与现在 `Notify` 失败的行为相同。
4. 终结器失败：
   - `parseSafely` 已经把 parser 的 panic 转成 `parser_panic`。但 `NormalizeAudit` 和 `PrepareWithLookup` 没有 recover，panic 会让进程崩溃〔核：`prepareTurn` 直接调用〕。提议给整个 `process` 加 recover：panic 时 `releaseProcessing` 并记稳定错误码。这同样改变 legacy 的行为，从崩溃进程变成退避重试，**【需维护者】**确认（K.14）。
   - 作业设一个截止时间，提议 2 分钟。截止时间在 `SaveParsedAudit` 提交之前到达时，必须显式调用 `releaseProcessing`，把记录放回 pending。不能只依赖下次启动的 `ResetProcessingParses`：扫描只取 pending，留在 processing 的记录在重启之前没有人会再处理。`releaseProcessing` 会让 `parse_save_failures` 加一并退避，第 5 次之后记终态错误 `parsed_result_save_failed`（`parser_writer.go` 的 `releaseProcessingParse`）〔核〕。超时是否计入这个次数见 K.14。
   - `SaveParsedAudit` 已经提交、只是应答被取消时，沿用现有逻辑：留在 processing，交给 `backfillUnsure`（`Worker.process`）〔核〕。
5. 方案 4.2 的回退写的是“raw 记 `full`，`parse_status=pending`”，那是针对第三步写的。在第二步里，提交先于解析，raw 已经以 `pending` 保留状态落库，回退就是“记录留在 pending，现有 worker 从库里读回”，不改保留状态。这与任务原文的字面不同，是证据语义上的一处偏离，列入 K.19 请维护者确认。

处理函数不等解析，只等 `CommitAudit`。

### G.3 从内存构造 `Input`，与库里读出的等价〔设〕

| `Input` 字段 | 现在（`parser/evidence.go`）〔核〕 | 内存来源 |
| --- | --- | --- |
| `Request`/`Response.Present` | 阶段行和 Body 行都存在 | 该阶段有 `stage.body` |
| `ContentType`/`ContentEncoding` | `decryptContentHeaders`：第一个非空值 | C.6 的同一规则，对内存里的 Header 快照求值 |
| `Data` 和 `Complete` | `readRawBody`：读块、核对 seq/offset、认证解密、解压、上限 `2 × MaxDecodedBodyBytes`、`HashComplete` 时核对 SHA-256、`complete` 由 state、hash、EOF、长度判定、不完整时错误码取 Body 的错误码或 `capture_partial`；然后 `decodeContent` | 把 `readRawBody` 拆成“从块序列组装”的公共函数，块序列来自内存段加暂存读回（F.5）。所有核对都一样，SHA-256 也照样核对 |
| `StatusCode` | `response_received` 阶段行的 `status_code` | `stage.statusCode` |
| `Headers`（allowlist） | `LoadParserRequestHeaders`，按小写名称和 `value_index` 排序后 `Add` | 内存里 `request_received` 的 Header 快照，同样过滤、同样排序 |
| `AuditID`/`Protocol`/`Endpoint` | `ParserAudit` | 会话 |

`prepareNormalizedTurn` 的 `CreatedAtNS = worker.now()`，仍是解析时刻，父轮次选择的语义不变〔核〕。

### G.4 父轮次推断的顺序保证

`chooseTurnParent` 按 `t.created_at_ns < 本轮 CreatedAtNS` 取候选（方案 2.1）。只要同一会话的轮次按交接顺序解析，后一轮就不会先于前一轮提交。

- 只有一个 goroutine、一个 FIFO，ID 作业也在同一个 FIFO 里。所以除 G.2 第 3 步（FIFO 满、退到扫描）以外，解析顺序等于 `Submit` 的调用顺序，也就是各请求 `CommitAudit` 应答的顺序。这与现在 `Notify` 的顺序保证相同。
- 退到扫描的 audit 可能被交接顺序在它之后的轮次超过。现在也有这个问题（队列容量 100），而且更容易触发。扫描按 `started_at_ns` 排序，只能部分缓解。

### G.5 附录 B.2 的队列容量问题

现在的解析队列容量 100，满了就放弃，之后靠每 30 秒一次、每次最多 100 条的扫描消化〔核：`QueueCapacity`、`Worker.scan`、`defaultScanInterval`〕。unified 的 FIFO 容量 4,096，又有 ID 作业兜底，突发不再落到扫描上，“结束到可查询”量到的是解析速度本身。

这会让 A/B 失真：积压超过 100 时，unified 的延迟优势来自排队方式，不来自写入路径。所以按 B.2 的要求，A/B 的工作负载必须让 legacy 的待解析积压保持在 100 以内。扫描取满一页时不等下一个 30 秒，这一修复留给维护者另外决定（K.17）。

---

## H. 开关与第二个存储

### H.1 `audit.write_path` 选什么〔设〕

| 层 | legacy | unified |
| --- | --- | --- |
| `internal/app` | 现状 | 读配置，把 `WritePath`、预算和暂存传给 `audit.NewManager(…, Options)`；构造 `staging`；把 `parserWorker.Submit` 注册为交接回调 |
| `internal/audit` | `Session` 现有的 Store 调用 | 分支放在 `Session` 内：阶段开始只记内存和快照；Body 走“unified 保留器”（内存段、落暂存、重复阶段比对）；`finish` 里构造 `AuditCommit` |
| `internal/proxy` | 不变 | 不变 |
| 存储 | 现有操作 | `CommitAudit`、`RestoreInFlight` |
| parser | `Notify` | `Submit` |

Body 采集拆成两层：观察层（哈希、长度、时间、SSE、终止事件探针、写失败标志）两条路径共用；保留层是一个接口，`legacyRetainer` 就是现在的 1 MiB 缓冲加 `AddChunk`，`unifiedRetainer` 是新的。`finishStageLocked` 的判定逻辑只有一份。

两条路径写出的行可以共存：读取方都按 `capture_version` 分派；SQLite 只写 v1。

### H.2 SQLite〔设〕

`internal/storage/sqlite` 是旧格式的离线导入源和大部分主机测试的存储（`internal/audit`、`internal/proxy`、`internal/parser`、`internal/query`、`internal/web` 的测试都用它）〔核：`*_test.go` 的 import〕。

提议：

- SQLite 实现 `CommitAudit` 的 **v1 形态**，即逐值 Header、不带块、不带 `capture_version`，以及 `RestoreInFlight`。实现就是在一个 savepoint 里依次调用它现有的 `insertStage`、`insertHeaders`、`insertBody`、`insertChunk`，加上带 `skipDedup` 的 `finishAudit`，代码量小。
- **不加 SQLite 迁移**。所以导入器对源版本 12 的检查不受影响，SQLite 也永远不会产生 v2 行。
- 会话通过一个能力接口 `interface{ SupportsHeaderBlock() bool }` 决定写 v1 还是 v2：PostgreSQL 返回 true，SQLite 返回 false。

这样，unified 的采集、合并、暂存和终结器在 SQLite 上的主机测试里全部覆盖；只有 Header 块、摘要 v2 和迁移 007 需要 PostgreSQL。依赖 PostgreSQL 的测试在没有 DSN 时跳过（方案第 7 节），验收报告要写明哪些在真实库上跑过。`internal/headerblock` 本身是纯函数，用测试向量覆盖。

C.7 改动了 `query.Store` 和 `parser.Store` 的方法：

- `QueryAuditDetail` 返回 `HeaderSource`；
- 新增 `LoadParserHeaderSource`；
- `ParserStage` 新增两个字段；
- `ListAudits` 的行新增两列。

所以 SQLite 的 `parser_reader.go`、`query_reader.go` 和 `reader.go` 也要跟着改，按 v1 返回。测试里实现了这些接口的假存储同样要改〔核〕：

- `internal/parser/worker_test.go` 的 `fakeStore`；
- `internal/parser/project_test.go` 的 `projectBackfillStore`；
- `internal/query/service_test.go` 的 `fakeStore`。

`audit.Store` 增加 `CommitAudit` 之后：`internal/audit/body_buffer_test.go` 的 `bufferStore` 嵌入 `audit.Store` 接口〔核〕，编译不受影响，但它拦截的是 `AddChunk`、`FinishAuditWithResult`，unified 用例要另加对 `CommitAudit` 的拦截；`failingFinalizeStore` 同理； `internal/proxy/stream_end_order_test.go` 的 `blockingFinishStore`（它嵌入 `*sqlite.Store`，只需覆盖 `CommitAudit`）。

---

## I. 测试与验收

### I.1 等价测试（legacy 对 unified）

- **夹具：** `internal/protofixture` 的四类协议，流式和非流式，包括多轮与分支、工具与多模态、未知事件、断流与取消、错误响应、上游不可达、拦截器拒绝、大于 1 MiB 和大于 3 MiB 的 Body、trailer。
- **时钟：** `Manager.now` 和 `Worker.now` 注入同一个确定的计数器时钟。要求：unified 的采集路径不比 legacy 多调用或少调用 `now()`，这样时间戳逐字节相同。这条约束本身也是一条测试。
- **比对：**
  1. 客户端收到的字节和时序事件（A.5 的三个事件）；
  2. 各表行：非密文列逐字节相同，密文列解密后的明文相同，按 B.6 的表逐列断言；v2 与 v1 的 Header 比对 `headerblock.Expand` 的输出；
  3. `query.Service.Get` 的 `Detail` JSON；
  4. Agent 门面的详情和各类导出，包括掩码之后的 Header；
  5. raw 下载；
  6. 重建导出；
  7. `parsed_results`、turn 图和完整性链的通过情况。
- **在哪里跑：** SQLite 上跑全部夹具（v1）；PostgreSQL 上再跑一遍（v2）。

### I.2 故障注入

沿用模块 14 §4 的手段：只读事务、触发器抛指定 SQLSTATE、延迟外键、容量为 1 的队列。

| 用例 | 期望 |
| --- | --- |
| `capture_failure_test.go` 的触发器 | 按 B.5 的对应表：INSERT 触发器的用例与 legacy 得到相同的行和完成日志；UPDATE 触发器的用例要补上 INSERT 版本；“stage enqueue” 由队列满的用例代替 |
| 容量为 1 的队列，`CommitAudit` 返回 `ErrQueueFull` | 按 K.3 的决定：写终态暂存，存储恢复后重放；或者以 failed 终结 |
| 整批存储失败 | 同上；writer 不健康，之后恢复 |
| 暂存目录写满（`max_bytes`、ENOSPC 模拟） | `capture_budget_exhausted`、partial、raw full、gap；转发字节不变 |
| 全局预算耗尽 | 同上；块边界变化属于合理差异 |
| 暂存文件损坏（尾部截断、中间 AEAD 失败、CRC 错、错的 `audit_id`） | 尾部截断：用前缀；中间损坏：导入前缀、留 `.corrupt`；孤儿文件：留 `.orphan` |
| 终结器 panic（注入 panic 的 normalizer） | `releaseProcessing`，之后由 worker 读库完成；进程不退出 |
| 交接之后、提交之前崩溃（在 `CommitAudit` 入队前杀进程） | 只有暂存文件或只有起始行；重启后按 F.7 恢复为 interrupted |
| 提交之后、解析之前崩溃 | 重启后暂存文件被删除，pending 扫描完成解析 |
| 导入提交之后、恢复之前崩溃 | 再次启动时导入幂等 |
| 以 unified 运行后切回 legacy 启动 | 暂存文件照样导入 |

### I.3 流结束顺序

`stream_end_order_test.go` 按两条路径各跑一遍。`blockingFinishStore` 同时覆盖 `CommitAudit`（unified 下挡的是它），A.5 的表逐格相同。另加一项：unified 下 `CommitAudit` 返回之前，“请求完成”日志不出现。

### I.4 旧行与旧事件

- 已有库（迁移 006 的状态，含 v1 行和三种事件）升级到 007 之后，链和载荷校验全部通过；
- v1 行与 v2 行在同一个库里共存，校验通过；
- 篡改测试：改 `capture_version`（1→2、2→1、2→3）、改 `user_agent_enc`、改块密文、改 `content_type`、删块行，每一种都使载荷校验失败；
- D.2 固定一个测试向量：给定一组行，摘要的十六进制值写进测试；
- 离线导入加首次启动，按 D.3 通过。

### I.5 4.2 的顺序测试

同一会话的两轮紧挨着结束，后一轮挂在前一轮下面。三种情形：两轮都带明文交接；前一轮被迫走 ID 作业（全局预算设得很小）；前一轮被迫退到扫描（FIFO 容量设为 1）。第三种只断言结果正确或给出已知的根；如果它暴露了乱序，作为已知限制写进文档。

### I.6 A/B

`cmd/audit-bench run` 增加 `--write-path legacy|unified`、`--staging-dir`、`--stage-bytes`，结果里增加暂存的写入字节、峰值暂存字节和 fsync 次数。

指标按方案第 7 节：每条 audit 的提交数、各表插入和删除行数（`body_chunks` 的删除应明显下降，`http_headers` 的插入在 v2 下为 0）、WAL、堆和 TOAST、进程内存峰值、首字节延迟、流结束延迟（`Finish` 之前的封块时间计入这一项）、结束到可查询、详情和导出的 p95。

工作负载：heavy 和 small 两档，并发和发送间隔调到 legacy 的待解析积压始终在 100 以内（G.5）；`stage_bytes` 跑 1 MiB 和 8 MiB 两档。第一步和第二步各做一次对照：第一步不带终结器，`Submit` 不注册，用 `Notify`。

---

## J. 工作拆分

### J.1 提交顺序（每个提交都能单独验证）

| # | 提交 | 验证 |
| --- | --- | --- |
| 1 | `storage` 类型：`AuditCommit` 等，`AuditRecord` 新字段，校验函数 | 编译，单元测试 |
| 2 | `internal/headerblock`：编码、解码、密封、`Expand`、UA 编码；固定测试向量 | 纯单元测试 |
| 3 | PostgreSQL 与 SQLite 的 `CommitAudit`（只支持 v1）：一个 savepoint、多行插入、`skipDedup`、已终结时幂等 | 用同一组输入分别走旧操作序列和 `CommitAudit`，行逐表相同 |
| 4 | `internal/audit` unified 保留器、内存合并、unified `finish`（v1，还没有暂存：超出预算即耗尽）；`audit.write_path` 配置 | 在 SQLite 上跑 I.1 和 I.3 |
| 5 | 暂存：格式、writer goroutine、读回、`RestoreInFlight`、启动导入、F.8 的时间触发；配置目录、compose 卷和 Dockerfile 里预建的目录 | I.2 的暂存用例 |
| 6 | 迁移 007、`capture_version`、摘要 v2、块的写入（`BeginAudit` 写 UA）、各读取方的 v2 路径、`LoadParserStage` 的两列 | 在 PostgreSQL 上跑 I.1 和 I.4 |
| 7 | 终结器：`Worker.Submit`、内存 `Input`、拆出 `readRawBody` 的公共组装、`process` 的 recover | I.5、G.3 的等价、回填水位测试 |
| 8 | 失败处理：降级重放、终态暂存与重放循环、大提交 `alone()` | I.2 的提交失败用例 |
| 9 | `audit-bench` 参数与 A/B；文档：模块 03、04、09、13、14、18、23，部署回滚，方案附录 D 记录 | A/B 报告 |

第 3 步的提交合入时，legacy 的行为完全不变：`CommitAudit` 还没有调用方。第 4 步之后，`unified` 可以在 SQLite 和 PostgreSQL（v1）上运行。第 6 步把 PostgreSQL 切到 v2。

### J.2 可以并行的部分与各自拥有的文件

| 部分 | 拥有的文件 | 依赖 |
| --- | --- | --- |
| P-types | `internal/storage/types.go`、`query_types.go`、`parser_types.go` | 最先，其他都依赖它 |
| P-hb | `internal/headerblock/*`（新） | P-types 的 `HeaderSource` 形状，可以先约定 |
| P-pg | `internal/storage/postgres/{writer.go, commit_writer.go(新), write_recovery.go, integrity.go, migrate.go, migrations/007_header_block.sql, parser_reader.go, query_reader.go, reader.go, types.go, recovery.go}` 及其测试 | P-types、P-hb |
| P-sqlite | `internal/storage/sqlite/{writer.go, commit_writer.go(新), parser_reader.go, query_reader.go, reader.go}` 及其测试 | P-types |
| P-audit | `internal/audit/{session.go, body.go, manager.go, retain.go(新), commit.go(新)}` 及其测试，`internal/proxy/*_test.go` | P-types、P-hb；暂存接口与 P-stage 约定 |
| P-stage | `internal/audit/staging/*`（新） | P-types；接口与 P-audit 约定 |
| P-parser | `internal/parser/{worker.go, evidence.go, backfill.go, project.go, finalize.go(新), types.go}` 及其测试，包括 `worker_test.go` 和 `project_test.go` 里的假存储 | P-types、P-hb |
| P-query | `internal/query/service.go` 及其测试，包括 `service_test.go` 里的假存储 | P-hb、P-types |
| P-cfg | `internal/config/*`、`internal/app/*`、`compose.yaml`、`Dockerfile`、`configs/*.yaml`、`doc/deployment/*` | 所有部分的接口确定之后 |
| P-bench | `internal/auditbench/*`、`cmd/audit-bench/*` | P-cfg |
| P-migrate | `internal/storage/migrate/*_test.go`（只加测试；`VerifyImportIntegrity` 的参数由 P-pg 改） | P-pg |

文档的修改放在最后一个提交，由一个人统一完成，避免冲突。

---

## K. 待维护者决定

每项给出问题、推荐的答案，以及它会改变什么。

1. **中途崩溃的证据（F.8、A.4）。** unified 下，未超出预算的在途请求崩溃时只剩起始行，请求 raw 和 Header 都会丢失。推荐：按时间落暂存，T 默认 10 秒。它改变模块 03 §12 和方案 3.2 第 4 条的表述，也让“1 MiB 等于今天的 flush 阈值，因此证据不少于今天”这条理由只对超过 1 MiB 的那部分 Body 成立。
2. **单阶段预算的默认值（F.4）。** 真实部署平均请求体约 1.1 MB，按 1 MiB，大部分 heavy 请求都要落暂存。推荐：A/B 跑 1 MiB 和 8 MiB 两档再定；如果坚持 1 MiB，就接受 unified 在真实负载上主要走暂存。它影响 IO 收益和磁盘写入量。
3. **`CommitAudit` 失败（B.5）。** 推荐：可隔离错误做降级重放；存储级错误和队列满时把终态写进暂存、恢复后重放，暂存不可用时以 failed 终结。它决定存储故障期间证据的丢失范围，以及重放成功的记录是否保留原终态。
4. **Header 块（C.2 到 C.4）。** 推荐：独立表 `http_header_blocks`；C.3 的二进制编码；AAD 为 `(audit_id, "header_block_v1", compression)`。这是新的落盘格式，以后的归档也要读它。
5. **摘要 v2（D.2）。** 推荐：按 D.2 的字节序列；`capture_version` 不作为字段，由域字符串绑定。这是新的完整性格式。
6. **`content_type`、`content_encoding` 明文列（C.6）。** 推荐：放在 `http_stages`，存 parser 实际选用的值，不设长度上限，进 v2 摘要。它们是新的明文。
7. **allowlist 读取方式（C.7）。** v2 下 parser 要在进程内解密整块再过滤。推荐：接受，并写进模块 09 §8。这是明文边界的改变。
8. **`user_agent_enc` 在 `BeginAudit` 时写入（C.5）。** 推荐：是。进行中和崩溃后的记录在列表里仍有 UA。
9. **耗尽时的 gap 原因（F.6）。** 推荐：复用 `queue_full`，阶段上用新错误码 `capture_budget_exhausted`，不改 CHECK。
10. **暂存目录的约束（F.1）。** 推荐：必须显式配置；不能与密钥目录重叠；compose 里单独一个卷（例如 `audit-staging:/staging`），Dockerfile 预建 `/staging` 并 chown 给 65532。目录不可用时 available 退回 legacy，strict 拒绝。它改变部署形态。
11. **fsync 策略（F.4）。** 推荐：后台组 fsync，每批 5 ms。代价约等于现在 `AddChunk` 的持久化时延。
12. **回滚（E.2）。** 推荐：先发只带读取能力的版本，再启用 unified；写过 v2 行之后，回滚目标不能早于那个版本。它改变发布流程。
13. **终结器是否保留 `ClaimPendingParse`（G.1）。** 推荐：保留。每条 audit 多一次同步操作，但不在处理函数的路径上。
14. **给 `Worker.process` 加 recover，以及终结器超时（G.2）。** 推荐：加 recover。normalizer 的 panic 从“进程崩溃”变成“退避重试，第 5 次失败后记错误”，对 legacy 同样生效。超时同样走 `releaseProcessing`，计入 5 次的次数，避免一条总是超时的记录无限重试。
15. **`http.Header.Values` 的非规范键怪癖（C.1）。** 推荐：v2 原样保留，与 v1 的行逐项相同；修复另开 issue，因为修复会改变证据内容。
16. **大提交单独成事务（B.5）。** 推荐：超过 16 MiB 走 `alone()`，批次累计字节上限 32 MiB。数值由 A/B 调整。
17. **附录 B.2 的扫描节奏。** 推荐：不在本阶段处理；unified 的 FIFO 已经避开了它。A/B 要控制 legacy 的积压。
18. **SQLite 的范围（H.2）。** 推荐：只做 v1 的 `CommitAudit` 和 `RestoreInFlight`，不加迁移。
19. **第二步的回退不改保留状态（G.2 第 5 条）。** 任务和 4.2 的回退写的是“raw 记 `full`、`parse_status=pending`”。第二步里提交先于解析，raw 已经以 `pending` 落库。推荐：终结器失败时保持 `pending`，由现有 worker 读库解析，之后按现有规则决定 `metadata` 或 `full`；不在提交时预先标 `full`。如果维护者要求按字面标 `full`，失败的记录就永远不会释放 raw，即使之后解析成功。

---

## 附：本文发现的、比方案假设更难或风险更大的地方

1. 中途崩溃的证据比现在少（A.4、F.8）。维护者定 1 MiB 默认值时的理由，只覆盖超过 1 MiB 的部分。
2. 真实负载的请求体刚好在 1 MiB 上下，默认预算会让大部分请求走暂存（F.4），等于部分重新引入了 5.1 否决乙时担心的本地写盘。
3. 一个操作装着整条 audit，一次批次失败丢掉的是整条证据，不再是几个块（B.5）。为了与 legacy 的故障行为对等，要写降级重放。
4. 终结器必须就是解析 worker 的 goroutine，否则会破坏回填水位的不变式（G.1）。
5. 离线导入的目标没有 `capture_version` 列，摘要的版本分派必须区分基线和运行时两种 schema（D.3）。
6. 一旦写过 v2 行，就没有只用 SQL 的回滚办法（E.2）。
7. allowlist 的读取从按名称解密变成整块解密（C.7）。
8. `Finish` 之前要压缩加密全部保留的 Body（请求侧原来在请求读完时就做了），分块和 HTTP/2 响应的结束时刻会相应推后（A.5）。两对合并时，封块的总量约为 legacy 的一半，净效果要 A/B 确认。
