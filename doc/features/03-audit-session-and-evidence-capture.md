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

Session 只持有阶段状态、hash、约 1 MiB 的当前采集缓冲和最多 100,000 个逻辑 SSE 时间点，不保留完整 Body；Stages 是稀疏 map，只包含已经触发的观察点。

## 4. interceptor 拒绝终态

route match 后先建立 audit 并记录已看到的入站 metadata，再执行 interceptor chain。首个主动 reject、body 上限拒绝、模块 error、panic、非法 Decision 或非客户端取消的 Body 读取失败，都以一次原子 FinishAudit 写入以下结果：

- forward_status=rejected。
- blocked_by 保存配置中的 interceptor id；框架自身在无法归属模块时使用 `interceptor_chain`。
- block_code 保存稳定、低基数代码，不保存 error 文本、Header、Query 或 Body。
- status_code 保存代理实际返回的 4xx 或 503。
- parse_status=skipped，不入 parser queue。

模块主动 reject 使用其约定的安全 4xx；body 超限固定为 413 和 `body_too_large`。error、panic、非法 Decision 和非客户端取消的 Body 读取失败固定为 503，并分别使用 `interceptor_error`、`interceptor_panic`、`interceptor_invalid_decision`、`interceptor_body_read_error`。这些 fail-closed 行为与 available/strict 无关。客户端取消使用 forward_status=client_cancelled，不设 blocked_by/block_code。blocked_by/block_code 只对 rejected 非空，普通 NewAPI 4xx/5xx 仍是实际转发结果，不能误标为 rejected。

stage、body_stream 和 chunk 只在真实观察开始时创建。没有调用 NewAPI 时，request_sent_to_newapi 及两个响应阶段必须不存在，而不是保存 not_started 空行。metadata reject 不为审计而 drain 入站 Body；若存在未读 Body，则第一个阶段和 capture_status 标 partial。body interceptor 已预读到 EOF 且证据成功落盘时，拒绝本身不导致 capture_status=partial。未触发的后三阶段也不计为采集缺失。

## 5. Body 采集

Observe 顺序固定：

1. 增加 observed_length 并更新 SHA-256。
2. 追加到约 1 MiB 聚合缓冲；Body 终结时立即 flush 尾块。
3. 按 Content-Type 和 magic 自适应 gzip；已压缩二进制保持 `none`。
4. 为异步写入创建拥有型副本并独立 AES-GCM 加密。
5. 提交 writer queue；失败则 stage/capture 标 partial 并记录 gap。

只有观察到 EOF 时 hash_complete=true。取消、Read/Write error 或进程退出时，hash 只代表已观察前缀。seq/offset 是应用层采集顺序，不是 TCP 或 HTTP chunk。SSE 另外按完整逻辑 event 记录结束 offset 和时间；总事件超过 100,000 时停止追加时间点，但继续统计实际 event count。

四个观察阶段在流式采集期间先各自保存 owning chunks。`FinishAudit` 的 writer 事务只有在成对阶段都完整、各自 chunk 聚合自洽、observed/stored length 相等且 SHA-256 完全一致时，才删除后一阶段的重复 chunks，并把其 `body_streams.source_stage` 改为前一阶段。若长度或 hash 不一致，后一阶段标记 `body_stage_mismatch`/partial，两个阶段的原始字节都保留，不能因预先共享掩盖短写、取消或代理改写错误。

body interceptor 按 route 中最大的模块上限加一个判定字节有界预读，且必须通过 request_for_newapi_received_from_nginx observer，因此它仍计算入站长度/hash并保存原始字节。多个模块共享同一只读缓存；放行时 proxy 使用未修改的缓存字节重建 Body，request_sent_to_newapi observer 再记录实际 replay；两阶段差异视为实现错误。metadata-only chain 不触发预读，继续由 Transport 的正常流式读取驱动两个请求 observer。

## 6. Header、Trailer 与 URI

http_headers 每个值保存 audit_id、stage、kind、name、value_index、value_length、value_enc。重复值不合并；Host、Method、Status、HTTP 版本和 ContentLength 放 http_stages。

Request-URI 可能包含 key，保存在 audit_records.request_uri_enc。无法保证 Header 原始大小写、全局线缆顺序或 request Trailer 经 Nginx 后仍存在。

## 7. AES-256-GCM

key_path 指向一个 32-byte 主密钥：存在则读取；不存在且数据库尚无审计数据时用 crypto/rand 原子生成。Unix 创建权限为 0600；Windows 使用当前用户私有数据目录的 ACL。

每个 Header 值、压缩后的 Body chunk、Request-URI、parsed result、content/binary object 和 stream timeline 使用独立 12-byte 随机 nonce：

~~~go
ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
~~~

数据库把 `nonce || ciphertext || tag` 保存为一个 BLOB。AAD 使用 NUL 分隔的受控字段：Request-URI 绑定 audit id/object type；Header 再绑定 stage/kind/name/value index；Body chunk v2 再绑定 owning stage/seq/compression；解析结果绑定 audit id/parser name。内容对象、二进制对象和 timeline 使用各自域分离 AAD。调用方不得自行定义其他格式。

首版只使用这个本地主密钥，不提供多层密钥、轮换或重写工具。需要更换时先完整备份旧数据库和旧 key，再创建新的空数据库和 key。

## 8. Writer 接口与模式

采集模块提交 BeginAudit、StartStage、AddHeader、AddChunk、FinishStage、FinishAudit 和 AddGap；parser 使用 SaveParsedAudit 原子写摘要、turn graph、对象、raw retention 和完整性事件。queue 固定 1024 ops。

available：queue/DB/key 失败时不阻塞代理，标 partial/failed，写结构化日志；DB 不可用时合并一个内存 gap，下一次成功写入时补记。

strict：BeginAudit 必须使用已加载的 key 同步 COMMIT；本次提交失败时返回 503，parser queue 不参与 admission。上一批写入留下的健康快照不替代这次提交，也不会永久阻止后续重试。Begin 成功后的 chunk 仍批量异步写，晚到故障只标 partial/gap，不提供逐块 durable ack。

## 9. audit_gaps

audit_gaps 只做进程级运维提示，字段为 id、started_at_ns、ended_at_ns、reason、request_count、detail、created_at_ns，不精确关联某个 audit。reason 使用 db_unavailable、queue_full、encryption_error、write_error、process_exit；detail 只能保存稳定错误码和计数，不保存请求数据。

进程内按固定 reason 各保留一个聚合 gap，同一 audit session 最多计数一次。DB 恢复时插入并清空；提前退出只能依赖日志，这是 available 的已知限制。

## 10. Parser

非 rejected 的 audit Finalize 后：

1. audit_records.parse_status 设为 pending。
2. audit_id 非阻塞放入内存 queue；满时只保留 pending。
3. 启动时及每 30 秒扫描少量 pending 记录补入队列。
4. worker 用条件更新把 pending 改为 processing，未抢到则跳过。
5. worker 从 SQLite 读取、解密并解析。
6. 在同一 writer 事务中 UPSERT parsed_results；若 normalizer 可用则保存 verified turn graph，并按结果把 raw retention 更新为 metadata/full，再更新 parse_status。

rejected audit 在 FinishAudit 时直接设为 skipped，永不入队。重启时先把遗留 processing 重置为 pending，再扫描已结束且 pending 的 audit 重新入队；解析结果只保留最新版本。

## 11. NewAPI 调用者身份

若成对配置 `newapi.access_token` 与 `newapi.user_id`，应用按[模块 11](11-newapi-request-identity.md)启用只读 NewAPI 管理集成。审计会话在 `response_received_from_newapi` 开始时读取合法的 `X-Oneapi-Request-Id`，并在 `FinishAudit` 中与终态一起持久化；存在 request ID 时将 `caller_status` 设为 `pending`，再唤醒单个后台 worker。

worker 通过 NewAPI 全站日志精确查询该 request ID，成功后只保存 `newapi_user_id`、`username`、`newapi_token_id`、`token_name` 和关联时间。没有访问 NewAPI 的 interceptor 拒绝、本地 fail-closed、passthrough、无上游响应或无 request ID 的记录不会进入身份解析。识别结果只用于审计展示和筛选，不参与放行；管理接口延迟、失败或最终未识别均不改变已完成的转发结果。

## 12. 崩溃恢复

启动后先验证 HMAC integrity event chain，再把 ended_at_ns 为空的 audit 改为 forward_status=interrupted、capture_status=partial、error_code=process_exit；仍为 streaming 的 stage/stream 改为 partial，raw retention 强制为 full，并按 owning chunks 修复可证明长度。每条恢复记录写 capture event，随后把遗留 processing 重置为 pending 并重新入队。不补造 Trailer、缺失 chunk、SHA-256 或精确结束时间；SQLite WAL 只保证已提交事务一致。

## 13. 测试

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
