# 模块 04：SQLite 存储与迁移

## 1. 目标

个人单机版使用一个 SQLite WAL 数据库保存 HTTP 边界证据、内容寻址的对话轮次、多模态对象、NewAPI 调用者关联、动态 User-Agent 规则和完整性事件。所有写入继续经过单 writer goroutine；管理查询使用独立只读连接池。

当前 schema generation 为 2，不兼容旧审计数据。目标不是把旧的“每个请求保存一份完整上下文”原地转换，而是在升级时破坏性重建审计表，避免继续携带旧结构和 O(n²) 数据。

## 2. 连接与 migration

~~~text
internal/storage/sqlite/{open.go,migrate.go,writer.go,reader.go,recovery.go}
internal/storage/sqlite/{graph_writer.go,graph_reader.go,timeline_reader.go,integrity.go}
internal/storage/sqlite/migrations/{001_init.sql,...,006_developer_key_fingerprint.sql}
~~~

固定连接参数：

~~~go
writerDB.SetMaxOpenConns(1)
writerDB.SetMaxIdleConns(1)
readerDB.SetMaxOpenConns(4)
readerDB.SetMaxIdleConns(2)
~~~

固定 pragma：

~~~sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;
~~~

reader 额外设置 `query_only=ON`。关闭时 best-effort 执行 `wal_checkpoint(PASSIVE)`。

`005_content_addressed_audit.sql` 会删除并重建旧审计表，创建 `schema_generation=2` 的新结构；`schema_migrations` 和动态 `user_agent_rules` 保留。升级前仍应做数据库与主密钥的联合离线备份，但程序不会迁移或兼容旧 audit 记录。migration 按数字版本顺序在事务内执行；数据库包含当前二进制未知版本时拒绝使用。

`006_developer_key_fingerprint.sql` 用 `ALTER TABLE` 为 `audit_records` 增加可空的 `api_key_fpr`（32 字节）和一个部分索引，用于把开发者会话限定在自己 Key 的记录上（[模块 19](19-developer-key-session.md)）。它就地升级旧库，不重建表也不清除数据。该列是访问控制索引而非证据，**不得**进入 `capturePayloadDigest`：一旦加入，旧库中每条历史记录的重算摘要都会改变，启动时的完整性链校验会失败。

## 3. 表结构

当前最终 schema 共 20 张表，按职责分组如下。

### 3.1 HTTP 审计与身份

| 表 | 用途 |
| --- | --- |
| schema_migrations | 已应用 migration 版本 |
| audit_records | audit 终态、schema generation、路由、状态、TTFT、调用者查询状态、入站 Key 指纹 |
| http_stages | 四个固定 HTTP 观察阶段 |
| http_headers | 独立加密的 Header/Trailer value |
| body_streams | 每阶段长度、SHA-256、来源阶段、保留状态、分块数和 SSE 事件统计 |
| body_chunks | `pending/full` 原始证据的大块压缩加密数据 |
| parsed_results | 模型、usage、错误和计数等窄摘要；可选加密回退 conversation |
| token_links | NewAPI 用户和 Token 名称关联，不保存完整 API Key |
| audit_gaps | 审计不可用或进程退出的聚合缺口 |
| user_agent_rules | 动态 UA 正则规则 |

`audit_records.ttft_ns` 保存从代理开始处理到收到上游首字节的时长。`blocked_by`、`block_code` 只允许在 `forward_status=rejected` 时出现。未触发的 HTTP 阶段不插入行，因此不存在 `request_sent_to_newapi` 是“没有访问 NewAPI”的权威证据。

`audit_records.api_key_fpr` 是入站凭据的 keyed 指纹（主密钥派生，无凭据时为 NULL），只用于开发者会话的作用域过滤，不还原 Key、不进入任何 DTO 或日志。

### 3.2 内容寻址对象与轮次图

| 表 | 用途 |
| --- | --- |
| content_objects | canonical JSON/item/envelope 的压缩加密对象 |
| binary_objects | 按解码后原始字节寻址的图片、文件和附件 |
| content_binary_refs | content object 到 binary object 的 JSON pointer、媒体类型和编码方式 |
| content_external_refs | `file_id` 等外部引用的加密值与稳定 hash |
| conversations | 协议、可选稳定 conversation key 和更新时间 |
| turns | audit 到 conversation 的可分支轮次节点、父节点、布局和验证 hash |
| turn_context_ops | `retain/delete/insert` 请求上下文增量 |
| turn_response_items | 当前轮响应 item 的有序引用 |

content/binary 主键都是 32-byte 域分离 SHA-256。binary object 的身份只由解码后的字节决定；对象级 `media_type` 固定为 `application/octet-stream`，实际出现位置的媒体类型保存在 `content_binary_refs`，避免同一字节因 MIME 标签不同而失去复用。

### 3.3 流式时间与防篡改

| 表 | 用途 |
| --- | --- |
| stream_timelines | 逻辑 SSE event 的数量、首末时间和压缩加密的 offset/time delta 序列 |
| integrity_events | HMAC-SHA-256 append-only 完整性链 |

时间线最多保存前 100,000 个事件时间点，但 `event_count` 保留实际总数；`timeline_complete=false` 明确表示时间点序列被截断。网络 read/write chunk 不作为长期 SSE 事件行。

## 4. HTTP Body 保存方式

每个阶段仍保存自己的 observed length、SHA-256、状态和时间。流式期间四阶段先独立写 owning chunks；`FinishAudit` 事务验证两个阶段都完整、chunk 聚合与长度自洽且 SHA-256 一致后，才执行以下合并：

- `request_sent_to_newapi.source_stage` 可以指向入站 request stage；
- `response_from_newapi_sent_to_nginx.source_stage` 可以指向上游 response stage；
- raw chunk 只挂在 owning source stage；
- query/raw 读取先解析 `source_stage`，再按顺序打开 owning chunks。

若成对阶段长度或 hash 不同，两个 `source_stage` 都保持指向自身，重复删除不发生，并以 `body_stage_mismatch`/partial 保留完整异常证据。

采集缓冲约 1 MiB 后才压缩、独立 AES-GCM 加密并提交，显著减少 SQLite 行、索引和 nonce/tag 开销。`retention_state` 固定为：

- `pending`：等待 parser、normalizer 和重建验证；
- `metadata`：普通 2xx/3xx 成功且重建已验证，删除 raw chunks，`stored_length/chunk_count` 归零；
- `full`：拦截、采集不完整、4xx/5xx、解析/normalization/重建失败或其他异常，保留完整 raw。

`metadata` 仍保留原始 observed length、SHA-256、Content-Type、阶段时间、SSE 统计和完整性链。管理端通过 reconstructed API 读取语义对象，不把 metadata 状态误报为“没有捕获 Body”。

## 5. 单 writer 与原子边界

writer queue 容量为 1024；最多聚合 64 个操作或等待 5 ms 后提交一个事务。BeginAudit 和 strict admission 使用同步 Ack；普通证据写入保持异步。

主要写操作包括：

- audit/stage/header/body 开始、分块和终结；
- audit 终态、调用者关联和 gap；
- parser claim/release；
- `SaveParsedAudit`；
- retention 与 UA 规则 CRUD。

`SaveParsedAudit` 在同一事务内完成：

1. UPSERT `parsed_results`；
2. 插入或复用 content/binary objects；
3. 选择父轮次并保存 turn delta；
4. 校验对象冲突、sequence hash 和 reconstruction hash；
5. 根据终态把 raw retention 切换为 `metadata` 或 `full`；
6. 写 `semantic_compacted` 或 `reconstruction_failed` 完整性事件；
7. 更新 `audit_records.parse_status`。

任一步失败都回滚整个事务，不会出现“raw 已删但 turn 未写完”的中间状态。

## 6. 读取与重建

管理列表只读取 audit、parsed summary、token link 和单独定向解密的入站 User-Agent。详情在一个只读事务中读取 HTTP 元数据和可选 turn graph；graph reader 会：

- 沿 parent/delta 链恢复当前 request refs；
- 批量读取所需 content objects、binary refs 和 binary objects；
- 稳定排序对象，避免大图读取退化为 O(n²)；
- 验证 object kind、semantic hash、compression 和长度；
- 交给 query 层认证解密并重建 provider JSON。

raw API 只对 `retention_state=full` 开放；`pending` 返回未就绪，`metadata` 返回 `410 raw_not_retained`。reconstructed API 对 verified turn 返回重建后的 provider request/response JSON。timeline API 按需认证解密 SSE 时间点。

## 7. 启动恢复与完整性链

应用启动顺序为：打开/迁移数据库、加载主密钥、派生 integrity signer、验证既有 event chain、恢复未终结 audit、启动 parser/caller worker、绑定监听器。

完整性验证分两段，因为两段的成本上界不同。启动段只做事件数量可界定的检查：整条 chain 的 MAC 链接，以及每个终结 audit 和每个 turn 是否都有对应事件；通过后即接受新的审计写入。第二段重算每个事件覆盖的证据摘要，必须回溯整个 turn graph，成本随会话深度而不是事件数增长，因此放到监听器绑定之后由后台完成，不阻塞转发。

后台段走只读连接池：writer 池只有一个连接，被长事务占住会阻塞全部审计写入。它按 conversation 分组，组内共享 turn ref 与 content object 缓存并在边界释放——父 turn 不跨 conversation，所以逐事件重建缓存会把 K 轮会话变成 O(K²) 次链回溯，而按 conversation 共享既能压回 O(K)，又把峰值内存限制在最大的单个会话上。摘要不一致意味着 chain 合法但底层 audit 行被改动，会把 store 置为 sticky 不健康（readiness 上报 database unavailable）；该状态不会被后续写入批次覆盖，而普通 health 标志会。两段都可由进程生命周期 context 取消，取消按中断处理，不记为校验失败。

恢复会把未终结 audit 标记为 `interrupted/partial/process_exit`，把 streaming stage/body 标为 partial，把 raw retention 强制为 `full`，并根据 owning chunks 修复可证明的 stored length 和 chunk count。不能证明的 SHA-256、EOF 和 timeline complete 会被清空或置为 false。每个恢复 audit 写 `capture_finalized`，并只增加一条聚合 process-exit gap；重复恢复幂等。

完整性链验证失败、终结 audit 缺少 capture event、turn 缺少 semantic event，都会使审计存储不可用；不会以忽略校验的方式继续写入。

## 8. Retention 与 GC

retention 删除旧 audit 前，若仍保留的子轮次依赖将删除的父轮次，会先把子轮次当前完整 request refs 物化为独立 root checkpoint，并标记 `link_reason=retention_checkpoint`。随后按叶到根删除目标 turns 和 audits，再清理：

- 没有 turn 的 conversations；
- 不再被 envelope、context op 或 response item 引用的 content objects；
- 不再被 content object 引用的 binary objects。

GC 使用 `NOT EXISTS` 可达性检查和对象引用索引，不维护可漂移的手工 ref_count。全局 integrity event chain 不因 audit retention 删除中间事件；对于已经删除的 audit，启动验证仍校验链本身，但不再重算已不存在的 payload。

## 9. 备份与文件收缩

数据库与 `audit.key` 必须作为同一备份集。运行中只能使用 SQLite backup API 创建一致性快照，不能直接复制正在使用的 `audit.db` 或把 `-wal/-shm` 当作备份。恢复后启动会验证 AES-GCM、对象 hash 和完整性链。

项目不自动 VACUUM。需要收缩文件时先停机并完成联合备份，再运行标准 SQLite `VACUUM`；WAL 体积应使用 checkpoint 管理，不能通过运行时删除 WAL 文件处理。

## 10. 最少测试

- 新库最终表集合和 schema generation 正确；migration 005 明确清除旧 audit 数据并保留 UA 规则职责。
- 同一 HTTP Body 的两个观察阶段只在终结校验后保存一份 owning chunks；不一致阶段各自保留并标记异常。
- 普通成功请求 verified 后 raw chunks 被删除，异常、拦截、解析和重建失败保留 full raw。
- OpenAI Responses/Chat/Completions 的 provider request/response 可精确重建。
- data URL 按解码字节复用；相同二进制在不同 MIME/Base64 写法下仍只有一个 binary object。
- retry、branch、truncate、edit、rollback、summary 和并行工具调用的 parent/delta 正确。
- retention 删除父轮次后保留子轮次仍可重建，孤立 content/binary object 被回收。
- SSE 大于 100,000 个事件时保留总数和截断语义，完整时间线严格校验首末点。
- recovery、integrity event 篡改、缺 event 和重复恢复测试通过。
- DB/WAL 扫描不到测试 Header、Body、二进制和主密钥明文。
