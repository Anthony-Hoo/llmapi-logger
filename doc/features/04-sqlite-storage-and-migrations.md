# 模块 04：SQLite 存储与迁移

## 1. 目标

个人单机版使用一个 SQLite WAL 数据库，保存四阶段证据、最新解析结果、可选 NewAPI 调用者身份、简单 gap 和动态 User-Agent 规则。写入由单 writer goroutine 串行完成，查询使用独立只读连接池。

不实现多节点、ORM或额外存储控制面；WAL 使用 SQLite 默认自动 checkpoint，迁移只记录数字版本，解析结果只保留最新一份。

## 2. 布局与连接

~~~text
internal/storage/sqlite/{open.go,migrate.go,writer.go,reader.go,recovery.go}
internal/storage/sqlite/migrations/{001_init.sql,004_user_agent_rules.sql}
~~~

`001_init.sql` 建立审计基线表、全部索引、request ID 调用者状态和 NewAPI 用户/Token 身份字段。`004_user_agent_rules.sql` 追加动态 UA 规则表，并创建首条默认启用规则；保留版本 2、3 是为了让仍使用旧审计基线的既有部署可以安全追加同一功能。sqlite 包内的 migrations/ 是唯一来源，并通过 go:embed 编译进单个二进制。

这个个人项目不提供旧数据库原地升级兼容。schema 基线发生不兼容变化时，停机删除 `audit.db`、`audit.db-wal`、`audit.db-shm` 和旧 `audit.key`，再启动生成空库；旧审计数据不迁移。

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

reader 额外设置 PRAGMA query_only=ON。使用 SQLite 默认自动 checkpoint；关闭时 best-effort 执行 PASSIVE checkpoint。

## 3. 十张表

| 表 | 关键字段与约束 |
| --- | --- |
| schema_migrations | version INTEGER PRIMARY KEY、applied_at_ns |
| audit_records | audit_id PK；started_at_ns/ended_at_ns；route_id/protocol/parser_name；method/path；request_uri_enc；mode；status_code；forward_status/capture_status/parse_status；blocked_by/block_code；error_code；newapi_request_id；caller_status/attempts/next_at/updated_at |
| http_stages | audit_id+stage PK；state、proto、method、host、status_code、content_length、started_at_ns/ended_at_ns、error_code |
| http_headers | audit_id+stage+kind+name+value_index PK；value_length、value_enc |
| body_streams | audit_id+stage PK；observed/stored_length、sha256、hash_complete、eof_seen、state、error_code |
| body_chunks | audit_id+stage+seq PK；offset、plaintext_length、observed_at_ns、data_enc |
| parsed_results | audit_id PK；parser_name/parser_version/status；request_model/response_model；requested_stream/observed_stream；response_id；usage_input/usage_output/usage_total；error_type/error_code；message_count/tool_call_count/has_tool_call；parsed_json_enc；parsed_at_ns |
| token_links | audit_id PK；newapi_user_id、username、newapi_token_id、token_name、linked_at_ns |
| audit_gaps | id INTEGER PK；started_at_ns/ended_at_ns、reason、request_count、detail、created_at_ns |
| user_agent_rules | id INTEGER PK；name；enabled；model_pattern；user_agent_pattern；created_at_ns/updated_at_ns |

stage 只允许四个固定名称。http_stages 外键指向 audit_records；http_headers 和 body_streams 外键指向同 audit_id/stage 的 http_stages；body_chunks 外键指向 body_streams；parsed_results 和 token_links 外键指向 audit_records。所有审计子表使用 ON DELETE CASCADE，schema_migrations 与 audit_gaps 独立。

forward_status、capture_status、parse_status 和 stage state 的允许值以模块 03 为准，并在 migration 中使用 CHECK 约束；所有 `*_at_ns` 使用 INTEGER Unix ns，所有 `*_enc` 使用模块 09 定义的 BLOB 格式。

拦截链不新增表。blocked_by 和 block_code 是 audit_records 上的可空 TEXT：forward_status=rejected 时二者必须同时为非空稳定标识，其他状态时必须同时为 NULL。status_code 保存代理本地返回的 4xx/503。只保存首个终止 chain 的 interceptor id 和稳定代码，不保存模块错误文本、调用栈或请求内容。

`blocked_by`、`block_code` 和对应 CHECK 已直接包含在首版 `001_init.sql` 中。尚未触发的 stage 不插入 http_stages，因此 request_sent_to_newapi 行不存在就是“未调用 NewAPI”的权威证据。OpenBody 未调用时也不创建空 body_stream。

audit_records 至少建立 started_at_ns、route_id+started_at_ns、capture_status+started_at_ns、parse_status+started_at_ns 索引。列表查询使用 started_at_ns+audit_id 游标，不使用深 OFFSET。

## 4. Migration runner

启动时：

1. 创建 db_path 父目录并打开 writer。
2. 设置 pragma。
3. 若 schema_migrations 不存在则创建。
4. 按数字前缀排序读取 migrations/。
5. 对每个未执行版本开启事务、执行 SQL、插入版本、COMMIT。
6. migration 失败则 storage 标记 unhealthy；available 仍可转发并写日志，strict 请求返回 503。
7. 数据库版本高于程序支持版本时 storage 保持 unhealthy；available 仍可只做代理，strict 请求返回 503。
8. 数据库已应用的每个版本都必须存在于当前二进制内嵌 migration 集合；允许文件编号留空，但不允许把其他架构使用过的未知版本仅因数字较小而视为兼容。

不提供自动 upgrade/downgrade。程序遇到高于当前基线的数据库版本时拒绝使用该库；migration 日志只输出版本与错误，不输出业务数据。

## 5. 单 writer

~~~go
type WriteOp struct {
    Kind string
    Data any
    Ack  chan error
}
~~~

容量固定 1024 ops。支持 BeginAudit、StartStage、AddHeader、AddChunk、FinishStage、FinishAudit、SaveParsedResult、AddGap、UpsertTokenLink、RetryCallerLookup 和 UA 规则 CRUD。拦截拒绝不增加额外审计 WriteOp 类型，由 FinishAudit 在同一事务写 forward_status=rejected、blocked_by、block_code、status_code 和 parse_status=skipped。FinishAudit 同时保存可选 request ID 并初始化 caller pending 状态。

writer 最多聚合 64 ops 或等待 5 ms，然后在一个事务中执行。BeginAudit 和 strict admission 带 Ack，调用方等待 COMMIT；普通 chunk 异步。

事务失败时：

- rollback。
- writer 标记 unhealthy。
- 通知带 Ack 的调用方。
- 后续 strict admission 返回 503。
- available 记录安全日志并聚合 gap。gap 只接受程序定义的 reason/detail 配对和计数，不保存底层 error 文本。

下一次事务成功后 writer 恢复 healthy，并 best-effort 写入内存 gap。

## 6. available 与 strict

available：queue 满时立即返回 dropped，不阻塞代理；当前 audit 标 partial/failed。DB 不可用时 gap 只存在内存和日志，恢复后插入 audit_gaps。

strict：BeginAudit 必须使用已加载的 key 成功 COMMIT；本次提交失败时返回 503，parser queue 不参与 admission。上一批写入留下的健康快照不替代这次提交，也不会永久阻止后续重试。Begin 后 chunk 仍是批量异步写，晚到故障只标 partial/gap，不宣称逐块 durable 或零缺口。

available/strict 只控制审计持久化故障是否阻止 admission。interceptor 主动 reject、body 超限、error、panic、非法 Decision 或 Body 读取失败都在 NewAPI 前终止，不能因 available 模式而放行；客户端取消按取消结束。

## 7. 读取

query API 只使用 readerDB：

- 列表主体读取 audit_records，并只 LEFT JOIN parsed_results 与 token_links 的窄明文字段，包括 request ID、caller status、用户 ID/用户名和 Token ID/名称；query 层另按 audit_id 定向读取入站阶段的加密 User-Agent，认证解密后用于普通列表展示和可选子串筛选，不扫描其他 Header。
- caller worker 只扫描 `caller_status=pending` 且到期的行；重试次数和下次时间均在 SQLite 中，进程重启后可继续。
- 详情按 audit_id 查询 stage、stream、header。
- 列表和详情直接读取 audit_records.blocked_by/block_code；它们不需要额外 JOIN。
- Body 按 stage+seq 分页读取并解密。
- 普通 raw 下载分批短读，避免长事务阻塞 WAL。
- 不提供复杂查询 DSL、多租户过滤或独立分析数据库。

## 8. Parser 写入

非 rejected 的请求 Finalize 成功时 audit_records.parse_status=pending，并尝试把 audit_id 放入内存 parser queue。worker 先用条件更新把 pending 改为 processing，再用 readerDB 读取证据；结果通过 writer 在同一事务中 UPSERT parsed_results，并把 parse_status 更新为 ok、partial、error 或 skipped。rejected audit 在 FinishAudit 时已是 skipped，扫描条件不得把它重新入队。

parsed_results 只保留最新 parser_version。进程重启先把 processing 重置为 pending，再扫描 pending 记录重新入队；不提供 reparse 管理 API。需要一次性回填派生数据时，用明确的 migration 更新 parse_status，复用正常 worker，不新增任务表或控制面。

## 9. 启动恢复

migration 后、parser 扫描 pending 记录前，由应用传入当前 Unix ns 执行一次恢复：

~~~sql
UPDATE audit_records
SET ended_at_ns = COALESCE(ended_at_ns, :recovered_at_ns),
    forward_status = 'interrupted',
    capture_status = 'partial',
    error_code = 'process_exit'
WHERE ended_at_ns IS NULL;
~~~

同时把仍为 streaming 的 http_stages/body_streams 标为 partial，并写入稳定 `process_exit`。Body 的 stored length 按已提交 chunk 的 plaintext_length 求和，observed length 至少覆盖已提交的 offset+length；清空不完整 SHA-256，并把 hash_complete/eof_seen 设为 false。遗留 processing 重置为 pending，再重新入队已结束且 pending 的 audit。

只有实际恢复了未终结 audit 时才写一条聚合 `process_exit` gap。重复调用不再修改已恢复记录，也不重复增加 gap。不推断未提交事务，不补造 Header、Trailer、chunk、上游响应或精确结束时间。

## 10. Retention

retention_days>0 时按[模块 12](12-retention-and-maintenance.md)的固定算法执行：启动后异步执行一轮，此后每 24 小时执行。只选 ended_at_ns 非空、started_at_ns 早于截止日且 parse_status 不是 processing 的记录；每个 writer 事务最多删除 200 个 audit_records，并依靠外键级联删除全部审计子表，同一事务最多清理 200 条过期 gap；单轮最多分别删除 5000 条 audit 和 5000 条 gap。

不自动 VACUUM；需要收缩文件时停机后手工执行。

## 11. 备份

数据库和 key 可分开存放，但必须作为同一个备份集，恢复时两者缺一不可。在线备份必须使用 SQLite backup API，不能只复制 audit.db 而忽略 WAL；完整流程见[部署备份说明](../deployment/backup-and-restore.md)。

## 12. 测试

- 空库执行 `001_init.sql` 和 `004_user_agent_rules.sql`；重复启动不重复执行。
- DB 版本高于程序时 storage 保持 unhealthy；available 继续代理，strict 返回 503。
- writer batch commit/rollback。
- 新库应用版本 1 和 4，表总数为十；版本 4 默认创建 `^gpt` / `^(codex-tui|Codex Desktop)` 启用规则，既有版本 1/2/3 数据库可追加版本 4；`audit_records` 和 `token_links` 从建库起就包含 request-id 调用者身份所需字段，且不存在 API Key 列。
- request ID 终态写入、pending 扫描、退避重试、resolved 原子回填和 terminal unresolved 均可恢复且幂等。
- interceptor 拒绝在一个事务内写 rejected、blocked_by/block_code、status_code、skipped，且不存在未触发的 NewAPI/响应 stage 或空 body_stream。
- strict BeginAudit commit 失败返回 503。
- available queue 满继续并产生 gap。
- reader 不占用 writer 连接。
- kill 后 WAL 恢复，未完成 audit/stage/body 变 partial，长度由已提交 chunk 恢复；重复恢复幂等且只生成一条聚合 gap。
- pending parser 重启恢复。
- retention 排除活动/processing 记录，audit/gap 分别遵守 200/5000 上限并级联删除审计子表。
- DB/WAL 无测试 secret 明文。
