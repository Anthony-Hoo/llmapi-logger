# 模块 13：安全日志、健康检查与生命周期

## 1. 目标

本模块提供个人部署需要的运行能力：一条安全的 LLM 请求完成日志、存活/就绪检查、异常退出恢复和有界关闭。首版不提供指标端点、tracing、告警平台或运行时重建整套依赖。

## 2. 请求完成日志

writer 遇到磁盘满、I/O、只读等存储级错误时整批失败并报告不健康，不能因空事务提交成功而向 ready 报告数据库可用。只有明确的操作局部错误才使用保存点隔离。

只读或无匹配行的幂等操作即使成功，也不能恢复 writer 健康；必须观察到排除回滚部分后的实际行变更成功提交。

writer 检测到存量内容/二进制对象或引用的身份损坏时，即使保存点隔离允许同批其他操作提交，完整性健康状态也会锁定为 failed。后台验证成功只允许 pending 转为 verified，不能覆盖已检测的失败。

程序输出 `slog` JSON。每个被进程内 Matcher 精确命中的 LLM route 结束时最多记录一条 `llm request completed`，字段固定为：

- `audit_id`（成功分配时）；
- `route_id`、`protocol`、`method`、不含 Query 的 escaped path；
- `status_code`、`duration_ms`、`ttft_ms`；
- `forward_status`、`capture_status`、`parse_status`；
- 拒绝时的 `blocked_by`、`block_code`；
- 存在故障时的稳定 `error_code`。

日志调用不传入 `http.Request` 或原始 error 对象。禁止记录 Query、Header value、Body、解析全文、admin token、上游凭据、主密钥、密文 BLOB 或底层数据库错误文本。

审计终结成功时，Session 使用 writer 在外层事务提交后回传的有效 capture status/error code 更新 TerminalSummary。局部或整批故障造成的采集丢失都必须在终结前标记，不能在完成日志中误报 complete。终结提交失败或 Ack 等待取消仍记录当时的未确认结果；后续补偿只更新审计存储并写恢复摘要日志，不回写已输出的请求日志。恢复行为及边界见[模块 04](04-sqlite-storage-and-migrations.md)。

writer 整批失败、审计 begin/finish、解析保存/release、保留清理和捕获恢复的失败日志增加固定白名单 `storage_error`：可区分 `sqlite_full`、`sqlite_busy`、`sqlite_read_only`、`sqlite_io_error`、`sqlite_corrupt`、`sqlite_constraint`、`object_integrity`、`queue_full`、`recovery_overflow` 等；无法分类时为 `unknown`，不输出底层错误文本。后台恢复成功只报告完成条目数，失败报告稳定类别及待恢复数量。

上下文洞察（[模块 20](20-context-insights.md)）在 parser goroutine 内派生数据，失败只写 Warn 日志，且从不改变已提交的解析状态。日志字段限于 `audit_id`、固定 `error_code`（可附固定枚举 `reason` 与 `storage_error` 类别），不含消息、工具名、路径、原始 Agent ID 或底层错误文本：

| `error_code` | 含义 |
| --- | --- |
| `analysis_failed` | 派生计算或链接阶段失败；行不写入，由回填补算 |
| `analysis_save_failed` | `audit_analysis` 写入失败（附 `storage_error` 类别） |
| `analysis_panic` | 分析器 panic 被捕获 |
| `request_headers_load_failed` | 解密白名单入站请求 Header 失败；仅丢弃 Agent 标识 Header，不降级解析状态 |
| `analysis_backfill_skipped` | 回填跳过该 audit，附 `reason`：`audit_missing`、`parser_not_registered`、`no_body`、`raw_unavailable`、`no_turn_graph`、`parse_not_usable`、`no_request_body`，以及 `failed`（失败无法靠等待恢复，见下行）；同一进程内不再尝试 |
| `analysis_backfill_failed` | 回填失败，附 `reason`（如 `horizon_failed`、`list_failed`、`audit_load_failed`、`evidence_read_failed`、`reconstruction_failed`、`analysis_failed`、`analysis_save_failed`、`analysis_panic`）、`storage_error` 与 `retry`：`retry=true` 是存储类失败，按 10、20、40、80 分钟退避重试、不放弃；`retry=false` 随后记一条 `reason=failed` 的跳过。`horizon_failed`、`list_failed` 不针对单条 audit，下一个 tick 再试 |
| `project_backfill_failed` | 项目标识回填失败，附 `reason`（如 `horizon_failed`、`list_failed`、`audit_load_failed`、`analysis_failed`、`project_identity_panic`）、`storage_error` 与 `retry`，含义同 `analysis_backfill_failed` |
| `project_backfill_skipped` | 项目标识回填放弃该 audit，`reason=failed`；同一进程内不再尝试 |

回填不引入新的健康状态或指标端点：它只在 parser 队列为空时每个扫描周期最多处理 20 条，不影响 `/readyz`。

parser 的两个码：`parser normalization failed`（`error_code=normalize_panic`，normalization 或轮次准备 panic，release 计一次失败）和 `parser job deadline exceeded`（`error_code=parse_deadline_exceeded`，作业从 claim 到保存超过 2 分钟），见模块 05 §5。

### 2.1 采集写入、本地暂存与采集设置

采集会话（模块 03 §13）的日志如下。gap 的 reason 没有新增：暂存拒绝导致的停止保留复用 `queue_full`，真实原因在阶段错误码上。`storage_error` 多了一个类别 `inbound_stage_not_stored`。

| 日志 | 字段 | 何时 |
| --- | --- | --- |
| `audit capture degraded` | `audit_id`、`route_id`、`error_code=capture_checkpoint_deferred`、`storage_error` | 检查点没能入队（写队列满等），或版本 2 的块封不出来；内容并入下一次写，不记 gap |
| `audit capture degraded` | `audit_id`、`route_id`、`stage`、`error_code=capture_budget_exhausted` 或 `staging_write_failed` | 一个阶段因暂存拒绝而停止保留；available 模式同时记一次 `queue_full` gap（模块 03 §13.4） |
| `audit capture degraded` | `audit_id`、`route_id`、`stage=request_for_newapi_received_from_nginx`、`error_code=start_stage_failed` | 起始行已提交、入站阶段行被拒绝（`ErrInboundStageNotStored`，模块 03 §13.9） |
| `audit capture degraded` | `audit_id`、`route_id`、`error_code=finish_audit_failed` | `CommitAudit` 连同重试最终失败（与已删去的 legacy 路径上 `FinishAudit` 失败时是同一条） |
| `audit staging write failed` | `audit_id`、`error_code=capture_budget_exhausted`（目录或磁盘满）或 `staging_write_failed` | 暂存 writer 写或 fsync 一个文件失败；码与之后被拒绝的阶段上的错误码相同（设计 F.6） |
| `audit staging file not removed` | `audit_id`、`error_category=staging_remove_failed`、`reason`（`not_found`、`permission_denied`、`no_space`、`io_error`） | 提交后、恢复后或导入后删除暂存文件失败 |
| `audit staged chunks not recovered` | `audit_id`、`error_category=staged_recovery_failed`、`storage_error` | 终结提交最终失败后，writer 恢复插入暂存块时被拒绝；audit 照常以 failed 终结，文件保留，下次启动改名为 `.orphan`（模块 03 §13.5） |
| `audit staging import completed` | `files`、`removed`、`orphaned`、`corrupt`、`unreadable`、`inserted_chunks`、`ignored_entries` | 启动导入结束，目录里有文件时（Info） |
| `audit staging file imported` | `audit_id`、`outcome`、`inserted_chunks`、`present_chunks`、`torn_tail` | 一个文件导入完并删除（Info） |
| `audit staging file kept` | `audit_id`、`reason`、`kept_as`、`inserted_chunks` | 文件改名保留：`reason` 为 `no_audit`、`no_body_row`（`.orphan`），、`finalized_without_chunks`（`.orphan`），或 `foreign_header`、`discontinuous_chunks`、`record_length`、`record_crc`、`record_metadata`、`record_sequence`、`record_authentication`（`.corrupt`） |
| `audit staging file not renamed` | `audit_id`、`kept_reason`（同上一行的 `reason`）、`error_category=staging_rename_failed`、`reason`（同 `not removed`） | 改名失败，文件留在原处 |
| `audit staging import failed` | `mode`、`error_category=recovery_failed`、`storage_error` | 导入时存储报错或文件读不出来；审计不可用 |
| `audit staging unavailable` | `mode`、`error_category=staging_unavailable`、`reason`（目录检查的码，没有配置时为 `staging_unavailable`；不带路径和错误原文） | 启动时暂存目录没有配置或检查不通过：两种模式下审计都不可用，available 不审计照常转发，strict 准入回 `503`（模块 01 §4 第 18 项）。在中断恢复之前记，这次启动不恢复、不终结任何 audit。以前 available 模式退回 legacy 时的 `audit staging unavailable, using the legacy write path` 和 legacy 下的 `audit staging directory unusable, nothing imported` 已经没有了 |
| `audit manager unavailable` | `mode`、`error_category=audit_unavailable`、`reason`（`unified_unsupported` 或 `invalid_audit_options`） | 审计管理器构造失败，例如存储不能承担这条写入路径（码名沿用 `unified_unsupported`） |
| `saved audit capture settings ignored` | `error_category=runtime_settings_invalid` | 启动时保存的重试次数读不出来或不合法，按配置文件运行 |
| `audit capture settings saved`、`audit capture settings reset to the configuration file` | `commit_retries` | 管理页面保存或重置重试次数（Info） |
| `audit capture settings request failed` | `error_code=settings_unavailable` | 设置接口遇到未归类的错误 |

可选 NewAPI 用户目录刷新成功时只记录用户数；失败时只记录固定 `newapi_user_catalog_refresh_failed` 类别；`/api/status` 换算系数刷新失败只记录 `newapi_status_refresh_failed`。调用者查询失败只记录 audit ID 和固定 `caller_*` 错误码；计费相关只记录 `billing_rate_missing`、`billing_backfill_scan_failed`、`billing_backfill_save_failed` 等稳定码。启动配置含已废弃的 `insights.pricing_file` 时输出一次 `deprecated_config` 警告，不记录路径。任何日志都不得包含管理 access token、用户 API Key、用户目录行、完整管理 URL、响应体、NewAPI 日志行或底层错误文本。

`/v1/models` 等安全非 LLM 请求即使经本程序 passthrough，也不创建 audit、不执行 interceptor，并且不写 `llm request completed`。错误 Method、受保护路径族和危险路径在分发边界 fail-closed，也不伪装成 LLM audit。

### 2.2 冷归档

冷归档（[模块 26](26-cold-archive.md)，默认关闭）只写稳定的码、计数、字节数和耗时，不写路径、文件名、会话内容或底层错误原文。完整的字段和失败的 `reason` 取值见模块 26 §19。

| 日志 | 字段 | 何时 |
| --- | --- | --- |
| `archive export only: hot store keeps growing` | `error_category=archive_export_only` | 启动，`archive.mode` 为 `export_only`：retention 的直接删除不组装，热库持续增长（Warn） |
| `archive verified removal active: …` | `error_category=archive_removal_active`、`format_version` | 启动，`archive_then_delete`：校验后移除对格式版本不低于 1 的包生效，`format_version` 是内置的 1（Warn）。原来格式版本低于 1 时另有的 `archive_removal_trial_format` 随格式冻结去掉了：runner 不再写版本 0 |
| `archive bundle check failed before removal: its members stay in the hot store` | `error_category=archive_bundle_check_failed`、`reason`、`bundle_kind` | 移除阶段，一个分段的包在它的第一批之前核对不过（文件缺失、大小或哈希不符、清单签名不对、清单与定稿时记下的 SHA-256 不同）：这次运行不移除它的成员，运行照常完成（Warn；每个分段每次运行一条，模块 26 §18.7） |
| `archive removal completed` | `event=archive_removal_completed` 与计数 | 移除阶段结束（Info，字段见模块 26 §19） |
| `archive is off and retention deletes directly again; to pause archiving set retention_days: 0` | `error_category=archive_direct_delete_resumed`、`retention_days` | 启动，归档关闭、`retention_days > 0`，而目录表里有运行记录（Warn） |
| `archive runner unavailable` | `error_category=archive_unavailable`、`reason`（`audit_unavailable`、`dir_<目录检查的码>`、`invalid_timezone`、`invalid_options`） | 归档开启而 runner 不能组装；代理和审计照常，直接删除仍不组装（Warn） |
| `audit key unavailable` | 原有字段，另加 `reason=archive_manifests_present` | 密钥文件缺失、数据库为空，而归档目录里有清单，所以不新建密钥（Warn） |
| `audit archive keys unavailable` | `mode`、`error_category=key_unavailable` | 归档子密钥派生失败，审计不可用（Warn） |
| `archive run completed` / `archive run failed` | `status`、`exported_audits`、`deferred_audits`、`integrity_failed_audits`、`excluded_audits`、`stale_audits`、`exported_gaps`、`refused_audits`、`sample_mismatch_audits`、`segments`、`disk_bytes`、`duration_ms`，按原因的 `deferred_<原因>`，可选 `reconciled_segments`、`deadline_reached`；失败时另有 `error_category=archive_failed`、`reason`、`storage_error` | 一次运行结束（Info / Warn）；失败后 10 分钟重试 |
| `archive run interrupted` | `error_category=archive_interrupted`、`exported_audits`、`duration_ms` | 运行被进程关闭取消（Warn） |
| `archive integrity check failed` | `error_category=archive_integrity_failed`、`reason` | 一条 audit 的原完整性事件复核或密文认证不过：它留在热库、登记推迟，存储的载荷校验状态置为失败（Error） |
| `archive record refused` | `error_category=archive_record_refused`、`reason`（包写入方的码：`invalid_record`、`order`、`context_mismatch`、`payload_mismatch`、`entry_too_large`） | 写入方拒绝一条记录：只有它留在热库、推迟为 `export_failed`，其余成员重写进分段，运行继续（Warn） |
| `archive sample mismatch` | `error_category=archive_sample_mismatch`、`reason=sample_mismatch` | 抽样时一条成员读出与热库不同而变更戳没变，不论是新发布的分段还是对账时 `publishing` 的分段：包作废，这条推迟为 `export_failed`，其余成员写进新包，运行继续（Warn） |
| `archive directory has manifests that do not verify`、`archive bundle unknown to the catalog does not verify` | `error_category=archive_manifest_unusable`，`manifests` 和 `unsupported_format_version`（其中格式版本不受支持的个数，例如留下的试行版本 0 的包），或 `reason` | 对账时有清单解析不了、签名不对、格式版本不受支持，或目录表不认识的包核对不过（Warn） |
| `archive bundle registered from the directory` | `bundle_kind`、`members` | 对账登记了一个目录表不认识、核对通过的包（Info） |

归档不加健康状态，也不进 `/readyz` 的字段。唯一的影响是复核不过时载荷校验状态置为失败，与后台载荷校验发现损坏时相同，database 因此报告不健康。运行记录只在 `archive_runs` 表里，管理界面不展示。

## 3. 管理面健康接口

管理 listener 提供：

~~~text
GET /healthz
GET /readyz
~~~

两者与受保护的 `/api/v1/*` 使用同一个管理鉴权 middleware，接受静态 Bearer token 或有效的七天 HttpOnly Cookie；即使监听在 loopback 也必须鉴权。静态 `/ui/` shell 可以匿名加载，但不包含状态或审计数据。

health、ready、详情 JSON、错误 JSON 和 raw Body 响应统一使用 `Cache-Control: no-store`；日志不记录 Admin Token 或返回的明文证据。

`/healthz` 在进程能够响应 HTTP 时返回存活，不代表审计可写。

`/readyz` 保持五个字段：

~~~json
{
  "status": "healthy",
  "database": "ok",
  "encryption_key": "ok",
  "parser_queue": 0,
  "caller_queue": 0
}
~~~

状态语义：

| status | HTTP | 条件 |
| --- | --- | --- |
| `healthy` | 200 | Store、cipher、audit manager 可用，已配置 parser/caller worker 已启动 |
| `degraded` | 200 | parser/caller worker 不可用；或 available 模式下审计依赖不可用但代理仍可转发 |
| `not_ready` | 503 | strict 模式下审计依赖不可用，新白名单请求会被 admission 拒绝 |

`parser_queue` 是 parser FIFO 的长度，最多到 4096（模块 05 §5）。gap flush 或单次用户目录刷新失败不改变 readiness；retention 批的存储级失败与其他 writer 批一样把 database 报为不可用，直到下一次写入成功；已配置 caller worker 无法启动时 readiness 降级。首版没有 `/metrics` 实现。

Store 的采集恢复积压尚未清空时 database 不报告 ok；恢复溢出会锁定不健康状态直到重启恢复。正常恢复必须成功提交实际变更，回滚过的修改和只读幂等重试不能使既有写入故障变成 healthy。strict 准入继续要求本次 BeginAudit 同步提交；恢复溢出时明确拒绝新审计。

## 4. 启动恢复

migration/open 和完整性链验证成功后、parser 扫描 pending 记录前，应用调用一次恢复。配置了 `audit.staging.dir` 时，恢复之前先导入上次留下的暂存文件，导入失败按恢复失败处理（模块 03 §13.6）。恢复本身：

- `ended_at_ns IS NULL` 的 audit 设为 `forward_status=interrupted`，结束时间使用本次恢复时间。无采集故障的记录写 `capture_status=partial`、`error_code=process_exit`；已标记采集失败的记录保留 `failed` 与原错误码（缺省 `capture_write_failed`）。
- 已标记采集失败的 audit 先复用正常终结的分块对账：子记录写 `capture_write_failed` 或 `capture_chunk_missing`，保留采集器已记录的 stage 错误码和已封存时间线标志。其余仍为 streaming 的 stage 和 body 设为 partial，并写稳定 `process_exit`。
- Body 的 stored length 从已提交 chunk 求和，observed length 至少覆盖已提交的 offset+length；未完成 hash、EOF 和 SHA-256 不伪造为完整。
- 只有实际恢复了 audit 时才增加一条聚合 `process_exit` gap；重复执行没有变化。
- 遗留 `parse_status=processing` 重置为 pending，再由 parser worker 扫描入队。

恢复不补造未提交的 Header、Trailer、chunk、上游响应或精确退出时间。
恢复事务失败时关闭本次 Store，不继续组装正常审计、查询和 parser：available 进入 degraded 并继续透明转发，strict 进入 not_ready 并拒绝新的白名单请求；修复后通过重启重试恢复。

## 5. 简单 gap

`audit_gaps` 只记录非敏感的时间范围、固定 reason/detail 和计数，用来说明 available 模式中未能持久化的审计范围。它不保存底层 error 文本，也不伪装成单条 audit。

DB 暂时写失败后，后续 writer 事务成功时可以补写内存中的聚合 gap。若进程在 DB 不可用时退出，只能依赖安全日志，不能承诺完整恢复。

## 6. 依赖故障与关闭

首版不在进程内周期性重建 Store、cipher、query 或 parser。available 模式若启动时 DB/key 不可用，会继续透明转发并处于 degraded；修复文件或权限后需要重启。已经打开的 Store 遇到短暂写失败，会由同一 writer 有界补记采集故障和失败终态；成功提交并清空恢复积压后恢复健康，无新请求时也会重试。解析 worker 对失败 release 同样保留有界重试，避免记录永久卡在 processing。

NewAPI 管理集成包含两个轻量后台任务：用户目录与 `/api/status` 的 `quota_per_unit` 在监听前刷新一次，之后每五分钟刷新；caller worker 单 goroutine 扫描 SQLite pending 行，按 request ID 做有限重试，并在没有到期查询的间隙以至少 500ms 的间隔逐条补查迁移前链接的计费（[模块 21](21-newapi-billing.md) §4），连续失败时暂停 1 分钟，随 worker 关闭停止。目录失败保留旧快照，pending 任务可跨重启恢复；两者都不重建数据面组件，也不改变已完成请求的结果。

收到 SIGINT/SIGTERM 后停止接收新请求，在 `shutdown_timeout_seconds` 配置的关闭窗口内尽量完成在途代理、parser 和 writer 队列，然后关闭 HTTP server 与 SQLite；默认 30 秒，长流部署可提高到与最长请求策略一致。超时退出留下的记录由下次启动恢复为 interrupted/partial。

## 7. 最少测试

- 请求完成日志字段完整，扫描不到 Query、Header value、Body、token、key 和底层 error 文本。
- 用户目录成功日志只有用户数；目录和 caller 查询失败日志只有 audit ID/稳定类别，不含管理凭证或返回内容。
- caller worker 启动失败使 readiness 降级；单条未识别、有限重试和用户目录刷新失败不阻断转发。
- 安全 passthrough 请求没有 audit/interceptor 调用或 LLM 请求完成日志；受保护/危险未匹配路径不会访问 NewAPI。
- `/healthz`、`/readyz` 和受保护的 `/api/v1/*` 缺失或使用错误管理凭证时返回 `401`。
- healthy/degraded/not_ready 的 JSON 和 HTTP 状态符合上表。
- 启动恢复正确修正未终结 audit、streaming stage/body、长度和 parser 状态，且重复执行幂等。
- 启动恢复对已标记采集失败的未终结 audit 复用正常终结的分块对账；保留 `capture_chunk_missing`、修复已 complete 但聚合不符的 Body，并将所有已保留 raw 设为 full 后签名。父记录使用 interrupted 转发状态并保留已知 failed 采集状态；无采集故障的普通中断仍用 partial/process_exit。
- 只有实际恢复记录时生成聚合 process_exit gap。
- available 启动依赖故障仍可转发，strict 返回 `503`；修复启动依赖后通过重启恢复。
- 优雅关闭不会把仍未完成的证据标成 complete。
- 洞察分析与回填失败只产生上表的固定错误码日志，不改变 `parse_status`，日志不含内容、工具名、路径或原始 Agent ID。
