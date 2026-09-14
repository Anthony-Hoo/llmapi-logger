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

审计终结成功时，Session 使用 writer 在外层事务提交后回传的有效 capture status/error code 更新 TerminalSummary。被保存点隔离的异步采集失败因此在数据库和完成日志中都呈现为 `failed / capture_write_failed`；事务提交失败或 Ack 等待取消则沿用未确认终结的错误路径，不发布未提交的 writer 结果。整批存储级失败丢弃的异步采集操作没有 Ack，也无法在已回滚的事务里留下标记，属于[模块 04](04-sqlite-storage-and-migrations.md)记录的已知边界。

可选 NewAPI 用户目录刷新成功时只记录用户数；失败时只记录固定 `newapi_user_catalog_refresh_failed` 类别。调用者查询失败只记录 audit ID 和固定 `caller_*` 错误码。任何日志都不得包含管理 access token、用户 API Key、用户目录行、完整管理 URL、响应体、NewAPI 日志行或底层错误文本。

`/v1/models` 等安全非 LLM 请求即使经本程序 passthrough，也不创建 audit、不执行 interceptor，并且不写 `llm request completed`。错误 Method、受保护路径族和危险路径在分发边界 fail-closed，也不伪装成 LLM audit。

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

retention、gap flush 或单次用户目录刷新失败不改变 readiness；已配置 caller worker 无法启动时 readiness 降级。首版没有 `/metrics` 实现。

## 4. 启动恢复

SQLite migration/open 成功后、parser 扫描 pending 记录前，应用调用一次恢复：

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

首版不在进程内周期性重建 Store、cipher、query 或 parser。available 模式若启动时 DB/key 不可用，会继续透明转发并处于 degraded；修复文件或权限后需要重启。已经打开的 Store 遇到短暂写失败，可以在后续 writer 事务成功时恢复健康。

NewAPI 管理集成包含两个轻量后台任务：用户目录在监听前刷新一次，之后每五分钟刷新；caller worker 单 goroutine 扫描 SQLite pending 行，按 request ID 做有限重试。目录失败保留旧快照，pending 任务可跨重启恢复；两者都不重建数据面组件，也不改变已完成请求的结果。

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
