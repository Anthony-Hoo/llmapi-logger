# 模块 13：安全日志、健康检查与生命周期

## 1. 目标

本模块提供个人部署需要的运行能力：一条安全的 LLM 请求完成日志、存活/就绪检查、异常退出恢复和有界关闭。首版不提供指标端点、tracing、告警平台或运行时重建整套依赖。

## 2. 请求完成日志

程序输出 `slog` JSON。每个被进程内 Matcher 精确命中的 LLM route 结束时最多记录一条 `llm request completed`，字段固定为：

- `audit_id`（成功分配时）；
- `route_id`、`protocol`、`method`、不含 Query 的 escaped path；
- `status_code`、`duration_ms`、`ttft_ms`；
- `forward_status`、`capture_status`、`parse_status`；
- 拒绝时的 `blocked_by`、`block_code`；
- 存在故障时的稳定 `error_code`。

日志调用不传入 `http.Request` 或原始 error 对象。禁止记录 Query、Header value、Body、解析全文、admin token、上游凭据、主密钥、密文 BLOB 或底层数据库错误文本。

`/v1/models` 等安全非 LLM 请求即使经本程序 passthrough，也不创建 audit、不执行 interceptor，并且不写 `llm request completed`。错误 Method、受保护路径族和危险路径在分发边界 fail-closed，也不伪装成 LLM audit。

## 3. 管理面健康接口

管理 listener 提供：

~~~text
GET /healthz
GET /readyz
~~~

两者与 `/api/v1/*` 使用同一个静态 Bearer middleware，即使监听在 loopback 也必须鉴权。静态 `/ui/` shell 可以匿名加载，但不包含状态或审计数据。

health、ready、详情 JSON、错误 JSON 和 raw Body 响应统一使用 `Cache-Control: no-store`；日志不记录 Admin Token 或返回的明文证据。

`/healthz` 在进程能够响应 HTTP 时返回存活，不代表审计可写。

`/readyz` 保持四个字段：

~~~json
{
  "status": "healthy",
  "database": "ok",
  "encryption_key": "ok",
  "parser_queue": 0
}
~~~

状态语义：

| status | HTTP | 条件 |
| --- | --- | --- |
| `healthy` | 200 | Store、cipher、audit manager 可用，已配置 parser 已启动 |
| `degraded` | 200 | parser 不可用；或 available 模式下审计依赖不可用但代理仍可转发 |
| `not_ready` | 503 | strict 模式下审计依赖不可用，新白名单请求会被 admission 拒绝 |

retention 或 gap flush 失败不改变 readiness。首版没有 `/metrics` 实现。

## 4. 启动恢复

SQLite migration/open 成功后、parser 扫描 pending 记录前，应用调用一次恢复：

- `ended_at_ns IS NULL` 的 audit 设为 `forward_status=interrupted`、`capture_status=partial`、`error_code=process_exit`，结束时间使用本次恢复时间。
- 仍为 streaming 的 stage 和 body 设为 partial，并写稳定 `process_exit`。
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

收到 SIGINT/SIGTERM 后停止接收新请求，在固定关闭窗口内尽量完成在途代理、parser 和 writer 队列，然后关闭 HTTP server 与 SQLite。超时退出留下的记录由下次启动恢复为 interrupted/partial。

## 7. 最少测试

- 请求完成日志字段完整，扫描不到 Query、Header value、Body、token、key 和底层 error 文本。
- 安全 passthrough 请求没有 audit/interceptor 调用或 LLM 请求完成日志；受保护/危险未匹配路径不会访问 NewAPI。
- `/healthz`、`/readyz` 和 `/api/v1/*` 缺失或使用错误 Bearer token 时返回 `401`。
- healthy/degraded/not_ready 的 JSON 和 HTTP 状态符合上表。
- 启动恢复正确修正未终结 audit、streaming stage/body、长度和 parser 状态，且重复执行幂等。
- 只有实际恢复记录时生成聚合 process_exit gap。
- available 启动依赖故障仍可转发，strict 返回 `503`；修复启动依赖后通过重启恢复。
- 优雅关闭不会把仍未完成的证据标成 complete。
