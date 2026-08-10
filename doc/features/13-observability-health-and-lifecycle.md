# 模块 13：日志、健康检查与进程生命周期

## 1. 目标

本模块只提供个人部署需要的基础运行信息：

- 能看出代理是否正常转发。
- 能看出审计数据库、加密 key 和后台解析是否可用。
- 进程退出时尽量完成在途请求和写队列。
- 日志不泄露 Header、Body、Query 或 Token。

首版不接入复杂 tracing、告警平台或多级健康状态机。

## 2. 日志

首版只输出结构化 JSON，避免增加日志格式配置。

每条请求日志只包含：

- `audit_id`
- `route_id`、`protocol`
- Method、Path、状态码
- 总耗时、响应首字节时间
- `forward_status`、`capture_status`、`parse_status`
- rejected 请求的 `blocked_by`、`block_code`
- 稳定错误码

禁止记录 Authorization、API Key、Header 值、Body、原始 Query 和解析后的提示词。

## 3. 健康接口

管理端提供两个简单接口：

```text
GET /healthz
GET /readyz
```

`/healthz` 只表示进程仍在运行。

这些是审计代理管理 listener 的接口，不是 NewAPI health/UI。数据 listener 只接收明确 LLM API 白名单请求；NewAPI health、login、admin、models、UI 和其他路径由 Nginx 直连，不进入本进程的代理、拦截或审计流程。

`admin_token` 在任何管理监听地址上都必填。`/healthz`、`/readyz`、`/metrics` 和全部 `/api/v1/*` 路由经过同一个静态 Bearer middleware，即使请求来自 loopback 也不例外；缺失或错误 token 返回 `401`。

静态 React UI shell 与其构建资源不含数据，可以无鉴权加载。页面必须先由用户输入 token 才能读取 health、ready、metrics 或审计数据，token 只保存在当前页面内存中。

`/readyz` 返回：

```json
{
  "status": "healthy",
  "database": "ok",
  "encryption_key": "ok",
  "parser_queue": 3
}
```

状态只使用：

- `healthy`：转发和审计均可用。
- `degraded`：仍可转发，但审计或解析有问题。
- `not_ready`：strict 模式不接收 LLM API 白名单请求。

Token 关联失败只显示为附加功能不可用，不影响主 readiness。

## 4. 简单指标

首版若实现 `/metrics`，只暴露少量低基数指标：

```text
audit_requests_total
audit_request_duration_seconds
audit_ttft_seconds
audit_capture_errors_total
audit_parser_errors_total
audit_writer_queue_length
audit_database_size_bytes
```

指标不使用 audit_id、model、token 名称或完整 path 作为 label。

## 5. 启动流程

```text
1. 加载并校验配置
2. 校验 `admin_token` 非空
3. 尝试打开 SQLite、执行 migration 并加载或生成 AES key
4. 启动单 writer 和 parser worker
5. 启动管理端口
6. 启动数据端口
7. available 模式后台每 30 秒重试不可用的审计依赖
```

失败行为保持简单：

- 配置或 NewAPI URL 非法：直接退出。
- strict 模式下数据库或 key 不可用：管理端可启动，但模型请求返回 `503`。
- available 模式下数据库或 key 不可用：继续代理，写 warning，并每 30 秒重试；这段时间只保留日志和进程级审计缺口，不写明文证据。
- parser 结束时标记 ok、partial、error 或 skipped，不影响数据面。

## 6. 进程恢复

不维护复杂 boot 表。启动后执行一次简单恢复：

- 查找 `audit_records.ended_at_ns IS NULL` 的记录。
- 写入 `forward_status=interrupted`、`capture_status=partial`、`error_code=process_exit` 和恢复时间。
- 未完成 Body 保持 `hash_complete=false`。
- 把仍为 streaming 的 stage/stream 标记为 partial。
- 把遗留 `parse_status=processing` 重置为 pending，再重新入队 pending 记录。

## 7. 优雅关闭

收到 SIGINT/SIGTERM 时：

1. 停止接收新请求。
2. 在总计 30 秒内尽量完成在途代理并清空审计写队列。
3. 关闭 parser worker 和 SQLite。

超时后直接退出，未完成记录在下次启动时按进程异常退出处理。

## 8. 最少测试

- healthy/degraded/not_ready 返回正确。
- 空 `admin_token` 在 loopback 和非 loopback 配置下都启动失败。
- API、health、ready 和 metrics 缺少或使用错误 Bearer token 时均返回 `401`。
- 无 token 可以加载静态 UI shell，但 shell 中不包含 health 状态、指标或审计数据。
- Nginx 直连的 NewAPI health/login/admin/models/UI/其他路径不产生本进程请求日志、interceptor 调用或 audit。
- 日志扫描不到测试 Token 和 Body。
- available 数据库故障仍能转发。
- strict 数据库故障拒绝新请求。
- kill 后重启能标记未完成记录。
- 优雅关闭不会产生 goroutine 泄漏。

## 9. 实施步骤

1. 实现安全日志字段和 request logger。
2. 实现 `admin_token` 必填校验，以及覆盖 `/healthz`、`/readyz`、`/metrics` 和管理 API 的统一 Bearer middleware。
3. 接入数据库/key/parser 状态。
4. 实现启动恢复和优雅关闭。
5. 增加故障与日志泄漏测试。
