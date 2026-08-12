# 模块 11：NewAPI 请求身份解析

## 1. 目标

本模块是个人部署中的可选增强：当 NewAPI 在 LLM 响应中返回 `X-Oneapi-Request-Id` 时，audit-proxy 用只读管理凭证查询 NewAPI 全站日志，把该请求关联到用户和访问令牌元数据。

关联结果只用于审计展示与筛选，不参与鉴权、配额、路由、interceptor 或流量放行。系统不读取、不匹配、不保存也不展示用户完整 API Key。

## 2. 配置

配置统一位于[模块 01](01-configuration-and-route-boundary.md)的 `newapi` 对象：

~~~yaml
newapi:
  url: https://newapi.example.com
  proxy_url: ""
  access_token: ""
  user_id: 0
~~~

`access_token` 与 `user_id` 必须同时配置或同时留空/0。两项留空时调用者识别关闭；审计、转发和 parser 仍正常工作。配置后，该凭证只用于以下只读管理请求，不能替代客户端 LLM 凭证，也不得返回给前端、写入审计库或普通日志。

管理请求复用 `newapi.url` 和可选的 `newapi.proxy_url`。未配置显式代理时固定直连，不读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。

## 3. 安全用户目录

程序启动时和之后每五分钟分页调用：

~~~http
GET /api/user/?p=0&size=100
Authorization: <newapi.access_token>
New-Api-User: <newapi.user_id>
Accept: application/json
~~~

只保留 `id`、`username`、`display_name`、`status` 和 `group`。每页最多 100 条，单次请求超时 10 秒，响应体上限 1 MiB；任一页异常时整次刷新失败并保留上一份成功快照。

受保护的 `GET /api/v1/newapi/callers` 返回该安全目录和最近刷新时间，供 React 主筛选选择 NewAPI 用户。目录只改善筛选体验，不用于判定某条 audit 的真实调用者。

## 4. Request ID 捕获

只有命中已配置 LLM route、实际访问 NewAPI 并收到响应的请求才可能解析调用者。审计层从 NewAPI 响应 Header 捕获合法的 `X-Oneapi-Request-Id`，在 `FinishAudit` 时写入：

~~~text
audit_records(
  newapi_request_id,
  caller_status, caller_attempts,
  caller_next_at_ns, caller_updated_at_ns
)
~~~

没有 request ID 的记录保持 `caller_status=none`。这包括本地 interceptor 拒绝、没有收到上游响应、NewAPI 未返回该 Header，以及所有无审计 passthrough 请求。

## 5. 全站日志查询

存在 request ID 时，记录先进入 `pending`。单个后台 goroutine 从 SQLite 扫描到期任务并精确调用：

~~~http
GET /api/log/?p=0&size=10&request_id=<X-Oneapi-Request-Id>
Authorization: <newapi.access_token>
New-Api-User: <newapi.user_id>
Accept: application/json
~~~

只接受 request ID 完全相等且所有返回项的用户和 Token 所有权一致的结果。成功后写入：

~~~text
token_links(
  audit_id, newapi_user_id, username,
  newapi_token_id, token_name, linked_at_ns
)
~~~

并把 `caller_status` 改为 `resolved`。NewAPI 日志可能晚于响应落库，因此首次未找到或临时错误后，最多再按 500ms、1s、2s、5s、10s、30s 重试六次；尝试次数和下次时间保存在 SQLite，进程重启后继续。最后仍失败则标为 `unresolved`，不无限请求 NewAPI。

`token_links.masked_key` 只因旧版 migration 兼容而保留；新链路始终写空，查询 API 和 UI 不再暴露该字段。

## 6. 查询与前端

列表和详情可返回 `newapi_request_id`、`caller_status`、`newapi_user_id`、`username`、`newapi_token_id` 和 `token_name`。主列表调用者显示规则：

- `resolved`：`@username · token_name · #token_id`。
- `pending`：识别中。
- `unresolved`：未识别。
- `none`：未关联。

主筛选按 `newapi_user_id` 精确查询；后端也支持 `username`、`newapi_token_id` 和 `token_name`，其中 Token ID 放在前端高级筛选。详情显示 request ID 和身份状态，任何接口都不返回完整或打码 API Key。

## 7. 故障与生命周期

- 用户目录刷新失败保留旧快照，不影响 audited proxy、passthrough、parser 或 readiness。
- 单次日志查询失败只更新持久化重试状态；终止未识别不影响原请求结果。
- worker 无法启动时 readiness 可降级，但不改变数据面放行结论。
- 内存唤醒队列满时不丢任务；SQLite 中的 pending 行会被周期扫描重新发现。
- 日志只记录 audit ID、数量和稳定错误类别，不记录管理凭证、用户凭证、完整管理 URL、响应体或日志行内容。

## 8. 最少测试

- `access_token`/`user_id` 成对校验，关闭时不创建管理客户端和 worker。
- 用户目录分页、响应上限、异常页、刷新保留旧快照和安全字段投影正确。
- request ID 精确查询使用管理 Header，并拒绝错误 ID、冲突所有者和异常响应。
- 响应 Header 被保存为 pending；成功查询原子写入用户/Token 身份并改为 resolved。
- 延迟日志按退避重试，重启可恢复 pending，达到上限改为 unresolved。
- interceptor 拒绝、passthrough 和无 request ID 响应不会创建身份关联。
- 管理 API、数据库新记录、错误和普通日志都不包含完整或打码用户 API Key。
- 用户筛选、Token ID 高级筛选，以及 pending/resolved/unresolved/none 的 UI 展示正确。
