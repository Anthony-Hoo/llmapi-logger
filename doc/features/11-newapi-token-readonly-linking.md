# 模块 11：NewAPI Token 只读关联

## 1. 目标

本模块是个人部署中的可选增强：通过 NewAPI 的只读 Token 列表 API 同步服务端已经打码的 Token 元数据，并把命中的 Token ID、名称和 `masked_key` 快照关联到 LLM audit。

关联结果只用于审计展示和按 API Key 筛选，不参与鉴权、配额、路由、interceptor 或流量放行。NewAPI 的实际响应始终是客户端凭据是否有效的唯一依据。本项目不会从目录 API 获取、返回或持久化原始 Token。

## 2. 配置

配置统一位于[模块 01](01-configuration-and-route-boundary.md)的 `newapi` 对象：

~~~yaml
newapi:
  url: https://newapi.example.com
  proxy_url: ""
  access_token: ""
  user_id: 0
~~~

`access_token` 与 `user_id` 必须同时配置或同时留空/0。两项留空时功能完全关闭；配置后，access token 只能用于 NewAPI 管理 API 的只读 Token 目录同步，不能用于客户端 LLM 请求，也不能返回给前端或写入日志、审计库。

目录请求复用 `newapi.url` 和可选的 `newapi.proxy_url`。未配置显式代理时固定直连，不读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。

## 3. 只读同步

同步器固定调用：

~~~http
GET /api/token/?p=0&size=100
Authorization: <newapi.access_token>
New-Api-User: <newapi.user_id>
Accept: application/json
~~~

页码从 0 开始，每页最多 100 条，并一直读取到响应中的 total。每个请求最多等待 10 秒，单页响应体最多 1 MiB。只接受 HTTP 200、`success=true`、稳定 total、唯一正整数 ID，以及符合 NewAPI 打码格式的 key；异常响应整次刷新失败，不发布半份目录。

每个条目只保留：

- `id`。
- `name`。
- `masked_key`。
- `status`。
- `group`。
- `unlimited_quota`。

程序启动监听前尝试刷新一次，之后每五分钟刷新。刷新成功后原子替换完整快照；刷新失败只记录不含凭据的 warning，继续使用上一份成功快照并正常转发。首次刷新失败时快照为空，下一周期自动重试。

## 4. 内存快照

内存快照包含一份用于管理页面的 Token 列表，以及 `masked_key -> Token` 的只读索引。请求热路径只读当前快照，不访问 NewAPI、不等待刷新锁。

NewAPI 的打码规则固定为：短 key 全部或部分替换为星号；长度大于 8 时保留前四位和后四位，中间使用十个星号。目录条目必须已经符合该规则。

两个不同 Token ID 若得到相同 `masked_key`，该值视为歧义并从请求关联索引中排除，但两条已打码记录仍可出现在管理页面目录中。这样不会用不唯一的脱敏值错误关联历史请求。

## 5. 请求凭据选择

匹配逻辑复用 NewAPI v1.0.0-rc.21 的凭据优先级和归一化：

1. 默认读取 `Authorization`。
2. Anthropic Messages/Models 路径存在 `x-api-key` 时覆盖 Authorization。
3. Gemini 路径的 Query `key` 再覆盖前述值。
4. Gemini 路径的 `x-goog-api-key` 最后覆盖 Query key。

Authorization 只识别 `Bearer ` 或 `bearer ` 前缀，并对前缀后的值去除首尾空白；由 x-api-key、Query key 或 x-goog-api-key 选出的值也会去除首尾空白。随后去掉可选 `sk-` 前缀，以及 NewAPI 渠道后缀分隔符后的内容，再使用同一打码算法查询内存索引。包含星号的来访值不参与关联，避免把已打码字符串误认为真实凭据。

原始请求凭据只存在于正常代理请求内存中，不会因为本模块新增落盘、日志或管理 API 暴露。

## 6. Audit 快照

命中配置 LLM route、成功创建 audit parent 后，审计管理器在 interceptor chain 之前做一次纯内存关联。找到唯一条目时，通过 SQLite 单 writer 幂等写入：

~~~text
token_links(audit_id, newapi_token_id, token_name, masked_key, linked_at_ns)
~~~

因此后续被 interceptor 拒绝的 audit 也可能保留当时的 Token 快照；这不代表凭据已由 NewAPI 接受。passthrough、危险路径 fail-closed、目录未配置、目录为空或没有唯一匹配时不创建 `token_links`。

Token 后续改名、禁用或删除不会回写历史 audit；新快照只影响后续请求。删除 audit 时由外键级联删除对应关联行。旧数据库经 migration v3 升级后，既有行的 `masked_key` 为空字符串。

## 7. 查询与前端

受保护的 `GET /api/v1/newapi/tokens` 返回当前已打码目录和最近成功刷新时间。React 筛选栏以 `#ID 名称 · masked_key` 显示 API Key 下拉项，提交时只发送 `newapi_token_id`；列表查询直接对 `token_links.newapi_token_id` 做精确匹配。

审计列表和详情可返回 `newapi_token_id`、`token_name`、`masked_key`，不会返回原始 Token。目录未启用或尚未成功刷新时，下拉只有“全部 API Key”，其他查询功能不受影响。

## 8. 故障与日志

- 目录刷新失败不影响 audited proxy、passthrough、available/strict admission 或 parser。
- 关联未命中或 `token_links` 写入失败不改变请求放行结果。
- 日志只记录稳定错误类别和成功刷新后的条目数，不记录 access token、用户 Token、完整请求 URL、响应体或目录行内容。
- 管理 API 只暴露已打码字段，并继续使用 Admin Token/七天 HttpOnly Cookie 与 `Cache-Control: no-store`。

## 9. 最少测试

- `access_token`/`user_id` 成对校验，关闭时不创建同步器。
- 分页从 0 开始、每页 100 条；请求 Header、超时、响应体上限和异常响应处理正确。
- 刷新成功原子替换目录；失败保留旧快照并按五分钟周期重试。
- 目录拒绝未打码 key、重复 ID、不稳定 total、过大响应和歧义 `masked_key` 关联。
- Authorization、Anthropic 和 Gemini 凭据优先级与归一化符合 NewAPI 行为。
- 请求热路径不访问网络；关联失败和写入失败不阻断 audit admission 或转发。
- 列表、详情和 Token 目录只出现 ID、名称与 `masked_key`，数据库和日志不包含原始 Token 或目录 access token。
- API Key 下拉提交 `newapi_token_id`，不会把原始 API Key 或哈希放进 URL。
