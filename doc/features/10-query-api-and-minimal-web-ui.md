# 模块 10：查询 API 与嵌入式 React UI

## 1. 目标

本模块为个人单机部署提供够用的审计浏览能力：列表、详情、原始请求/响应读取、删除单条记录，以及同步导出单条或筛选结果。

首版范围固定为单机浏览、单条删除和当前请求内完成的导出。

## 2. Listener 与访问控制

- 默认监听 `127.0.0.1:8081`，与代理数据面使用独立 `http.Server` 和 mux。
- `admin_token` 在 loopback 和非 loopback 上都必填；为空时服务拒绝启动。
- `/api/v1/*`、`/healthz`、`/readyz` 和 `/metrics` 全部经过同一个 Bearer middleware，规则见 [模块 09](09-security-encryption-and-redaction.md)。
- `/ui/` 的 HTML shell 与构建后的静态资源可以无鉴权加载，但其中不得包含审计数据、运行状态或 secret。
- 管理路由只注册到管理面，不得出现在代理数据面。

## 3. 固定限制

管理监听和 token 直接使用[模块 01](01-configuration-and-route-boundary.md)的 admin_listen、admin_token。首版把列表默认/最大条数固定为 50/200，查询超时固定为 10 秒，同步导出固定最多 500 条、512 MiB、2 分钟；不增加第二套配置 schema。所有上限由服务端强制执行。

## 4. 数据读取边界

单条审计查询使用 `audit_records`、`http_stages`、`http_headers`、`body_streams`、`body_chunks`、`parsed_results` 和 `token_links`。audit_gaps 是进程级缺口，单独查询，不伪装成某条 audit 的精确子记录。

列表以 audit_records 为主，可 LEFT JOIN parsed_results 和 token_links 的窄明文字段用于模型和 Token 筛选；不得读取或解密 Header value、Body chunk 或 parsed_json_enc。

## 5. 列表 API

~~~http
GET /api/v1/audits?limit=50&before_started_at_ns=...&before_id=...
~~~

可选筛选参数：`from_ns`、`to_ns`、`protocol`、`path`、`model`、`status_code`、`forward_status`、`blocked_by`、`block_code`、`capture_status`、`newapi_token_id`、`token_name`。

排序固定为 `started_at_ns DESC, audit_id DESC`。下一页同时传上一页末项的 `before_started_at_ns` 和 `before_id`；不使用 offset 分页。

响应摘要明确包含 `forward_status`、`blocked_by` 和 `block_code`。本地拒绝使用 `forward_status=rejected`；未阻断的请求后两项为空。`limit` 缺省 50，最大 200；非法筛选返回 `400`。

## 6. 详情 API

~~~http
GET /api/v1/audits/{audit_id}
~~~

详情返回：审计元数据、四阶段时间和状态、`forward_status`、`blocked_by`、`block_code`、Header 名称与长度、Body 总长度/hash、parsed result 摘要和 Token 关联。拒绝记录直接展示阻断组件和稳定错误码，不从错误文本反推原因。

详情默认不返回 Header value、Body bytes 或完整 parsed JSON。记录不存在返回 `404`。

## 7. 原始请求与响应

~~~http
GET /api/v1/audits/{audit_id}/raw/request
GET /api/v1/audits/{audit_id}/raw/response
~~~

两个端点只返回 Body 原始字节：request 读取 request_sent_to_newapi，response 读取 response_received_from_newapi。响应 Header 中返回内容类型、捕获长度和 X-Audit-Complete: true|false；完整 URI 与 Header value 通过显式导出获取。

实现按 `body_chunks.seq` 顺序分批短读、逐块解密和写出，不把完整 Body 一次加载到内存。body_streams 不完整时仍可返回已捕获字节，但必须标记不完整。

## 8. 删除单条

~~~http
DELETE /api/v1/audits/{audit_id}
~~~

- 仅允许删除已终结记录；活动记录返回 `409`。
- 通过单 SQLite writer 删除 audit_records，并依靠已测试的外键级联删除全部审计子表。
- 删除成功返回 `204`，不存在返回 `404`。
- 首版不提供批量删除 API；批量清理由 retention 模块负责。

UI 删除操作必须二次确认并显示 `audit_id`。删除不可撤销。

## 9. 同步导出

~~~http
GET /api/v1/audits/{audit_id}/export?format=zip
GET /api/v1/audits/{audit_id}/export?format=json
GET /api/v1/audits/export?format=json&from_ns=...&to_ns=...
~~~

单条记录支持 zip 或 json；筛选结果只支持 json 数组，筛选参数与列表一致。导出在当前 HTTP 请求内完成并直接流式返回。

超过 max_records、预计解密后字节数超过 max_bytes 或执行超时，分别返回 413 或 504。具体文件布局见 [模块 12](12-retention-export-and-maintenance.md)。

## 10. React UI

前端固定使用 React、TypeScript、Vite、Tailwind CSS 和 shadcn/ui。源码目录统一为 `internal/web/frontend`，Vite 输出目录统一为 `internal/web/dist`，由 `internal/web/embed.go` 使用 `//go:embed dist/*` 编入最终二进制。生产环境只运行 Go 服务，不启动 Node、Vite dev server 或独立静态文件服务。

公开加载的 shell 首先显示 token 输入页。使用 shadcn `Input` 的 password 类型和 `Button` 接收 token，React 只把 token 保存在组件 state/context 内存中。统一 fetch client 为每个数据请求附加 `Authorization: Bearer ...`；刷新、关闭标签页或收到 `401` 后清空 token。禁止 localStorage、sessionStorage、Cookie、IndexedDB、URL query/hash 和 Service Worker 持久化。

页面与组件：

- 列表：shadcn `Table`、`Input`、`Select`、`Badge`、`Pagination` 和 `Skeleton`，可筛选并醒目展示 `rejected`、`blocked_by` 和 `block_code`。
- 详情：`Card`、`Tabs`、`Badge`、`Separator`，展示阶段、拒绝/阻断字段、Header 名、parsed 摘要和 Token link。
- 原始查看：`ScrollArea`、`Alert` 和下载 `Button`；显式请求原始 Body，不自动加载大内容。
- 删除：`AlertDialog` 显示 `audit_id` 并要求二次确认。
- 导出：`Dialog`、格式 `Select`、`Progress` 和 `Sonner`，调用同步导出端点。
- 缺口提示：页面顶部使用 `Alert` 和 `Badge` 展示最近的进程级 `audit_gaps`，不得暗示其精确对应某条 audit。

进程级缺口使用单独接口：

~~~http
GET /api/v1/gaps?from_ns=...&to_ns=...&limit=100
~~~

## 11. 错误与资源控制

- Bearer token 缺失或错误返回 `401`。
- SQLite busy、writer 不可用或查询超时返回 `503`。
- 密文认证失败返回 `500`，错误体不包含敏感数据。
- 客户端取消时立即停止 SQLite 迭代、解密和导出。
- 原始流开始写出后发生错误只能中断连接并记录 `audit_id`。
- 导出和原始读取使用有界 buffer，不复制完整 Body。

## 12. 最小接口

~~~go
type AuditQuery interface {
    List(ctx context.Context, f Filter, c Cursor, limit int) (Page, error)
    Get(ctx context.Context, auditID string) (AuditDetail, error)
    ListGaps(ctx context.Context, fromNS, toNS int64, limit int) ([]Gap, error)
    StreamRaw(ctx context.Context, auditID string, side Side, w io.Writer) error
    Delete(ctx context.Context, auditID string) error
    Export(ctx context.Context, f Filter, format Format, w io.Writer) error
}
~~~

读取可以使用只读连接池；删除必须提交给单 SQLite writer，避免绕过写入串行化。

## 13. 测试

- 分页排序稳定，无重复或遗漏；`forward_status=rejected`、`blocked_by`、`block_code` 的筛选和列表/详情展示一致，且列表 SQL 不访问三个敏感大表。
- 原始读取按 chunk 顺序输出并正确标记完整性；大 Body 场景内存保持有界。
- 活动记录删除得到 `409`，终结记录删除后所有审计子表无孤儿行。
- ZIP/JSON 导出命中记录数、字节数和超时上限。
- gaps 接口只返回进程级时间区间，不声称精确关联某个 audit。
- loopback 和非 loopback 的 API 都要求 Bearer；未带 token 时只有静态 UI shell 可加载。
- React token 只存在内存且刷新后必须重新输入；各页面使用约定的 shadcn 组件。
- Vite 构建产物可被 Go embed 提供，生产测试中没有 Node 监听端口或进程。
- API 和 UI 错误中不泄露 Header、Body、token 或密钥。

## 14. 实施步骤

1. 实现 Filter、Cursor 和列表/详情 SQL。
2. 实现 Header/Body/parsed result 的按需解密读取。
3. 实现单条事务删除。
4. 实现同步 ZIP/JSON 流式导出。
5. 实现独立管理 listener、`admin_token` 必填校验和 Bearer middleware。
6. 用 React、Vite、Tailwind CSS 和 shadcn/ui 实现 token 输入、列表、详情、原始查看、删除、导出与缺口提示。
7. 把 Vite 产物接入 Go embed，并完成分页、取消、资源上限、鉴权、泄漏和无 Node 运行依赖测试。
