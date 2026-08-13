# 模块 10：查询 API 与最小 React UI

## 1. 目标与范围

本模块为个人单机部署提供三个审计查询入口，并提供一个受保护的动态 User-Agent 规则控制面：包含最小摘要和入站 User-Agent 的紧凑审计列表、包含 conversation/Request-URI/Header/Trailer 明文的单条详情，以及按需读取的原始请求/响应 Body。页面默认把 parser 结果渲染成便于审计的多轮对话，同时保留原始 HTTP 证据，不承担通用日志平台职责。

首版明确不做：

- 单条或批量删除审计 API。UA 规则删除属于明确的配置操作。
- 在线导出。
- `audit_gaps` 查询页面和 gaps UI。
- reparse 管理端点。
- 完整供应商 parsed object、跨 audit 自动串联会话或 wire-level 抓包重建。单条 audit 内的协议无关 conversation 已包含在详情中。

retention 只在后台删除过期审计，不扩展本模块的只读查询接口。

## 2. Listener 与访问控制

- 管理面默认监听 `127.0.0.1:8081`，与代理数据面使用独立 `http.Server` 和 mux。
- `admin_token` 在 loopback 和非 loopback 上都必填；为空或包含空白字符时服务拒绝启动。
- 受保护的 `/api/v1/*`、`/healthz` 和 `/readyz` 都经过同一个管理鉴权 middleware，接受 Bearer token 或有效的管理 Cookie，规则见[模块 09](09-security-encryption-and-redaction.md)。
- `/ui/` 的 HTML shell 与静态资源可以无鉴权加载，但不得包含审计数据、运行状态或 secret。
- 管理路由只注册到管理面，不得出现在代理数据面。

管理凭证缺失或错误统一返回 `401`。监听在 loopback 不是绕过鉴权的理由。`POST /api/v1/session` 验证 admin token 并设置七天过期的 HttpOnly Cookie；`DELETE /api/v1/session` 用于注销。

## 3. 数据边界

查询只会看到被进程内 Matcher 精确命中的 LLM API route。`/v1/models`、NewAPI 健康检查、登录、管理和前端等安全非 LLM 请求即使经本程序 passthrough，也不会创建 audit，因此不会出现在列表、详情或 raw 接口中。受保护或危险的未匹配路径 fail-closed，同样不创建 audit。

列表主体读取 `audit_records`，并可关联 `parsed_results` 和 `token_links` 的窄摘要字段；调用者摘要只包含 NewAPI request ID、识别状态、用户 ID/用户名和 Token ID/名称。Web 层会按用户 ID 使用内存中的安全用户目录动态补充 `display_name`，不改变 SQLite schema；目录中没有对应显示名时前端回退到已保存的用户名。此外，query 层会为每条候选记录定向读取并认证解密 `request_for_newapi_received_from_nginx` 阶段的入站 `User-Agent`，把首个值放入列表 DTO；不会借此加载其他 Header。详情由 query 层读取并认证解密 `request_uri_enc`、每条 `http_headers.value_enc` 和 `parsed_results.parsed_json_enc`；后者只提取并校验 conversation。Body bytes 仍不随详情返回。

## 4. 列表 API

~~~http
GET /api/v1/audits?limit=50&before_started_at_ns=...&before_id=...
~~~

最小范围支持时间、协议、路径、模型、User-Agent、NewAPI 用户、用户名、Token ID/名称、状态码、转发状态、阻断组件/代码和捕获状态等简单筛选。主筛选聚焦调用者用户、模型和 User-Agent；Token ID、路径、状态及其他诊断条件属于高级筛选。模型保持精确匹配；普通列表无论是否设置筛选都会解密并返回入站 User-Agent，设置筛选后使用不区分大小写的子串匹配，每次最多扫描 2000 条候选记录，达到上限时通过下一页 cursor 继续。页面从安全用户目录选择 `newapi_user_id`，列表 SQL 对 `token_links.newapi_user_id` 做精确筛选；Token ID 高级筛选同样是窄列精确匹配。排序固定为 `started_at_ns DESC, audit_id DESC`，使用 `before_started_at_ns + before_id` 做 keyset 分页；默认 50 条，最大 200 条。

列表返回紧凑摘要、解密后的入站 `user_agent`，以及 `newapi_request_id`、`caller_status` 和可选的用户/Token 身份字段；不返回完整或打码 API Key。底层 DTO 仍保留路径和状态等窄字段供详情选择与高级筛选使用，但主列表行不展示这些诊断字段。非法参数返回 `400`。

受保护的 `GET /api/v1/newapi/callers` 返回最近一次成功同步的安全用户目录和 `refreshed_at`。每项只包含 ID、用户名、显示名、状态和分组；管理集成未配置或尚未成功刷新时返回空数组，页面仍可使用其他筛选。

受保护的 `/api/v1/user-agent-rules` 支持 `GET`、`POST`，`/api/v1/user-agent-rules/{id}` 支持 `PUT`、`DELETE`。请求体只接收名称、启用状态、模型正则和 User-Agent 正则；无效 JSON、未知字段或无效 RE2 正则返回通用 `400`，不得回显请求值或底层错误。持久化成功后规则立即生效。

## 5. 详情 API

~~~http
GET /api/v1/audits/{audit_id}
~~~

详情返回审计元数据、原始 `request_uri`、实际存在的 HTTP 阶段、每个 Header/Trailer 值、Body 长度/hash/完整性、parser 最小摘要、conversation，以及可选的 NewAPI request ID、识别状态和用户/Token 身份。Header 数组逐项返回，不合并同名多值：

~~~json
{
  "request_uri": "/v1/chat/completions?trace=...",
  "conversation": {
    "schema_version": 1,
    "messages": [
      {
        "index": 0,
        "role": "user",
        "phase": "request",
        "direction": "client_to_upstream",
        "content": [{"index": 0, "type": "text", "text": "..."}]
      }
    ]
  },
  "headers": [
    {
      "stage": "request_sent_to_newapi",
      "kind": "header",
      "name": "Authorization",
      "value_index": 0,
      "value_length": 20,
      "value": "Bearer ..."
    }
  ]
}
~~~

该响应包含敏感明文，只能通过 Admin Token 读取，并固定 `Cache-Control: no-store`。interceptor 拒绝的记录直接展示 `forward_status=rejected`、`blocked_by` 和 `block_code`，不会伪造未发生的 NewAPI 或响应阶段。记录不存在返回 `404`；Request-URI/Header/parsed JSON 认证失败、长度不一致或 conversation schema 非法时整条详情返回通用完整性错误，不返回部分明文。

## 6. 原始请求与响应 Body

~~~http
GET /api/v1/audits/{audit_id}/raw/request
GET /api/v1/audits/{audit_id}/raw/response
~~~

request 读取 `request_sent_to_newapi`，response 读取 `response_received_from_newapi`。服务按 `body_chunks.seq` 顺序分批读取、逐块解密并写出，避免把完整 Body 再复制到一个大缓冲区。

响应使用 `application/octet-stream`，固定 `Cache-Control: no-store`，并通过响应 Header 返回 observed/stored length、SHA-256 和 `X-Audit-Complete`。证据不完整时可以返回已保存字节，但必须明确标记不完整；阶段或记录不存在返回 `404`。

仍处于 `streaming` 的 Body 暂不开放 raw 下载，返回 `409 raw_not_finalized`。只有阶段已经终结为 complete 或 partial 后才读取，因此元数据与不可再变化的分块保持一致，不为个人版引入长时间持有的数据库流式快照。

## 7. React UI

前端固定使用 React、TypeScript、Vite、Tailwind CSS 和 shadcn/ui。源码目录为 `internal/web/frontend`，构建产物为 `internal/web/dist`，由 Go embed 编入二进制；生产环境不需要 Node 或 Vite dev server。

公开 shell 首先探测已有管理 Cookie；Cookie 有效时直接加载列表，失效时显示 token 输入页。登录请求成功后由服务设置七天过期的 HttpOnly Cookie，前端不再保存 token，也不写入 localStorage、sessionStorage、IndexedDB、URL 或 Service Worker。所有管理请求使用 `credentials: same-origin`；收到 `401` 后回到登录页。

详情页面保持三个层次：

- 列表与筛选：使用紧凑的原生 `ul/li/button` 列表，主行只展示调用者、时间、模型和 User-Agent，避免表格横向滚动；resolved 调用者优先显示当前安全用户目录中的显示名，缺失时回退用户名，Token 名称和 `ID` 各占一行。模型列保持窄宽度和单行省略，User-Agent 获得主要剩余宽度并允许自然换行。pending/unresolved/none 分别显示识别中、未识别和未关联。主筛选提供 NewAPI 用户、模型和 User-Agent，Token ID、路径、状态及其他诊断条件收进默认折叠的高级筛选。
- 对话审计主视图：按 parser 给出的顺序展示 system/developer/user/assistant/tool；标明 request/response 和数据方向；assistant 的 text part 使用 `react-markdown` + `remark-gfm` 安全渲染，不启用 raw HTML，只允许 HTTP、HTTPS、mailto 和相对链接，远程图片降级为文字；system/user/tool/reasoning 保持原始文本或 JSON。reasoning 默认折叠；tool call 显示名称、call id、arguments，tool result 显示关联 id 和结果。JSON 字符串只在前端格式化，不改写存储值。
- 辅助证据折叠区：包含 Request-URI、四阶段、每个 Header/Trailer 值、Body 完整性和应用层原始 HTTP 重建。Body 只有用户点击查看后才加载到页面内存；有效 UTF-8 且不含明显二进制控制字节时内联预览，否则提示下载原始字节。
- UA 拦截规则页：列出状态、名称、模型正则和 User-Agent 正则，支持新增、编辑、启停和删除；说明 Go RE2、默认区分大小写、重叠规则全部需要通过及热生效语义。

重建视图用于排查应用层输入/输出，不是 wire dump：不恢复 TCP/TLS、HTTP/2 frame、Header 原始大小写/顺序或传输 chunk framing。下载始终保存 raw API 返回的原始 Body 字节，不使用页面渲染文本重新编码。

组件优先复用 shadcn/ui 的 `Button`、`Input`、`Card`、`Badge`、`Alert`、`Skeleton` 和 `Separator`；审计记录本身使用语义化原生列表。页面不增加维护或 gaps 控制面。

## 8. 错误与资源控制

- 单次查询超时固定为 10 秒，不增加额外配置。
- SQLite 不可用或查询超时返回 `503`。
- 密文认证失败返回 `500`，错误体和日志不包含敏感数据。
- 客户端取消后停止 SQLite 迭代、解密和 raw 输出。
- raw 开始写出后发生错误时中断输出并记录稳定错误码，不追加伪 JSON 错误体。
- 管理 JSON、错误和 raw 响应全部使用 `Cache-Control: no-store`。

## 9. 最小接口

~~~go
type AuditQuery interface {
    Healthy() bool
    List(ctx context.Context, f Filter, c Cursor, limit int) (Page, error)
    Get(ctx context.Context, auditID string) (Detail, error)
    RawMeta(ctx context.Context, auditID string, side Side) (RawMetadata, error)
    StreamRaw(ctx context.Context, auditID string, side Side, w io.Writer) error
}
~~~

该接口只读，不需要写入队列、删除方法或导出任务抽象。

## 10. 最少测试

- 列表 keyset 分页稳定，筛选非法值返回 `400`；列表只定向读取入站 User-Agent 密文，不读取其他敏感大字段。
- 详情按 stage/kind/name/value_index 返回全部已保存 Header/Trailer 值和 Request-URI；篡改密文或长度不一致时不返回部分详情。
- 详情能恢复 conversation 的消息顺序、reasoning、tool call/result；parsed JSON 密文/AAD/schema/index/type 篡改返回通用完整性错误。
- 列表会读取并返回入站 User-Agent，但不读取或返回 Request-URI、其他 Header value、Body、parsed JSON 或 conversation 全文。
- raw 按 chunk 顺序输出，并正确报告长度、hash 和完整性；大 Body 输出内存有界。
- loopback 和非 loopback 的 API、health、ready 均要求 Bearer token 或有效管理 Cookie；只有静态 UI shell 和登录端点可匿名访问。
- 登录 Cookie 属性和固定过期时间正确；刷新可恢复会话，注销、过期或 `401` 后回到登录页；前端存储和 URL 中没有 admin token。
- NewAPI 用户、模型、User-Agent 和 Token ID 筛选语义正确；管理 API、URL、日志和审计库均不接收用户 API Key。
- `newapi/callers` 只返回安全用户目录；列表和详情正确展示 request ID、caller status、用户与 Token 元数据，且不含任何用户 API Key 字段。
- 审计列表主行只包含调用者、时间、模型和 User-Agent；conversation 是详情默认主视图，assistant 文本支持 GFM Markdown 且原始 HTML 不执行，其他角色、reasoning 和工具内容保持原始展示；路径、状态、raw/Header 辅助证据默认折叠，raw Body 按需预览和下载。
- Vite 构建产物可由 Go embed 提供，生产运行不依赖 Node。
- 未授权响应、静态 UI shell 和日志不泄露 Header value、Body、admin token 或主密钥；已授权列表只允许返回入站 User-Agent 这一项 Header 明文，详情和 raw 是其余敏感证据的明确读取入口。

## 11. 实现边界

storage 的普通列表主体查询不加载敏感密文，但会按每个候选 audit 定向返回入站 User-Agent 密文；query 层始终认证解密其首个值用于列表展示，启用 User-Agent 筛选时再在固定扫描上限内执行不区分大小写的子串匹配。调用者筛选直接使用 `token_links` 的用户/Token 窄列，不解密凭据 Header。详情查询只加载所需密文；query 层负责 AAD 重建、认证解密、conversation 校验和 DTO 映射；web 层负责 Admin Token、七天 Cookie、`no-store`、稳定错误、安全用户目录和 raw streaming；React 页面不持久化 token 或 Body，并只在用户动作后读取 raw Body。
