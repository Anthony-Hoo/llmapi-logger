# 模块 10：查询 API 与最小 React UI

## 1. 目标与范围

本模块只为个人单机部署提供三个数据能力：非敏感审计列表、包含 Request-URI/Header/Trailer 明文的单条详情，以及按需读取的原始请求/响应 Body。页面用于快速查看代理实际观察到的 LLM API HTTP 证据，不承担通用日志平台或运维控制台职责。

首版明确不做：

- 单条或批量删除 API。
- 在线导出。
- `audit_gaps` 查询页面和 gaps UI。
- reparse 管理端点。
- 完整 parsed JSON、对话全文或 wire-level 抓包重建。

retention 只在后台删除过期审计，不扩展本模块的只读查询接口。

## 2. Listener 与访问控制

- 管理面默认监听 `127.0.0.1:8081`，与代理数据面使用独立 `http.Server` 和 mux。
- `admin_token` 在 loopback 和非 loopback 上都必填；为空或包含空白字符时服务拒绝启动。
- `/api/v1/*`、`/healthz` 和 `/readyz` 都经过同一个 Bearer middleware，规则见[模块 09](09-security-encryption-and-redaction.md)。
- `/ui/` 的 HTML shell 与静态资源可以无鉴权加载，但不得包含审计数据、运行状态或 secret。
- 管理路由只注册到管理面，不得出现在代理数据面。

Bearer token 缺失或错误统一返回 `401`。监听在 loopback 不是绕过鉴权的理由。

## 3. 数据边界

查询只会看到被进程内 Matcher 精确命中的 LLM API route。`/v1/models`、NewAPI 健康检查、登录、管理和前端等安全非 LLM 请求即使经本程序 passthrough，也不会创建 audit，因此不会出现在列表、详情或 raw 接口中。受保护或危险的未匹配路径 fail-closed，同样不创建 audit。

列表只读取 `audit_records`，并可关联 `parsed_results` 和 `token_links` 的窄摘要字段，不加载敏感密文。详情由 query 层读取并认证解密 `request_uri_enc` 和每条 `http_headers.value_enc`；Body bytes 与 `parsed_json_enc` 仍不随详情返回。

## 4. 列表 API

~~~http
GET /api/v1/audits?limit=50&before_started_at_ns=...&before_id=...
~~~

最小范围支持时间、协议、路径、模型、状态码、转发状态、阻断组件/代码、捕获状态和可选 Token 名称关联等简单筛选。排序固定为 `started_at_ns DESC, audit_id DESC`，使用 `before_started_at_ns + before_id` 做 keyset 分页；默认 50 条，最大 200 条。

列表只返回非敏感摘要，并明确包含 `forward_status`、`blocked_by` 和 `block_code`。非法参数返回 `400`。

## 5. 详情 API

~~~http
GET /api/v1/audits/{audit_id}
~~~

详情返回审计元数据、原始 `request_uri`、实际存在的 HTTP 阶段、每个 Header/Trailer 值、Body 长度/hash/完整性、parser 最小摘要和可选 Token 名称关联。Header 数组逐项返回，不合并同名多值：

~~~json
{
  "request_uri": "/v1/chat/completions?trace=...",
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

该响应包含敏感明文，只能通过 Admin Token 读取，并固定 `Cache-Control: no-store`。interceptor 拒绝的记录直接展示 `forward_status=rejected`、`blocked_by` 和 `block_code`，不会伪造未发生的 NewAPI 或响应阶段。记录不存在返回 `404`；Request-URI/Header 认证失败或长度不一致时整条详情返回通用完整性错误，不返回部分明文。

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

公开 shell 首先显示 token 输入页。token 只保存在 React state/context 内存中，每个数据请求附加 `Authorization: Bearer ...`；刷新、关闭页面或收到 `401` 后清空。不得写入 localStorage、sessionStorage、Cookie、IndexedDB、URL 或 Service Worker。

页面保持三块：

- 列表与简单筛选：展示协议、路径、模型、状态、捕获/解析状态和拦截结果。
- 详情：展示审计摘要、Request-URI、四阶段中实际存在的阶段、每个 Header/Trailer 对应值、Body 摘要和 parser 摘要。
- 原始 HTTP 证据：按 `request_sent_to_newapi` 和 `response_received_from_newapi` 重建应用层起始行、Header 和 Trailer；Body 只有用户点击查看后才加载到页面内存。有效 UTF-8 且不含明显二进制控制字节时内联预览，否则提示使用下载按钮保存原始字节。

重建视图用于排查应用层输入/输出，不是 wire dump：不恢复 TCP/TLS、HTTP/2 frame、Header 原始大小写/顺序或传输 chunk framing。下载始终保存 raw API 返回的原始 Body 字节，不使用页面渲染文本重新编码。

组件优先复用 shadcn/ui 的 `Button`、`Input`、`Table`、`Card`、`Badge`、`Alert`、`Skeleton` 和 `Separator`。页面不增加维护或 gaps 控制面。

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

- 列表 keyset 分页稳定，筛选非法值返回 `400`，列表查询不读取敏感大字段。
- 详情按 stage/kind/name/value_index 返回全部已保存 Header/Trailer 值和 Request-URI；篡改密文或长度不一致时不返回部分详情。
- 列表不读取或返回 Request-URI、Header value、Body 或 parsed JSON 全文。
- raw 按 chunk 顺序输出，并正确报告长度、hash 和完整性；大 Body 输出内存有界。
- loopback 和非 loopback 的 API、health、ready 均要求 Bearer token；只有静态 UI shell 可匿名加载。
- React token 只存在内存，刷新后必须重新输入；详情显示逐项 Header/Trailer，raw Body 按需预览和下载。
- Vite 构建产物可由 Go embed 提供，生产运行不依赖 Node。
- 未授权响应、列表、静态 UI shell 和日志不泄露 Header value、Body、admin token 或主密钥；授权详情和 raw 是明确的敏感证据读取入口。

## 11. 实现边界

storage 查询层只加载所需密文；query 层负责 AAD 重建、认证解密和 DTO 映射；web 层负责 Admin Token、`no-store`、稳定错误和 raw streaming；React 页面只在用户动作后读取敏感证据，不持久化 token 或 Body。
