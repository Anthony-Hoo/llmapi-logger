# 模块 10：查询 API 与 React UI

## 1. 目标与范围

管理面提供：审计列表、单条详情、verified provider JSON 重建、逻辑 SSE 时间线、异常 raw Body、NewAPI 安全调用者目录和动态 User-Agent 规则。页面以多轮对话和轮次图为主，HTTP raw 证据作为按需辅助信息。

不提供批量导出、单条/批量 audit DELETE、reparse API、gaps UI、跨库分析或 wire-level 抓包重建。

## 2. Listener 与鉴权

- 管理面使用独立 listener，默认 `127.0.0.1:8081`。
- `/api/v1/*`、`/healthz`、`/readyz` 都要求 Bearer token 或有效 HttpOnly Cookie。
- `/ui/` shell 和静态资源可匿名加载，但不包含审计数据或配置。
- `POST /api/v1/session` 以一次性 admin token 换取七天 Cookie；`DELETE` 注销；`GET` 返回当前身份供前端引导。
- 存在两种身份：管理员读取全部记录与站点配置；开发者用 NewAPI 用户 API Key 登录，只读取该 Key 的记录，详见[模块 19](19-developer-key-session.md)。开发者访问管理员专属端点返回 403。
- `POST /api/v1/session` 按来源地址限流失败登录（5 分钟 10 次 → 429 + `Retry-After`）。
- 所有证据 JSON、错误、raw、reconstructed 和 timeline 响应都使用 `Cache-Control: no-store`。

## 3. 列表 API

~~~http
GET /api/v1/audits?limit=50&before_started_at_ns=...&before_id=...
~~~

支持时间、协议、路径、模型、User-Agent、NewAPI 用户、用户名、Token ID/名称、状态码、转发状态、阻断组件/代码和捕获状态等窄筛选。排序固定为 `started_at_ns DESC, audit_id DESC`，使用 `started_at_ns + audit_id` keyset cursor，默认 50、最大 200；`conversation`/`collapse` 筛选不改变排序和分页语义。

列表 SQL 只读取 audit、parsed summary 和 token link 窄列；query 层为每个候选 audit 单独读取并认证解密入站 User-Agent。User-Agent 筛选是不区分大小写的子串匹配，每次最多扫描 2000 个候选。列表不会读取 Request-URI、其他 Header、Body、parsed conversation 或 content/binary objects。

列表 DTO 包含 TTFT、request/response model、caller status、可选用户/Token 元数据、入站 User-Agent 和所属 conversation。Web 层使用安全用户目录按 user ID 补充 `display_name`；前端优先显示显示名，不暴露完整用户名作为主标签，Token 名称和 ID 分行显示。

`conversation=<conv_...>` 只返回 turn 归属于该内容寻址会话（详见[模块 18](18-content-addressed-conversation-storage.md)）的审计记录，按 `turns.conversation_id` 匹配，走 `turns_conversation_created_idx` 索引，不引入新 schema。`collapse=conversation` 时每个 conversation 只保留 `started_at_ns`/`audit_id` 意义上最新的一条；`collapse` 仅接受 `conversation`，其他非空值返回 `400 invalid_query`。被拦截、未解析等没有 turn 的记录不属于任何 conversation，始终逐条列出，不参与折叠去重。两个参数同时出现时以 `conversation` 为准，`collapse` 被忽略——查看单个会话应看到该会话的全部轮次。开发者会话中的代表记录选择与轮次计数均限定在该 API Key 的 scope 内。

开发者会话的作用域在解析 query 之后由服务端注入，客户端无法触及或替换；显式携带 `newapi_user_id`、`username`、`newapi_token_id`、`token_name` 返回 400，而不是静默覆盖。

## 4. 详情 API

~~~http
GET /api/v1/audits/{audit_id}
~~~

detail、raw、reconstructed 和 timeline 共用 `serveAuditResource` 中唯一一处授权闸门。开发者请求不属于自己或被策略拦截排除的 audit 时，返回与不存在相同的 `404`，不提供存在性预言。

详情返回：

- audit 状态、TTFT、路由、模型、调用者和 NewAPI request ID；
- 所属 conversation id（无 turn 时为空）及该 conversation 的总轮数（仅在有 conversation id 时返回）；
- 原始 Request-URI；
- 四阶段元数据和逐项 Header/Trailer value；
- Body 的 source stage、observed/stored length、SHA-256、retention state、chunk count、首末观测时间和 SSE event count；
- parsed summary；
- 可选 turn graph 元数据；
- 协议无关 conversation。

verified turn 详情会在 query 层恢复完整 request refs、解密对象、恢复 binary marker、重建 provider request/response、比较 sequence/reconstruction hash，再生成 conversation。任一对象或 hash 校验失败时整条详情返回通用完整性错误，不返回部分明文。

turn 字段包括 conversation/turn/parent id、parent base、link reason/confidence、request/response layout、item count、sequence/reconstruction SHA-256、previous response id、response id 和 reconstruction status。

## 5. Provider JSON 重建

~~~http
GET /api/v1/audits/{audit_id}/reconstructed/request
GET /api/v1/audits/{audit_id}/reconstructed/response
~~~

只对 verified turn 可用。返回从 envelope、有序 item refs 和 binary objects 重建的 provider JSON，而不是从 UI conversation 反向生成。data URL 与 inline file data 使用原始二进制恢复；`file_id` 等外部引用保留。

OpenAI JSON 请求/非流式响应要求 canonical 语义与原 Body 一致。SSE 响应返回可审计的聚合语义对象和 event descriptors，不宣称返回原始 SSE wire bytes；需要原字节时只有异常 full raw 才提供。

UI 提供“下载重建请求 JSON”和“下载重建响应 JSON”，不会把页面渲染文本重新编码作为证据。

## 6. 原始 Body

~~~http
GET /api/v1/audits/{audit_id}/raw/request
GET /api/v1/audits/{audit_id}/raw/response
~~~

request 映射到 `request_sent_to_newapi`，response 映射到 `response_received_from_newapi`。服务先解析 `source_stage`，再按 owning chunk 的 seq/offset 逐块认证解密、解压和流式输出。

状态语义：

- `full`：返回原始字节，并通过响应 Header 给出 observed/stored length、SHA-256 和 complete；
- `pending` 或 stage streaming：`409 raw_not_finalized`；
- `metadata`：`410 raw_not_retained`，表示 raw 已在 verified 重建后主动释放，不是证据丢失；
- stage/audit 不存在：`404`。

UI 在 metadata 状态直接解释“原始 Body 已完成校验并释放”，不显示必然返回 410 的 raw 查看/下载按钮。只有 full evidence 才按用户动作加载到页面内存。

## 7. SSE 时间线

~~~http
GET /api/v1/audits/{audit_id}/timeline/request
GET /api/v1/audits/{audit_id}/timeline/response
~~~

timeline 返回 stage、observed length、实际 event count、首末 event 时间、complete 标志和 delta 解码后的 offset/time points。完整时间线要求点数、首末时间和总事件严格一致；超过 100,000 个事件时只保存前 100,000 点，`event_count` 仍是实际总数且 `complete=false`。

UI 默认只显示 TTFT、Body 首末观测、SSE event count 和 complete 状态；用户点击后才读取并校验完整 points，再显示首末逻辑事件时间和已保存点数。

## 8. React UI

源码位于 `internal/web/frontend`，Vite 输出到 `internal/web/dist` 并由 Go embed 打包；生产不依赖 Node。

主要视图：

- 审计列表：时间、调用者、窄模型列和可换行 User-Agent；异常记录显示短状态提示；有所属 conversation 的行显示会话短 ID，按会话折叠开启且该会话轮数大于 1 时额外显示「N 轮」徽标。列表头提供「按会话折叠」开关，默认开启；查看单个会话（见下）时该开关不出现，因为此时应显示全部轮次。
- 轮次与内容存储：conversation/parent/link、item count、布局、sequence/reconstruction hash 和 verified 状态；提供 reconstructed JSON 下载。详情头在该记录属于某个 conversation 时提供「查看同会话」按钮，点击后对列表应用该 conversation 的筛选；筛选生效时列表上方显示会话横幅（含会话 ID）和「清除会话筛选」操作，取消后恢复折叠视图。
- 对话审计：system/developer/user/assistant/tool、reasoning、tool call/result 按原顺序展示。
- 流式响应时序：TTFT、event count、首末观测、timeline complete 和按需 timeline 校验。
- 原始 HTTP 证据：默认折叠，显示 stage/Header/Trailer/Body hash/retention；full raw 按需预览或下载。
- UA 规则：Go RE2 正则的新增、编辑、启停和删除，持久化后热生效。

登录页提供管理员令牌与开发者 API Key 两种模式。开发者视图隐藏 UA 规则入口、调用者筛选和 Token ID 筛选，header 显示身份 chip；审计列表与详情组件本身不变。前端裁剪只为体验，边界一律由服务端强制。

assistant text 使用 `react-markdown` + `remark-gfm`，不启用 raw HTML；只允许安全链接，远程图片降级为文本。其他角色、reasoning、工具参数和结果保持原始文本/JSON，不因展示而改写存储值。

页面重建的是应用层 HTTP 视图，不恢复 TCP/TLS、HTTP/2 frame、Header 原始大小写/顺序或传输 chunk framing。

## 9. 最小接口

~~~go
type AuditQuery interface {
    Healthy() bool
    List(context.Context, Filter, Cursor, int) (Page, error)
    Get(context.Context, string) (Detail, error)
    ReconstructTurn(context.Context, string) (ReconstructedTurn, error)
    Timeline(context.Context, string, Side) (StreamTimeline, error)
    RawMeta(context.Context, string, Side) (RawMetadata, error)
    StreamRaw(context.Context, string, Side, io.Writer) error
}
~~~

接口只读；不包含删除、导出或维护任务抽象。

## 10. 错误与资源控制

- 单次 query timeout 固定 10 秒。
- SQLite 不可用或超时返回通用 `503`。
- GCM、length、marker、hash 或 reconstruction 失败返回通用 `500 evidence_unavailable`。
- 客户端取消后停止迭代、解密和输出。
- raw 已开始写出后发生错误时直接中断，不追加伪 JSON。
- UI 不自动加载 raw Body 或最多 100,000 点的 timeline。

## 11. 最少测试

- 列表 keyset、窄筛选、User-Agent 定向解密、TTFT 映射、`conversation` 筛选、`collapse=conversation` 折叠语义及二者同时出现时的互斥优先级。
- 详情逐项 Header/Trailer、Body retention/source/timeline 字段和 display name。
- verified turn 的 complex Responses 请求/响应精确重建，包括 developer、reasoning、并行工具、PNG、`file_id`、inline file data 和 usage。
- reconstructed/timeline 路由鉴权、`no-store` 和稳定错误。
- metadata raw 不可读取且 UI 不显示 raw 按钮；full raw 大 Body 内存有界。
- timeline 完整/截断语义、首末时间和 point count 校验。
- conversation 安全 Markdown、角色顺序、工具关联和未知内容展示。
- 前端 API、组件、TypeScript 检查和生产构建。
- 双角色鉴权、会话 API 三态、开发者作用域强制与管理端点 403，详见[模块 19](19-developer-key-session.md)。
- 未授权响应、静态 shell、列表和日志不泄露 Request-URI、Header、Body、conversation、Token、Key 指纹或主密钥。
