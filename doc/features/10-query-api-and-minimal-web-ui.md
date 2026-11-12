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

支持时间、协议、路径、模型、User-Agent、NewAPI 用户、用户名、Token ID/名称、状态码、状态段（`status_class`：`4xx`/`5xx`/`error`）、转发状态、阻断组件/代码、捕获状态，以及上游策略拒绝分类（`upstream_error_class`：`cyber_policy`/`misalignment_policy`/`content_policy`/`content_filter`/`moderation_blocked`/`safety_policy`）等窄筛选。列表 DTO 增加 `parsed_error_type`、`parsed_error_code`、`upstream_error_class` 三个可空字段用于展示上游拒绝。排序固定为 `started_at_ns DESC, audit_id DESC`，使用 `started_at_ns + audit_id` keyset cursor，默认 50、最大 200；`conversation`/`collapse` 筛选不改变排序和分页语义。`status_class=error` 匹配 `status_code` 在 400–599 的记录；`status_code` 为空的记录（例如在收到上游响应头之前就取消的请求）不计入，收到上游响应头后取消仍保留上游状态码。任何上述行级筛选生效时会话折叠（`collapse`）都被忽略，按轮次逐条列出，避免命中的较早轮次被同会话更新的轮次隐藏；User-Agent 也在不折叠的候选集上过滤。分页 cursor 和开发者身份 scope 不关闭折叠。

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
- parsed summary（含上游策略拒绝分类 `upstream_error_class`）；
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

前后端使用相同边界选择：请求优先 `request_sent_to_newapi`，没有该 Body 时回退入站请求；响应优先 `response_received_from_newapi`，没有该 Body 时回退发给客户端的响应。UI 的 Body、Header/Trailer、Content-Type、缺块提示和 raw 按钮均采用同一选择。首选 Body 存在但 raw 已压缩释放时，不改用另一边界的 Body 绕过保留策略。

证据卡片标题也按实际选中的 stage 命名：回退请求显示接收入站请求，回退响应显示返回响应，不将本地证据误标为发往或来自 NewAPI。

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

时间线 API 采用与 raw/UI 相同的 Body 首选和回退规则，并通过 `source_stage` 读取 owning 时间线，用 owning stage 构造解密 AAD。若首选 Body 存在但没有时间线，不越过它读取另一观察边界。返回的 complete=false 表示时间点序列被截断，或观察到的 SSE 在最后一个事件结束前中断；时间点在采集时按观察到的字节生成，与 raw 分块是否落盘无关。缺块 Body 的已封存时间线因此保持原有 complete，详情中的 Body 时间线标志与之一致；分块缺失由 Body 状态和 `capture_chunk_missing` 表达。

~~~http
GET /api/v1/audits/{audit_id}/timeline/request
GET /api/v1/audits/{audit_id}/timeline/response
~~~

timeline 返回 stage、observed length、实际 event count、首末 event 时间、complete 标志和 delta 解码后的 offset/time points。完整时间线要求点数、首末时间和总事件严格一致；超过 100,000 个事件时只保存前 100,000 点，`event_count` 仍是实际总数且 `complete=false`。

UI 默认只显示 TTFT、Body 首末观测、SSE event count 和 complete 状态；用户点击后才读取并校验完整 points，再显示首末逻辑事件时间和已保存点数。

## 8. React UI

源码位于 `internal/web/frontend`，Vite 输出到 `internal/web/dist` 并由 Go embed 打包；生产不依赖 Node。

页面在宽屏下使用「窄列表栏 + 宽详情」双栏布局：列表是左侧固定宽度的滚动栏（分页控件内置其中），详情占据剩余宽度并随页面滚动。详情内部以解析出的对话为主体：身份头（audit id、转发状态、导出与「查看同会话」操作）和关键信息条（时间、模型、调用者、HTTP 状态、TTFT、User-Agent）之后立即展示对话审计；HTTP 请求概览、解析摘要、流式时序与存储/原始证据全部下沉到对话之后。

主要视图：

- 审计列表：时间、调用者、窄模型列和可换行 User-Agent；异常记录显示短状态提示；上游策略拒绝额外显示“上游安全拒绝: <class>”短标签。高级筛选提供 HTTP 状态段和精确状态码、上游拒绝分类下拉，非法状态码或非法分类在字段旁就地提示，修改输入时清除提示，校验失败不提交筛选；有所属 conversation 的行显示会话短 ID，按会话折叠开启且该会话轮数大于 1 时额外显示「N 轮」徽标。列表头提供「按会话折叠」开关，默认开启；查看单个会话（见下）或任何行级筛选生效时该开关均不出现，因为此时应逐轮显示匹配记录。
- 对话审计：system/developer/user/assistant/tool、reasoning、tool call/result 按原顺序展示。详情头提供「导出会话 JSON」：前端把已获取的解析 conversation 连同关键审计元数据（audit/conversation/turn id、时间、模型、调用者、User-Agent）另存为本地 JSON 文件，面向阅读而非字节重放，不新增服务端导出 API；没有解析 conversation 时按钮禁用。
- 工具流量内联图片：tool call 参数与 tool result 中的 base64 图片（data URL、Anthropic `source.data`、Gemini `inline_data` 三种形态）在展示层渲染为缩略图，点击进入全屏查看器：滚轮以光标为中心缩放、拖动平移、双击在适应屏幕与原始大小间切换，多图时两侧箭头按钮与 ←/→ 方向键循环切换（切换时重置缩放），Esc 或点击背景关闭；展示用 JSON 中的 base64 载荷替换为「[图片 #n 类型 大小]」占位符以保持可读。图片全部来自 data: URL，渲染不发起网络请求；该替换只作用于展示副本，不改写存储值。未识别内容块沿用同一提取逻辑，但用户消息中的图片块在 DTO 中被截断到 4 KiB，通常无法完整渲染。
- 轮次与内容存储：conversation/parent/link、item count、布局、sequence/reconstruction hash 和 verified 状态；提供 reconstructed JSON 下载；在详情中位于「存储与原始证据」下，默认折叠。详情头在该记录属于某个 conversation 时提供「查看同会话」按钮，点击后清除所有行级筛选及其输入草稿，再对列表应用该 conversation 筛选，保留折叠偏好与服务端身份 scope；筛选生效时列表上方显示会话横幅（含会话 ID）和「清除会话筛选」操作。清除会话筛选仅移除 conversation；若在会话视图中重新应用了行级筛选，仍按轮次展示，否则按已保存的折叠偏好展示。
- 流式响应时序：TTFT、event count、首末观测、timeline complete 和按需 timeline 校验。
- 原始 HTTP 证据：默认折叠，显示 stage/Header/Trailer/Body hash/retention；full raw 按需预览或下载。
- UA 规则：Go RE2 正则的新增、编辑、启停和删除，持久化后热生效。
- 关键词拦截规则（[模块 22](22-content-policy.md)）：模型 RE2、动作（拦截/仅记录）、关键词逐行编辑、扫描范围复选（默认全部 7 类）；新增、编辑、启停和删除后立即生效。规则命中在访问 NewAPI 前返回本地 `400`，审计记录稳定 block code；开发者视图隐藏该入口。

登录页提供管理员令牌与开发者 API Key 两种模式。开发者视图隐藏 UA 规则入口、调用者筛选和 Token ID 筛选，header 显示身份 chip；审计列表与详情组件本身不变。前端裁剪只为体验，边界一律由服务端强制。

assistant text 使用 `react-markdown` + `remark-gfm`，不启用 raw HTML；只允许安全链接，远程图片降级为文本。其他角色、reasoning、工具参数和结果保持原始文本/JSON（内联 base64 图片的展示层占位替换除外），不因展示而改写存储值。

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

缺块 raw 使用 `X-Audit-Missing-Chunks: true` 和 `X-Audit-Complete: false` 明示：返回体仅按原顺序拼接已保存片段，不能作为完整 HTTP Body。页面和下载提示同时说明缺块。只有 full/partial 且带 `capture_chunk_missing` 标记的证据允许向前跳过缺失序号；仍验证原序号的 GCM/AAD、每块解压后长度、无重叠的偏移、观察长度边界和实际输出长度。没有该标记的 gap、错误密文、重叠或越界仍返回完整性错误。原始 seq/offset 继续保存在审计分块中，不伪造缺失字节。

## 11. 上下文洞察 API 与页面

上下文洞察（[模块 20](20-context-insights.md)）在既有鉴权和 Cookie 之上增加五个只读端点。`insights.enabled=false` 时全部返回 `404 not_found`，洞察页入口隐藏。所有响应带 `Cache-Control: no-store`；查询参数只接受下表列出的键，未知键、重复键和非法取值返回 `400 invalid_query`；单次查询沿用 10 秒超时。JSON 结构以 `internal/insights/apitypes.go` 为唯一契约，前端 `src/types.ts` 与之镜像。

| 端点 | 参数 | 返回 |
| --- | --- | --- |
| `GET /api/v1/insights/overview` | `from_ns`、`to_ns`（默认近 7 天，范围上限 400 天）、`group_by=model\|protocol\|client\|caller\|token`（默认 `model`）、`tz_offset_min`（-840 到 840，用于按本地日分桶） | 请求数、会话数、Agent 树数、归一化用量各桶、缓存命中率、实际计费（`cost_usd`、`billed_requests`、`unbilled_requests`）与 `billing_enabled`，按日序列，近 8 周热力图，构成混合，分组小计（`group_by=client` 时分组 `label` 为词表显示名），`client_labels` |
| `GET /api/v1/insights/sessions` | `from_ns`、`to_ns`、`sort=recent\|tokens\|context`、`cursor`（不透明 keyset，且绑定排序键）、`limit`（默认 20，最大 100） | 会话卡片：首末时间、步数/轮数、用量、末步构成与 prompt 总量、模型、窗口、`tree_id`、子 Agent 数、调用者；响应带 `client_labels` |
| `GET /api/v1/insights/sessions/{session_id}/trend` | 无 | 逐步序列：构成、用量、事件、时间、turn 标号；最多 2000 步，超出时返回最近一段并标记 `truncated` |
| `GET /api/v1/insights/agent-trees/{tree_id}` | 无 | Agent 树节点与边，节点带客户端声明的显示名 `name`（由该节点最新一条非附属分析的 `detail_enc` 解密读出，缺失时省略）；某节点的父指纹没有作用域内分析行时（父 Agent 不在作用域内、已过期或尚未分析）返回 `visible=false` 的占位节点。单节点根也可读取（无害）。响应带 `client_labels` |
| `GET /api/v1/audits/{audit_id}/composition` | 无 | 解密 `detail_enc`：逐条目清单、与上一步差异、文件活动、Agent 身份；经 `authorizeAudit`；响应带 `client_labels` |

`client_labels` 是客户端键到词表 `clients.<key>.label` 的映射（[模块 20](20-context-insights.md) §6），没有任何客户端设置 `label` 时整个字段省略。前端先查该映射（设置了 `label` 的客户端一律显示 `label`，包括内置键），再退回内置客户端的默认中文名，最后原样显示键名，与服务端 `group_by=client` 的分组名替换一致。

作用域：作用域由会话身份决定，**从不**取自查询参数。管理员看到全部记录；开发者会话的每条 SQL 聚合都逐行套用与审计列表相同的 `conditionWithAliases` 条件，只统计自己 Key 产生的步骤。共享会话或 Agent 树只暴露调用者自己的步骤，作用域内没有步骤的会话、树和审计一律返回 `404`（不区分“不存在”和“无权访问”）。开发者不能使用 `caller` 与 `token` 分组，会话卡片的 `caller` 为 `null`。

口径要点：

- 会话卡片的角色、末步构成和 prompt 总量取该会话**最新的 main/subagent 步骤**；压缩、标题、review 等附属请求只在会话只有附属步骤时才作为兜底。附属请求不开启新 turn，也不产生事件。
- `trees`、`tree_id` 与 `subagents` 只对**真实 Agent 树**计数：根在作用域内拥有 2 个及以上不同节点指纹，或其任一步骤带有 `agent_link_source`。没有客户端 Agent ID 的普通会话使用合成节点指纹，不算树，`tree_id` 为空。
- 成本是 NewAPI 实际计费，在查询时按 `token_links` 的 `quota / quota_per_unit` 求和（[模块 21](21-newapi-billing.md)）；趋势估算保持原始值，由前端按真实 prompt 总量锚定。

洞察页是 Dashboard 的 `insights` 视图（不引入路由）：KPI 栏、日用量柱图、8 周热力图（点击某天筛选会话）、会话卡片（构成条、用量、子 Agent 数，可排序）；点击卡片进入会话趋势（Step/Turn、Total/Delta 切换和事件标记）与 Agent 树；审计详情新增“上下文构成”一节。开发者登录同样可见，但只含自己的数据。

## 11a. 组织项目周报 API 与页面

可选的组织项目周报（[模块 23](23-org-project-reports.md)）挂在 `/api/v1/org/*`。`org_reports.enabled=false` 时所有路径对任何调用者都返回 `404 not_found`，导航入口隐藏；会话响应的 `org_reports_enabled` 告诉前端是否显示。开启后除 `GET /api/v1/org/me/weekly` 外全部是管理员端点，developer 会话一律 `403 forbidden`。所有响应带 `Cache-Control: no-store`；写入只接受一个 JSON 对象（未知字段 `400 invalid_input`，上限 64 KiB），错误映射为 `400 invalid_input`、`404 not_found`、`409 conflict`、`503 org_unavailable`，响应从不回显提交内容。

| 端点 | 说明 |
| --- | --- |
| `GET /api/v1/org/settings` | 时区、周起始、合并阈值、进入排名的客户端、异常阈值 |
| `GET /api/v1/org/catalog` | 组、项目（含规则）、成员、主体分类；`service_candidates` 列出尚未分类的 NewAPI 管理员账号 |
| `POST /api/v1/org/groups`、`PUT/DELETE /api/v1/org/groups/{id}` | `{name, enabled}`；名称大小写不敏感唯一；仍有项目或成员的组不能删除（409） |
| `POST /api/v1/org/projects`、`PUT/DELETE /api/v1/org/projects/{id}` | `{name, group_id(null=统一项目), enabled, rules:[{kind, pattern}]}`；`kind` 为 `repo_url`（规范化 remote 的通配，`*` 不跨 `/`，`**` 跨段；字面量同时比对 OpenCode 项目哈希）、`repo_name`（仓库名或路径任一段）、`path_glob`（规范化路径通配）、`agent_project`（等于 `X-Agent-Project`）；每项目最多 32 条 |
| `POST /api/v1/org/projects/preview` | `{week?, group_id, rules, project_id?}`：用草稿规则试匹配一周的去重标识，返回命中请求数、来源数、用户数，以及其中原本未归属、原本属于其他项目的请求数；不修改目录 |
| `PUT/DELETE /api/v1/org/members/{user_id}` | `{group_id}`；每个 NewAPI 用户只属于一个组 |
| `PUT/DELETE /api/v1/org/principals/{user\|token}/{id}` | `{class: human\|service}`；Token 分类优先于其用户 |
| `GET /api/v1/org/unattributed?week=&limit=` | 本周（或指定周）未归属的仓库/目录 Top N（默认 20，最大 200），按需解密后返回明文值和一条规则草稿；仅管理员 |

报告端点（加载一整周及前后各 24 小时，超时 30 秒；重新生成 2 分钟）：

| 端点 | 说明 |
| --- | --- |
| `GET /api/v1/org/weekly?week=&group_id=&metric=hours\|tokens\|cost` | 已冻结周读快照（`frozen=true`），本周与尚未冻结的周实时计算（同一目录快照下 1 分钟内复用）。`users` 是排名行（按所选指标降序，`rank` 从 1 开始），每行含项目分段、覆盖率 `coverage`、根会话数、峰值/平均并行、逐日时长、异常标记；`unresolved` 汇总无法识别调用者的请求；`service` 是服务/系统分区；`projects` 是本周出现的项目及名称；`group_id=0` 表示未分组用户 |
| `GET /api/v1/org/weekly/trend?weeks=N&group_id=` | 最近 N 周（默认 8，最大 12，含本周）每周的排名合计与按项目的时长/Token/计费 |
| `GET /api/v1/org/projects/{id}/weekly?week=` | 某项目（`-1` 未归属、`-2` 无项目上下文）的贡献者、时长与成本 |
| `POST /api/v1/org/weekly/regenerate?week=` | 按当前规则与仍在 retention 内的证据重新计算并覆盖该周快照；本周不能冻结（400） |
| `GET /api/v1/org/me/weekly` | **developer 可用**：只返回会话身份对应 NewAPI 用户本周的一行（用户 id 取自签名 Cookie，不接受任何查询参数）；管理员或身份未知时 `row=null` |

`week` 是周起始日的本地日期 `YYYY-MM-DD`（按 `org_reports.timezone`），不是周起始日返回 400；省略表示本周。目录变更沿用 `content_policy_rules` 的模式：先在内存里对候选目录整体编译校验（失败则数据库与快照都不动），再持久化，最后原子替换快照；未冻结的周因此立即按新规则重新归属。

“项目周报”页（导航在“用量洞察”之后，按需加载 recharts）：周选择器（上一周/下一周/本周）、项目组筛选、指标切换（时长/Token/计费）、已冻结或实时标记与“重新生成”；KPI（排名口径时长、Token、计费、身份覆盖率）；按项目分段堆叠的排名横向柱图与明细表（覆盖率、并行、异常标记徽标，其他客户端时长单列）；人 × 项目热力矩阵（点击列头打开项目视角：贡献者、时长与成本）；近 8 周趋势；服务/系统分区与未识别调用者汇总。developer 登录看到的是“我的本周”卡片：自己的时长、项目分布和逐日时长。

“项目组与项目”页（仅管理员、仅开启时可见，按需加载）：组与成员、主体分类（管理员账号一键标为服务）、项目与规则编辑（含“预览命中”）、项目列表、本周未归属 Top 20（“生成规则草稿”预填项目表单）。

**导航分层（2026-11-12）**：顶部主导航只放阅读类页面——审计记录、用量洞察、项目周报、会话分析；配置类页面收进管理员可见的“系统配置”一项，进入后用左侧分栏切换（窄屏时分栏变成一行，位于内容上方）：

| 分栏 | 内容 | 出现条件 |
| --- | --- | --- |
| UA 拦截规则 | 模型与 User-Agent 的拦截规则 | 始终 |
| 关键词拦截 | 请求内容的关键词规则 | 始终 |
| 项目组与项目 | 上一段所述的组、成员、项目与规则 | 开启组织周报 |
| 周报与分析 | 项目周报的时区、周起始日、合并间隔、排名客户端和标记阈值；会话分析的模型阶段是否启用、模型名、提示词版本 | 开启组织周报或会话分析 |

“周报与分析”里，会话分析的运行时间和模型阶段（地址、模型名、Key、并发、输出上限等）可以直接修改并保存，保存的值覆盖配置文件、从下一轮分析起生效，并提供“测试连接”和“恢复为配置文件的值”；可改的项、接口和生效规则见 24 §4.1。项目周报的合并间隔、排名客户端和两个标记阈值同样可以修改并保存，保存后未冻结的周立即按新值计算，已冻结的周要“重新生成”；时区和每周起始日只读（23 §3）。developer 登录看不到“系统配置”。

## 12. 最少测试

- 列表 keyset、窄筛选、User-Agent 定向解密、TTFT 映射、`conversation` 筛选、`collapse=conversation` 折叠语义及二者同时出现时的互斥优先级；`status_class` 与独立 `status_code` 筛选，以及所有行级筛选优先于折叠、较早匹配轮次可见的规则。
- 状态码草稿空白、前导零、非法字符、全角数字和 99/100/599/600 边界；查看同会话清除行级筛选并保留折叠偏好（纯函数覆盖）；字段校验提示的渲染与无障碍属性。
- 缺失首块、中间块、尾块或全部分块后，已保存片段仍可读取，metadata/HTTP Header/UI 都明确表示缺块；已知缺块不放宽 GCM、越界、重叠或未标记 gap 的校验。
- 详情逐项 Header/Trailer、Body retention/source/timeline 字段和 display name。
- verified turn 的 complex Responses 请求/响应精确重建，包括 developer、reasoning、并行工具、PNG、`file_id`、inline file data 和 usage。
- reconstructed/timeline 路由鉴权、`no-store` 和稳定错误。
- metadata raw 不可读取且 UI 不显示 raw 按钮；full raw 大 Body 内存有界。
- timeline 完整/截断语义、首末时间和 point count 校验；Body 缺块不改变已封存时间线的 complete。
- conversation 安全 Markdown、角色顺序、工具关联和未知内容展示。
- 前端 API、组件、TypeScript 检查和生产构建。
- 双角色鉴权、会话 API 三态、开发者作用域强制与管理端点 403，详见[模块 19](19-developer-key-session.md)。
- 未授权响应、静态 shell、列表和日志不泄露 Request-URI、Header、Body、conversation、Token、Key 指纹或主密钥。
- 洞察端点的 404（关闭时）、
o-store、未知/重复参数、开发者作用域逐行强制、真实树判定与附属请求口径（见 §11）。
- 关键词规则 CRUD 的鉴权、开发者 403、96 KiB 请求体上限、invalid_rule/not_found 映射与内容不回显；前端 panel 渲染、关键词行解析、扫描范围默认全选，以及 Phase 2 分类筛选/列表标签。
