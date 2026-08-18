# 模块 19：开发者 API Key 会话

## 1. 目标与范围

管理面提供第二种身份：NewAPI 用户提交自己的 API Key 登录，只读取该 Key 产生的审计记录，用于审计 agent 调用链并优化 agentic 架构。

管理员身份、数据面字节路径、passthrough、interceptor 放行结论和既有 Cookie 格式都不改变。本模块不引入用户账户、多租户、配额展示或写操作。

## 2. 凭据指纹

`security.NormalizeNewAPIKey` 逐字复刻 NewAPI `TokenAuthReadOnly` 的规约：去 `Bearer ` 前缀、去 `sk-` 前缀、取首个 `-` 之前的片段。NewAPI 把 `sk-abc-suffix` 与 `sk-abc` 视为同一 token，指纹必须建立在同一规约上，否则同一把 Key 的不同写法会互相看不见。

`security.ExtractCredential` 枚举全部入站凭据传输方式（`Authorization` Bearer 或裸值、`X-Api-Key`、`X-Goog-Api-Key`、query `key`），与 `require_credential` 拦截器共用同一份传输清单。两者语义不同：拦截器要求 `Authorization` 必须是 Bearer 方案，指纹提取额外接受裸值，因为 NewAPI 接受裸值。

`security.CredentialFingerprinter` 用 HMAC-SHA-256(主密钥, `llmapi-logger/credential-fingerprint-key/v1\x00`) 派生子密钥，镜像 `IntegritySigner`。指纹是 keyed 标签：无主密钥不可验证、不可反查，永不出现在任何 API 响应、日志或错误文本中。

## 3. 捕获与存储

`audit.Manager.Begin` 在 interceptor 之前、构造 `AuditRecord` 时计算指纹，写入 `audit_records.api_key_fpr`（32 字节，无凭据时为 NULL）。因此被拦截的请求同样带指纹。未装载主密钥时指纹器为 nil，全部写 NULL，行为与本模块引入前一致。

`006_developer_key_fingerprint.sql` 用 `ALTER TABLE` 增列并建部分索引。

**硬性约束**：`api_key_fpr` 不得进入 `capturePayloadDigest`。它是访问控制索引而非证据；一旦加入完整性摘要，旧库中每条历史记录的重算摘要都会改变，启动时的链校验会失败并锁死进程。代价是作用域归属不具备防篡改性，被捕获的字节仍然具备 —— 这一取舍由 `TestAPIKeyFingerprintStaysOutsideTheEvidenceChain` 锁定。

## 4. 登录

~~~yaml
developer_login:
  enabled: false
~~~

默认关闭。启用后 `POST /api/v1/session` 接受 `{"api_key": "sk-…"}`（与 `token` 二选一，多给或都不给返回 400）。

服务端以该 Key 为凭据调用 NewAPI：

~~~http
GET {newapi.url}/api/log/token
Authorization: Bearer <用户 API Key>
Accept: application/json
~~~

该端点由 NewAPI 的 `TokenAuthReadOnly` 保护：只拒绝不存在/被禁用的 token 与被封禁用户，**不校验过期与配额**。这正是本项目需要的语义 —— Key 过期或额度耗尽后仍可审计它做过什么。响应 `data` 是扁平日志数组，所有项的用户与 Token 所有权必须一致；空数组表示 Key 有效但尚未使用，会话退化为纯指纹作用域。

登录不复用 `newapi.access_token`/`user_id`，与管理集成互相独立。Key 只作为这一次上游请求的凭据，不落库、不写日志、不回显。

错误分级：`enabled=false` → 403 `developer_login_disabled`；Key 被拒 → 401；NewAPI 不可达或异常 → 502 `newapi_unavailable`。

`POST /api/v1/session` 按来源地址做失败限流（5 分钟 10 次 → 429 + `Retry-After`），管理员与开发者两条路径共用；登录成功清零计数。

## 5. 会话

沿用无服务端状态的签名 Cookie，同名 `llmapi_logger_session`、同 7 天寿命、HttpOnly、SameSite=Strict、Secure-on-TLS。

- 管理员：`v1.<expiresUnix>.<mac>`，格式与密钥完全不变，既有 Cookie 继续有效。
- 开发者：`v2.<expiresUnix>.<b64url(payload)>.<mac>`，payload 为紧凑 JSON `{fpr, tid?, uid?, usr?, tkn?}`，MAC 覆盖前三段。

两者密钥都由 `admin_token` 派生但域串不同（`admin-session` / `developer-session`），跨角色签名互不通过。轮换 `admin_token` 会一次性作废全部会话。`developer_login` 关闭后，已签发的 v2 Cookie 立即失效，而不只是隐藏登录入口。

`GET /api/v1/session` 返回当前身份（`role`、`expires_at`、开发者的展示身份），供前端启动引导；无有效会话返回 401。响应不含指纹。

## 6. 作用域

开发者会话的读取范围由两个条件共同构成，二者在同一段代码内产生，不得分开施加：

~~~sql
-- 归属
(a.api_key_fpr = ? OR t.newapi_token_id = ?)
-- 策略拦截排除
AND (a.forward_status <> 'rejected' OR a.block_code IN (<允许清单>))
~~~

`token_links.newapi_token_id` 是历史兜底：本模块之前捕获、由[模块 11](11-newapi-request-identity.md) 关联的记录没有指纹。未解析出 token 的会话只按指纹匹配，不会退化成匹配所有未关联记录。

**策略拦截排除取 fail-closed 允许清单**：默认隐藏全部 `forward_status='rejected'` 的本地拦截记录，只放行显式列出的非策略 block code（当前仅 `body_too_large`）。理由：`blocked_by`/`block_code` 描述的是站点防护策略本身，若改成"隐藏 401"式黑名单，将来任何以其他状态阻断的策略型拦截器都会默认泄漏。`user_agent_not_allowed`、`credential_required` 与三个 `interceptor_*` 框架异常码因此都不可见。

NewAPI 上游自己返回的 401/403（Key 过期、分组无权限、额度耗尽）**可见** —— 那是开发者自己调用链的真实上游响应，`forward_status` 为 `completed` 而非 `rejected`，不涉及本地防护策略。

SQL 条件与 Go 侧 `AuditScope.Allows` 是同一规则的两种渲染，由 `TestScopeSQLAndPredicateAgreeAcrossVisibilityMatrix` 用同一组记录交叉验证。

## 7. 接口边界

开发者可读：`GET /api/v1/audits` 及 `/api/v1/audits/{id}` 的 detail、`raw/{side}`、`reconstructed/{side}`、`timeline/{side}`，深度与管理员一致（解密 Header、Request-URI、conversation 重建、重建 JSON、时序、留存的 raw 证据）。

管理员专属，开发者返回 403 `forbidden`：`/healthz`、`/readyz`、`/metrics`、`/api/v1/newapi/callers`、`/api/v1/user-agent-rules*`。

作用域在 `parseListQuery` 之后由服务端注入，任何 query string 都无法触及或替换它。开发者显式携带 `newapi_user_id`、`username`、`newapi_token_id`、`token_name` 返回 400 `invalid_query`，而不是静默覆盖。

detail 系列在 `serveAuditResource` 有唯一一处授权闸门（`query.Service.Authorize`），四个子端点不会各自漂移。不属于自己或命中策略拦截排除的 audit 与不存在的 audit 一律返回 404，不提供存在性预言。

## 8. React UI

登录页提供「管理员令牌 / 开发者 API Key」双模式切换，两个输入都是密码框，仍不写 localStorage/sessionStorage。启动时调用 `GET /api/v1/session` 判定身份与角色，替代原先"乐观渲染 + 首次列表 401 探测"。

开发者视图隐藏 UA 规则入口、调用者筛选下拉、NewAPI Token ID 筛选，header 显示身份 chip（token 名或用户名）。审计列表与详情组件本身不变。前端裁剪只为体验，边界一律由服务端强制。

## 9. 最少测试

- 归一化：`sk-abc`、`sk-abc-suffix`、`Bearer sk-abc`、裸 `abc` 归一到同一指纹；`Bearer ` 归一为空。
- `HasCredential` 保持拦截器既有语义（`Authorization` 必须 Bearer），不因共用传输清单而放宽。
- 四种传输方式落同一指纹；无凭据与未装载指纹器写 NULL。
- 旧库应用 006 后完整性链仍然通过；改写 `api_key_fpr` 不影响链校验。
- 可见性矩阵：策略 401 不可见、`body_too_large` 可见、上游 401 可见、未知 block code 默认不可见；管理员对以上全部可见。
- SQL 条件与 `Allows` 在同一矩阵上结论一致。
- `ValidateTokenKey` 的有效/空数组/401 拒绝/不可达/超大响应/所有者冲突六态。
- v2 Cookie 往返、篡改、过期、跨角色伪造；`developer_login` 关闭后 v2 Cookie 失效。
- 角色门禁矩阵；作用域强制注入；调用者筛选 400；非归属 detail/raw/reconstructed/timeline 404。
- 登录限流 429 + `Retry-After`，成功登录清零。
- 端到端：两把 Key 各自只看到自己的记录，管理员看到全部，跨租户详情 404，管理端点 403。
