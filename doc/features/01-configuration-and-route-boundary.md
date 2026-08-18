# 模块 01：配置、路由与单机边界

## 1. 目标

本文件是个人单机版配置 schema 的唯一来源。只暴露部署者真正需要的字段，writer、WAL、batch、checkpoint、连接池和 HTTP 超时使用代码内默认值。

`routes` 只定义需要审计和拦截的 LLM API 白名单，不用于枚举 NewAPI 的全部接口。进入数据端口的安全非 LLM 请求由 passthrough 透明转发；受保护 LLM 路径族和危险路径不能进入 passthrough。

## 2. 完整 YAML

~~~yaml
listen: 0.0.0.0:8080
admin_listen: 127.0.0.1:8081
newapi:
  url: http://127.0.0.1:3000
  proxy_url: ""
  response_header_timeout_seconds: 300
  preserve_host: false
  access_token: ""
  user_id: 0
mode: available
db_path: ./data/audit.db
key_path: ./data/audit.key
admin_token: "replace-with-a-random-token"
developer_login:
  enabled: false
shutdown_timeout_seconds: 30
retention_days: 30

interceptors:
  require-client-credential:
    type: require_credential
  optional-body-limit:
    type: max_body_bytes
    config:
      max_bytes: 2097152

routes:
  - {id: openai-chat-completions, method: POST, path: /v1/chat/completions, match: exact, parser: openai.chat_completions, interceptors: [require-client-credential]}
  - {id: openai-completions, method: POST, path: /v1/completions, match: exact, parser: openai.completions, interceptors: [require-client-credential]}
  - {id: openai-responses, method: POST, path: /v1/responses, match: exact, parser: openai.responses, interceptors: [require-client-credential]}
  - {id: openai-responses-compact, method: POST, path: /v1/responses/compact, match: exact, parser: openai.responses_compact, interceptors: [require-client-credential]}
  - {id: anthropic-messages, method: POST, path: /v1/messages, match: exact, parser: anthropic.messages, interceptors: [require-client-credential]}
  - id: gemini-generate-content
    method: POST
    path: /v1beta/models/{model}:generateContent
    match: template
    parser: gemini.generate_content
    interceptors: [require-client-credential]
  - id: gemini-stream-generate-content
    method: POST
    path: /v1beta/models/{model}:streamGenerateContent
    match: template
    parser: gemini.stream_generate_content
    interceptors: [require-client-credential]
~~~

主配置由 --config 指定。YAML decoder 拒绝未知字段；个人部署不提供逐字段环境变量覆盖。

## 3. 固定内部默认值

| 项目 | 默认值 |
| --- | --- |
| read header / idle timeout | 10 s / 120 s |
| NewAPI dial | 10 s |
| NewAPI response header | 300 s，可配置 1–86400 s |
| 审计 Body 聚合块 | 约 1 MiB，自适应压缩后独立加密 |
| writer queue / batch | 1024 ops / 64 ops 或 5 ms |
| SQLite busy timeout | 5 s |
| parser workers | 1 |
| NewAPI 管理请求 / 用户目录刷新 | 10 s / 5 min |
| graceful shutdown | 30 s，可配置 1–86400 s |

新增调优项前必须先有基准或故障测试证明需要。

## 4. 校验

启动与 validate-config 共用以下检查：

1. listen 与 admin_listen 合法且不相同。
2. `newapi.url` 只有 http/https scheme、host、可选端口；禁止 userinfo、path、query、fragment。
3. `newapi.proxy_url` 为空表示直接连接；非空时必须是绝对 `http://host[:port]` 或 `https://host[:port]`，禁止前后空白、userinfo、任何 path（包括 `/`）、query 和 fragment，端口必须合法。
4. `newapi.response_header_timeout_seconds` 为 1–86400；默认 300 秒。
5. `newapi.access_token` 与 `newapi.user_id` 成对可选：前者为空时后者必须为 0；前者非空时不能包含空白，且 user_id 必须为正整数。
6. mode 只能是 available 或 strict。
7. db_path、key_path 非空，父目录可创建。
8. `shutdown_timeout_seconds` 为 1–86400；默认 30 秒。
9. retention_days 为 0 或 1–3650；0 表示禁用自动清理。
10. admin_token 在任何 admin_listen 下都必须非空且不能包含空白字符；监听非 loopback 时还必须由部署者提供 TLS 或可信反代。
11. `developer_login.enabled` 默认 false。启用后开发者用 NewAPI 用户 API Key 登录并只读取自己 Key 的记录（[模块 19](19-developer-key-session.md)）；它只依赖已必填的 `newapi.url`，不需要 `newapi.access_token`/`user_id`。主密钥不可用时该登录自动保持关闭。
12. interceptor id 唯一，type 已注册，type-specific config 可解析；未知 type 启动失败。
13. route id 唯一，method/path/parser 非空，引用的 interceptor 必须存在。
14. match 只能是 exact 或 template，规则不得重叠。

validate-config 只检查配置，不要求 DB 或 NewAPI 在线。

## 5. Matcher

exact 要求 Method 和 Path 完全相同。template 首版只支持一个完整 {model} segment，字符集固定为 [A-Za-z0-9._-]+，不得跨斜杠。不支持任意正则、prefix、星号或 catch-all。

~~~go
type RouteMatch struct {
    RouteID    string
    Parser     string
    Interceptors []string
    PathParams map[string]string
}

type Matcher interface {
    Match(method, escapedPath string) (RouteMatch, bool)
    AllowsPassthrough(escapedPath string) bool
}
~~~

匹配输入使用 Request.URL.EscapedPath；Query 不参与。Matcher 同时维护“可审计 route”和“受保护路径族”：

- exact route 的规范路径及其后代均受保护，Method 不参与 passthrough 放行判断。
- template route 的固定前缀家族受保护；例如配置 `/v1beta/models/{model}:generateContent` 后，同一前缀下未配置的动作也不会直通。
- percent-encoded 和有限层数的重复编码等价路径按解码后的形式判断，不能通过编码改写逃逸。
- 尾随斜杠、重复斜杠、反斜杠、encoded slash/backslash、dot segment、非法 escape 等非规范路径全局 fail-closed。

## 6. 三态数据面分发

Nginx 示例把全部 NewAPI 数据面请求交给本进程，分发器按以下顺序判断：

1. `Match(method, escapedPath)` 命中：建立 audit，执行该 route 的 interceptor chain，通过后走审计代理。
2. 未命中且 `AllowsPassthrough(escapedPath)` 为 true：走无审计 passthrough，透明转发 Method、Path、Query、Header 和 Body，不执行 interceptor、不创建 audit_records。
3. 其余情况：交给受限代理返回固定 404，不访问 NewAPI，不创建 audit_records。

第二类仅用于真正无关且路径规范的 NewAPI 请求，例如 `GET /v1/models`、登录、管理、健康检查或 NewAPI 前端资源。配置路径的错误 Method、exact 子路径、template 家族、编码等价形式和危险路径属于第三类。错误响应不回显 Query、Header 或 token。

~~~json
{"error":{"code":"audit_route_not_allowed","message":"route is not enabled"}}
~~~

## 7. NewAPI Rewrite 与显式代理

整个进程只有一个 `newapi.url`，以及一个可选的 `newapi.proxy_url`：

- Scheme 与 URL.Host 来自 `newapi.url`。出站 Host 默认也来自该 URL；`newapi.preserve_host: true` 时改为保留入站 Host。
- Path、RawPath、RawQuery、ForceQuery 来自入站请求。
- 不修改 Method、Body、ContentLength、TransferEncoding 或认证 Header。
- 请求不能通过 Header、Query 或 route 选择其他后端。
- 审计代理和 passthrough 共享同一套 Rewrite 和 Transport 参数。
- `newapi.response_header_timeout_seconds` 同时应用于两个分支，限制等待上游响应头/流式首包的时间。
- `newapi.proxy_url` 只控制本程序到 `newapi.url` 的 Transport；它不改变目标 URL、Host、审计阶段或路由边界。
- `newapi.proxy_url` 为空时固定直连，不读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`；非空时所有 NewAPI 请求都经过该显式 HTTP(S) 代理，HTTPS 目标使用标准 CONNECT。

`newapi.access_token` 与 `newapi.user_id` 配置后，程序使用同一 `newapi.url` 和显式代理执行两类只读管理请求：每五分钟同步全站用户的安全字段，以及按 LLM 响应中的 `X-Oneapi-Request-Id` 查询全站日志并回填调用者身份。失败只记录安全 warning，不影响审计代理、passthrough 或已完成的响应。该管理凭证不参与客户端 LLM 请求鉴权，也不得返回到管理 API、数据库或日志。两项都留空/0 时完全关闭 NewAPI 调用者识别。

`newapi.preserve_host` 只改变出站 Host，不改变连接目标；可信边缘建立的 `X-Forwarded-Host`、`X-Forwarded-Port` 与其他 `X-Forwarded-*` 一并透传。首版不提供任意 explicit Host 值、SOCKS/PAC 或带凭据的代理 URL。

## 8. 入站拦截边界

只有 Matcher 命中的 LLM API 请求才执行有序 interceptor chain。Matcher 命中后、ReverseProxy 接触 NewAPI 前运行；首个 reject 立即返回，不再运行后续模块，也不创建 request_sent_to_newapi 或响应阶段。passthrough 请求完全绕过 interceptor 和 audit；interceptor 配置不能扩大 route 或把受保护路径改为直通。

metadata interceptor 只读取克隆后的 Method、Path、Query、Header、ContentLength 和 route 参数，不读取或修改 Body。body interceptor 必须显式声明上限；引擎只预读一次，超过上限在调用 NewAPI 前返回 `413` 和 `block_code=body_too_large`，允许时用原始字节重新构造 Body。未配置 body interceptor 的路由保持原有流式行为。

模块 panic 或返回 error 时统一 fail-closed 为 503，与 available/strict 无关。完整接口和扩展步骤见[模块 17](17-request-interceptor-chain.md)。

## 9. Key 与模式

key_path 指向 32-byte 主密钥：存在则读取；不存在且数据库尚无审计数据时用 crypto/rand 原子生成。Unix 创建权限设为 0600；Windows 依赖 key 所在目录的当前用户 ACL，并在文档中明确要求使用私有数据目录。key 内容不写日志或数据库。

服务可先启动 listener，再检查审计依赖。

available：key/DB 不健康时仍转发，写结构化日志；DB 恢复后 best-effort 写 audit_gaps，不伪造完整 audit。

strict：每个白名单请求访问 NewAPI 前检查 key、DB、writer 和 writer queue，并同步提交 BeginAudit；失败返回 503。parser queue 不参与 admission。两种模式都不保证突然退出时零缺口。

## 10. 管理面

admin_listen 默认 127.0.0.1:8081，提供 health、ready、audit 列表/详情、verified reconstructed JSON、SSE timeline 和异常 raw Body。无论监听地址是否 loopback，所有管理 API 都必须鉴权。CLI 使用静态 Bearer token；Web UI 登录成功后使用七天过期的 HttpOnly Cookie。启用 `developer_login` 后另有一种身份：NewAPI 用户提交自己的 API Key 登录，只读取该 Key 产生的记录，且不能访问 health、ready、调用者目录与 UA 规则（[模块 19](19-developer-key-session.md)）。普通列表只额外解密入站 User-Agent，用于展示和筛选；其他 Header、Request-URI、Body 与 conversation 不进入列表。详情会解密 Request-URI 和逐项 Header/Trailer 值；raw request/response Body 只对 `retention_state=full` 按需读取，metadata 使用 reconstructed API。静态 UI shell 不返回数据，可以先加载并让用户输入 token。管理面不进入公开 NewAPI server。

## 11. 测试

- 默认七条 route、`/v1/models` 等安全 passthrough 和相邻负例。
- 错误 Method、exact 子路径、template 家族未配置动作、percent/double encoding、尾随/重复斜杠、反斜杠、encoded slash 和 dot segment 均 fail-closed，Fake NewAPI 零调用。
- unknown YAML、重复 id、重叠模板。
- `newapi.url` 带 path/query/userinfo。
- `newapi.proxy_url` 的空值直连、合法 HTTP(S) 代理，以及 userinfo/path/query/fragment/非法端口负例。
- `newapi.access_token`/`newapi.user_id` 成对校验；关闭时不创建管理客户端，启用时只能读取安全用户目录和精确 request-id 日志。
- 环境中设置 `HTTP_PROXY`/`HTTPS_PROXY` 时，空 `newapi.proxy_url` 仍直连；显式配置时 Fake NewAPI 只能通过 Fake Proxy 收到请求。
- available DB 失败仍转发。
- strict key/DB 不健康返回 503，Fake NewAPI 未收到请求。
- loopback 和非 loopback 的管理 API 在无 token/错误 token 时均返回 401。
- interceptor 顺序、首个 reject 短路、模块异常 fail-closed，且 Fake NewAPI 未收到被拦截请求。
- 未启用 body interceptor 时保持流式；启用后允许请求的 replay Body 与原字节一致。
- health、登录、管理、模型列表和前端页面通过 passthrough 到达 NewAPI，不产生 audit 或 interceptor 调用。
- Body 超限固定返回 `413`，审计记录 `block_code=body_too_large`。
