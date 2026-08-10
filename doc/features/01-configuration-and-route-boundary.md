# 模块 01：配置、路由与单机边界

## 1. 目标

本文件是个人单机版配置 schema 的唯一来源。只暴露部署者真正需要的字段，writer、WAL、batch、checkpoint、连接池和 HTTP 超时使用代码内默认值。

`routes` 只定义需要审计和拦截的 LLM API 白名单。NewAPI 的健康检查、登录、管理、模型列表、前端页面及其他路径不属于本代理配置范围，必须由 Nginx 直接转发到 NewAPI。

## 2. 完整 YAML

~~~yaml
listen: 0.0.0.0:8080
admin_listen: 127.0.0.1:8081
newapi_url: http://127.0.0.1:3000
mode: available
db_path: ./data/audit.db
key_path: ./data/audit.key
admin_token: "replace-with-a-random-token"
retention_days: 30
newapi_token_db_path: ""

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
| NewAPI dial / response header | 10 s / 5 min |
| Body chunk | 32 KiB |
| writer queue / batch | 1024 ops / 64 ops 或 5 ms |
| SQLite busy timeout | 5 s |
| parser workers | 1 |
| graceful shutdown | 30 s |

新增调优项前必须先有基准或故障测试证明需要。

## 4. 校验

启动与 validate-config 共用以下检查：

1. listen 与 admin_listen 合法且不相同。
2. newapi_url 只有 http/https scheme、host、可选端口；禁止 userinfo、path、query、fragment。
3. mode 只能是 available 或 strict。
4. db_path、key_path 非空，父目录可创建。
5. retention_days 为 0 或 1–3650；0 表示禁用自动清理。
6. admin_token 在任何 admin_listen 下都必须非空；监听非 loopback 时还必须由部署者提供 TLS 或可信反代。
7. newapi_token_db_path 为空表示关闭 Token 名称关联；非空时只做只读访问。
8. interceptor id 唯一，type 已注册，type-specific config 可解析；未知 type 启动失败。
9. route id 唯一，method/path/parser 非空，引用的 interceptor 必须存在。
10. match 只能是 exact 或 template，规则不得重叠。

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
}
~~~

匹配输入使用 Request.URL.EscapedPath；Query 不参与。错误 Method、尾随斜杠、encoded slash、反斜杠和 dot segment 默认拒绝。

## 6. 非白名单

Nginx 是第一层白名单，只有 `routes` 中的 LLM API 路径进入代理；NewAPI 的健康检查、登录、管理、模型列表、前端页面及其他路径直接到 NewAPI，不审计也不拦截。代理仍做第二层校验：

- 命中：建立 audit，执行该 route 的 interceptor chain，通过后转发。
- 未命中：返回 404，不创建 audit_records。
- 响应不回显 Query、Header 或 token。

~~~json
{"error":{"code":"audit_route_not_allowed","message":"route is not enabled"}}
~~~

## 7. NewAPI Rewrite

整个进程只有一个 newapi_url：

- Scheme、URL.Host 和出站 Host 来自 newapi_url。
- Path、RawPath、RawQuery、ForceQuery 来自入站请求。
- 不修改 Method、Body、ContentLength、TransferEncoding 或认证 Header。
- 请求不能通过 Header、Query 或 route 选择其他后端。

首版不提供 preserve/explicit Host 模式。

## 8. 入站拦截边界

只有 Matcher 命中的 LLM API 请求才执行有序 interceptor chain。Matcher 命中后、ReverseProxy 接触 NewAPI 前运行；首个 reject 立即返回，不再运行后续模块，也不创建 request_sent_to_newapi 或响应阶段。健康检查、登录、管理、模型列表、前端页面及其他 NewAPI 请求不应到达本进程，误直连代理时仍按非白名单返回 404，且不创建 audit。

metadata interceptor 只读取克隆后的 Method、Path、Query、Header、ContentLength 和 route 参数，不读取或修改 Body。body interceptor 必须显式声明上限；引擎只预读一次，超过上限在调用 NewAPI 前返回 `413` 和 `block_code=body_too_large`，允许时用原始字节重新构造 Body。未配置 body interceptor 的路由保持原有流式行为。

模块 panic 或返回 error 时统一 fail-closed 为 503，与 available/strict 无关。完整接口和扩展步骤见[模块 17](17-request-interceptor-chain.md)。

## 9. Key 与模式

key_path 指向 32-byte 主密钥：存在则读取；不存在且数据库尚无审计数据时用 crypto/rand 原子生成。Unix 创建权限设为 0600；Windows 依赖 key 所在目录的当前用户 ACL，并在文档中明确要求使用私有数据目录。key 内容不写日志或数据库。

服务可先启动 listener，再检查审计依赖。

available：key/DB 不健康时仍转发，写结构化日志；DB 恢复后 best-effort 写 audit_gaps，不伪造完整 audit。

strict：每个白名单请求访问 NewAPI 前检查 key、DB、writer 和 writer queue，并同步提交 BeginAudit；失败返回 503。parser queue 不参与 admission。两种模式都不保证突然退出时零缺口。

## 10. 管理面

admin_listen 默认 127.0.0.1:8081，提供 health、audit 列表/详情、原始读取、单条删除、同步导出和可选 metrics。无论监听地址是否 loopback，所有管理 API 都必须校验 admin_token。静态 UI shell 不返回数据，可以先加载并让用户输入 token。管理面不进入公开 NewAPI server。

## 11. 测试

- 默认七条 route 与相邻负例。
- 错误 Method、尾随斜杠、encoded slash。
- unknown YAML、重复 id、重叠模板。
- newapi_url 带 path/query/userinfo。
- available DB 失败仍转发。
- strict key/DB 不健康返回 503，Fake NewAPI 未收到请求。
- loopback 和非 loopback 的管理 API 在无 token/错误 token 时均返回 401。
- interceptor 顺序、首个 reject 短路、模块异常 fail-closed，且 Fake NewAPI 未收到被拦截请求。
- 未启用 body interceptor 时保持流式；启用后允许请求的 replay Body 与原字节一致。
- health、登录、管理、模型列表和前端页面不进入代理，不产生 audit 或 interceptor 调用。
- Body 超限固定返回 `413`，审计记录 `block_code=body_too_large`。
