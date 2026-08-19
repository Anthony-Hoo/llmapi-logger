# 模块 02：透明 HTTP 代理

## 1. 目标

使用 net/http/httputil.ReverseProxy 把数据面请求转发到唯一 NewAPI。进程内 dispatcher 先分流：配置的 LLM API route 使用审计代理；安全且无关的 NewAPI 路径使用无审计 passthrough；受保护或危险的未匹配路径返回 404。只有被放行并实际转发的 LLM route 最多产生四阶段事件：

1. request_for_newapi_received_from_nginx
2. request_sent_to_newapi
3. response_received_from_newapi
4. response_from_newapi_sent_to_nginx

透明指应用层 HTTP 语义和 Body 字节尽量不变，不代表 wire-level 抓包保真。阶段按实际触发惰性创建；拦截链在 NewAPI 前拒绝时，不创建尚未触发的 NewAPI 与响应阶段。

`GET /v1/models`、NewAPI health/login/admin/UI 等真正非 LLM 请求即使进入本程序，也会透明 passthrough，不执行 interceptor、不创建 audit。配置路径的错误 Method、exact 子路径、template 家族未配置动作、编码等价形式和危险路径不属于 passthrough，固定 fail-closed。

## 2. 包与组件

~~~text
internal/routing/
internal/interceptor/
internal/proxy/
internal/audit/
internal/app/data_plane.go
~~~

app 的 data-plane handler 只负责三态分发。proxy 提供 audited handler 和 passthrough handler；两者共享 Rewrite、Transport、BufferPool、SSE flush 和错误处理，只有 audited handler 依赖 routing、interceptor 与 audit 接口。proxy 不执行 SQL，不调用协议 parser。默认路径不完整缓冲 Body；只有 LLM route 显式启用 body interceptor 时，才允许按模块声明的上限预读一次。

从 http.DefaultTransport.Clone 创建 Transport。`newapi.proxy_url` 为空时固定 `Proxy=nil`；非空时使用解析后的显式 HTTP(S) proxy URL。两种情况都不使用 ProxyFromEnvironment。其余固定 DisableCompression=true、ForceAttemptHTTP2=true、MaxIdleConns=128、MaxIdleConnsPerHost=64；ResponseHeaderTimeout 来自 `newapi.response_header_timeout_seconds`，默认 300 秒。

ReverseProxy 固定 Rewrite、Transport、ModifyResponse、ErrorHandler、32 KiB 传输 BufferPool 和 FlushInterval=-1；该 BufferPool 与审计落库的约 1 MiB 聚合块不是同一概念。禁止 httputil.DumpRequest、DumpResponse，以及对未限长 Body 直接使用 io.ReadAll；body interceptor 只能通过统一 helper 读取 `limit+1` 的有界数据。

## 3. Rewrite

按顺序执行：

1. Scheme 与 URL.Host 设置为配置的 `newapi.url`；Out.Host 默认使用上游 Host，`preserve_host=true` 时保留入站 Host。
2. Path、RawPath、RawQuery、ForceQuery 从入站请求原样复制。
3. 不修改 Method、Body、ContentLength、TransferEncoding 或认证 Header。
4. 不调用 ParseForm 或 url.Values.Encode。
5. hop-by-hop Header 交给 ReverseProxy 处理。

显式代理只改变 Transport 建立到 `newapi.url` 的网络路径，不参与 Rewrite，也不能扩大 LLM API 白名单或 passthrough 范围。`newapi.url` 为 HTTPS 时由 Transport 通过 HTTP(S) 代理执行 CONNECT，目标 Scheme、Host、Path、Query 和请求 Body 仍遵循上述规则。

Nginx 应覆盖 X-Real-IP、X-Forwarded-For、X-Forwarded-Proto、X-Forwarded-Host、X-Forwarded-Port。代理只把它们当普通加密证据，不用于鉴权。

## 4. 入站 interceptor chain

Matcher 命中 route 且审计 Begin 完成或按 available 规则降级后，proxy 在 Rewrite 和任何 NewAPI I/O 之前，按 route 配置顺序执行 interceptor chain。模块由编译进二进制的 registry 创建；它只能返回放行或拒绝结论，不能改写请求、选择其他上游、直接写 ResponseWriter 或访问 SQLite。

~~~go
type Requirements struct {
    NeedsBody    bool
    MaxBodyBytes int64
}
type Interceptor interface {
    Requirements() Requirements
    Check(context.Context, RequestView) (Decision, error)
}
type Decision struct {
    Allow      bool
    StatusCode int
    BlockCode  string
}
~~~

chain entry 另外保存配置中的 interceptor id，并把它作为审计字段 blocked_by。RequestView 是只读快照：metadata 模块只能看到 Method、EscapedPath、Query、Header、Host、ContentLength、route id 和 path params，完全拿不到 Body handle；模块不得保留 RequestView、启动后台 goroutine，或访问网络、数据库、文件和子进程。

Body 规则固定如下：

1. 未配置 body interceptor 时不预读，ReverseProxy 保持原有流式读取。
2. body 模块必须声明 1–512 MiB 的 MaxBodyBytes。chain 编译时计算该 route 的最大上限；执行到第一个 body 模块时，已知 ContentLength 超过 routeMax 会直接拒绝，否则入站审计 wrapper 使用 `io.LimitReader(routeMax+1)` 有界读到 EOF。
3. 原始字节只缓存一次并通过只提供 Len/Open 的 BodyView 共享。执行每个 body 模块前检查其自身上限；超过时返回 413，blocked_by 为该模块 id，block_code 固定为 `body_too_large`，不调用模块或 NewAPI。
4. 全部模块放行后，关闭原始 Body，并用缓存的原始字节重建 ReadCloser；Method、Header、ContentLength、TransferEncoding、Trailer 和字节顺序不变。模块看到的解析结果或副本不得替代这份 replay 数据。
5. Body 读取失败时 fail-closed，不能把已读前缀发送给 NewAPI；如果是请求 context 已取消，则按客户端取消结束，不再尝试写 503 JSON。

有效 allow 必须是 Allow=true 且 StatusCode/BlockCode 为空；有效 reject 必须是 Allow=false、StatusCode 在 400–499 且 BlockCode 非空。第一个 reject 立即短路，后续模块不执行。模块直接使用请求 context，首版不另设每模块超时；调用边界只做 recover。error、panic 或非法 Decision 分别归一为 `interceptor_error`、`interceptor_panic`、`interceptor_invalid_decision`，非客户端取消的 Body 读取失败使用 `interceptor_body_read_error`。这些场景统一返回 503，且对 available 与 strict 完全相同。

主动 reject 中的 `401` 固定返回通用 `unauthorized` JSON，其他 4xx（含 Body 超限 `413`）固定返回 `request_rejected` JSON，执行异常固定返回 `interceptor_unavailable` JSON；响应不回显 interceptor id、BlockCode、模块错误、Header、Query 或 Body。审计可用时仍以 forward_status=rejected、blocked_by、block_code、status_code 和 parse_status=skipped 结束；request_sent_to_newapi、response_received_from_newapi、response_from_newapi_sent_to_nginx 均不创建。

## 5. 审计接口

~~~go
type Sink interface {
    Healthy() bool
    Begin(context.Context, BeginInput) (Exchange, error)
}
type Exchange interface {
    StartStage(Stage, StageMeta)
    Headers(Stage, http.Header)
    OpenBody(Stage) BodyObserver
    Trailers(Stage, http.Header)
    Finish(FinishResult)
}
type BodyObserver interface {
    Observe([]byte) error
    Close(err error, eof bool)
}
~~~

Observe 必须复制异步持有的数据；返回后 proxy 可以立即复用底层 buffer。

## 6. 请求流程

1. Matcher 检查 Method + EscapedPath。
2. 精确命中 route 时进入 audited handler；未命中且路径可安全直通时进入 passthrough；其余进入 audited handler 的固定 404 分支。
3. passthrough 直接执行公共 Rewrite 和 RoundTripper，不创建 audit、执行 interceptor 或写 LLM 请求完成日志。
4. audited route 在 strict 下检查 Sink.Healthy 并同步 Begin，失败返回 503；available Begin 失败时写 gap 日志并继续。
5. 创建 request_for_newapi_received_from_nginx，保存入站 metadata/Header，并安装入站 Body wrapper。
6. 执行 route 的 interceptor chain。metadata-only 链不触碰 Body；body 链按第 4 节有界预读并准备原字节 replay。
7. 首个 reject、body 超限、error、panic、非法 Decision 或 Body 读取失败立即关闭入站 Body、写本地错误响应并 Finish；NewAPI Transport 不得被调用，后续三个阶段不得创建。客户端取消则直接结束。
8. 全部放行后执行 Rewrite，包装出站 Body 并开始 request_sent_to_newapi。
9. RoundTripper 请求 NewAPI；响应到达后依次记录 response_received_from_newapi 和 response_from_newapi_sent_to_nginx，最后保存 Trailer 与终态。

audit_id 用 crypto/rand 生成。ID 失败时 available 可继续但只写无 ID 日志，strict 返回 503；禁止回退到时间戳或 math/rand。

## 7. Body wrapper

ReadCloser 规则：

- 先调用底层 Read。
- n>0 时记录 p[:n]；n 与 EOF/error 同时出现也先记录。
- Close 只调用一次并原样返回错误。
- 不改变 ContentLength，不为 NoBody 安装 wrapper。
- 请求允许双 wrapper，因为入站读取和 Transport 读取是不同观察点。
- body interceptor 的有界预读必须经过入站 wrapper；放行后的原字节 replay 再经过出站 wrapper。两阶段应得到相同 length/hash。
- metadata reject 不为记录证据而额外 drain Body；关闭未读 Body，并按模块 03 的完整性规则结束入站阶段。

每个 observer 同步更新 length/hash，并把字节聚合到约 1 MiB 后自适应压缩、独立加密，再提交 owning chunk。四阶段先各自采集；只有终结事务确认成对阶段的完整长度和 SHA-256 完全一致时，才删除后一阶段的重复 chunks 并通过 `source_stage` 复用前一阶段。短写或字节不一致会保留各自 chunks，并以 `body_stage_mismatch`/partial 进入异常证据路径。

## 8. ResponseWriter

wrapper 只实现 Header、WriteHeader、Write、Unwrap。Write 先调用底层，再仅记录成功的 p[:n]，原样返回 n/error。未显式 WriteHeader 时记录隐式 200。

Unwrap 返回真实 writer，使 http.ResponseController 能发现 Flusher。不要匿名嵌入底层 writer，避免可选接口绕过 Write。

## 9. SSE、错误与取消

FlushInterval=-1，wrapper 保持 Flush；原始 chunk 不是 SSE event，parser 只能异步拼接。默认不设置 WriteTimeout，关闭服务时使用 `shutdown_timeout_seconds` 控制的 graceful shutdown，默认 30 秒。

| 场景 | 行为 |
| --- | --- |
| 安全且与 LLM 受保护路径族无关的非白名单 | 透明 passthrough，不审计、不拦截 |
| 错误 Method、受保护 LLM 路径族、编码近似或危险路径 | 404，NewAPI 不收到请求 |
| interceptor 主动 reject | 模块指定的安全 4xx，首个拒绝短路，NewAPI 不收到请求 |
| body interceptor 超过上限 | 413，block_code=body_too_large，原 Body 不转发 |
| interceptor error/panic/非法结果或 Body 读取失败 | 503，available/strict 均 fail-closed |
| strict admission 失败 | 503，NewAPI 不应收到请求 |
| 显式代理连接失败 | 按 NewAPI Transport 失败返回 502；超时仍按既有超时规则返回 504 |
| NewAPI dial/TLS/round trip 失败 | 502 |
| response header 超时 | 504 |
| 客户端取消 | 取消 NewAPI context，不补错误 JSON；若响应已完整接收且全部写给客户端（含流终止事件后的断开），审计终态为 completed 而非 client_cancelled，完成日志同步清除暂记的取消错误码 |
| NewAPI 断流 / writer 短写 | 终止流并记录成功前缀、partial |
| available 审计失败 | 继续转发，日志 + best-effort gap |
| strict admission 后晚到审计失败 | partial/gap；不撤回已发送响应 |

响应 Header 已提交后不得写第二个状态码或附加错误 JSON。

## 10. Header 与 Trailer

Header 按名称和值列表保存，不合并 Set-Cookie 等多值字段；Host 单独记录。

Go 客户端直连时，在 request Body EOF 后读取 Request.Trailer。请求经过 Nginx 后可能丢失，这是已知限制，不设发布阻断门。Response Trailer 在 NewAPI Body EOF 后读取，能否到最终客户端取决于 Nginx 版本与配置。

## 11. 数据面安全

listen 默认 0.0.0.0:8080，生产用防火墙、容器网络或 ACL 只允许 Nginx；同机建议 127.0.0.1:8080。

审计分支日志只允许 audit_id、route_id、stage、status、bytes、duration、稳定错误码；禁止 Authorization、Cookie、Query 全文、Header 值与 Body。passthrough 不产生 `llm request completed` 日志。

## 12. 测试

- JSON、gzip、multipart、binary、empty、large Body。
- 重复 Query、RawPath、重复 Header、204/1xx/Trailer。
- SSE 每字节/随机块写入与立即 flush。
- 上传/响应取消、NewAPI reset、ResponseWriter 短写。
- available DB 失败继续；strict admission 503。
- Nginx 将全部数据面请求交给 dispatcher；health、login、admin、models、UI 等安全非 LLM 路径由 passthrough 到达 NewAPI，interceptor 调用数和 audit_records 增量均为 0。
- 配置 route 的错误 Method、exact 子路径、template 家族未配置动作、percent/double encoding 和危险路径返回 404，NewAPI 调用数为 0。
- metadata interceptor 不读取 Body，未启用 body 模块时首字节仍按流式到达 NewAPI。
- body interceptor 在 0、limit、limit+1 和 chunked Body 下按 route 最大上限只预读一次；放行时 replay 字节完全一致，模块自身超限时 413。
- Body 读取失败或非法 Decision 均返回 503，NewAPI 零调用；客户端取消按取消结束。
- 多模块按配置顺序运行；首个 reject 后续模块不执行，Fake NewAPI 未收到请求。
- `newapi.proxy_url` 为空时即使存在环境代理也直连；显式配置后请求通过 Fake HTTP Proxy 到达 Fake NewAPI，HTTPS CONNECT 路径可用。
- 模块 reject、error、panic 和非法 Decision 在 available/strict 下均返回约定状态，并记录 blocked_by/block_code、parse_status=skipped；未触发阶段无空行。
- 完整场景四阶段 length/hash 一致，取消场景准确反映前缀。
