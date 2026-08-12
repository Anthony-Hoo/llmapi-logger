# 模块 17：入站请求拦截链

## 1. 目标与边界

本模块只处理进程内 Matcher 精确命中的 LLM API route，在请求交给 audited ReverseProxy 和 NewAPI 之前执行本地放行检查。

`/v1/models`、NewAPI 健康检查、登录、管理和前端等安全非 LLM 请求由 data-plane dispatcher 送入 passthrough，不执行拦截器，也不创建 audit。配置路径的错误 Method、编码近似、exact 子路径、template 受保护家族和危险路径 fail-closed；interceptor 配置不能扩大 route 或 passthrough 范围。

首版拦截器只能检查并返回 allow/reject，不得修改 Method、URL、Header、Body 或上游地址，也不做响应拦截。

## 2. 执行顺序

~~~text
Nginx -> data-plane dispatcher -> 进程内 Matcher
                                  |- exact LLM route -> BeginAudit -> interceptor chain
                                  |                                      |- allow -> audited ReverseProxy -> NewAPI
                                  |                                      `- reject -> 本地固定 JSON
                                  |- safe unrelated -> passthrough ReverseProxy -> NewAPI
                                  `- protected/unsafe mismatch -> 404
~~~

规则：

- 每个 route 配置一条有序 chain，数组顺序就是执行顺序。
- 第一个 reject 立即短路，后续模块和 NewAPI 都不再执行。
- 未配置拦截器时行为与原透明代理相同。
- available/strict 只控制审计故障；已启用拦截器的 error 或 panic 始终 fail-closed。
- passthrough 和分发器的 404 分支都不会调用 chain。

## 3. 配置

配置字段只在模块 01 定义。本模块使用顶层实例定义和 route 引用：

~~~yaml
interceptors:
  require-client-credential:
    type: require_credential
  optional-body-limit:
    type: max_body_bytes
    config:
      max_bytes: 2097152

routes:
  - id: openai-chat-completions
    method: POST
    path: /v1/chat/completions
    match: exact
    parser: openai.chat_completions
    interceptors: [require-client-credential]
~~~

启动时必须拒绝重复 id、未知 type、未知配置字段、非法 Body 上限和 route 对不存在实例的引用。配置成功后 registry 与 chain 不再变化。

## 4. 扩展接口

~~~go
type Factory func(id string, raw map[string]any) (Interceptor, error)

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
    BlockCode string
}
~~~

新增模块只需：

1. 实现 Interceptor。
2. 在 app 组装处显式注册 Factory。
3. 定义严格解码的 config struct。
4. 增加单元测试和一条代理集成测试。

不使用动态库、脚本或 init 自动注册。实例会被并发复用，必须是只读或自行保证并发安全。

## 5. RequestView

RequestView 提供 route id、Method、EscapedPath、Host、ContentLength、PathParams，以及 Header/Query 的只读副本。

metadata interceptor 返回 NeedsBody=false，只能读取这些元数据。需要 Body 的模块必须返回 NeedsBody=true 和 1–16 MiB 的 MaxBodyBytes。

BodyView 只提供 Len 和 Open() io.Reader，不暴露可修改的底层字节。未声明 NeedsBody 的模块始终看不到 Body。

拦截器不得持有 RequestView、启动后台 goroutine、访问网络、数据库、文件或子进程。`Check` 直接使用请求 context，不额外引入远程调用、任务队列或独立超时机制。

## 6. Body 拦截

只有 route chain 包含 Body interceptor 时才预读 Body：

1. 第一阶段审计 observer 读取客户端 Body。
2. 按该 route 所需最大上限加一个判定字节进行有界缓冲。
3. 多个 Body interceptor 共享同一份只读缓冲，不重复读取客户端。
4. 某模块自己的上限被超过时，在调用该模块前返回 `413` 和 `block_code=body_too_large`。
5. 全部 allow 后，以同一字节序列重建 req.Body，再交给出站阶段和 ReverseProxy。

不得使用无界 io.ReadAll，不解压、不解析后重写，也不改变原 ContentLength、TransferEncoding、Header、RawQuery 或 Trailer。原 ContentLength 为 -1 时继续保持 -1。

首版只使用 `MaxBodyBytes` 做每请求有界缓冲，不增加全局 semaphore、配额管理或调度器。未配置 Body interceptor 的路由不预读 Body，继续保持流式和背压；若后续基准证明并发缓冲会造成实际内存问题，再增加最小限流措施。

## 7. 决策与拒绝响应

显式 reject 只允许 400–499 状态码和稳定的 BlockCode。响应正文由框架固定生成，模块不能自定义 Header 或正文：

~~~json
{"error":{"code":"request_rejected","message":"request rejected"}}
~~~

模块 error、panic、非法 Decision 或非客户端取消导致的 Body 读取失败固定返回 503：

~~~json
{"error":{"code":"interceptor_unavailable","message":"request cannot be processed"}}
~~~

响应不得包含 interceptor id、BlockCode、Header、Query、Body、token 或内部错误。日志只记录 audit_id、route_id、blocked_by、block_code、耗时和稳定错误类别。

## 8. 审计语义

audit_records 增加 blocked_by 和 block_code，并允许 forward_status=rejected。

被拒绝时：

- forward_status=rejected。
- blocked_by 和 block_code 保存首个终止 chain 的模块 id 与稳定代码。
- status_code 保存本地返回的 4xx 或 503。
- parse_status=skipped，不进入 parser queue。
- request_for_newapi_received_from_nginx 保存实际观察到的元数据和 Body 前缀。
- 不创建 request_sent_to_newapi、response_received_from_newapi、response_from_newapi_sent_to_nginx。

metadata reject 未读取非空 Body 时，第一阶段 hash_complete=false；完整缓冲后 reject 时可以保存完整 length/hash。后续三个阶段缺失是预期策略结果，不记为 audit gap。

## 9. 首版内置模块

require_credential 是 metadata interceptor，只检查以下来源是否至少存在一个非空值：

- Authorization: Bearer
- x-api-key
- x-goog-api-key
- Gemini Query key

它不校验凭据真伪，也不依赖或查询可选的 NewAPI 调用者解析。缺失时返回 401 和 credential_required；request-id 身份回填发生在上游响应后，是独立审计增强，不能改变拦截结论。

max_body_bytes 是 Body interceptor，配置 max_bytes；超过时返回 `413` 和 `block_code=body_too_large`，未超过时 allow。它按原始 Body 字节计数，不解压 gzip，也不按字符数或 JSON token 数计算。

## 10. 最少测试

- 只有 Matcher 精确命中的 LLM API route 进入 chain；`/v1/models` 等安全非 LLM 请求 passthrough，不审计也不拦截。
- 错误 Method、exact 子路径、template 家族未配置动作、percent/double encoding 和危险路径在 chain 之前 fail-closed，NewAPI 零调用。
- chain 严格按配置顺序执行，第一个 reject 后调用 NewAPI 次数为零。
- error、panic、非法 Decision 和非取消的 Body 读取失败均固定 503；客户端取消按取消结束。
- metadata-only chain 不读取 Body。
- Body chain 对 JSON、gzip、multipart、binary 和未知长度 Body 只缓冲一次，allow 后逐字节 replay。
- 上限、上限加一和客户端取消行为正确；超限统一返回 `413` 并记录 `block_code=body_too_large`。
- rejected audit 的 blocked_by、block_code、状态和四阶段缺失语义正确。
- 响应、日志、SQLite 和 WAL 不泄露凭据或 Body。

## 11. 实现边界

routing 决定哪些请求能进入 chain；app 负责三态分发；interceptor 只产生 allow/reject；proxy 负责本地拒绝响应和 NewAPI I/O；audit 记录 blocked_by/block_code。任一层都不能让 interceptor 扩大路由或把受保护路径降级为 passthrough。
