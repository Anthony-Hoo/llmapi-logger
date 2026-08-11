# AI API 审计代理：个人单机版总体设计

> 状态：当前实现基线
> 日期：2026-08-11
> 上游需求：[AI_API_AUDIT_PROXY_KICKOFF.md](../../AI_API_AUDIT_PROXY_KICKOFF.md)

## 1. 目标与边界

本项目是部署在 Nginx 与 NewAPI 之间的个人审计代理：单用户、单机、一个 Go 二进制、一个 NewAPI 后端、一个 SQLite WAL 数据库和一个本地主密钥文件。

数据端口统一接收 NewAPI 请求，但只有进程内 Matcher 精确命中的 LLM API route 才会保存原始 HTTP 证据、执行可插拔拦截链并异步解析 OpenAI/Anthropic/Gemini JSON/SSE。`/v1/models` 等真正无关的 NewAPI 请求走无审计 passthrough；配置路径的错误 Method、编码/双重编码等价形式、子路径、受保护模板路径族和危险非规范路径 fail-closed，不访问 NewAPI。

~~~text
Client -> Nginx -> Data-plane dispatcher
                         |- configured LLM route -> interceptor + audit proxy -> NewAPI
                         |- safe unrelated route -> passthrough proxy ----------> NewAPI
                         `- protected/unsafe mismatch -> 404
~~~

代理只能证明 Nginx、代理和 NewAPI 三者边界上实际观察到的数据；看不到 NewAPI 后方的渠道选择、厂商原始请求/响应、内部重试或渠道密钥。首版也不承诺 TCP、TLS、HTTP/2 frame、Header 原始大小写或 chunk framing 级保真，不支持 WebSocket/Realtime。

## 2. 固定四阶段

| 阶段 | 观察点 |
| --- | --- |
| request_for_newapi_received_from_nginx | 代理读取 Nginx 请求 Body |
| request_sent_to_newapi | NewAPI Transport 读取出站 Body |
| response_received_from_newapi | ReverseProxy 读取 NewAPI 响应 Body |
| response_from_newapi_sent_to_nginx | ResponseWriter 成功接受响应字节 |

每阶段独立保存元数据、Header/Trailer、observed length、stored length、SHA-256、完整性状态和 Body chunk。取消、短写或网络错误可能让相邻阶段不同，不能共用一个 summary。

## 3. 架构

~~~text
Nginx -> Data-plane dispatcher -> Matcher
                    |- exact LLM match -> Interceptor Chain -> Audited ReverseProxy -> NewAPI
                    |                         |                    |
                    |                         +---- Audit Session -+
                    |                                  |
                    |                         single SQLite writer -> SQLite WAL
                    |                                  |
                    |                            in-memory parsers
                    |- safe unrelated path -> Passthrough ReverseProxy -----------> NewAPI
                    `- protected/unsafe mismatch -> fixed 404
~~~

建议目录：

~~~text
cmd/audit-proxy/
internal/{config,routing,proxy,audit,conversation,storage/sqlite,parser,query,web}/
internal/storage/sqlite/migrations/
configs/
~~~

热路径只做路由、入站拦截、流式 wrapper、长度/hash、32 KiB 字节复制和队列提交。默认 metadata 拦截器不读取 Body；只有路由显式启用 body 拦截器时才有界预读一次并原字节回放。JSON/SSE/gzip 解析仍在请求结束并落库后异步运行。启动恢复、retention 和安全日志属于后台运维能力，不改变代理字节路径。

## 4. 运行模式

available：审计失败时继续转发，当前记录标 partial/failed，写安全 JSON 日志；DB 可写时插入 audit_gaps，短暂写失败时暂存进程内聚合 gap，后续 writer 事务成功时补记。启动时 DB/key 不可用不会在进程内复杂重建依赖，修复后需要重启；故障期间若进程退出只能依赖日志。

strict：每个白名单请求访问 NewAPI 前，必须使用已加载的 key 同步提交 audit_records 起始行；本次提交成功才证明当前 DB/writer 可写，失败返回 503，NewAPI 不应收到请求。上一批写入留下的健康快照不单独决定 admission。

strict 只保证请求开始时 fail-closed。通过 admission 后仍可能遇到崩溃、磁盘故障或最终批事务失败；首版不逐块 fsync，不宣称绝对零缺口，也不能撤回已经发送的响应。

## 5. 数据面分发、代理与 Trailer

审计代理和 passthrough 都使用 net/http/httputil.ReverseProxy、同一套 Rewrite 与显式 HTTP(S) 上游代理设置，固定保留 Path、RawPath、RawQuery、ForceQuery，出站目标与 Host 使用 `newapi.url`。审计分支额外安装 audit wrapper 和 interceptor；passthrough 不创建 audit、不解析，也不写 LLM 请求完成日志。

分发器只允许规范且与受保护 LLM 路径族无关的未匹配请求直通，例如 `GET /v1/models`。配置 exact 路径及其后代、template 路径前缀家族、错误 Method、percent/double encoding 等价路径，以及尾随斜杠、重复斜杠、反斜杠、encoded slash 和 dot segment 等危险形式统一进入 fail-closed 分支并返回 404。

Go 客户端直连代理时可捕获 request Trailer；经过 Nginx 后不保证保留，作为已知限制，不设发布阻断门。Response Trailer 在链路支持时尽力转发和记录。

## 6. 配置与固定默认值

YAML 只保留 listen、admin_listen、`newapi`（url、可选 proxy_url、成对可选 access_token/user_id）、mode、db_path、key_path、必填 admin_token、retention_days、interceptors 和 routes。`newapi.proxy_url` 为空时强制直连，不读取环境代理；access_token/user_id 配置后只读同步 NewAPI 已打码 Token 目录。完整格式见 [01](01-configuration-and-route-boundary.md)。

| 项目 | 固定默认值 |
| --- | --- |
| 数据面 / 管理面 | 0.0.0.0:8080 / 127.0.0.1:8081 |
| mode | available |
| Body chunk | 32 KiB |
| writer queue / batch | 1024 ops / 64 ops 或 5 ms |
| SQLite | WAL、synchronous=FULL、busy_timeout=5000 |
| parser workers | 1 |
| NewAPI Token 目录 | 10 秒请求超时、每 5 分钟刷新 |
| retention / shutdown | 30 天 / 30 秒 |

宿主机同机部署建议把数据面改为 127.0.0.1:8080；容器部署用内部网络和 ACL 只允许 Nginx 访问。

## 7. 数据与加密

SQLite 只保留九张表：

1. schema_migrations
2. audit_records
3. http_stages
4. http_headers
5. body_streams
6. body_chunks
7. parsed_results
8. token_links
9. audit_gaps

采用单 writer goroutine + 简单批事务，查询使用独立只读连接池。migration 只按数字版本顺序执行；数据库版本高于程序支持版本时拒绝启动。

key_path 存放 32-byte 主密钥：存在则读取，不存在且数据库尚无审计数据时自动生成。每个 Header 值、Body chunk、原始 Request-URI 和解析结果用 AES-256-GCM 独立随机 nonce 加密，数据库保存固定格式的 `nonce || ciphertext || tag` BLOB；首版不提供密钥轮换工具。

详细设计见 [03](03-audit-session-and-evidence-capture.md) 与 [04](04-sqlite-storage-and-migrations.md)。

## 8. Parser 与管理面

Finalize 后把 audit_records.parse_status 设为 pending，并把 audit_id 放入内存 parser queue。固定一个 worker 解密证据，为 OpenAI、Anthropic 和 Gemini 的常见 JSON/SSE 生成非敏感摘要，同时聚合协议无关的多轮消息、reasoning、工具调用和工具结果。摘要写入窄列，conversation 只合并进 `parsed_json_enc` 后加密落盘；parser v2 migration 会把 v1 结果一次性置回 pending，复用正常 worker 回填旧记录。

管理面默认 127.0.0.1，但 loopback 也必须使用 admin_token。CLI 可直接发送静态 Bearer token；React 静态 shell 不含数据，登录成功后改用七天过期的 HttpOnly Cookie，刷新页面可恢复会话。普通列表只定向解密入站 User-Agent，主视图只展示调用者、时间、模型和 User-Agent，并支持模型精确筛选、User-Agent 子串筛选和按 NewAPI Token ID 的 API Key 下拉筛选；路径、状态和原始 HTTP 等信息放在详情或高级筛选。目录刷新失败会保留旧快照且不影响转发，审计只保存 Token ID、名称和 `masked_key`。受保护的详情会解密 conversation、Request-URI 与每个 Header/Trailer 值。React + TypeScript + Vite + Tailwind CSS + shadcn/ui 页面默认按角色顺序展示对话，assistant 文本使用禁用 raw HTML、危险链接协议和远程图片加载的 GFM Markdown，reasoning 折叠，工具调用/结果单独展示；原始 HTTP、Header 和完整性信息默认折叠，Body 仍通过独立 raw API 按需读取。这不是 wire dump。管理 JSON 与 raw 响应均禁止缓存。

## 9. 模块索引

| 模块 | 文档 |
| --- | --- |
| 01 | [配置、路由与单机边界](01-configuration-and-route-boundary.md) |
| 02 | [透明 HTTP 代理](02-transparent-http-proxy.md) |
| 03 | [审计会话与证据采集](03-audit-session-and-evidence-capture.md) |
| 04 | [SQLite 存储与迁移](04-sqlite-storage-and-migrations.md) |
| 05 | [协议解析框架](05-parser-framework.md) |
| 06 | [OpenAI 兼容协议解析器](06-openai-protocol-parser.md) |
| 07 | [Anthropic Messages 协议解析器](07-anthropic-protocol-parser.md) |
| 08 | [Gemini GenerateContent 协议解析器](08-gemini-protocol-parser.md) |
| 09 | [本地加密、脱敏与管理面保护](09-security-encryption-and-redaction.md) |
| 10 | [查询 API 与最小 Web UI](10-query-api-and-minimal-web-ui.md) |
| 11 | [NewAPI Token 只读关联](11-newapi-token-readonly-linking.md) |
| 12 | [保留清理](12-retention-and-maintenance.md) |
| 13 | [日志、健康检查与生命周期](13-observability-health-and-lifecycle.md) |
| 14 | [测试与发布检查](14-test-benchmark-and-fault-injection.md) |
| 15 | [Nginx 与部署](15-nginx-and-deployment-integration.md) |
| 16 | [开源项目参考取舍](16-open-source-reference-assessment.md) |
| 17 | [入站请求拦截链](17-request-interceptor-chain.md) |

## 10. 当前实现范围

当前仓库包含数据面三态分发、LLM route/interceptor、透明 ReverseProxy、四阶段加密证据、SQLite 单 writer、异步 parser、加密 conversation、受 Token 保护的查询与 React + shadcn/ui 对话审计、启动恢复、聚合 gap、retention、安全日志和单机构建部署材料。项目仍不提供 metrics、在线导出、DELETE、自动 VACUUM、WebSocket/Realtime 审计或复杂运行时重连。

## 11. 最小验收

- OpenAI、Anthropic、Gemini 常见流式/非流式请求正常转发。
- JSON、gzip、multipart、binary、empty、large Body 不被改写。
- 四阶段名称、length、hash 和完整性状态正确。
- SSE 立即 flush；记录 direct 与 proxy 的 TTFT 差异，结果作为优化参考而非发布门禁。
- strict 在请求开始时 key/DB 不健康返回 503，Fake NewAPI 未收到请求。
- available 记录失败仍转发，并存在日志或 audit_gaps。
- `/v1/models` 等安全非 LLM 请求透明到达 NewAPI，且不建 audit、不执行 interceptor；错误 Method、编码近似、受保护 LLM 路径族与危险路径返回 404，NewAPI 零调用。
- DB/WAL 无测试 secret 明文。
- 拦截链首个 reject 会在调用 NewAPI 前返回；记录 blocked_by/block_code，后续 NewAPI 阶段不存在。
- 未启用 Body 拦截器时保持流式；启用后允许请求的 Body 回放字节与原请求完全一致，超限固定为 `413` 和 `block_code=body_too_large`。
- 重启后 pending parser 恢复，parser v1 结果可由 migration 一次性回填 conversation，未完成 audit 标 partial。
- 只有实际恢复未终结记录时增加 process_exit 聚合 gap，重复恢复幂等。
- retention 只小批量删除已终结且非 processing 的过期记录，并级联子表。
- 请求完成日志不含 Query、Header value、Body、token、key 或底层错误文本。
- NewAPI Token 目录只同步已打码字段，每五分钟刷新；失败保留旧快照且不影响转发，关联只落 Token ID、名称和 `masked_key`。
- healthy/degraded/not_ready 与 available/strict 语义一致。
- 管理列表只返回紧凑摘要和解密后的入站 User-Agent，不返回其他 Header、Request-URI、Body 或 conversation；详情在 Admin Token 下返回 conversation、Request-URI 与逐项 Header/Trailer 值，raw request/response Body 只按需读取，所有管理证据响应禁止缓存。
- loopback 访问列表、详情、raw、health 和 ready 同样必须携带 Bearer token 或有效管理 Cookie。

## 12. 文档优先级

本 README 说明总体方向；01 是配置字段的唯一来源，04 是 SQLite schema 的唯一来源，09 是鉴权和加密格式的唯一来源。其余模块只引用这些定义，不再各自扩展配置、表或安全机制。
