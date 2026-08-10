# AI API 审计代理：个人单机版总体设计

> 状态：可实施基线  
> 日期：2026-08-10  
> 上游需求：[AI_API_AUDIT_PROXY_KICKOFF.md](../../AI_API_AUDIT_PROXY_KICKOFF.md)

## 1. 目标与边界

本项目是部署在 Nginx 与 NewAPI 之间的个人审计代理：单用户、单机、一个 Go 二进制、一个 NewAPI 后端、一个 SQLite WAL 数据库和一个本地主密钥文件。

首版只处理同时由 Nginx 选入、且被进程内 Matcher 命中的 LLM API 白名单请求：透明转发、保存原始 HTTP 证据、在送往 NewAPI 前执行可插拔拦截链、异步解析常见 OpenAI/Anthropic/Gemini JSON/SSE，并提供本地查询页面。NewAPI 的健康检查、登录、管理、模型列表、前端页面及其他请求由 Nginx 直连 NewAPI，不进入审计代理、不执行拦截器，也不创建 audit。

~~~text
Client -> Nginx
            |- LLM API 白名单 -> Audit Proxy -> NewAPI -> Provider
            `- NewAPI 其他路径 -> NewAPI
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
Nginx LLM API 白名单 -> Handler -> Matcher -> Interceptor Chain -> ReverseProxy -> NewAPI
                                  |              |                         |
                                  +--------------+----- Audit Session -----+
                                                         |
                                                   bounded queue
                                                         |
                                                single SQLite writer
                                                         |
                                                     SQLite WAL
                                                         |
                                                in-memory parsers
~~~

建议目录：

~~~text
cmd/audit-proxy/
internal/{config,routing,proxy,audit,storage/sqlite,parser,query,web}/
internal/storage/sqlite/migrations/
configs/
~~~

热路径只做路由、入站拦截、流式 wrapper、长度/hash、32 KiB 字节复制和队列提交。默认 metadata 拦截器不读取 Body；只有路由显式启用 body 拦截器时才有界预读一次并原字节回放。JSON/SSE/gzip 解析仍在请求结束并落库后异步运行。

## 4. 运行模式

available：审计失败时继续转发，当前记录标 partial/failed，写结构化日志；DB 可写时插入 audit_gaps，DB 不可用时暂存一个进程内 gap 汇总，下一次成功写入时补记。进程提前退出时只能依赖日志。

strict：每个白名单请求访问 NewAPI 前，确认 key 可读、DB/writer 可写、队列健康，并同步提交 audit_records 起始行；失败返回 503，NewAPI 不应收到请求。

strict 只保证请求开始时 fail-closed。通过 admission 后仍可能遇到崩溃、磁盘故障或最终批事务失败；首版不逐块 fsync，不宣称绝对零缺口，也不能撤回已经发送的响应。

## 5. 代理与 Trailer

使用 net/http/httputil.ReverseProxy、Rewrite、自定义 RoundTripper 和 ResponseWriter wrapper。固定保留 Path、RawPath、RawQuery、ForceQuery，出站 Host 使用 newapi_url，DisableCompression=true，FlushInterval=-1。Body 只流式旁路，不使用 io.ReadAll，也不解析后重发。

非白名单请求直接打到代理时返回 404 且不建 audit。Nginx 仍是第一层白名单：只有明确列出的 LLM API 路径进入审计代理和拦截链；健康检查、登录、管理、模型列表、前端页面及其他 NewAPI 路径直接到 NewAPI，既不审计也不拦截。

Go 客户端直连代理时可捕获 request Trailer；经过 Nginx 后不保证保留，作为已知限制，不设发布阻断门。Response Trailer 在链路支持时尽力转发和记录。

## 6. 配置与固定默认值

YAML 只保留 listen、admin_listen、newapi_url、mode、db_path、key_path、必填 admin_token、retention_days、可选 newapi_token_db_path、interceptors 和 routes。完整格式见 [01](01-configuration-and-route-boundary.md)。

| 项目 | 固定默认值 |
| --- | --- |
| 数据面 / 管理面 | 0.0.0.0:8080 / 127.0.0.1:8081 |
| mode | available |
| Body chunk | 32 KiB |
| writer queue / batch | 1024 ops / 64 ops 或 5 ms |
| SQLite | WAL、synchronous=FULL、busy_timeout=5000 |
| parser workers | 1 |
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

Finalize 后把 audit_records.parse_status 设为 pending，并把 audit_id 放入内存 parser queue。固定一个 worker 解密证据，为 OpenAI、Anthropic 和 Gemini 的常见 JSON/SSE 响应生成最小摘要，并 UPSERT parsed_results。重启时扫描 pending 记录重新入队；解析不重建完整对话或全文。

管理面默认 127.0.0.1，但 loopback 也必须使用 admin_token。API、health、ready，以及以后若启用的 metrics，统一校验静态 Bearer token；React 静态 shell 不含数据，可先加载再由用户输入 token。阶段 3 的数据功能只做列表、详情、原始请求/响应 Body 和简单筛选，UI 固定使用 React + TypeScript + Vite + Tailwind CSS + shadcn/ui。单条删除、ZIP/批量导出、gaps UI 和 reparse 管理端点暂不实现。

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
| 12 | [保留与可选单条 JSON 导出](12-retention-export-and-maintenance.md) |
| 13 | [日志、健康检查与生命周期](13-observability-health-and-lifecycle.md) |
| 14 | [测试与性能检查](14-test-benchmark-and-fault-injection.md) |
| 15 | [Nginx 与部署](15-nginx-and-deployment-integration.md) |
| 16 | [开源项目参考取舍](16-open-source-reference-assessment.md) |
| 17 | [入站请求拦截链](17-request-interceptor-chain.md) |

## 10. 个人开发计划：4–6 周兼职

### 阶段 1：代理与配置

建立 Go 工程、精简 YAML、route matcher、interceptor registry/chain、ReverseProxy、fake NewAPI 和透明性测试。完成 metadata 拦截、固定拒绝响应、JSON、gzip、binary、Query/Header、非白名单 404。

退出：白名单透明转发，未知路径不产生 audit。

### 阶段 2：SQLite 与证据

实现九表 migration、单 writer、四阶段 tap、length/hash、Header/Trailer、主密钥 AES-GCM、available/strict admission。

退出：完整请求四阶段可比较；DB/WAL 找不到测试 secret 明文。

### 阶段 3：Parser 与最小页面

实现 OpenAI、Anthropic 和 Gemini 常见 JSON/SSE 的最小摘要解析，使用单 worker、内存队列和 pending 恢复；管理面只提供列表、详情、raw 请求/响应 Body，并使用 React + TypeScript + Vite + Tailwind CSS + shadcn/ui 构建页面。

本阶段不做单条删除、ZIP/批量导出、gaps UI、reparse 管理端点或复杂全文重建。

退出：parser 失败不影响响应；三协议常见 JSON/SSE 能得到可查询摘要；loopback 管理 API 未带 Bearer token 时返回 401。

### 阶段 4：最小运维收口

实现按 retention_days 清理旧审计；如果个人使用确有需要，再增加可选的单条 JSON 导出。阶段 4 不扩展 ZIP、批量导出、批量删除或后台导出任务。

退出：到期且已终结的记录可小批量清理，现有透明代理、审计、解析和查询能力保持不变。

## 11. 最小验收

- OpenAI、Anthropic、Gemini 常见流式/非流式请求正常转发。
- JSON、gzip、multipart、binary、empty、large Body 不被改写。
- 四阶段名称、length、hash 和完整性状态正确。
- SSE 立即 flush；记录 direct 与 proxy 的 TTFT 差异，结果作为优化参考而非发布门禁。
- strict 在请求开始时 key/DB 不健康返回 503，Fake NewAPI 未收到请求。
- available 记录失败仍转发，并存在日志或 audit_gaps。
- 非白名单不建 audit；DB/WAL 无测试 secret 明文。
- 拦截链首个 reject 会在调用 NewAPI 前返回；记录 blocked_by/block_code，后续 NewAPI 阶段不存在。
- 未启用 Body 拦截器时保持流式；启用后允许请求的 Body 回放字节与原请求完全一致，超限固定为 `413` 和 `block_code=body_too_large`。
- 重启后 pending parser 恢复，未完成 audit 标 partial。
- 管理面只暴露阶段 3 最小查询范围，loopback 访问列表、详情、raw、health 和 ready 同样必须携带 Bearer token。

## 12. 文档优先级

本 README 说明总体方向；01 是配置字段的唯一来源，04 是 SQLite schema 的唯一来源，09 是鉴权和加密格式的唯一来源。其余模块只引用这些定义，不再各自扩展配置、表或安全机制。
