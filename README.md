# llmapi-logger

`llmapi-logger` 是一个面向个人部署的 AI API 审计代理，放在客户端/Nginx 与 NewAPI 之间，用于记录指定 LLM API 请求在代理边界上实际经过的 HTTP 数据。

进入数据端口的请求由进程内分发器分成三类：明确配置的 OpenAI、Anthropic 和 Gemini LLM API 路由执行拦截与审计；`/v1/models` 等真正无关的 NewAPI 请求透明直通；错误 Method、受保护 LLM 路径族、编码近似和危险路径固定拒绝，不能借直通分支绕过规则。

```text
Client -> Nginx -> llmapi-logger
                         |- configured LLM API -> intercept + audit -> NewAPI
                         |- safe non-LLM API --> passthrough --------> NewAPI
                         `- protected/unsafe mismatch -> 404
```

## 主要用途

- 流式保存客户端请求和 NewAPI 响应的原始 HTTP 证据。
- 在请求发往 NewAPI 前运行可配置的本地拦截链，拒绝不符合要求的 LLM 请求。
- 对常见 OpenAI、Anthropic、Gemini JSON/SSE 生成便于检索的摘要，并聚合为协议无关的多轮对话、reasoning、工具调用和工具结果。
- 通过本地 React + shadcn/ui 页面优先查看按角色排列的对话审计；Request-URI、每个 Header/Trailer 值和原始请求/响应 Body 作为默认折叠的辅助证据保留。
- 在个人单机环境中辅助排查请求差异、流式中断、上游错误和审计缺口。

## 核心能力

- 基于 Method + Path 的进程内 LLM API 白名单。
- 三态数据面分发：配置的 LLM 路由审计、安全的非 LLM 路径直通、受保护或危险的未匹配路径 fail-closed。
- 基于 `net/http/httputil.ReverseProxy` 的流式转发，支持 SSE 及时 flush，并可为 NewAPI 上游显式指定 HTTP(S) 代理。
- 可插拔入站拦截器，首个拒绝立即短路且不会访问 NewAPI。
- 分别记录四个代理观察点：
  - Nginx 请求到达代理；
  - 代理请求发往 NewAPI；
  - NewAPI 响应到达代理；
  - 代理响应写回 Nginx。
- 保存各阶段的 Header、Trailer、Body chunk、长度、SHA-256 和完整性状态。
- 使用本地 AES-256-GCM key 加密敏感 Header、Query、Body 和解析结果。
- SQLite WAL 存储、单 writer、有界写队列和自动 migration。
- OpenAI、Anthropic、Gemini 常见 JSON/SSE 的异步解析，以及统一的多轮对话和工具调用视图。
- React、TypeScript、Vite、Tailwind CSS 和 shadcn/ui 管理页面。
- loopback 管理端同样强制鉴权；CLI 可用静态 Bearer token，Web UI 登录后使用七天过期的 HttpOnly Cookie；敏感详情和 raw 响应禁止缓存。
- 可选只读同步 NewAPI 已打码的 Token 目录，为审计记录保存 Token ID、名称和 `masked_key` 快照，并在页面按 API Key 下拉筛选。
- assistant 输出使用安全的 GFM Markdown 展示；禁用原始 HTML、危险链接协议和远程图片加载。
- 启动异常记录恢复、简单审计 gap、按天 retention 和安全 JSON 日志。

## 默认白名单

示例配置包含以下 `POST` 路径：

```text
/v1/chat/completions
/v1/completions
/v1/responses
/v1/responses/compact
/v1/messages
/v1beta/models/{model}:generateContent
/v1beta/models/{model}:streamGenerateContent
```

`routes` 只列出需要审计的 LLM API，不需要枚举 NewAPI 的全部普通接口。进入数据端口后：

- Method 与规范化 Path 精确命中 route：建立 audit、执行 interceptor，通过后转发。
- `/v1/models`、登录、管理、健康检查和前端等安全且与受保护 LLM 路径族无关的请求：透明转发，不审计、不拦截。
- 配置路径的错误 Method、exact 路径的子路径、template 前缀家族中的未配置动作、percent/double encoding 等价形式，以及尾随斜杠、重复斜杠、反斜杠、encoded slash 和 dot segment 等危险形式：返回固定 `404`，不访问 NewAPI，也不创建 audit。

仓库 Nginx 示例把所有数据面请求统一送入本程序，由同一分发器落实上述边界。

## 审计模式

`available` 是默认模式。审计存储暂时不可用时继续转发请求，并通过安全日志或聚合 gap 表明证据可能不完整。

`strict` 模式要求每个请求在访问 NewAPI 前成功提交 audit 起始记录。本次提交失败时返回 `503`，请求不会发送给 NewAPI。

两种模式都不会放宽拦截器规则：拦截器拒绝、异常、非法结果或 Body 超限始终在访问 NewAPI 前终止请求。

## 快速开始

本机构建需要 Go 1.25+、Node.js 22+ 和 pnpm。

Windows：

```powershell
New-Item -ItemType Directory -Force .\data | Out-Null
Copy-Item .\configs\audit-proxy.example.yaml .\data\audit-proxy.yaml
# 编辑配置并替换 admin_token
.\scripts\build.ps1
.\bin\audit-proxy-windows-amd64.exe `
  --config .\data\audit-proxy.yaml `
  --validate-config
.\bin\audit-proxy-windows-amd64.exe `
  --config .\data\audit-proxy.yaml
```

Linux：

```bash
mkdir -p ./data
cp ./configs/audit-proxy.example.yaml ./data/audit-proxy.yaml
# 编辑配置并替换 admin_token
bash ./scripts/build.sh
./bin/audit-proxy-linux-amd64 \
  --config ./data/audit-proxy.yaml \
  --validate-config
./bin/audit-proxy-linux-amd64 \
  --config ./data/audit-proxy.yaml
```

默认管理页面地址为：

```text
http://127.0.0.1:8081/ui/
```

静态页面可以加载，但读取审计数据、`/healthz`、`/readyz` 和受保护的 `/api/v1/*` 都需要配置中的 `admin_token`。Web UI 登录成功后使用带固定过期时间的 HttpOnly Cookie，刷新页面无需重复输入；Bearer 方式仍可供 curl 和其他本地客户端使用。

详情 API 会在鉴权后解密 Request-URI、每个已保存的 Header/Trailer 值，以及 parser 生成的协议无关 conversation。conversation 正文、reasoning、工具参数和结果与解析摘要一起存放在 `parsed_json_enc` 密文中，列表 API 不读取它们。请求/响应 Body 仍通过单独的 raw API 按需读取；页面只在用户点击后加载 Body，有效 UTF-8 可直接预览，二进制内容保留下载；这些管理响应均带 `Cache-Control: no-store`。

NewAPI 相关配置统一放在 `newapi` 下：`url` 是唯一上游，`proxy_url` 是可选显式 HTTP(S) 代理。若 audit-proxy 所在环境不能直接访问远程 NewAPI，宿主机二进制通常可填写 `http://127.0.0.1:7897`；Podman/WSL 要访问仅监听 Windows loopback 的 Clash，则使用 host network 并填写同一地址，而不是 `host.containers.internal`。空值表示直接连接，程序不会隐式读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。

`newapi.access_token` 与 `newapi.user_id` 必须同时配置或同时留空。配置后，程序只读调用 NewAPI Token 列表接口，同步服务端已经打码的 Token 元数据；启动时刷新一次，之后每五分钟刷新。刷新失败不影响 LLM 转发，并保留上一份成功快照。审计库只保存匹配时的 Token ID、名称和 `masked_key`，不保存 NewAPI 原始 Token。详细说明见[部署说明](doc/deployment/README.md)和 [Token 只读关联](doc/features/11-newapi-token-readonly-linking.md)。

## Docker Compose

仓库提供 Nginx、audit-proxy 和 NewAPI 的最小 Compose 示例：

```bash
# 先替换 configs/audit-proxy.docker.yaml 中的 admin_token
docker compose build audit-proxy
docker compose up -d
```

Compose 默认只公开 Nginx 的 `80` 端口；管理端发布到宿主机 `127.0.0.1:8081`，数据端和 NewAPI 只存在于私有 bridge 网络。正式使用时应将 NewAPI 镜像固定到自己验证过的 tag 或 digest。

详细步骤见[部署说明](doc/deployment/README.md)。

## 数据与安全

- 默认数据库为 SQLite WAL，数据库和 `audit.key` 必须作为同一个备份集保存。
- 在线备份必须使用 SQLite backup API，不能只复制正在使用的主 DB 文件。
- 普通请求完成日志不记录 Query、Header value、Body、token、key 或底层错误文本。
- 管理端即使只监听 loopback，也必须鉴权；支持 Bearer token 和 Web UI 的七天 HttpOnly Cookie。
- 审计列表不返回敏感值；详情和 raw Body 会返回明文证据，只能通过受 Admin Token 保护的管理接口读取。
- 对话视图是从原始 JSON/SSE 派生的便捷展示；原始 HTTP 证据、长度、哈希和完整性状态仍是权威依据。
- 配置文件、数据库和 key 应只允许运行账户访问。

备份流程见[备份与恢复](doc/deployment/backup-and-restore.md)。

## 项目边界

- 本项目只能记录 Nginx、audit-proxy 和 NewAPI 边界上实际观察到的数据。
- 它看不到 NewAPI 后方的渠道选择、厂商请求、厂商原始响应、内部重试或渠道密钥。
- 它不提供 TCP、TLS、HTTP/2 frame、Header 原始大小写或 chunk framing 级别的取证保真。
- 当前不支持 WebSocket/Realtime、多租户、高可用、在线导出、DELETE API 或自动 VACUUM。
- 这是个人单机项目，不以企业级审计平台为目标。

## 开发与验证

```bash
go test -count=1 ./...
go vet ./...

cd internal/web/frontend
pnpm install --frozen-lockfile
pnpm test
pnpm build
```

## 更多文档

- [总体设计与模块索引](doc/features/README.md)
- [配置与路由边界](doc/features/01-configuration-and-route-boundary.md)
- [透明 HTTP 代理](doc/features/02-transparent-http-proxy.md)
- [入站请求拦截链](doc/features/17-request-interceptor-chain.md)
- [查询 API 与管理页面](doc/features/10-query-api-and-minimal-web-ui.md)
- [Nginx 与部署](doc/features/15-nginx-and-deployment-integration.md)
- [仓库架构说明](AGENTS.md)
