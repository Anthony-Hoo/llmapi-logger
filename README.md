# llmapi-logger

`llmapi-logger` 是一个面向个人部署的 AI API 审计代理，放在 Nginx 与 NewAPI 之间，用于记录指定 LLM API 请求在代理边界上实际经过的 HTTP 数据。

它只接管明确配置的 OpenAI、Anthropic 和 Gemini LLM API 白名单。NewAPI 的登录、管理、模型列表、健康检查、前端页面及其他请求仍由 Nginx 直接转发，不进入本程序，也不会被审计或拦截。

```text
Client -> Nginx
            |- LLM API whitelist -> llmapi-logger -> NewAPI -> Provider
            `- other NewAPI paths ----------------> NewAPI
```

## 主要用途

- 流式保存客户端请求和 NewAPI 响应的原始 HTTP 证据。
- 在请求发往 NewAPI 前运行可配置的本地拦截链，拒绝不符合要求的 LLM 请求。
- 对常见 OpenAI、Anthropic、Gemini JSON/SSE 响应生成便于检索的摘要。
- 通过本地 React + shadcn/ui 页面查询审计记录和读取原始 Body。
- 在个人单机环境中辅助排查请求差异、流式中断、上游错误和审计缺口。

## 核心能力

- 基于 Method + Path 的进程内 LLM API 白名单。
- 基于 `net/http/httputil.ReverseProxy` 的流式转发，支持 SSE 及时 flush。
- 可插拔入站拦截器，首个拒绝立即短路且不会访问 NewAPI。
- 分别记录四个代理观察点：
  - Nginx 请求到达代理；
  - 代理请求发往 NewAPI；
  - NewAPI 响应到达代理；
  - 代理响应写回 Nginx。
- 保存各阶段的 Header、Trailer、Body chunk、长度、SHA-256 和完整性状态。
- 使用本地 AES-256-GCM key 加密敏感 Header、Query、Body 和解析结果。
- SQLite WAL 存储、单 writer、有界写队列和自动 migration。
- OpenAI、Anthropic、Gemini 常见 JSON/SSE 的异步解析。
- React、TypeScript、Vite、Tailwind CSS 和 shadcn/ui 管理页面。
- loopback 管理端同样强制使用静态 Bearer token。
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

Nginx 白名单和程序内 routes 应保持一致。直接访问数据端口时，未命中的路径返回 `404`，不会创建 audit。

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

静态页面可以加载，但读取审计数据、`/healthz`、`/readyz` 和 `/api/v1/*` 都需要配置中的 `admin_token`。

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
- 管理端即使只监听 loopback，也必须使用 Bearer token。
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
