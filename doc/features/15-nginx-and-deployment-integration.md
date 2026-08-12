# 模块 15：Nginx 与单机部署

## 1. 目标

Nginx 把完整 NewAPI 数据面统一送入 audit-proxy，由进程内 dispatcher 做三态分流：配置的 LLM API route 执行拦截与审计，安全非 LLM 请求透明 passthrough，受保护或危险的未匹配路径 fail-closed。这样 Nginx fallback 不能绕过 Method、编码变体或 LLM 路径族保护。仓库提供宿主机和 Docker Compose 两种单机方式，不设计高可用、服务发现或额外控制面。

~~~text
Client -> Nginx -> audit-proxy:8080 dispatcher
                         |- audited LLM -> [optional HTTP(S) proxy] -> NewAPI:3000
                         |- safe passthrough ------------------------> NewAPI:3000
                         `- protected/unsafe mismatch -> 404
~~~

管理端口 `8081` 不进入公开 Nginx；即使只绑定 `127.0.0.1`，health、ready 和管理 API 也必须鉴权。CLI 可使用静态 Bearer token，Web UI 使用七天过期的 HttpOnly Cookie。

## 2. Nginx 路由

仓库提供：

~~~text
configs/nginx/llmapi-logger.conf
configs/nginx/proxy-common.inc
~~~

Nginx 不再复制应用 route matcher，也不根据 Method/Path 选择 NewAPI fallback。`location /` 的全部数据面请求都发送到 `audit_proxy_backend`；NewAPI 不作为 Nginx 的并列 fallback upstream。

进程内配置仍只审计以下五个固定 POST 路径：

~~~text
/v1/chat/completions
/v1/completions
/v1/responses
/v1/responses/compact
/v1/messages
~~~

Gemini 只接受从头到尾锚定的两种模板：

~~~text
/v1beta/models/[A-Za-z0-9._-]+:generateContent
/v1beta/models/[A-Za-z0-9._-]+:streamGenerateContent
~~~

进程内 dispatcher 的行为：

- 上述 Method + Path 精确命中：执行 route interceptor 和四阶段审计。
- `GET /v1/models`、NewAPI health/login/admin/UI 等规范且与受保护 LLM 路径族无关的请求：透明 passthrough，不审计、不拦截。
- 相同 LLM Path 的错误 Method、exact 路径后代、Gemini 受保护模板前缀下的未配置动作、percent/double encoding 近似，以及尾随/重复斜杠、反斜杠、encoded slash、dot segment 等危险路径：固定 404，不访问 NewAPI。

将这一判断集中在 Go 进程内，避免 Nginx `$uri` 规范化或规则遗漏形成绕过；配置新的 LLM route 时不需要在 Nginx 复制一份路径正则。

## 3. 透明代理参数

公共片段对全部数据面请求固定：

- HTTP/1.1；
- `proxy_request_buffering off`、`proxy_buffering off`、`proxy_cache off`、`gzip off`；
- `proxy_next_upstream off`，避免 POST 重试和重复计费；
- 一小时 send/read timeout，五秒 connect timeout；
- `proxy_pass` 只含 upstream，没有 URI 后缀，保留原 Path 与 Query；
- 覆盖 `X-Real-IP`、`X-Forwarded-*` 并清空客户端 `Forwarded`，只信任当前边缘 Nginx 建立的转发身份。

若 Nginx 前还有可信负载均衡器，应单独配置 real_ip 模块；不要直接恢复使用客户端传入的 `X-Forwarded-For`。

## 4. 多阶段镜像

根目录 `Dockerfile` 分三步：

1. Node 22 build stage 安装固定 pnpm 版本，使用 `pnpm-lock.yaml --frozen-lockfile` 构建 React/Vite 资源。
2. Go 1.25 build stage 将新 dist 覆盖到 embed 目录，并以 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 编译。
3. distroless nonroot 运行 stage 只复制 Go 二进制和空挂载目录。

最终镜像不含 Node、pnpm、`node_modules`、前端源码、Go 源码、编译器或 SQLite CLI。管理页面由 Go embed 提供。

## 5. Compose 网络

根目录 `compose.yaml` 使用一个私有 backend bridge network：

- Nginx 发布 `80:80`，所有请求只转发到 audit-proxy。
- audit-proxy 只 `expose` 数据端 `8080`，不发布到宿主机。
- 管理端只发布 `127.0.0.1:8081:8081`。
- NewAPI 只 `expose` `3000`。
- audit 与 NewAPI 使用独立 volume。

Docker 配置使用 `0.0.0.0:8080`/`0.0.0.0:8081` 是为了容器网络和 loopback 端口映射；它不代表管理端公开暴露。`admin_token` 仍必填；可选的 `newapi.access_token`/`newapi.user_id` 只用于只读同步安全用户目录和按 request ID 查询全站日志。承载这些凭证的配置文件必须限制宿主机权限。

NewAPI 镜像版本由使用者按现有部署固定到验证过的 tag/digest；audit-proxy 的 passthrough 不解析或修改 NewAPI 的非 LLM 路由。

## 6. Podman/WSL/Clash 显式上游代理

默认 `newapi.proxy_url: ""`，audit-proxy 直接连接 `newapi.url`，且不读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。只有运行环境确实无法直连远程 NewAPI 时才配置显式代理：

~~~yaml
newapi:
  url: https://newapi.example.com
  proxy_url: http://127.0.0.1:7897
  access_token: ""
  user_id: 0
~~~

上述 Podman/WSL 示例用于“单个 audit-proxy 容器 + 远程 `newapi.url`”，要求容器使用 host network，并在 WSL mirrored networking 下启用 host address loopback；host network 模式不再配置 `-p`/`ports`，应用自身继续监听需要的 `0.0.0.0` 端口。这样 `127.0.0.1:7897` 才能到达仅监听 Windows loopback 的 Clash mixed/HTTP 端口。默认 bridge 中的 `host.containers.internal` 可能只到 Podman bridge gateway，不能当作 Windows loopback 的等价地址。仓库三服务 Compose 保持 bridge + 本地 NewAPI 直连，不需要此设置；宿主机直接运行二进制时也通常写 `http://127.0.0.1:7897`。

此配置只改变 audit-proxy 到 `newapi.url` 的连接路径；审计分支、passthrough 分支、用户目录同步和 request-id 日志查询都使用同一显式代理设置，但只有配置 LLM route 会创建 audit。它不改变 NewAPI 自己访问模型供应商的网络。首版只支持无凭据的 HTTP(S) forward proxy，不支持 SOCKS、PAC 或环境变量自动发现。

## 7. 构建与部署材料

~~~text
Dockerfile
.dockerignore
compose.yaml
configs/audit-proxy.docker.yaml
configs/nginx/*
scripts/build.ps1
scripts/build.sh
doc/deployment/README.md
doc/deployment/backup-and-restore.md
~~~

构建脚本生成 Windows/Linux amd64 的 CGO=0 二进制。完整启动、配置校验、Nginx 校验和管理面检查见[单机部署说明](../deployment/README.md)。

## 8. 数据备份

数据库和 `audit.key` 必须作为一个备份集。在线数据库处于 WAL 模式时必须使用 SQLite `.backup`，不能直接复制主 DB 文件。最终镜像不为此加入 SQLite CLI；从宿主机或受控工具容器执行。详见[备份与恢复](../deployment/backup-and-restore.md)。

## 9. 验收

- Nginx 统一送入 audit-proxy，不存在可绕过进程内边界的 NewAPI fallback。
- `/v1/models` 等安全非 LLM 请求经 passthrough 到达 NewAPI，且不会产生 audit/interceptor 调用。
- 错误 Method、受保护 LLM 路径族、编码近似与危险路径返回 404，NewAPI 零调用。
- SSE 首块不因 Nginx buffering 延迟，原 Path/Query 保留。
- 模型 POST 不自动重试。
- 管理端只发布到宿主机 loopback，并始终要求 Bearer token 或有效管理 Cookie。
- `newapi.proxy_url` 空值不受环境代理影响；配置显式代理时，审计、passthrough、用户目录和 request-id 日志查询都能经代理到达远程 NewAPI，只有 LLM route 记录四阶段证据。
- `newapi.access_token`/`newapi.user_id` 配置后每五分钟同步安全用户目录，并异步回填 request ID 对应的用户/Token 身份；失败不影响转发，完整用户 API Key 不进入该链路。
- 最终镜像不含 Node 或源码，单一 Go 二进制提供 API 和 React UI。
- Windows/Linux amd64 CGO=0 构建成功。
- 实际部署环境中的 `nginx -t`、Compose 配置检查和 smoke test 有真实结果；未执行时明确记录为未验证。

首版不提供 metrics、在线导出、DELETE、自动 VACUUM 或复杂运行时重连。
