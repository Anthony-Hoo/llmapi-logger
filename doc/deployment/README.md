# 单机部署

本项目的生产形态是一个 Go 二进制。React 管理页面已经嵌入二进制，运行时不需要 Node、pnpm 或 Vite。

## 1. 网络边界

推荐拓扑：

~~~text
Internet/LAN -> Nginx :80
                  `- 全部数据面 -> audit-proxy :8080 dispatcher -> NewAPI :3000

localhost -> audit-proxy management :8081
~~~

- 数据端口 `8080` 只允许 Nginx 访问。
- 管理端口 `8081` 只发布到宿主机 `127.0.0.1`，但 `/healthz`、`/readyz` 和 `/api/v1/*` 仍全部要求 Bearer token。
- 配置的 LLM route 执行拦截与审计；NewAPI 登录、管理、模型列表、页面和健康检查等安全非 LLM 请求经 passthrough 转发，不创建 audit。
- 错误 Method、受保护 LLM 路径族、编码近似和危险路径在进程内返回 404，不访问 NewAPI。

## 2. 本机构建

需要 Go 1.25+、Node 22+ 和 pnpm。两个脚本都会先用锁文件安装前端依赖并构建嵌入资源，再生成 `CGO_ENABLED=0` 的 Windows/Linux amd64 二进制：

~~~powershell
.\scripts\build.ps1
~~~

~~~bash
bash ./scripts/build.sh
~~~

输出：

~~~text
bin/audit-proxy-windows-amd64.exe
bin/audit-proxy-linux-amd64
~~~

宿主机部署从 `configs/audit-proxy.example.yaml` 复制配置，至少替换 `admin_token`。若 NewAPI 允许长时间等待首包，将 `newapi.response_header_timeout_seconds` 设置为高于 NewAPI 自身超时，并同步提高 `shutdown_timeout_seconds`、Nginx read/send timeout 与容器 stop grace period。只有需要让 NewAPI 继续观察公网域名时才启用 `newapi.preserve_host`。如需识别“哪个 NewAPI 用户通过哪个 Token 发起请求”，再成对填写 `newapi.access_token` 与 `newapi.user_id`；它们只用于读取安全用户目录和按 request ID 查询全站日志。配置文件和 `audit.key` 只应允许运行账户读取。

启动前可以只校验配置：

~~~bash
./bin/audit-proxy-linux-amd64 \
  --config ./configs/audit-proxy.example.yaml \
  --validate-config
~~~

宿主机 Nginx 使用 `configs/nginx/llmapi-logger.conf` 时，把 `audit_proxy_backend` 从 Compose 服务名改成实际地址，通常是 `127.0.0.1:8080`。同时把应用配置的数据监听地址设为 `127.0.0.1:8080`。

## 3. Docker Compose

仓库根目录的 `compose.yaml` 提供 Nginx、audit-proxy 和 NewAPI 的最小组合：

- 只有 Nginx 的 `80` 对外发布。
- 管理端只发布为 `127.0.0.1:8081`。
- audit-proxy 数据端和 NewAPI 只存在于 Compose 私有 bridge 网络，没有 host 端口；NewAPI 仍可访问外部模型供应商。
- audit 数据和 NewAPI 数据使用不同 volume。

首次启动前编辑 `configs/audit-proxy.docker.yaml`，把示例 `admin_token` 替换为随机长 token，并限制文件权限。需要 NewAPI 调用者识别时同时填写 `newapi.access_token` 和正整数 `newapi.user_id`；两项都留空/0 时关闭该功能。正式使用时也应把 `compose.yaml` 中的 NewAPI 镜像固定到自己验证过的 tag 或 digest。

### 3.1 敏感配置与环境变量注入

仓库中的 YAML 只能保存占位符。真实生产域名、主机信息、API Key、NewAPI 管理凭据和 Admin Token 不得进入本仓库的 Git 历史、GitHub 分支、PR、Issue 或 CI 日志。

本地自动化可以从根目录 `.env.example` 复制出 `.env.local` 作为私密数据源；`.env.local` 已由 `.gitignore` 排除。建议只保存部署脚本需要的变量，例如 `LLMAPI_DEPLOY_HOST`、`LLMAPI_PUBLIC_BASE_URL`、`LLMAPI_VALIDATION_API_KEY`、`LLMAPI_VALIDATION_MODEL`、`LLMAPI_NEWAPI_ACCESS_TOKEN` 和 `LLMAPI_NEWAPI_USER_ID`，并把文件权限限制为当前维护账户可读。

audit-proxy 当前只读取 YAML，不直接读取上述环境变量。部署脚本必须在仓库外生成权限受限的运行时配置，例如 `/etc/audit-proxy/config.yaml`，再以只读方式挂载或传给进程；本地渲染文件可使用 `configs/*.local.yaml`、`configs/*.private.yaml` 或 `configs/*.runtime.yaml` 命名，这些名称也已被忽略。不要提交渲染结果，也不要在日志中输出完整环境变量或完整渲染配置。

私有运维知识库可以在得到维护负责人授权后保存真实资料；从私有知识库派生到本仓库的任何内容仍必须先脱敏。

~~~bash
docker compose build audit-proxy
docker compose up -d
~~~

配置校验和管理面检查：

~~~bash
docker compose run --rm --no-deps audit-proxy \
  --config /etc/audit-proxy/config.yaml --validate-config

curl -H 'Authorization: Bearer REPLACE_ME' \
  http://127.0.0.1:8081/healthz

curl -H 'Authorization: Bearer REPLACE_ME' \
  http://127.0.0.1:8081/readyz
~~~

`/healthz` 只表示进程存活。`/readyz` 返回 `healthy`、`degraded` 或 `not_ready`；available 模式下审计依赖不可用会降级但继续转发，strict 模式下会以 `503 not_ready` 拒绝新的白名单请求。

## 4. 显式上游代理（Podman/WSL/Clash）

audit-proxy 默认直接连接 `newapi.url`，不会读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。如果远程 NewAPI 在 Podman/WSL 中因 DNS、Fake-IP 或网络策略无法直连，可在应用配置中明确指定一个 HTTP(S) forward proxy：

~~~yaml
newapi:
  url: https://newapi.example.com
  proxy_url: http://127.0.0.1:7897
  response_header_timeout_seconds: 300
  preserve_host: false
  access_token: ""
  user_id: 0
~~~

宿主机直接运行 audit-proxy 时，上述地址会直接连接 Clash loopback。Podman/WSL 容器要连接仅监听 Windows `127.0.0.1` 的 Clash，使用已验证的最小组合：

1. Windows 用户目录的 `.wslconfig` 使用 mirrored networking，并启用 host address loopback：

   ~~~ini
   [wsl2]
   networkingMode=Mirrored

   [experimental]
   hostAddressLoopback=true
   ~~~

   修改后重启 WSL 和 Podman Machine。
2. audit-proxy 容器使用 host network。
3. 不再配置 `-p` 或 Compose `ports`；应用自身监听 `0.0.0.0:8080` 和 `0.0.0.0:8081`。
4. `newapi.proxy_url` 设置为 Clash 的 loopback mixed/HTTP 地址，例如 `http://127.0.0.1:7897`。

这套步骤用于“单个 audit-proxy 容器 + 远程 NewAPI”。仓库默认的 Nginx/audit-proxy/NewAPI 三服务 Compose 继续使用 bridge，让 audit-proxy 直连 Compose 内的 NewAPI，不需要为了本功能改成 host network。

默认 Podman bridge 中的 `host.containers.internal` 可能只解析到 bridge gateway（例如 `10.88.0.1`），无法连接只监听 Windows loopback 的 Clash，因此不要把它当作本场景的替代方案。host network 会让容器监听直接进入 Podman/WSL 网络边界，只应在可信开发机上使用并配合主机防火墙。

配置为空字符串时强制直连：

~~~yaml
newapi:
  url: https://newapi.example.com
  proxy_url: ""
  response_header_timeout_seconds: 300
  preserve_host: false
  access_token: ""
  user_id: 0
~~~

该代理用于 audit-proxy 到 `newapi.url` 的全部出站请求，包括审计分支、passthrough、安全用户目录和 request-id 日志查询；只有配置 LLM route 会创建 audit。它不会配置 NewAPI 到模型供应商的出口。首版不支持 SOCKS、PAC、代理凭据或环境变量自动发现。修改后重启 audit-proxy，再分别验证一条带有效上游凭据的 LLM 请求和一个 `/v1/models` passthrough 请求。

## 5. NewAPI 调用者身份

`newapi.access_token` 和 `newapi.user_id` 是一对可选的 NewAPI 管理凭证。配置后，audit-proxy 启动时读取一次 `/api/user/`，之后每五分钟刷新，只保留用户 ID、用户名、显示名、状态和分组等安全字段。刷新失败不影响 LLM 转发，并继续使用上一份成功快照。

当 LLM 响应包含 `X-Oneapi-Request-Id` 时，后台 worker 通过 `/api/log/?request_id=...` 精确查询并回填用户 ID、用户名、Token ID 和 Token 名称。NewAPI 日志可能延迟，因此任务会有限重试并把状态保存在 SQLite；失败或最终未识别都不影响原请求。Web UI 按用户筛选，Token ID 放在高级筛选；系统不会读取、保存或展示用户完整 API Key。若不需要此功能，将 access_token 留空且 user_id 设为 0。

## 6. Nginx 路由保证

`configs/nginx/llmapi-logger.conf` 把全部数据面请求统一送进 audit-proxy。进程内 routes 只审计以下 Method + Path：

~~~text
/v1/chat/completions
/v1/completions
/v1/responses
/v1/responses/compact
/v1/messages
/v1beta/models/<model>:generateContent
/v1beta/models/<model>:streamGenerateContent
~~~

Gemini 的 `<model>` 只允许字母、数字、点、下划线和连字符。`/v1/models` 等安全非 LLM 路径由 passthrough 转发；相同 LLM 路径的非 POST、受保护路径家族、编码近似和危险路径固定返回 404。

公共代理片段明确关闭请求/响应 buffering、cache、gzip 和 upstream retry。`proxy_pass` 没有 URI 后缀，因此保留原 Path 和 Query。转发身份 Header 由边缘 Nginx 覆盖，不接受客户端伪造的 `X-Forwarded-For` 或 `Forwarded` 值。示例 read/send timeout 为 `65m`，用于覆盖最高 `3900s` 的长流部署；实际值必须不短于应用的响应头等待策略。

配置变更后应在实际部署环境执行：

~~~bash
nginx -t
# 或
docker compose exec nginx nginx -t
~~~

然后分别验证一个审计流式请求、一个 `/v1/models` passthrough 请求，以及一个错误 Method/编码近似的 fail-closed 请求。仓库不把未实际运行的 Docker/Nginx smoke test 记为通过。

## 7. 数据和备份

SQLite 数据库与 `audit.key` 必须作为一个备份集保存。运行中不能直接复制 `audit.db`；在线备份必须使用 SQLite `.backup`。具体流程见 [备份与恢复](backup-and-restore.md)。

最终镜像只包含 distroless 运行环境、Go 二进制和空的数据/配置挂载目录，不包含 Node、pnpm、前端源码、Go 源码或构建工具。
