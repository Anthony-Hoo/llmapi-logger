# 单机部署

本项目的生产形态是一个 Go 二进制。React 管理页面已经嵌入二进制，运行时不需要 Node、pnpm 或 Vite。

## 1. 网络边界

推荐拓扑：

~~~text
Internet/LAN -> Nginx :80
                  |- LLM POST 白名单 -> audit-proxy :8080 -> NewAPI :3000
                  `- 其他请求 ---------------------> NewAPI :3000

localhost -> audit-proxy management :8081
~~~

- 数据端口 `8080` 只允许 Nginx 访问。
- 管理端口 `8081` 只发布到宿主机 `127.0.0.1`，但 `/healthz`、`/readyz` 和 `/api/v1/*` 仍全部要求 Bearer token。
- NewAPI 的登录、管理、模型列表、页面、健康检查以及任何非白名单请求不进入 audit-proxy。

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

宿主机部署从 `configs/audit-proxy.example.yaml` 复制配置，至少替换 `admin_token`。配置文件和 `audit.key` 只应允许运行账户读取。

启动前可以只校验配置：

~~~bash
./bin/audit-proxy-linux-amd64 \
  --config ./configs/audit-proxy.example.yaml \
  --validate-config
~~~

宿主机 Nginx 使用 `configs/nginx/llmapi-logger.conf` 时，把两个 upstream 地址从 Compose 服务名改成实际地址，通常是 `127.0.0.1:8080` 和 `127.0.0.1:3000`。同时把应用配置的数据监听地址设为 `127.0.0.1:8080`。

## 3. Docker Compose

仓库根目录的 `compose.yaml` 提供 Nginx、audit-proxy 和 NewAPI 的最小组合：

- 只有 Nginx 的 `80` 对外发布。
- 管理端只发布为 `127.0.0.1:8081`。
- audit-proxy 数据端和 NewAPI 只存在于 Compose 私有 bridge 网络，没有 host 端口；NewAPI 仍可访问外部模型供应商。
- audit 数据和 NewAPI 数据使用不同 volume。

首次启动前编辑 `configs/audit-proxy.docker.yaml`，把示例 `admin_token` 替换为随机长 token，并限制文件权限。正式使用时也应把 `compose.yaml` 中的 NewAPI 镜像固定到自己验证过的 tag 或 digest。

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

audit-proxy 默认直接连接 `newapi_url`，不会读取 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。如果远程 NewAPI 在 Podman/WSL 中因 DNS、Fake-IP 或网络策略无法直连，可在应用配置中明确指定一个 HTTP(S) forward proxy：

~~~yaml
newapi_url: https://newapi.example.com
newapi_proxy_url: http://127.0.0.1:7897
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
4. `newapi_proxy_url` 设置为 Clash 的 loopback mixed/HTTP 地址，例如 `http://127.0.0.1:7897`。

这套步骤用于“单个 audit-proxy 容器 + 远程 NewAPI”。仓库默认的 Nginx/audit-proxy/NewAPI 三服务 Compose 继续使用 bridge，让 audit-proxy 直连 Compose 内的 NewAPI，不需要为了本功能改成 host network。

默认 Podman bridge 中的 `host.containers.internal` 可能只解析到 bridge gateway（例如 `10.88.0.1`），无法连接只监听 Windows loopback 的 Clash，因此不要把它当作本场景的替代方案。host network 会让容器监听直接进入 Podman/WSL 网络边界，只应在可信开发机上使用并配合主机防火墙。

配置为空字符串时强制直连：

~~~yaml
newapi_proxy_url: ""
~~~

该代理只用于 audit-proxy 到 `newapi_url` 的白名单请求，不会接管 Nginx 直连的 NewAPI 登录、管理、模型列表或页面请求，也不会配置 NewAPI 到模型供应商的出口。首版不支持 SOCKS、PAC、代理凭据或环境变量自动发现。修改后重启 audit-proxy，再通过一条带有效上游凭据的白名单请求验证响应和 audit 记录。

## 5. Nginx 路由保证

`configs/nginx/llmapi-logger.conf` 只把以下大小写敏感、完整路径匹配的 `POST` 请求送进 audit-proxy：

~~~text
/v1/chat/completions
/v1/completions
/v1/responses
/v1/responses/compact
/v1/messages
/v1beta/models/<model>:generateContent
/v1beta/models/<model>:streamGenerateContent
~~~

Gemini 的 `<model>` 只允许字母、数字、点、下划线和连字符；正则从路径开头锚定到结尾。相同路径上的非 POST 请求及所有其他路径都直连 NewAPI。

公共代理片段明确关闭请求/响应 buffering、cache、gzip 和 upstream retry。`proxy_pass` 没有 URI 后缀，因此保留原 Path 和 Query。转发身份 Header 由边缘 Nginx 覆盖，不接受客户端伪造的 `X-Forwarded-For` 或 `Forwarded` 值。

配置变更后应在实际部署环境执行：

~~~bash
nginx -t
# 或
docker compose exec nginx nginx -t
~~~

然后分别验证一个白名单流式请求和一个 NewAPI 非白名单请求。仓库不把未实际运行的 Docker/Nginx smoke test 记为通过。

## 6. 数据和备份

SQLite 数据库与 `audit.key` 必须作为一个备份集保存。运行中不能直接复制 `audit.db`；在线备份必须使用 SQLite `.backup`。具体流程见 [备份与恢复](backup-and-restore.md)。

最终镜像只包含 distroless 运行环境、Go 二进制和空的数据/配置挂载目录，不包含 Node、pnpm、前端源码、Go 源码或构建工具。
