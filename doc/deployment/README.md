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

## 4. Nginx 路由保证

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

## 5. 数据和备份

SQLite 数据库与 `audit.key` 必须作为一个备份集保存。运行中不能直接复制 `audit.db`；在线备份必须使用 SQLite `.backup`。具体流程见 [备份与恢复](backup-and-restore.md)。

最终镜像只包含 distroless 运行环境、Go 二进制和空的数据/配置挂载目录，不包含 Node、pnpm、前端源码、Go 源码或构建工具。
