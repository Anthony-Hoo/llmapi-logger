# 当前版本部署入口

运行时已改为 PostgreSQL。请先按 [PostgreSQL 新部署/离线迁移](postgresql-migration.md) 配置并迁移；不得删除源 SQLite 审计数据来完成升级。当前备份步骤见 [备份与恢复](backup-and-restore.md)。

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

需要 Go 1.27+、Node 24 LTS 和 pnpm 10.15.0。两个脚本都会先用锁文件安装前端依赖并构建嵌入资源，再生成 `CGO_ENABLED=0` 的 Windows/Linux amd64 二进制：

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
bin/agent-packages/            # Agent 接入的 Skill 安装包（五个平台）与 manifest.json
~~~

`agent-packages/` 必须与 audit-proxy 二进制放在同一目录下，Agent 接入的下载接口从那里读取；只部署二进制而不带它时，代理照常运行，只是“Agent 接入”页生成不了安装提示词。

构建不会清空 `internal/web/dist`，以保留受跟踪的 `.gitkeep`。在同一工作区重复构建时，旧的哈希资源会一并嵌入二进制，但页面只引用最新资源。正式发布应使用干净 checkout 或 Docker 多阶段构建。

宿主机部署从 `configs/audit-proxy.example.yaml` 复制配置，至少替换 `admin_token` 并设置 `database_url`。若 NewAPI 允许长时间等待首包，将 `newapi.response_header_timeout_seconds` 设置为高于 NewAPI 自身超时，并同步提高 `shutdown_timeout_seconds`、Nginx read/send timeout 与容器 stop grace period。只有需要让 NewAPI 继续观察公网域名时才启用 `newapi.preserve_host`。如需识别“哪个 NewAPI 用户通过哪个 Token 发起请求”，再成对填写 `newapi.access_token` 与 `newapi.user_id`；它们只用于读取安全用户目录和按 request ID 查询全站日志。配置文件和 `audit.key` 只应允许运行账户读取。

代理和 Body interceptor 的传输上限为 512 MiB；异步 parser 为限制单 worker 内存，当前请求侧和响应侧各最多解码 64 MiB。超过 parser 上限的请求仍按原字节转发并保留 `full` raw，但不会生成 verified turn，也不会获得 item/binary 内容寻址压缩。部署前应根据真实请求分布确认 64 MiB 是否覆盖正常流量，不能把 512 MiB 传输上限当成 normalizer 上限。

启动前可以只校验配置：

~~~bash
./bin/audit-proxy-linux-amd64 \
  --config ./configs/audit-proxy.example.yaml \
  --validate-config
~~~

宿主机 Nginx 使用 `configs/nginx/llmapi-logger.conf` 时，把 `audit_proxy_backend` 从 Compose 服务名改成实际地址，通常是 `127.0.0.1:8080`。同时把应用配置的数据监听地址设为 `127.0.0.1:8080`。

### 2.1 PostgreSQL 切换

本版本不执行旧 generation 2 清库流程。保留原 SQLite 数据与密钥，按 [离线迁移](postgresql-migration.md) 导入空 PostgreSQL，验证后再切换。不要通过删除数据库来升级或释放空间。

## 3. Docker Compose

仓库根目录的 `compose.yaml` 提供 Nginx、audit-proxy、PostgreSQL 和 NewAPI 的最小组合：

- 只有 Nginx 的 `80` 对外发布。
- 管理端只发布为 `127.0.0.1:8081`。
- audit-proxy 数据端、PostgreSQL 和 NewAPI 只存在于 Compose 私有 bridge 网络，没有 host 端口；NewAPI 仍可访问外部模型供应商。
- audit 数据、本地暂存（3.2）、PostgreSQL 数据和 NewAPI 数据使用不同 volume。
- PostgreSQL 显式设置了几项内存、检查点和自动清理参数，起点按约 8 GB 内存的单机定，未经实测；各项作用、覆盖变量和改后要看的指标见[数据库参数](postgresql-migration.md#数据库参数)。

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

### 3.2 本地暂存目录（`audit.staging`）

采集会话把 Body 留在内存里：请求 Body 读完时、响应 Body 在请求结束时才写库（[模块 03](../features/03-audit-session-and-evidence-capture.md) §13）。单个阶段超过 `audit.memory.stage_bytes`（默认 8 MiB），或全进程预算 `global_bytes` 已满时，超出的部分先封成与 `body_chunks` 相同的密文块，写到 `audit.staging.dir` 下每条 audit 一个文件，提交时再读出写库，提交成功后删除文件。进程在提交前退出时，下次启动先把这些文件里的块导入数据库，再做中断恢复。

暂存目录里只有密文和块的元数据（阶段、序号、偏移、长度、时间），没有密钥；但它与数据库一样是证据的一部分，备份和权限按审计数据对待。

放在哪里：

- 用单独的卷。`compose.yaml` 为此加了命名卷 `audit-staging:/staging`，Docker 配置写 `audit.staging.dir: /staging`；镜像里预建了 `/staging`，属主是运行用户 65532，权限 0700。
- 卷要在与数据库同样可靠的盘上：文件按批 fsync，丢了它，超大 Body 在崩溃时的那部分证据也就没了。
- 不能放在只读根文件系统上，进程写不进去。
- 不能放在 `/tmp`：它是 64 MB 的 tmpfs，在内存里，容量不够，重启后清空，崩溃后导入不到任何东西。
- 不能放在密钥所在的目录 `/data`，也不能包含它或位于其中：配置校验会拒绝。暂存的密文和打开它的密钥不应在同一个卷、同一份备份里。

启动时检查目录：不存在就以 0700 创建；Linux 上要求属主是当前用户，权限不含组和其他用户；还要能在里面创建并删除一个探针文件。`audit.staging.dir` 必填。检查不通过时，两种模式下审计都不可用（以前 available 模式退回 legacy 写入，这条退路已经没有了）：日志 `audit staging unavailable` 的 `reason` 字段说明原因（`not_directory`、`wrong_owner`、`open_permissions`、`not_writable` 等），available 模式不审计照常转发，strict 模式准入回 503。

`audit.staging.max_bytes`（默认 4 GiB）限制目录里全部文件的大小。写满、磁盘满或写文件出错时，该阶段停止保留后续字节，阶段记为 partial，错误码为 `capture_budget_exhausted`（写错误为 `staging_write_failed`），raw 全部保留，转发不受影响。

导入时无法确认的文件不会被删：没有对应 audit、缺 Body 行、或 audit 已终结却缺文件里的块的改名为 `<audit_id>.orphan`；中间记录校验失败、文件头不是这条 audit、块与库里的接不上的改名为 `<audit_id>.corrupt`，导入其中校验通过的前半部分。这两类文件计入 `max_bytes`，确认无用后由运维手动清理。有文件读不出来（例如权限不对）时导入整体失败，审计不可用，日志 `audit staging import failed`；修好后重启。

终结提交最终失败时文件也留在目录里，计入 `max_bytes`。数据库恢复可写之后，writer 的恢复在把这条 audit 以 failed 终结的同一个事务里先写入暂存的块，提交后删除文件；进程在那之前退出时，下次启动照常导入。恢复插入暂存块被拒绝时 audit 照样终结，文件保留，下次启动改名为 `.orphan`（[模块 03](../features/03-audit-session-and-evidence-capture.md) §13.5）。

### 3.3 升级与回滚

legacy 写入路径已删去，`audit.write_path` 不再选择任何东西（[模块 01](../features/01-configuration-and-route-boundary.md) §4 第 18 项；设计实施记录 R.8）。升级之前：

1. **必须先准备暂存卷并配置 `audit.staging.dir`**（3.2）。这一项现在两种模式下都必填，没有它配置校验失败，进程拒绝启动。Docker 部署用 `compose.yaml` 的 `audit-staging` 卷和示例配置里的 `audit:` 段。
2. 配置里有 `write_path: legacy` 的要删掉这一行（或改成 `unified`）：它会被拒绝，错误说明 legacy 写入路径已在这个版本删去。
3. 以前 available 模式下暂存不可用会退回 legacy 写入；这个退路已经没有了。启动时暂存目录不可用（属主、权限、不是目录、不能写等），两种模式下审计都不可用：日志 `audit staging unavailable`（`error_category=staging_unavailable`，`reason` 说明原因），available 模式不审计照常转发，`/readyz` 降级；strict 模式拒绝白名单请求（503）。两种模式下审计存储都已关闭，管理端的查询、导出和 Agent 门面也读不到已有的记录，直到修好目录后重启。所以升级后看一眼启动日志和 `/readyz`。
4. 上一个版本留下的未终结 audit（legacy 写的采集版本 1）在第一次启动时照常恢复终结；版本 1 的旧行照常读取和校验，不改写。

回滚：没有切回的开关。回滚只能换回上一个版本的二进制，而 PostgreSQL 上这个版本写的是采集版本 2，更早的版本（不含迁移 007 的）读不了这些行，也打不开版本 7 的库：

1. 处理暂存目录。等待不会让它变空：`.stg` 文件只在提交得到确认或启动导入时删除，`.orphan`、`.corrupt` 从不自动删除。用当前版本加原来的 `staging.dir` 启动一次，确认目录里没有 `.stg` 文件；改名保留的文件由运维确认后手动处理（3.2）。
2. 停止新版本，做数据库与 `audit.key` 的联合备份。
3. 回到含迁移 007、仍有 legacy 路径的上一个版本时，它能读版本 2 的行，配置里的 `audit:` 段可以保留（去掉 `write_path` 或写 `unified`/`legacy`，那个版本两者都认）。
4. 回到更早、不含迁移 007 的版本时：删掉配置文件里的整个 `audit:` 段（旧版本按 `KnownFields` 加载配置，遇到不认识的段会拒绝启动），并撤销迁移。库里有版本 2 的行时，版本 7 的回滚 SQL 会报错并什么都不改，只能从写入版本 2 之前的备份恢复，并放弃之后的审计数据（[回滚到 schema 版本 6](postgresql-migration.md#回滚到-schema-版本-6)）。
5. 启动旧版本。

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

默认 Podman bridge 中的 `host.containers.internal` 可能只解析到容器 bridge gateway，而无法连接只监听 Windows loopback 的本地代理，因此不要把它当作本场景的替代方案。host network 会让容器监听直接进入 Podman/WSL 网络边界，只应在可信开发机上使用并配合主机防火墙。

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

当 LLM 响应包含 `X-Oneapi-Request-Id` 时，后台 worker 通过 `/api/log/?request_id=...` 精确查询并回填用户 ID、用户名、Token ID 和 Token 名称。NewAPI 日志可能延迟，因此任务会有限重试并把状态保存在 PostgreSQL；失败或最终未识别都不影响原请求。Web UI 按用户筛选，Token ID 放在高级筛选；系统不会读取、保存或展示用户完整 API Key。若不需要此功能，将 access_token 留空且 user_id 设为 0。

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

## 7. 数据、保留状态和备份

PostgreSQL 数据库与 `audit.key` 必须作为一个备份集保存，使用一致快照备份与已验证的恢复流程。具体流程见 [备份与恢复](backup-and-restore.md)。

普通 OpenAI 与 Anthropic 2xx/3xx 在 provider reconstruction 校验通过后进入 `metadata`：raw chunks 已释放，但长度、SHA-256、Content-Type、时间、对象图、重建 hash、SSE timeline 和完整性事件仍在。拦截、解析/normalization/重建失败和没有 turn 的异常保持两侧 `full`；两个请求阶段不完整或不一致时请求侧也保持 `full`。有 verified turn 的上游异常按侧保留（模块 18 §6）：响应侧 `full`；5xx、401、403、408、409、429、499、客户端取消，以及带 `upstream_error_class` 的 400/422，在两个请求阶段一致时请求侧释放为 `metadata`；`upstream_error_class` 为空的 400/422 和其他未列出的状态请求侧仍 `full`。验收脚本应分别验证 reconstructed API 与 full raw，不能把正常记录 raw、或异常记录的请求 raw 返回 410 误判为丢失。回滚到旧二进制能照常读取这些行，但按新规则写入的记录没有请求 raw 可以返回。

Anthropic Messages 自解析器版本 3 起写 turn 并释放 raw。写出这类记录后不能回退到更早的版本：旧版本不认识 `anthropic.*` 重建布局，这些记录的详情会报完整性错误，而 raw 已经释放。升级只能前滚。

最终镜像只包含 distroless 运行环境、Go 二进制、`/agent-packages` 下的 Skill 安装包和空的数据/配置挂载目录，不包含 Node、pnpm、前端源码、Go 源码或构建工具。

## 8. 上下文洞察

insights 默认启用，无需额外部署步骤。开关、NewAPI 实际计费、上下文窗口与词表覆盖、各客户端（Claude Code、Codex、OpenCode、dsh、ZCode、pi）的接入提示，以及自研 Agent 通过 X-Agent-* Header 归入 Agent 树的约定见[洞察与 Agent 接入指南](insights-and-agent-headers.md)。

## 9. Agent 接入（命令行与 Skill）

Agent 接入让用户本机的编码 Agent（Claude Code、Codex 一类）经命令行 `llmaudit` 代表用户查询审计记录、用量、周报与会话分析，管理员另可修改配置。它**默认关闭**，设计见[模块 25](../features/25-agent-access.md)，接口见[接口合同](../features/25-agent-access-contract.md)。

### 9.1 开启

~~~yaml
agent_access:
  enabled: true
  allow_write: false   # 默认只读；只有确实需要经 Agent 修改配置时才打开
  public_url: ""       # 写进安装提示词的地址；为空时使用浏览器当前访问的地址
~~~

开启后网页上出现“Agent 接入”页，两种身份都可见：

- 安装卡片：选择 Agent 种类与平台（可选填写 Skill 目录），生成一段安装提示词，交给本机的 Agent 逐步执行。提示词里带一条 30 分钟内有效、最多下载 30 次的签名链接，Agent 会核对 SHA-256 后才解压，只安装到以 `llmapi-audit` 结尾的目录，并在最后用浏览器授权登录、用 `llmaudit whoami` 验证。链接过期后回到这一页重新生成即可。
- 已授权设备：设备名、档位、签发与到期时间、最近使用时间，可逐个撤销。管理员另有“Agent 最近的改动”。

`public_url` 应是用户的 Agent 实际能访问到的管理面地址。为空时取浏览器这次访问的协议与 Host（不读 `X-Forwarded-*`），所以 TLS 终止在反向代理、或管理面挂在子路径下时必须设置它；它只能由 ASCII 字母、数字与 `-._~:/%[]` 组成，否则启动报错。管理面只在本机 loopback 上时，只有同一台机器上的 Agent 能用；要给其他机器用，必须有意暴露管理端口，后果见[模块 15](../features/15-nginx-and-deployment-integration.md) §1（本程序不提供 TLS；经同一反向代理的客户端共用一个限流计数桶）。

轮换 `admin_token` 会让全部 Agent 令牌和全部未过期的下载链接失效。

### 9.2 升级与回滚顺序

配置加载是严格模式，迁移 004 会让旧版本打不开审计存储，所以顺序是固定的：

- **升级**：先部署包含模块 25 的版本，此时配置里没有 `agent_access`，功能关闭，迁移 004 在启动时自动应用；确认运行正常后，再把 `agent_access` 段写进配置并重启。
- **回滚到不含模块 25 的版本**：
  1. 从配置里删掉整个 `agent_access` 段（包括 `enabled: false` 的写法），否则旧版本因未知键启动失败。
  2. 停止新版本后，在库里删除 `agent_tokens`、`agent_audit_log` 两张表，并删除 `schema_migrations` 里版本为 4 的行，否则旧版本因 schema 版本过新打不开审计存储（进程照常起来，`available` 模式不留 audit 照常转发，`strict` 模式回 `503`）。库的版本高于 4 时，先按 [PostgreSQL 运行与离线迁移](postgresql-migration.md)里的回滚各节，从新到旧撤销之后的迁移（现在是 007、006、005），再做这一步。操作前先做数据库与 `audit.key` 的联合备份（[备份与恢复](backup-and-restore.md)）。
  3. 再启动旧版本。已签发的 Agent 令牌随表一起消失；重新升级后用户需要重新授权。

~~~sql
-- 仅在回滚到不含模块 25 的版本时执行，并且先停止新版本、做好备份
BEGIN;
DROP TABLE IF EXISTS agent_audit_log;
DROP TABLE IF EXISTS agent_tokens;
DELETE FROM schema_migrations WHERE version = 4;
COMMIT;
~~~
