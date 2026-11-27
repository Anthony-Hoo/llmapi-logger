# AGENTS.md

本文件只说明仓库目标、布局和主要架构方向。详细设计见 `doc/features/`。

## 项目方向

这是一个个人使用的单机 AI API 审计代理，部署在客户端/Nginx 与 NewAPI 之间：

```text
客户端 -> Nginx -> data-plane dispatcher
                         |- 配置的 LLM API -> interceptor + audit proxy -> NewAPI
                         |- 安全的非 LLM API -> passthrough proxy --------> NewAPI
                         `- 受保护或危险的未匹配路径 -> 404
```

核心目标：

- 只对明确配置的 OpenAI、Anthropic、Gemini LLM API 路由执行拦截、审计和异步解析。
- 让 `/v1/models` 等真正无关的 NewAPI 请求透明直通，不创建 audit，也不执行 interceptor。
- 对配置路径的错误 Method、编码/双重编码变体、子路径、受保护模板路径族和危险路径 fail-closed，不能落入直通分支。
- 在四个代理观察点流式采集客户端请求与 NewAPI 响应；普通成功请求经内容重建验证后释放长期 raw；异常记录按侧保留：响应侧保留完整原始证据，已通过重建校验的请求侧按模块 18 §6 的状态码规则释放或保留。
- 使用 PostgreSQL、AES-256-GCM、内容寻址的 conversation/turn/multimodal object 和 React + shadcn/ui 提供本地审计、重建与异常证据查看。
- 解析或 available 模式下的审计失败不能篡改已经放行的请求和响应。

本项目只能看到代理与 NewAPI 边界，无法看到 NewAPI 后方的渠道选择、厂商原始请求/响应、内部重试或渠道密钥。

## 仓库布局

```text
AI_API_AUDIT_PROXY_KICKOFF.md   # 原始需求
README.md                       # 仓库用途与运行入口
doc/features/                   # 总体方案和模块设计
doc/deployment/                 # 单机、容器与备份说明
Dockerfile / compose.yaml       # 多阶段镜像与单机 Compose

cmd/audit-proxy/                # 程序入口
cmd/llmaudit/                   # Agent 接入的命令行（入口；逻辑在 internal/agentcli）
cmd/audit-bench/                # A/B 压测与存储 IO 测量工具（入口；逻辑在 internal/auditbench）
skill/llmapi-audit/             # Agent 接入的 Skill 包源文件（SKILL.md、references/）
internal/
  app/                          # 启动、组件组装和数据面三态分发
  config/                       # 配置
  routing/                      # LLM 白名单及安全直通边界
  interceptor/                  # 入站拦截器、注册表和执行链
  proxy/                        # 审计代理与无审计 passthrough 代理
  audit/                        # 审计会话、阶段与 Body 采集
  auditmodel/                   # canonical object、hash、delta 与重建
  bodycodec/                    # raw/timeline 自适应压缩
  headerblock/                  # 每条 audit 一个 Header 块的编码、密封与读取（capture_version 2）
  newapi/                       # NewAPI 安全用户目录与 request-id 调用者解析
  conversation/                 # 协议无关的消息、reasoning、工具调用与结果 DTO
  storage/postgres/             # PostgreSQL 读写和内嵌 migration
  storage/sqlite/               # 旧格式离线导入验证与兼容测试
  storage/migrate/              # 只读 SQLite 到空 PostgreSQL 的离线迁移
  parser/                       # OpenAI/Anthropic/Gemini 摘要与 conversation 聚合
  security/                     # 本地 AES-GCM 加密
  query/                        # 受保护的查询与证据解密
  retention/                    # 简单保留清理
  streamtimeline/               # SSE offset/time delta 编解码
  observability/                # 安全 JSON 请求日志
  agentapi/                     # Agent 门面与命令行共用的信封、错误码、接口登记表（只依赖标准库）
  agentaccess/                  # Agent 令牌、授权码、计划、限流与审计
  agentcli/                     # 命令行 llmaudit 的实现
  agentdist/                    # Skill 安装包：清单、签名下载链接、下载处理、安装提示词、可重复打包
  protofixture/                 # 四协议确定性合成流量夹具与 fake upstream
  auditbench/                   # audit-bench 的实现：负载驱动、统计快照、结果与对比、只读分布
  web/
    frontend/                   # React、Vite、shadcn/ui 源码
    dist/                       # 构建后由 Go embed 的静态产物

configs/                        # 应用与 Nginx 示例配置
scripts/                        # Windows/Linux 发布构建
tests/                          # 跨模块集成测试
```

## 架构边界

- `app` 的 data-plane dispatcher 是统一入口：精确 route match 进入审计代理；安全且无关的路径进入 passthrough；其余请求交给审计代理返回固定 `404`。
- `routing` 同时维护配置路由与受保护路径族。错误 Method、配置 exact 路径的后代、template 前缀家族、编码等价形式和非规范路径都不得直通。
- `interceptor` 只在 route match 后、访问 NewAPI 前运行；首个拒绝立即短路，模块异常默认拒绝。interceptor 不能扩大路由范围。
- 默认拦截器只读请求元数据；需要 Body 的模块必须声明上限，由框架统一预读并原字节回放，超限固定为 `413` 和 `block_code=body_too_large`。
- passthrough 与审计代理共享 NewAPI rewrite 和显式上游代理设置，但 passthrough 不创建 audit、不解析、不执行 interceptor，也不写 LLM 请求完成日志。
- `audit` 采集层只处理字节、长度、哈希、时间和完整性状态；四阶段先独立采集，只有终结事务确认成对 Body 完全一致才合并 `source_stage`。parser 在请求完成后异步生成摘要；OpenAI、Anthropic 与 Gemini normalizer 再写可分支 turn、content/binary object、重建 hash 和 raw retention，失败不影响转发。
- 可选的 `newapi` 集成只读同步安全用户目录，并用上游 `X-Oneapi-Request-Id` 查询全站日志回填用户与 Token 身份；不读取或保存完整 API Key，解析失败不影响转发。
- PostgreSQL 使用持有 session advisory lock 的固定连接和单 writer goroutine，查询使用独立只读连接；多语句证据快照使用 repeatable read。启动恢复、gap 和 retention 只维护审计数据，不改变代理字节路径。
- 管理 API、health 和 ready 在任何监听地址都必须鉴权：CLI 使用静态 Admin Token，Web UI 使用由该 Token 登录换取的七天 HttpOnly Cookie。可选的 `developer_login` 提供第二种身份：NewAPI 用户用自己的 API Key 登录，以同等只读深度只能看到该 Key 产生的记录；管理端点返回 403，他人记录与本地策略拦截记录返回 404。作用域由主密钥派生的 keyed 指纹加既有 token 关联判定，系统仍不保存完整或打码 API Key。审计主列表只展示调用者、时间、模型、入站 User-Agent、会话归属标识与 scope 内轮次计数；普通列表会逐条只解密该 User-Agent 供展示和子串筛选，不读取其他 Header、Request-URI、Body 或 conversation 内容。详情按需重建 verified conversation/provider JSON；raw request/response Body 只对 `retention_state=full` 开放；assistant 文本使用禁用原始 HTML 的安全 Markdown 展示。
- 可选的 `agent_access`（默认关闭，模块 25）提供第三种管理面凭据 Agent 令牌：由网页会话在授权确认页签发给本机命令行 `llmaudit`，只能调用 `/api/agent/v1/*` 门面，身份与可见范围同签发它的会话，库里只存 HMAC；门面不接受 Cookie 与管理 Token，`/api/v1/*` 也不接受 Agent 令牌。门面下只有两条匿名路径：`POST /api/agent/v1/token`（一次性授权码加 PKCE 兑换令牌）与 `GET /api/agent/v1/dl/<签名>/<文件名>`（凭 `admin_token` 派生密钥签名、30 分钟有效的链接下载清单内的 Skill 安装包）。门面只组合既有服务，不复制业务校验；凭据类 Header 与查询参数的值不输出，分析模型的 API Key 只能由用户在终端输入。
- 敏感 Header、raw Body、Query、fallback conversation、content/binary object 和 timeline 使用一个本地 AES-256-GCM key 加密；管理证据响应使用 `Cache-Control: no-store`。
- 普通 JSON 日志只记录稳定状态和耗时，不记录 Query、Header value、Body、Token、key、密文或底层错误文本。

## 方向原则

- 优先保持实现简单、可读、单机可运行，不提前引入分布式组件或额外控制面。经确认的例外是模块 25 的 Agent 门面 `/api/agent/v1/*`：它是给本机编码 Agent 用的第二个管理入口，但只组合网页已有的服务，授权与能力都以网页为准，默认关闭。
- `routes` 只描述需要审计的 LLM API，不用于枚举 NewAPI 的全部普通接口。
- 四阶段长度/hash、内容对象、重建校验和完整性链共同构成长期证据；逐字节 raw 只对异常记录的保留侧长期承诺，规则见模块 18 §6（异常记录的响应侧总是保留，请求侧只在没有 turn、两个请求阶段不一致、`upstream_error_class` 为空的 400/422 或未列出的状态时保留；响应不完整、因响应而解析不完整或未被规范化、但请求可用的记录得到只有请求的轮次，响应侧保留、请求侧同样按此规则判定）。
- 新增审计路径时同时更新 route、受保护路径边界、parser、Nginx 示例和测试。
- 改变观测边界或模块职责时同步更新 `doc/features/README.md` 和对应模块文档。

## 敏感信息与公开发布边界

- 本仓库及其 Git 历史、GitHub 分支、PR、Issue、Actions 日志和发布产物一律按公开信息处理。
- 禁止提交真实公司/组织名称、生产域名、服务器地址或账号、本地主机名和绝对路径、客户数据、API Key、Access Token、Admin Token、密码、私钥、证书私钥、完整 DSN、`audit.key` 或其他可用于访问真实环境的信息。
- 示例只能使用占位符、`example.com` 和 RFC 文档保留地址；测试不得嵌入任何真实生产标识或凭据。
- 真实值只能保存在仓库外的受限文件，或 `.gitignore` 已覆盖的本地 `.env.local`、私密配置覆盖文件中。部署自动化可以把环境变量作为输入，生成仓库外的只读运行时 YAML；生成文件不得回写或提交到本仓库。
- audit-proxy 当前读取 YAML 配置，并不会因为变量存在于 `.env.local` 就自动读取它们。使用环境变量时，必须由部署脚本、systemd/容器入口或其他受控工具显式渲染运行时配置。
- 不在命令、测试失败信息、普通日志或配置回显中输出完整敏感值。提交、变基和推送前必须扫描暂存区及最终提交范围。
- 与私有运维知识库协作时，公开仓库只保留脱敏模板、变量名和操作原则；真实环境资料只进入明确授权的私有知识库或凭据存储。
