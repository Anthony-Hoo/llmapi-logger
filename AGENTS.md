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
- 流式保存客户端请求与 NewAPI 响应在四个代理观察点的原始证据。
- 使用 SQLite、AES-256-GCM 和 React + shadcn/ui 提供本地查询、协议无关对话审计与原始证据查看。
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
internal/
  app/                          # 启动、组件组装和数据面三态分发
  config/                       # 配置
  routing/                      # LLM 白名单及安全直通边界
  interceptor/                  # 入站拦截器、注册表和执行链
  proxy/                        # 审计代理与无审计 passthrough 代理
  audit/                        # 审计会话、阶段与 Body 采集
  newapi/                       # NewAPI 已打码 Token 目录同步与请求关联
  conversation/                 # 协议无关的消息、reasoning、工具调用与结果 DTO
  storage/sqlite/               # SQLite 读写和内嵌 migration
  parser/                       # OpenAI/Anthropic/Gemini 摘要与 conversation 聚合
  security/                     # 本地 AES-GCM 加密
  query/                        # 受保护的查询与证据解密
  retention/                    # 简单保留清理
  observability/                # 安全 JSON 请求日志
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
- `audit` 采集层只处理字节、长度、哈希和完整性状态；parser 在请求完成后异步生成非敏感摘要和协议无关 conversation，失败不影响转发。
- 可选的 `newapi` 目录只读同步 NewAPI 已打码 Token 元数据；请求关联只保存 Token ID、名称和 `masked_key` 快照，刷新或关联失败不影响转发。
- SQLite 使用单 writer goroutine，查询使用独立只读连接。启动恢复、gap 和 retention 只维护审计数据，不改变代理字节路径。
- 管理 API、health 和 ready 在任何监听地址都必须鉴权：CLI 使用静态 Admin Token，Web UI 使用由该 Token 登录换取的七天 HttpOnly Cookie。列表不返回敏感值；详情可按授权返回 conversation、Request-URI 与每个 Header/Trailer 值，raw request/response Body 只按需解密读取；assistant 文本使用禁用原始 HTML 的安全 Markdown 展示。
- 敏感 Header、Body、Query 和 conversation 全文使用一个本地 AES-256-GCM key 加密；管理 JSON 和 raw 响应使用 `Cache-Control: no-store`。
- 普通 JSON 日志只记录稳定状态和耗时，不记录 Query、Header value、Body、Token、key、密文或底层错误文本。

## 方向原则

- 优先保持实现简单、可读、单机可运行，不提前引入分布式组件或额外控制面。
- `routes` 只描述需要审计的 LLM API，不用于枚举 NewAPI 的全部普通接口。
- 原始证据比解析结果重要；解析结果可以重新生成。
- 新增审计路径时同时更新 route、受保护路径边界、parser、Nginx 示例和测试。
- 改变观测边界或模块职责时同步更新 `doc/features/README.md` 和对应模块文档。
