# AGENTS.md

本文件用于说明仓库目标、布局和主要架构方向。详细设计见 `doc/features/`。

## 项目方向

这是一个个人使用的单机 AI API 审计代理，部署在 Nginx 与 NewAPI 之间：

```text
客户端 -> Nginx
            |- LLM API 白名单 -> audit-proxy -> NewAPI
            `- NewAPI 其他路径 -> NewAPI
```

核心目标：

- 只透明转发指定的 OpenAI、Anthropic、Gemini LLM API 白名单接口。
- 流式保存客户端请求和 NewAPI 响应的原始证据。
- 在请求发往 NewAPI 前通过可插拔拦截链执行本地放行规则。
- 使用 SQLite 提供本地查询。
- 提供 React + shadcn/ui 管理页面。
- 解析失败或审计失败时不篡改请求和响应。

NewAPI 的健康检查、登录、管理、模型列表、前端页面及其他路径由 Nginx 直连，不进入本程序、不审计也不拦截。本项目也看不到 NewAPI 后方的渠道选择、厂商请求、厂商原始响应或内部重试。

## 仓库布局

```text
AI_API_AUDIT_PROXY_KICKOFF.md   # 原始需求
doc/features/                   # 总体方案和模块设计
doc/deployment/                 # 单机、容器与备份说明
Dockerfile / compose.yaml       # 多阶段镜像与单机 Compose

cmd/audit-proxy/                # 程序入口
internal/
  app/                          # 启动和组件组装
  config/                       # 配置
  routing/                      # 路径白名单
  interceptor/                  # 入站拦截器、注册表和执行链
  proxy/                        # HTTP 反向代理
  audit/                        # 审计会话、阶段与 Body 采集
  storage/sqlite/               # SQLite 读写和内嵌 migration
  parser/                       # OpenAI/Anthropic/Gemini 解析
  security/                     # 本地 AES-GCM 加密
  query/                        # 查询 API
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

- `proxy` 只负责透明转发，不解析协议、不直接操作 SQLite。
- `interceptor` 在 route match 后、访问 NewAPI 前运行；首个拒绝立即短路，模块异常默认拒绝。
- 拦截器只作用于 Nginx 选入且进程内 Matcher 命中的 LLM API 白名单；NewAPI 的健康检查、登录、管理、模型列表、前端页面和其他接口由 Nginx 直连，不进入本程序、不审计也不拦截。
- 默认拦截器只读请求元数据；需要 Body 的模块必须显式声明上限，并由框架统一预读和原字节回放，超限固定为 `413` 和 `block_code=body_too_large`。
- `audit` 的采集层只处理字节、长度、哈希和完整性状态。
- parser 在请求完成后异步运行，失败不影响转发。
- SQLite 使用单 writer goroutine，查询使用独立只读连接。
- 启动恢复、gap 和 retention 只维护审计数据，不改变代理字节路径。
- 管理端默认监听 `127.0.0.1`，但本机和非 loopback 访问管理 API 都必须使用同一个静态 Token。
- 敏感 Header、Body、Query 和解析全文使用一个本地 AES-256-GCM key 加密。
- 普通 JSON 日志只记录稳定状态和耗时，不记录 Query、Header value、Body、Token、key 或底层错误文本。

## 开发原则

- 优先保持实现简单、可读、单机可运行。
- 不为了未来扩展提前引入分布式组件或额外控制面。
- 不把 NewAPI 非 LLM 路径加入代理 route，也不允许 interceptor 扩大路径白名单。
- 原始证据比解析结果重要；解析结果可以重新生成。
- 新增审计路径时同时更新路由、parser、Nginx 示例和测试。
- 如果实现改变了观测边界或模块职责，先同步更新 `doc/features/README.md` 和对应模块文档。
