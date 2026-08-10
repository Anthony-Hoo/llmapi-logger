# NewAPI 下游 AI 接口审计前置代理——项目需求启动文档

版本：0.2　状态：开发启动基线

## 1. 项目目标与审计边界

开发一个部署在 Nginx 与 NewAPI 之间的透明审计代理，只记录下游客户端调用 NewAPI 指定模型接口时的完整 HTTP 请求与响应。

```text
AI 客户端 → Nginx ─┬─ 指定模型接口 → 审计代理 → NewAPI
                    └─ 其他所有接口 ─────────→ NewAPI

NewAPI → 上游渠道/模型厂商（不经过本项目，不在审计范围内）
```

本项目能记录的是“客户端请求”和“NewAPI 响应”。它不能看到 NewAPI 实际选择的渠道、发给厂商的请求、厂商原始响应、重试过程或渠道密钥；代码、字段名、页面和文档均不得暗示具备这些能力。

首版采用 **Go + SQLite（WAL）**。DuckDB 只可用于后续离线查询或 Parquet 分析，不进入转发热路径。优先级为：**转发兼容性 > 审计证据完整性 > 查询体验**。

## 2. 需要审计的接口

首版只为以下协议实现独立识别与解析器，路由规则必须可配置：

| 协议 | 默认纳入审计的 NewAPI 路径 |
| --- | --- |
| OpenAI 兼容 | `/v1/chat/completions`、`/v1/completions`、`/v1/responses`、`/v1/responses/compact`；embedding、rerank、图片和音频路径可按配置显式启用 |
| Anthropic | `/v1/messages` |
| Gemini | `/v1beta/models/{model}:generateContent`、`/v1beta/models/{model}:streamGenerateContent`；兼容部署可配置 `/v1/models/{model}:*` |

必须采用精确路径或受控正则白名单，不能简单拦截整个 `/v1`。`/health`、登录、用户、管理、计费、模型列表等非白名单路径，以及 NewAPI 的前端页面，均由 Nginx 直接转发到 NewAPI，不进入审计代理、不产生审计记录。

每种协议在保留原始证据之外生成独立的派生字段，例如模型、是否流式、消息/输入、工具调用、usage、响应 ID 和错误信息。解析失败只标记 `parse_error`，不得影响转发或丢弃原始记录。新增协议应通过新增解析器和路由配置完成，不能修改通用转发逻辑。

## 3. 转发兼容性要求

- 审计代理只有一个业务后端：NewAPI。保留原始 Method、Path、Query、Body 字节及所有端到端 Header；`Host` 可按 NewAPI 地址显式设置，并同时记录入站值与实际出站值。
- 响应状态码、Header、Trailer 和 Body 必须按从 NewAPI 收到的内容返回。禁止 JSON 反序列化后重新序列化，禁止修改模型名、认证信息、提示词、工具调用或 SSE 事件。
- 请求和响应都必须边转发边旁路记录，不能为了审计完整缓冲 Body。SSE 收到后立即 Flush，保持事件字节与顺序；解析器不得位于转发关键路径。
- 支持 JSON、gzip、multipart、二进制、大 Body、空 Body、长连接、客户端取消与背压；关闭自动响应解压/再压缩。HTTP hop-by-hop Header 和分块方式允许由标准代理库按规范重建，但必须有明确说明。
- 不实现协议转换、模型路由、自动重试、缓存、Key 池、内容过滤或计费。WebSocket/Realtime 不在首版审计范围，Nginx 配置不得把它误路由后声称已记录。
- 同时记录与 Nginx 的 socket 对端和真实客户端 IP；后者只信任由受控 Nginx 覆盖写入的 `X-Real-IP` / `X-Forwarded-For`，部署文档必须说明信任边界。

## 4. 审计记录与本地能力

每次白名单调用生成唯一 `audit_id`，至少保存：

- 从 Nginx 收到的请求、实际发给 NewAPI 的请求、从 NewAPI 收到的响应，以及实际返回的响应；各阶段名称必须明确包含“NewAPI”，避免与厂商上游混淆。
- 时间、TTFT、客户端地址、NewAPI 地址、HTTP 版本、Method、Host、原始 Path/Query、状态码、重复 Header、Trailer、错误、取消方和完整性状态。
- 请求/响应原始 Body、长度和 SHA-256；流式内容保存方向、序号、时间和原始字节块。解析后的 JSON/SSE 视图只是索引，不能替代原始证据。
- 默认完整保存；若配置 Body 上限，仍需继续计算完整长度与哈希，并记录截断位置和原因。
- 可选只读关联 NewAPI 数据库，将下游令牌映射为 token ID/名称；关联失败不得影响转发，令牌明文不得出现在普通列表或日志中。

SQLite 使用 WAL、migration、单写队列和批量事务；提供保留天数、磁盘配额、清理与导出。提供默认仅监听 loopback 的查询 API/简洁页面，可按时间、`audit_id`、协议、路径、模型、状态码和 token 名称筛选。

敏感 Header 和 Body 必须加密落盘，页面默认脱敏，解密查看需要鉴权并记录查看行为。支持 `available`（转发优先并告警审计缺口）和 `strict`（无法可靠审计时拒绝白名单请求）两种运行策略。

## 5. Nginx 配置文档要求

交付 `docs/nginx.md`，至少包含：

- 一份可直接修改的完整示例：仅上述白名单路径 `proxy_pass` 到审计代理，兜底 `location /` 仍指向原 NewAPI；不得要求用户改变 NewAPI 的登录、健康检查、管理或前端访问方式。
- 分别展示 OpenAI、Anthropic、Gemini 的精确/锚定正则 `location`；`proxy_pass` 不附加 URI 后缀，确保保留原 URI 和 Query。
- 设置 `proxy_http_version 1.1`、`proxy_buffering off`、`proxy_request_buffering off`、`proxy_cache off` 和足够长的读写超时；正确传递 `Host`、认证 Header，并由 Nginx 覆盖写入 `X-Real-IP`、`X-Forwarded-For`、`X-Forwarded-Proto`。
- Docker 与宿主机两种地址示例，`nginx -t`、平滑 reload 和 curl 验证步骤；验证模型接口会产生记录，而 health、登录和管理接口不会产生记录。
- 分别给出“审计代理故障即失败”的严格配置，以及可选的“故障时直连 NewAPI”配置；后者必须明确提示会形成审计缺口。
- 审计查询/管理端口不得复用公开的 NewAPI 路径，默认不对公网开放。
- 说明 NewAPI 新增或变更模型接口后，管理员必须显式更新路径白名单；未知路径默认继续直连 NewAPI。

## 6. 验收标准

1. 三类协议的流式与非流式白名单请求均按 `Nginx → 审计代理 → NewAPI` 转发并生成正确协议记录；未知字段、畸形 JSON 或解析器故障不影响原始请求和响应。
2. health、登录、管理、模型列表及任意非白名单路径均按 `Nginx → NewAPI` 直连，审计库中没有对应记录。
3. JSON、gzip、multipart、二进制及大 Body 在代理两侧的长度与哈希一致；Path、重复/编码 Query、端到端 Header、状态码和 Trailer 不丢失。
4. SSE 首块立即转发且字节和顺序一致；本地回环基准中代理增加的 TTFT P95 不高于 10 ms。
5. 客户端中断、NewAPI 超时、磁盘满、SQLite 锁竞争和进程异常退出后，记录状态准确，数据库不损坏；`available` 与 `strict` 均有端到端测试。
6. 提供自动化测试证明代理观测范围止于 NewAPI，产品中不存在“厂商请求/厂商响应”等误导字段。

## 7. 首版交付物与参考取舍

- Go 服务、三个协议解析器、示例配置、SQLite migration、最小查询 API/页面、Dockerfile 和跨平台构建说明。
- `docs/nginx.md`、审计字段说明、安全与保留策略说明、已知边界，以及单元、透明性、SSE 性能和故障测试。
- 借鉴 `newapi-logger` 的部署方式和 token 名称关联；借鉴 `claude-tap`、`HttpProxyMcp` 等项目的 SQLite WAL、流式旁路记录、多值 Header、二进制 Body 和时间线设计，但不沿用“全部路径经过代理”或会重建数据包的实现。

开发 agent 可自行决定包结构和内部接口，但不得扩大审计边界、把 NewAPI 后方渠道数据当作可见信息，或通过静默降级牺牲转发兼容性。
