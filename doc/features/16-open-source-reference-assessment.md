# 模块 16：开源项目参考取舍

## 1. 目的

本文只记录几个参考项目中值得借鉴的做法，避免首版继续扩张功能。参考源码用于理解架构，不作为直接复制代码的依据。

## 2. 参考结论

| 项目 | 借鉴 | 不采用 |
| --- | --- | --- |
| `newapi-logger` | Nginx 前置部署、简洁审计页面 | catch-all 全路径代理、完整缓冲 Body、明文日志 |
| `claude-tap` | 协议 parser、SSE 状态机、简单 viewer | 修改请求内容、自动解压重写、多种代理模式 |
| `HttpProxyMcp` | 多值 Header、二进制 Body、列表/详情分离 | HTTPS MITM、完整读取 Body、复杂桌面集成 |
| `NewAPI` | 路由和 Token 规范化事实 | channel、计费、重试和厂商 adapter 代码 |

## 3. `newapi-logger`

可借鉴：

- 在 Nginx 和 NewAPI 之间独立部署。
- 用最小后台任务补充调用者显示信息。
- 用简单管理页查看最近请求。

不采用：

- 所有 `/v1` 或全部路径都进入代理。
- 请求/响应完整读入内存后再转发。
- 队列满时无提示丢弃。
- Token、Header 和 Body 明文保存。

## 4. `claude-tap`

可借鉴：

- OpenAI、Anthropic、Gemini 分开解析。
- SSE 按事件增量处理。
- 原始记录和页面展示分离。

不采用：

- 修改模型请求或强制压缩策略。
- WebSocket、MITM、客户端配置注入等额外模式。
- 为调试体验重建原始响应。

## 5. `HttpProxyMcp`

可借鉴：

- Header 使用多值结构。
- Body 使用二进制字段而不是只存字符串。
- 列表不加载大 Body，详情按需读取。

不采用：

- 全网 HTTPS MITM 和根证书。
- 同步完整读取大 Body。
- 复杂 MCP/桌面控制能力。

## 6. `NewAPI`

NewAPI 只作为外部后端契约：

- 确认需要代理的模型路径。
- 确认响应 request ID、全站日志和用户目录的管理接口契约。
- 确认审计代理看不到其内部渠道选择和厂商请求。

不复制 NewAPI 的鉴权、路由、计费、重试或 adapter 实现。

## 7. 入站拦截链取舍

参考项目普遍证明代理扩展点必须与协议解析和持久化解耦，但本项目不照搬请求重写、全量 Body 缓冲或动态插件系统。首版选择一个编译期 registry 加 route 级有序 chain：模块只有只读检查权，首个 reject 终止，不能修改请求或改选上游。

interceptor 只作用于进程内 Matcher 精确命中的 LLM API route。NewAPI health、login、admin、models、UI 和其他安全非 LLM 请求走 passthrough，不进入拦截或审计；本项目不把 interceptor 扩张成 NewAPI 的全局权限层。

metadata 模块默认拿不到 Body，因此启用 credential、Header 或路径规则不会破坏上传和 SSE 的流式特性。确实需要 Body 的模块必须在配置中显式启用并声明 max_bytes；框架最多预读一次，允许时只把原始字节 replay 给 NewAPI，不能用模块解析或规范化后的数据替换请求。超过上限返回 413。

首版不引入 Go 动态 plugin、Yaegi、WASM、OPA/CEL、Envoy ext_authz 或独立策略服务。这些方案适合跨团队发布或集中策略管理，但会增加供应链、隔离和部署面；个人单机版用编译内模块、稳定 id/block code、请求 context 和 panic recover 即可。模块 error、panic 或非法 Decision 一律在 NewAPI 前返回 503，available/strict 都不放行。

拦截只保存最终结果到 audit_records，不建立逐模块事件表。这样保留“谁以什么稳定原因阻断”的审计能力，同时避免把插件调试日志、错误堆栈或敏感输入写入数据库。

## 8. 基础组件

首版优先使用成熟、简单的基础组件：

- Go `httputil.ReverseProxy`：负责标准 HTTP 反向代理。
- SQLite WAL：负责单机持久化和查询。
- Nginx：负责公网入口并把完整数据面统一送入进程内 dispatcher。
- Go 标准库 AES-GCM：负责本地敏感数据加密。

不在在线链路引入 DuckDB、Parquet、消息队列或外部数据库。

## 9. 许可证原则

- 只复制许可证明确允许且确实必要的小段实现。
- 没有明确许可证的仓库只借鉴思路。
- 默认独立实现代理、存储和安全逻辑。
- 引入新依赖时记录许可证即可，不建设复杂法务流程。

## 10. 对本项目的最终影响

首版只保留：

1. 精确路径透明代理。
2. SQLite 四阶段元数据、异常 raw 和内容寻址的 OpenAI turn/multimodal object 存储。
3. 三个协议的基础解析，以及 OpenAI provider JSON 重建。
4. 本地查询页面。
5. 可选 request-id 调用者身份回填。
6. 仅面向 LLM 白名单请求的有序入站 interceptor chain；Body 检查必须有界且原字节回放。

不因参考项目已有某项功能就自动加入本项目。
