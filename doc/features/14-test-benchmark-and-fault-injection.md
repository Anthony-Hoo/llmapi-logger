# 模块 14：测试与性能检查

## 1. 目标

测试重点只有三件事：

1. 代理没有改坏请求和响应。
2. 审计与解析故障遵循模式语义，而 interceptor 拒绝或异常一定在 NewAPI 前 fail-closed。
3. 流式接口不会因为记录功能产生明显卡顿，前端静态产物可以由 Go 二进制独立提供。

首版不建设复杂测试平台，使用 Go 标准测试、`httptest`、临时 SQLite 和一个 fake NewAPI 即可。

## 2. 测试目录

```text
tests/
  fixtures/       # 脱敏 JSON/SSE 样本
  integration/    # 代理端到端测试
  fault/          # 数据库与网络故障
  benchmark/      # SSE 和大 Body 基准
internal/web/frontend/src/**/*.test.tsx  # React 基本交互与 API mock
```

## 3. 单元测试

至少覆盖：

- Method + Path 白名单匹配。
- URL Path、RawQuery 和重复参数保留。
- Header 多值复制。
- AES-GCM 加解密和错误 key。
- Body chunk 序号、长度和 SHA-256。
- interceptor registry、route 顺序、稳定 block code 与 panic recover。
- OpenAI、Anthropic、Gemini 基本 JSON/SSE 解析。
- Token 凭据选择和只读内存 map 精确查找。

## 4. 透明转发测试

Fake NewAPI 记录实际收到的请求，并返回固定响应。测试比较客户端、代理记录和 fake NewAPI 三侧数据。

请求类型：

- 普通 JSON
- gzip
- multipart
- 二进制
- 空 Body
- 16–64 MiB 大 Body
- 重复 Header 和 Query

响应类型：

- 2xx、4xx、5xx
- gzip
- 二进制
- 空 Body
- SSE

断言 Method、Path、Query、Header、状态码和 Body 字节一致。Header 原始大小写、TCP 包和 HTTP chunk framing 不属于比较范围。

## 5. 入站 interceptor 测试

使用带调用计数的 fake interceptor 和 Fake NewAPI，至少覆盖：

- chain 严格按 route 配置顺序执行；首个 reject 后的模块调用次数为 0，Fake NewAPI 请求数为 0。
- metadata 模块收到的 RequestView 没有 Body handle。用 `io.Pipe` 慢速上传证明模块执行和 NewAPI 首次读取前没有预读完整 Body；未配置 body 模块时仍保持流式。
- body 模块在 0、limit、limit+1、未知 ContentLength、gzip、multipart 和二进制输入下只预读一次。允许请求到达 Fake NewAPI 的 Body、ContentLength、TransferEncoding 和 Header 与原请求一致。
- 多个 body 模块复用同一缓存；后续更小上限按自身 id 返回 413，不再次读取客户端 Body。
- 主动 reject 使用首个模块的 4xx/block_code；body 超限使用 413/`body_too_large`。
- error、panic、非法 Decision 和非客户端取消的 Body 读取失败，在 available 与 strict 下都返回 503，不调用 NewAPI，也不执行后续模块；客户端取消单独验证 client_cancelled。
- 每个拒绝 audit 都是 forward_status=rejected、blocked_by/block_code 非空、parse_status=skipped；只存在真实触发的入站阶段，不存在 request_sent_to_newapi 或响应阶段。

## 6. SSE 测试

Fake NewAPI 逐块发送 SSE：

```text
data: first

data: second

```

断言：

- 首块能立即到达客户端。
- 字节顺序不变。
- 客户端取消后连接能释放。
- parser 产生正确的消息和 usage 摘要。

本地基准记录 direct 与 proxy 两组 TTFT，用于发现明显回归；个人部署不设硬性能门禁。

## 7. 故障测试

只保留最常见场景：

| 场景 | available | strict |
| --- | --- | --- |
| SQLite 无法打开 | 继续转发并告警 | 返回 503 |
| 写入过程中 SQLite 失败 | 继续转发，记录 gap | 当前请求可能 partial；后续 admission 返回 503 |
| key 文件不可用 | 不写敏感数据，继续转发并告警 | 返回 503 |
| parser panic/错误 | 转发不受影响 | 转发不受影响 |
| interceptor 主动 reject | 首个 4xx reject 短路 | 相同 |
| interceptor error/panic/非法结果 | 503，NewAPI 未收到请求 | 相同 |
| NewAPI 超时/断开 | 返回代理错误并记录 | 相同 |
| 客户端取消 | 取消 NewAPI context | 相同 |

不模拟复杂多节点、分布式锁或长期 WAL checkpoint 故障。

## 8. Nginx 测试

使用一份真实 Nginx 配置验证：

- 默认模型白名单进入审计代理。
- NewAPI health、login、admin、models、UI 和其他非 LLM 白名单路径直接进入 NewAPI；这些请求的 proxy、interceptor 和 audit 调用计数均为 0。
- SSE buffering 已关闭。
- Query 没有因 `proxy_pass` URI 改写而丢失。

响应 Trailer 可在所用 Nginx 版本支持时测试。客户端请求 Trailer 经 Nginx 不作为首版保证。

## 9. React、Vite 与 Go embed 测试

前端固定在 `internal/web/frontend`，使用 React、Vite 和 shadcn/ui。Vitest + Testing Library 负责组件与基本交互测试，使用 MSW 或等价 fetch mock 模拟管理 API，不依赖正在运行的 Go 服务。至少覆盖 token 输入、Authorization Header、列表加载、筛选/翻页、详情打开、删除确认、导出触发，以及 401 后清空内存 token 并回到输入页。

前端验收顺序固定：

1. `npm ci` 安装锁定依赖。
2. `npm run test -- --run` 执行 API mock 和基本交互测试。
3. `npm run build` 由 Vite 输出 `internal/web/dist`。
4. Go 测试从 `//go:embed dist/*` 的 fs 启动 httptest server，验证 `/ui/`、JS/CSS 资源和 SPA fallback 均来自嵌入产物，且静态文件不含 token 或审计数据。
5. 多阶段镜像 smoke test 验证页面和 API 只靠最终 Go 二进制运行；最终镜像中找不到 node、npm、node_modules 或 Vite dev server 进程。

Node/npm 只属于前端构建阶段。运行镜像不得安装 Node，也不得通过 sidecar 或启动脚本运行前端服务。

## 10. 建议命令

```bash
cd internal/web/frontend
npm ci
npm run test -- --run
npm run build
cd ../../..
go test ./...
go test -race ./...
go test ./tests/integration/...
go test ./tests/fault/...
go test ./tests/benchmark/... -bench .
```

## 11. 发布前检查

- 三协议至少各有一个流式和非流式用例。
- 非白名单路径无审计记录。
- 数据库和普通日志扫描不到测试明文 Token。
- available/strict 的 SQLite 故障行为符合文档。
- interceptor 顺序、首 reject、body 原字节 replay、limit+1、error/panic/非法 Decision、Body 读取失败和拒绝审计均通过，Fake NewAPI 未收到被拒绝请求。
- Nginx 直连的 health/login/admin/models/UI/其他非白名单路径不进入代理、拦截或审计。
- loopback 与非 loopback 管理 API 在缺少或使用错误 Bearer token 时均被拒绝。
- 首启 key 生成、错误 key、Token schema mismatch、同步 JSON/ZIP 导出、retention 和停机 VACUUM 至少各有一个用例。
- React API mock 与基本交互测试通过；`npm run build` 产物可由 Go embed 提供。
- 最终运行镜像不含 Node/npm/node_modules，启动后没有 Node 或 Vite 进程。
- Linux 与 Windows 至少各运行一次启动 smoke test。
- 示例 Nginx 配置通过 `nginx -t`。

## 12. 完成定义

核心透明性、interceptor fail-closed、SSE、解析、数据库故障、路由隔离、React 基本交互、前端构建/Go embed 和无 Node 运行镜像测试通过即可。性能报告记录实际结果，不为个人项目建立复杂 CI 矩阵或长期性能基线平台。
