# 模块 14：测试与发布检查

## 1. 目标

个人项目的测试集中验证四件事：

1. 白名单请求和响应没有被代理改写。
2. interceptor 在 NewAPI 前 fail-closed，审计故障遵循 available/strict 语义。
3. 加密证据、异步 parser、查询和管理鉴权能够串成完整链路。
4. 阶段 4 的恢复、gap、retention、安全日志和 readiness 行为稳定。

不建设独立故障平台、复杂性能门禁或多环境 CI 矩阵。

## 2. 现有测试布局

~~~text
internal/**/**_test.go                  # 模块单元测试
tests/integration/                     # 代理、持久化和管理 API 端到端测试
internal/web/frontend/src/*.test.ts    # 前端 API 与格式化测试
~~~

测试使用 Go 标准库、`httptest`、临时 SQLite、fake NewAPI 和 Vitest；不依赖外部 NewAPI 服务。

## 3. 核心覆盖

- Method + Path 白名单，以及非白名单 `404` 且不创建 audit。
- Path、RawQuery、重复 Query/Header、JSON、gzip、multipart、binary、空 Body 和大 Body 透明性。
- SSE 首块及时 flush、字节顺序和取消释放。
- interceptor 顺序、首个 reject、panic/error/非法结果、Body 单次预读与原字节 replay、`413 body_too_large`。
- 四阶段 length/hash/完整性、AES-GCM 篡改检测、DB/WAL 明文扫描。
- OpenAI、Anthropic、Gemini 常见 JSON/SSE 与 gzip 限额。
- parser pending/processing 恢复、panic 隔离和加密 parsed JSON。
- 列表、详情、raw 流式解密、Bearer 鉴权和匿名静态 UI shell。
- 启动 interrupted/partial 恢复、聚合 gap、retention 级联、三态 readiness 和安全 JSON 日志。

## 4. 固定验证命令

~~~bash
cd internal/web/frontend
pnpm install --frozen-lockfile
pnpm test
pnpm build
cd ../../..

go test -count=1 ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o ./bin/audit-proxy ./cmd/audit-proxy
~~~

跨平台发布二进制使用：

~~~powershell
.\scripts\build.ps1
~~~

或：

~~~bash
bash ./scripts/build.sh
~~~

两个脚本都生成 Windows/Linux amd64、`CGO_ENABLED=0` 的二进制。

## 5. Nginx 与容器检查

静态检查应确认：

- 只有五个固定 POST 路径和锚定 Gemini POST 路径选择 audit-proxy。
- 其他 Method/Path 选择 NewAPI。
- buffering、cache 和 upstream retry 已关闭。
- `proxy_pass` 没有 URI 后缀。
- 管理端只绑定宿主机 `127.0.0.1:8081`，数据端没有 host port。
- 最终镜像没有 Node、前端源码、Go 源码或构建工具。

实际有 Docker/Nginx 的环境再执行 `docker compose config`、镜像构建、`nginx -t` 和流式 smoke test。未运行的外部工具检查不得写成已通过。

## 6. 发布前清单

- `pnpm test`、`pnpm build`、`go test -count=1 ./...` 和 `go vet ./...` 通过。
- Windows/Linux amd64 的 CGO=0 构建通过。
- DB/WAL 与普通日志中找不到测试凭据、Body 或主密钥明文。
- strict admission 故障不会调用 Fake NewAPI；available 审计故障仍能转发并产生安全日志或 gap。
- 重启恢复、retention 批次边界和级联删除测试通过。
- loopback 管理 API 缺少 Bearer token 时返回 `401`。
- 路由、parser、示例配置和 Nginx 白名单保持一致。

本阶段不验收指标、导出、手工删除、自动 VACUUM、复杂重连或长期性能基线。
