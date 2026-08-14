# 模块 14：测试与发布检查

## 1. 目标

发布门禁验证五类结果：

1. 代理协议与路由没有被审计功能改写；
2. interceptor、available/strict 和调用者关联语义不回退；
3. OpenAI 多轮/多模态内容按对象复用且任意轮可准确重建；
4. raw retention、SSE timeline、recovery、retention checkpoint 和完整性链可靠；
5. 数据库、构建产物和 Git 变更不包含敏感明文或真实部署资料。

测试只使用临时 SQLite、`httptest`、fake NewAPI 和脱敏 fixture，不连接真实生产。

## 2. 测试布局

~~~text
internal/auditmodel/*_test.go            # canonical/hash/binary/delta/rebuild
internal/storage/sqlite/*_test.go         # schema/writer/graph/integrity/recovery/retention
internal/parser/**/*_test.go              # JSON/SSE/normalizer/evidence limits
internal/query/*_test.go                  # detail/reconstruction/timeline/capacity
internal/web/*_test.go                    # 管理 API、鉴权和 no-store
tests/integration/*_test.go               # 代理到 SQLite/API 的端到端链路
internal/web/frontend/src/*.test.*        # API client、UI、格式化和安全 Markdown
~~~

## 3. 内容寻址专项覆盖

- OpenAI Chat、Completions、Responses/Compact 的 JSON 与 SSE。
- developer/system/user/assistant/tool、reasoning、并行 tool call/result、客户端 metadata。
- Responses 完整历史重复发送、`previous_response_id` 和 conversation key。
- root、continuation、retry、branch、truncate、middle edit、rollback、summary compression。
- data URL 按解码字节 hash；不同 Base64 padding/header/MIME 的同一 PNG 只保存一个 binary object。
- `file_id` 外部引用、inline `file_data` 和实际附件字节。
- provider request/response canonical 重建 hash、sequence hash 和 object conflict 校验。
- 24 轮重复完整历史容量回归：context ops 近似线性，content object 数显著低于 item occurrence，SQLite 体积显著低于重复 wire Body。

## 4. 证据与故障覆盖

- 四阶段 length/hash/source stage，约 1 MiB raw chunk 聚合和双阶段字节复用。
- 正常 2xx/3xx verified 后 raw 为 metadata；拦截、4xx/5xx、采集不完整、parser/normalizer/rebuild 失败保留 full。
- malformed inline binary 时四阶段 raw 可完整下载，不能误删。
- SSE 网络 read 分块不会产生百万小行；逻辑 event count、TTFT、首末 event、100,000 点截断语义正确。
- AES-GCM/AAD、content/binary hash、length/compression、HMAC event chain 篡改失败。
- process-exit recovery 把未终结记录和 timeline 标 partial/full，重复执行幂等。
- retention 删除父轮次前生成 root checkpoint；保留子轮次继续重建，孤立对象被 GC。
- 成对 HTTP Body 只在终结时确认完整长度/hash 一致后合并；人为制造长度或字节差异时保留两份 owning chunks 并标记 `body_stage_mismatch`。
- writer 事务失败、queue 满、parser panic、caller 延迟与客户端取消不泄露底层错误或敏感数据。

## 5. 固定验证命令

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

跨平台发布构建：

~~~powershell
.\scripts\build.ps1
~~~

~~~bash
bash ./scripts/build.sh
~~~

Windows 脚本输出 Windows/Linux amd64，均使用 `CGO_ENABLED=0`。若本机 PATH 没有 Node，可以直接使用受控工具链中的 Node 调用本地 `node_modules`；这不改变源码或锁文件。

## 6. 本地容器与服务 smoke

具备 Docker/Podman 时至少验证：

- 镜像构建和 `docker compose config`；
- 最终镜像不含 Node、pnpm、Go 源码或构建工具；
- fake/upstream 环境下一个非流式请求、一个 SSE 请求、一个 `/v1/models` passthrough 和一个 fail-closed 路径；
- 管理 API 缺凭证为 401，登录 Cookie 可读取列表；
- verified 请求 reconstructed JSON 可下载、raw 返回 410；异常请求 raw 可下载；
- 重启后数据库 quick check、integrity chain 和历史重建正常。

没有可用容器运行时或 Nginx 时，应明确记录“未执行”，不能写成已通过。

## 7. 脱敏与明文扫描

发布前扫描以下范围：

- 临时测试 DB、WAL 和 SHM；
- 普通 JSON 日志；
- `git diff`、暂存区和最终提交范围；
- `internal/web/dist` 与跨平台二进制可搜索字符串；
- README、doc、configs、scripts 和测试 fixture。

禁止出现真实公司/组织名称、生产域名、服务器地址或账号、本地绝对路径、API Key、Access/Admin Token、密码、私钥、完整 DSN、客户消息或多模态数据。公开示例只使用 `example.com`、占位符和文档保留地址。

`.env.local`、`configs/*.local.yaml`、`*.private.yaml`、`*.runtime.yaml` 必须保持 Git ignored；扫描工具不得把这些真实值回显到可公开日志。

## 8. 发布前清单

- 当前分支为 `main`，没有额外特性分支。
- 前端 test、TypeScript、Vite build、Go full test、vet、Windows/Linux CGO=0 构建全部通过。
- `git diff --check` 通过，生成的 `internal/web/dist` 与源码一致。
- schema 20 表、generation 2、破坏性 migration 和默认 UA 规则测试通过。
- provider JSON 重建、随机轮次抽查、容量回归和 full/metadata retention 测试通过。
- 512 MiB 代理/拦截上限与 64 MiB parser 单侧解码上限已分别验证和记录，验收报告不得混淆两者。
- recovery、retention checkpoint/GC 和 integrity chain 测试通过。
- DB/WAL/日志/构建产物/Git diff 脱敏扫描通过。
- loopback 管理 API 仍要求 Bearer/Cookie，Cookie 与 Markdown 安全测试通过。
- Nginx/容器 smoke 若环境可用则通过；否则在验收报告中列为未执行。
- 生产清库、部署、Git commit 和 push 必须在本地验收报告提交后取得维护者明确批准。
