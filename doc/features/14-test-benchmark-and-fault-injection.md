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

## 9. 协议夹具与 A/B 压测工具

issue #59 的 P0 基线（`doc/design/issue-59-unified-write-cold-archive.md` 第 6、7 节和附录 A）需要两样东西：贴近真实线格式的四协议流量，以及在真实 PostgreSQL 上量出空间与 IO 的工具。两者都是库加一个薄命令，后续的协议适配、新写路径和冷归档直接复用。

### 9.1 夹具：`internal/protofixture`

按种子确定性生成完全合成的流量。正文只由固定音节拼成，标识符出自同一个生成器，唯一的图片是由种子画出的 4×4 PNG，所以库里和日志里不可能出现真实数据；同一种子、同一参数生成逐字节相同的请求和响应。

覆盖的协议与路由（与 `configs/audit-proxy.example.yaml` 一致）：

| 协议 | 路径 | parser | 流式形态 |
| --- | --- | --- | --- |
| OpenAI Responses | `/v1/responses` | `openai.responses` | `event:` 加 `data:`，以 `response.completed` 结束 |
| OpenAI Chat Completions | `/v1/chat/completions` | `openai.chat_completions` | `data:` 块，末尾 usage 块和 `[DONE]` |
| Anthropic Messages | `/v1/messages` | `anthropic.messages` | `message_start` 到 `message_stop`，含 `ping` |
| Gemini | `/v1beta/models/{model}:generateContent`、`:streamGenerateContent?alt=sse` | `gemini.generate_content`、`gemini.stream_generate_content` | CRLF 分隔的 `data:` 块，每块带累计 usage |

命名场景（`protofixture.Catalog()` 枚举全部组合，流式与非流式各一份；断流类只有流式）：

| 场景 | 内容 |
| --- | --- |
| `basic`、`multi_turn` | 单轮；三轮，每轮重发完整历史 |
| `branch` | 同一前缀的两个不同续写 |
| `tool_calls` | 一轮并行调用两个工具，下一轮带回两个结果 |
| `multimodal` | 用户消息内联 PNG（data URL、base64 source、`inlineData`） |
| `reasoning` | Responses reasoning 摘要与 `encrypted_content`、Chat `reasoning_content`、Anthropic thinking 加 `signature_delta` 和 `citations_delta`、Gemini `thought` 片段 |
| `usage_shapes` | 各协议少见的 usage 形态：Chat 每块 `usage: null`、Anthropic `cache_creation` 细分和 `message_delta` 里重复的累计输入、Gemini `toolUsePromptTokenCount` 与各类 details |
| `extensions` | parser 不消费的事件和字段：注释心跳、`response.output_text.annotation.added`、自造的扩展事件、`server_tool_use` 块、`citationMetadata`、`thoughtSignature`、请求与响应里的未知顶层字段 |
| `error_400`、`error_401`、`error_422`、`error_429`、`error_500`、`error_503` | 各协议的 JSON 错误体（503 用 NewAPI 自己的错误信封） |
| `stream_missing_terminal` | 流干净结束但缺少结束事件 |
| `stream_client_cancel` | 客户端在一个事件的数据中间放弃 |
| `stream_upstream_abort` | 上游在一个事件的数据中间断开连接 |

系统提示和工具定义只由种子和协议决定，同一协议的所有会话共用一份，和同一客户端在真实部署里的表现一样，跨会话的对象共享因此可以被测量。

规模参数：`HistoryItems`（第一轮已有的历史条数）、`ItemBytes`（每条消息、工具参数或工具输出的字节数）、`DeltaBytes`（每个流式增量）、`ToolDefinitions`、`SystemBytes`。小档用默认值；`HistoryItems=214, ItemBytes=4600, ToolDefinitions=12, SystemBytes=12000` 得到约 1 MB 的请求体和约 220 个上下文条目，与附录 A.1 的部署相当。

每个 exchange 附带独立推算的期望值：解析状态、错误码、请求与响应模型、响应 id、usage、消息数和工具调用数。`protofixture_test.go` 把全部夹具送进仓库现有的 parser 逐项比对；OpenAI 的 `ok` 结果还要过 `NormalizeAudit` 和 `PrepareWithLookup`，因为 worker 会在这两步失败时把 `ok` 降成 `partial`。

fake upstream（`protofixture.Upstream`）是一个 `http.Handler`：客户端先登记 exchange 拿到 id，请求时带上 `X-Protofixture-Exchange: <id>`。代理原样转发请求头，upstream 据此取出 exchange，核对转发来的方法、路径和请求体，再按块写出并逐块 flush；断流场景在 `CutAt` 处断开或等待客户端离开。响应头 `X-Oneapi-Request-Id` 填 exchange id，它落在带索引的 `audit_records.newapi_request_id` 列上，压测工具因此不用解密任何东西就能找到每个请求的 audit。这个请求头和其他请求头一样被加密记录，每条 audit 多两行 Header。

夹具测试固定了两处现状，作为发现而不是被掩盖：

- Gemini parser 没有结束事件检查：在两个事件之间干净结束的流解析为 `ok`，与完整的流无法区分（`TestFindingGeminiStreamWithoutTerminalParsesOK`）。
- Anthropic 流聚合器忽略 `signature_delta` 和 `citations_delta`，两者都进不了解析出的会话（`TestFindingAnthropicDropsSignatureAndCitations`）。这正是设计 4.1 第 4 条要补的未消费事件保真。

为了让流量真的到达上游，Responses 夹具使用 `Codex Desktop/…` User-Agent 和 `Originator` 头，Chat 夹具使用非 gpt 模型：迁移内置的默认 UA 规则只允许 Codex 客户端调用 gpt 模型，其他客户端会在本地被拦截。

### 9.2 压测工具：`cmd/audit-bench`

逻辑在 `internal/auditbench`，命令只做参数和信号处理。三个子命令：

- `run`：在一个进程里启动 fake upstream、fake NewAPI 管理接口（`/api/status`、`/api/user/`、`/api/log/`）和真实应用，经代理的真实监听地址发送工作负载，按阶段快照统计并写出 `<prefix>.json` 与 `<prefix>.md`。
- `compare A.json B.json`：把两次结果的差异打印成 Markdown 表。工作负载或 PostgreSQL 参数不同、审计条数不同、任一结果被其他会话污染时先给出警告。
- `dist`：对已有审计库做只读聚合，给出设计 5.3、5.4 需要的两个分布：每个会话（以及每个会话每个 UTC 日）的轮次数直方图、每个会话的去重对象字节直方图（内容对象加它们引用的二进制对象）、无 turn 的 audit 数与其 Body 字节，以及“各会话分别去重后的对象字节之和”与“全局去重后的对象字节”之比。每个会话的对象集由该会话各轮的两个 envelope、insert 的上下文条目和响应条目组成；父轮次落在别的会话里时这个集合会漏掉继承的条目，所以同时报告这样的轮次数，非零时比值只是下限。只读取计数、长度和哈希，不选任何内容列；在一个只读、可重复读、带语句超时的事务里执行，只输出聚合值。

连接串只从环境变量 `AUDIT_BENCH_DATABASE_URL` 读取，不接受命令行参数，也不打印；错误只给 SQLSTATE 或固定描述。目标 schema 已有审计表时 `run` 拒绝执行；`--fresh-schema` 在目标库里新建 `audit_bench_<时间>_<随机>` schema 使用，`--drop-schema` 在结束后删除它（只删本次创建的那一个）。

`run` 打开 insights 分析与组织报表，配置一个指向 fake NewAPI 的管理身份，所以调用者回填、insights 回填和项目标识回填都会运行；`retention_days=0`，会话分析关闭。

工作负载参数：`--profile small|heavy`、`--seed`、`--conversations`、`--turns`、`--concurrency`、`--mix`（协议权重）、`--stream-share`、`--abnormal-share`（每轮之前插入一个异常请求的概率；异常请求不推进会话，下一请求是同一轮的重试）、`--branch-share`、`--history-items`、`--item-bytes`、`--delta-bytes`、`--tool-definitions`、`--system-bytes`、`--upstream-first-byte`、`--upstream-chunk-delay`。协议和流式会话数按权重精确分配（最大余数法），同一工作负载两次运行发送相同的流量。

四个阶段，每个边界一次快照：

| 阶段 | 内容 |
| --- | --- |
| load | 流量进行中 |
| drain | 等到每条 audit 都有终态解析状态、调用者查询完成、insights 与项目标识回填没有候选；剩余不变的候选视为永久跳过并报告 |
| reads | 经管理 API 读抽样 audit 的详情和两侧导出（`/api/v1/audits/{id}`、`/reconstructed/{side}`，没有可验证重建时回退 `/raw/{side}`），逐个串行 |
| idle | 没有任何流量和工具查询，暴露回填循环空转的成本（附录 A.4） |

本地运行（占位符自行替换；PostgreSQL 容器不发布端口时，二进制放进共享其网络命名空间的容器里执行）：

~~~powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -o <scratch>/audit-bench ./cmd/audit-bench
$env:GOOS=''; $env:GOARCH=''; $env:CGO_ENABLED=''
podman run --rm --network container:<pg-container> -v "<scratch>:/t" -w /t `
  -e "AUDIT_BENCH_DATABASE_URL=postgres://<user>:<password>@127.0.0.1:5432/<database>?sslmode=disable" `
  <go-image> /t/audit-bench run --fresh-schema --profile heavy --output /t/baseline
podman run --rm -v "<scratch>:/t" <go-image> /t/audit-bench compare /t/baseline.json /t/candidate.json
podman run --rm --network container:<pg-container> -v "<scratch>:/t" `
  -e "AUDIT_BENCH_DATABASE_URL=..." <go-image> /t/audit-bench dist --schema <schema>
~~~

在 Linux 主机上可以直接执行 `go run ./cmd/audit-bench run ...`。提交号取自二进制的 VCS 信息（`go build` 在 Git 工作区里自动写入）；取不到时用 `--commit` 指定，否则结果里有警告。

### 9.3 数字的含义

单位与附录 A.1 一致：MB 是 10^6 字节，kB 是 10^3 字节，延迟是毫秒。每个阶段的数字都是两次快照的差值。

| 数字 | 来源与含义 |
| --- | --- |
| 分表 Heap、TOAST、Indexes | `pg_relation_size`、`pg_total_relation_size(reltoastrelid)`、`pg_indexes_size`，阶段末的大小和阶段内增量 |
| Rows | 结束后的精确 `count(*)`，在最后一次快照之后执行，不影响计数器 |
| Inserted、Updated、HOT updated、Deleted、Seq scans、Index scans | `pg_stat_user_tables`，只取本 schema 的表，与同库其他 schema 隔离 |
| Heap / Index / TOAST read、hit | `pg_statio_user_tables` 的块数，read 是未命中共享缓冲区的读 |
| Cluster WAL、WAL records、Full-page images | `pg_stat_wal`，整个实例 |
| WAL by LSN | `pg_current_wal_lsn()` 的差值，整个实例，不受统计刷新延迟影响 |
| Writer backend WAL、reads/hits/writes/extends | PostgreSQL 18 的 `pg_stat_get_backend_wal`、`pg_stat_get_backend_io`，只算应用唯一的 writer 会话（按它持有的 advisory lock 找到），与其他会话隔离 |
| WAL outside writer | Cluster WAL 减 writer：读连接的页面修剪、autovacuum、检查点和其他会话 |
| Commits excl. tool | `pg_stat_database.xact_commit` 减去工具自己的事务数；整个数据库。它包含应用读连接池的每一条只读语句，不等于 writer 的提交数：reads 和 idle 阶段几乎没有 writer WAL，却有上百次提交。减少读回的改动（4.2 第二步）会让这个数下降，但那不是 writer 少提交了 |
| per audit | 总量除以写入的 audit 条数 |
| time to first byte、time to end | 客户端从发出请求到读到首字节、读完响应（取消场景为放弃时刻） |
| end of response to queryable | 客户端读完响应到 audit 行出现终态解析状态；按 `--poll-interval`（默认 100 ms）用一次索引查询轮询全部未决请求，精度就是这个间隔 |
| detail、export p50/p95 | reads 阶段经管理 API 串行读取的耗时 |
| Go memory peak、peak resident set | `runtime/metrics` 每 200 ms 采样的峰值和 Linux 的 VmHWM；应用、fake upstream 和压测驱动在同一进程，三者合计 |
| parse status as expected | 每个请求的终态解析状态与夹具期望逐条比对 |

统计口径：

- 每次快照是工具的一个只读事务，事务内先调 `pg_stat_force_next_flush()`；工具的每个事务都计数，并从提交数里减去。工具在 load 和 drain 阶段的轮询查询次数单独列出；reads 和 idle 阶段工具不查询任何审计表，只每 2 s 读一次 `pg_stat_activity` 统计其他会话。
- PostgreSQL 的计数器由各会话自己刷新：忙碌会话最长约 1 s，空闲会话约 10 s。drain、reads、idle 的快照之前等待 `--settle`（默认 11 s）。load 与 drain 之间不等待，所以两者的分界按计数器看是近似的，load+drain 合计和 WAL by LSN 是准确的；短到一两秒的 load 阶段尤其如此。
- 同一实例上有其他会话时，Cluster WAL、WAL by LSN 和数据库提交数都包含它们的工作。结果记录采样到的其他会话数和 writer 之外的 WAL，超过阈值时标为污染并给出警告；这时只看分表和 writer 会话的数字。

### 9.4 局限

- 数据是合成的。文本可压缩性、工具定义体积、会话长度分布和协议构成都与真实部署不同，绝对值只能看量级；A/B 的价值在于同一工作负载下两个提交或两种配置的差。
- 数据库是本地的，参数是谁的就记录谁的（`shared_buffers`、`fsync`、`synchronous_commit`、`max_wal_size`、`checkpoint_timeout`、`wal_compression` 等写进结果）。本地测试库常见 `fsync=off`，提交延迟和检查点行为与生产不同。
- idle 阶段能否看到回填重扫取决于时长。parser worker 每 30 s 一跳，insights 回填（`backfillRescanInterval`）和项目标识回填（`projectBackfillRescanInterval`）在一次扫描没有候选之后都要等 10 分钟才再扫；计时从最后一次空扫算起，可能落在 drain 里。短于约 10.5 分钟的 idle 可能一次重扫都没有，默认 11 分钟。不重扫时 idle 里也有别的读：本地 smoke 的 idle 阶段 `audit_records` 每秒约一次顺序扫描，推断来自 NewAPI 调用者 worker 每秒一次的待办查询（`ListDueCallerLookups`），这么小的表上规划器选了顺序扫描，大表上未必；组织报表的周快照任务也在 idle 里写入。
- 到可查询的延迟只有在待解析积压不超过 100 条时才反映写入和解析路径。解析 worker 的内存队列容量是 100（`parser.QueueCapacity`），满了以后的 audit 留在 `pending`，由每 30 秒一次、每次最多 100 条的扫描重新入队；突发超过这个量时，量到的是扫描间隔。要比较写入路径，把并发和会话数调到积压不溢出。
- 读取阶段的抽样按请求在工作负载里的位置排序后用种子洗牌，同一工作负载的两次运行读到同一批位置上的 audit，详情与导出的分位数因此可比。
- 时间到可查询的延迟包含轮询间隔；内存峰值包含压测驱动和 fake upstream 自身。
- 被中断的 `run`（信号、超时、连接中断）不会删除它用 `--fresh-schema` 建的 schema，名字打印在开头，需要手动删除。
- `dist` 的“每个会话每天”按 `turns.created_at_ns`（解析时间）的 UTC 日分组，只是归档按天切段时的近似。
