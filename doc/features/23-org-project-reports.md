# 模块 23：组织项目周报与使用合规

> 状态：M0–M4 已实现；M5 由[模块 24](24-session-analysis.md)承接（其 S0–S3 已实现，合规模式 S4 未开始）；§11 待确认项仍未关闭，见 §13.5
> 日期：2026-11-06
> 依赖：[11 NewAPI 请求身份](11-newapi-request-identity.md)、[20 上下文洞察](20-context-insights.md)、[21 实际计费](21-newapi-billing.md)、[22 关键词规则](22-content-policy.md)
> 本文记录设计动机与开发拆分；落地后配置、表和 API 按惯例并入 01/04/10，以那里为唯一来源。

## 1. 目标与边界

面向“团队共用一个 NewAPI”的部署，按 NewAPI 用户回答三个问题：

1. 这周谁在哪个项目上用了多久 AI、花了多少钱，并给出排名。
2. 每个项目组配置哪些项目（统一项目 + 组内专属项目），流量能否自动归属到项目。
3. （后期）没有归属到项目的流量里，是否存在与工作无关的用途。这一项已改由[模块 24](24-session-analysis.md)设计和实现，本文只保留指向（§9）。

边界：

- **整个功能可选，默认关闭。** 个人自用部署不感知任何变化：不跑提取、不跑作业、不显示入口，相关 API 返回 404。
- 只做统计与线索，不做自动处罚、自动封禁或个人效率评分；排名口径固定为“AI 活跃时长”，不称为工作时长。
- 沿用模块 20 的明文边界：仓库路径、remote URL、cwd 只以 keyed 指纹 + 密文保存；只有匹配到管理员配置的规则后，才写入明文 `project_id`。
- 代理字节路径不变，全部计算在异步 worker 或查询时完成。

## 2. 前置调研结论

### 2.1 Codex 如何上报项目

依据 openai/codex main 分支源码（`core/src/turn_metadata.rs`、`core/src/responses_metadata.rs`、`git-utils/src/info.rs`、`core/src/context/world_state/environment.rs`）：

| 位置 | 内容 |
| --- | --- |
| `<environment_context>`（user 角色消息） | `<cwd>`、`<workspace_roots>`、shell、日期等；**没有 git 字段** |
| 请求体 `client_metadata["x-codex-turn-metadata"]`（规范载体，值是 JSON 字符串） | `session_id`、`thread_id`、`turn_id`、`parent_thread_id`、`request_kind`、`workspaces` 等 |
| Header `x-codex-turn-metadata`（兼容投影） | 同上，去掉 `tool_namespaces_info`；仅 `request_kind` 有值时发送 |

`workspaces` 结构：键是仓库根目录的绝对路径（原生格式，Windows 为 `C:\...`），值为 `associated_remote_urls`（全部 fetch remote，按 remote 名索引，已剥离凭据，scp 形式原样保留）、`latest_git_commit_hash`、`has_changes`。git 信息由后台任务异步收集，组装请求时读取当时的缓存；cwd 不是 git 仓库时为空。

实际部署抽样（只读明文元数据）：所有 Codex 入站请求都带该 Header；值长度呈双峰（约 98% 在 700–1300 字节，其余 200–500 字节），且每个 Codex 线程都至少有一条长值。**长值包含 `workspaces` 仍是推断**，M1 开工前需解密一长一短两条样本确认（§11）。短值并不集中在线程开头，所以“git 信息尚未收集完”不能解释它，原因待查。

### 2.2 其他常用客户端的上报机制

调研对象为各客户端 2026-11 的当前源码或官方文档：Claude Code（2.1.3xx 发行包与官方网关文档）、OpenCode（`anomalyco/opencode` v1/v2）、pi（`earendil-works/pi`，原 `badlogic/pi-mono`）、dsh（`deepseek-ai/deepseek-harness`）、ZCode（`zai-org/ZCode`）。**除 Codex 和 OpenCode v2 外，没有客户端上报 git remote URL**，项目只能靠工作目录或仓库根路径来推断。

| 客户端 | 协议 | 工作目录 / 仓库信号 | 会话与父子标识 | 附属请求 | 自定义 Header |
| --- | --- | --- | --- | --- | --- |
| Claude Code | 仅 Anthropic Messages | 会话开头一条 meta user 消息：`# Environment` 段的 ` - Primary working directory: <path>`、` - Is a git repository:`；变化时追加 `# Environment update`（`<new> (was <old>)`）。`# gitStatus` 只有分支、状态和最近提交，**没有 remote URL**。仓库根可从 `Contents of <root>\CLAUDE.md (project instructions…)` 推出 | `X-Claude-Code-Session-Id`（≥2.1.86，父子共用）；`x-claude-code-agent-id`/`x-claude-code-parent-agent-id`（≥2.1.139，仅子 Agent）；`metadata.user_id` 是 JSON 字符串，内含 `session_id` | `x-claude-code-request-class` 等提示头**默认不发**，需设 `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`（≥2.1.273） | `ANTHROPIC_CUSTOM_HEADERS`（静态，每行 `Name: Value`） |
| OpenCode v2（≥2.0.21） | 随 provider（Chat / Responses / Messages） | 系统提示第二段 `<env>`：`Working directory:`、**`Workspace root folder:`**（git 顶层）、`Is directory a git repo:`；变化时追加 `The environment you are running in is now:` | `x-opencode-session-id`（自身）、`x-opencode-parent-session-id`/`x-parent-session-id`（直接父）；**`x-opencode-project`** = `sha1("git-remote:" + 规范化 origin)`，无 origin 时为根提交 SHA 或 `global`，发给所有 provider | 标题请求没有 `<env>`，只能按 Header 归属；压缩请求以固定的尾部用户消息识别 | `provider.<id>.options.headers`，支持 `{env:VAR}` |
| OpenCode v1（≥1.18.34） | 同上 | `<env>` 只有 `Working directory:`，没有仓库根 | `x-opencode-session-id`、`x-opencode-parent-session-id`；`x-opencode-project`/`x-opencode-client` **只发给 Zen**，自建网关收不到 | 同上 | 同上，可覆盖内置头 |
| pi | 随 provider | 系统提示 `<cwd>\n<path>\n</cwd>`（≥0.86，反斜杠转为 `/`）；更早版本为 `Current working directory: <path>`；`<project_instructions path="<abs>/AGENTS.md">` 可推出仓库根；没有 git 信息 | 只有 OpenAI Responses 默认带 `session-id`、`x-client-request-id` 和 `prompt_cache_key`；Chat Completions、Anthropic 默认**不带任何会话标识**；没有内置子 Agent | 压缩请求用全新 uuid，且不带会话标识（系统提示以 `You are a context summarization assistant.` 开头）；**缓存预热**会在会话空闲后最多 60 分钟内持续发请求 | `models.json` 的 `headers`，支持 `$ENV` 和 **`!command`（每次请求执行，可动态取仓库名）** |
| dsh 原生适配器 | Anthropic Messages | 请求体 `dsh_session_log.session.cwd`（会话创建时的目录，子 Agent 继承父目录）；另有 user 消息 `Current working directory: "<path>".`；没有 git 信息 | `x-deepseek-harness-session-id`（每个 Agent 一个）；父会话在 **`dsh_session_log.session.parentSession`**（不是现有词表里的 `.header.`），附 `origin`、`delegationDepth`；`x-deepseek-harness-user-id` 每台机器一个 | `x-deepseek-harness-compact: 1` | 不可配置 |
| dsh 经 pi-ai 适配器 | 随配置 | 只剩 user 消息里的 `Current working directory:` | **没有任何会话标识** | 无标记 | `providers.<route>.headers`（静态），或 `request-headers` 插件 |
| ZCode（智谱 Z.ai，开源） | Anthropic Messages / OpenAI Responses / Chat | meta user 消息（`<system-reminder>` 包裹，也可能作为 system 消息出现）：` - Primary working directory: <cwd>`、` - Is a git repository:`，格式几乎照搬 Claude Code；`# gitStatus` 没有 remote URL | `x-session-id`（去掉 `sess_` 前缀）、`x-zcode-session-type`（`main`/`subagent`/`side_chat`/`other`）、`x-zcode-trace-id`；UA `ZCode/<ver>`、`X-Title: Z Code@electron\|cli`；Anthropic 协议下 `metadata.user_id` 内含 `session_id`。**子 Agent 如何关联父会话尚未确认** | `x-zcode-query-source`：`compact`、`session_title`、`project_memory_*` 等 | provider 配置 `api.headers`（静态） |

实际部署抽样（只读明文元数据）：请求约 88% 来自 Codex，约 6% 来自经词表接入的自研框架，约 5% 来自无法识别的客户端；dsh 只占极少量，而且走的是 pi-ai 适配器路径，不带会话头；Claude Code 基本没有流量。所以 M1 按 Codex → 自研框架 → 其他客户端的顺序实现，但识别规则一次覆盖全部客户端。

对现有实现的影响（与本功能无关，但调研时发现）：

- 词表 `dsh.parent_body_paths` 写的是 `dsh_session_log.header.parentSession`，实际字段是 `dsh_session_log.session.parentSession`，dsh 子 Agent 因此连不上父节点；相关测试也是按错误的结构构造的。
- 模块 20 §5.8 中 OpenCode 的版本号需要更正：会话头从 v1.18.34 / v2.0.21 开始提供；`x-opencode-session` 在 v2.0.0–v2.0.18 指自身，从 v2.0.19 起指"亲和会话"（子会话指直接父，fork 指来源）。Responses 的 `prompt_cache_key` 是直接父会话，而不是根会话。
- 默认词表还没有 ZCode 和 pi，它们目前会落进 `unknown`。

### 2.3 时长算法参考：tokscale

`junhoyeo/tokscale` 的 `crates/tokscale-core/src/sessionize.rs`：按 `(client, session_id)` 分组，消息区间 `[ts, ts+duration_ms]`，下一段开始不晚于当前块结束 + 3 分钟即合并；会话活跃时长 = 各块时长之和；**全局总时长是各会话直接相加**（并行会话重复计算）；另有 `max_concurrent_sessions`（扫描线）和跨零点按比例拆到各天。

本项目直接沿用，差异只有一处：代理拥有每个请求真实的开始/结束时间，单条请求也有时长，不像 tokscale 里没有 duration 的消息只是一个点。

### 2.4 实测分布（用于定默认值）

| 指标 | Codex | 说明 |
| --- | --- | --- |
| 同根会话相邻请求间隔 ≤30s | 93.5% | |
| 30s–3m | 3.7% | |
| 3–5m | 0.6% | 3 分钟正落在低谷，默认阈值取 3 分钟 |
| 5–15m / 15–60m / >1h | 1.0% / 0.6% / 0.6% | |
| 请求时长 p50 / p90 / p99 | 13.8s / 49.3s / 144.4s | 必须用真实起止时间，而不是把请求当成点 |
| 子 Agent 并入根会话后的总时长变化 | 约 −7% | 并入对结果影响小 |
| 跨用户或跨 Token 的根会话 | 0 | 按根会话归属不会有歧义 |

阈值敏感性：多数用户从 3 分钟放宽到 10 分钟只增加 10%–30%；但脚本类调用（大量单请求会话、几十个并行）在 10 分钟口径下会膨胀 4 倍以上。因此阈值不宜放大，且必须有 §6 的排名防护。

## 3. 配置

~~~yaml
org_reports:
  enabled: false             # 默认关闭
  timezone: Asia/Shanghai    # 日/周边界
  week_start: monday
  idle_gap_seconds: 180      # 同一根会话内的合并阈值
  ranked_clients: [codex, claude_code, opencode, dsh, pi, zcode, custom]  # 进入时长排名的客户端；词表覆盖新增的客户端可追加
  anomaly:
    max_concurrent_roots: 10       # 周内峰值并行根会话超过即标记
    max_single_request_roots: 200  # 周内单请求根会话超过即标记
  llm_classification:              # 保留字段，必须为 false；功能由顶层 session_analysis 提供（模块 24）
    enabled: false
~~~

启动校验：`enabled=true` 时必须同时配置 `newapi.access_token`/`user_id`（身份）且 `insights.enabled=true`（会话与 Agent 树），否则拒绝启动。项目组、项目和规则存数据库并在管理页维护，不进 YAML，避免把真实仓库名写进配置样例。

**页面上可改的项（2026-11-12）**：管理员可以在"系统配置 → 周报与分析"里修改 `idle_gap_seconds`、`ranked_clients` 和 `anomaly` 的两个阈值并保存。

- 保存的值存放在 `runtime_settings` 表的 `org_reports` 一行，覆盖配置文件里的同名项，重启后仍然生效；"恢复为配置文件的值"删除这一行。保存时跑与启动相同的校验，不过返回 400 和字段说明。
- **`ranked_clients` 在页面上是勾选，不是输入**：可选项是洞察词表能识别的客户端（内置的加上词表覆盖里新增的），由接口的 `clients` 返回。请求先由词表判定属于哪个客户端，这里只决定哪些进排名；词表里没有的键不会命中任何请求，所以页面保存时拒绝这样的键（400）。配置文件里仍可以写任意格式合法的键，启动时如果其中有词表不认识的，记一条 `org_ranked_client_unknown` 告警；页面会把它们单独标出，保存时去掉。要让新客户端进排名，先在洞察词表里加识别规则。
- 保存后立即生效：未冻结的周（含本周）下一次读取就按新值计算，1 分钟的结果复用也不会返回旧值。**已冻结的周保持原来的快照**，要按新值重算需要对该周点"重新生成"。
- `enabled`、`timezone`、`week_start` 只能在配置文件里改：后两项决定每一周的起止，改动会移动已经保存的周的边界。
- 启动时保存的值读不出或校验不过，记一条 `runtime_settings_invalid` 告警并忽略，按配置文件启动。
- 接口（仅管理员，开发者 403，未启用时 404）：`GET`、`PUT`、`DELETE /api/v1/settings/org-reports`。原有的 `GET /api/v1/org/settings` 返回当前生效的值。

原设计里的子开关 `org_reports.llm_classification` 不再使用：对应的功能由顶层开关 `session_analysis` 提供（[模块 24](24-session-analysis.md) §4）。这个键仍保留在配置结构里，已有的配置文件照常加载，但值必须为 false，设为 true 会拒绝启动。`session_analysis` 只依赖 `insights.enabled`，不依赖 `org_reports`；两者都开启时，会话分析额外得到项目归属、项目与项目组范围的周报（§13.6）。

## 4. 数据模型（PostgreSQL migration 002）

| 表 | 说明 | 生命周期 |
| --- | --- | --- |
| `audit_project_identity` | 每条 audit 一行：`source`（`codex_turn_metadata`/`agent_header`/`cwd`/`none`）、`remote_fpr`、`repo_root_fpr`、`cwd_fpr`（keyed HMAC）、`identity_enc`（规范化 remote URL、仓库根目录、cwd 的密文） | 随 audit 级联删除 |
| `project_groups` | `id`、`name`、`enabled` | 管理数据 |
| `projects` | `id`、`name`、`group_id`（NULL = 全员统一项目）、`rules`（JSON：`repo_url` 通配 / `repo_name` / `path_glob` / `agent_project`） | 管理数据 |
| `group_members` | `newapi_user_id` → `group_id`，每人只属于一个组 | 管理数据 |
| `principal_class` | 按 `newapi_user_id` 或 `newapi_token_id` 标记 `human`/`service` | 管理数据 |
| `org_weekly_stats` | （周, 组, 用户, 项目）→ 活跃时长、根会话数、请求数、Token 四桶、实际计费、峰值并行、身份覆盖率；`frozen_at` | **不级联**，超过 retention 仍保留 |

- 所有派生表都不进 HMAC 完整性链（与 `audit_analysis`、`token_links` 先例一致），并用测试锁定。
- 新表不进 SQLite→PostgreSQL 离线迁移（`internal/storage/migrate/tables.go`），因为旧格式里没有这些数据。
- 不在 `audit_analysis` 上加列，也不提升 `AnalysisVersion`：现有回填每 30 秒最多 20 条，重算全部历史需要约两天且依赖 Body 重建；而 Codex 的项目标识只依赖 Header，可以单独快速回填。

## 5. 项目识别

### 5.1 提取（异步，按 audit）

每条请求提取三类信号，按强弱排序：**remote**（remote URL 或可比对的项目哈希）> **root**（仓库根路径）> **cwd**（工作目录，可能是仓库的子目录）。另有显式声明 **declared**（`X-Agent-Project`），它优先于以上三类。

| 信号 | 来源（按客户端） |
| --- | --- |
| declared | 任意客户端的 `X-Agent-Project` Header（与模块 20 §11 的 `X-Agent-*` 属同一套词表机制） |
| remote | Codex：请求体 `client_metadata["x-codex-turn-metadata"]`（没有时取同名 Header），值是 JSON 字符串，需再解析一层，读 `workspaces.*.associated_remote_urls`（优先 `origin`，保留全部）。OpenCode v2：`x-opencode-project` Header（sha1 哈希，比对方式见下文） |
| root | Codex：`workspaces` 的键；OpenCode v2：`<env>` 的 `Workspace root folder:`；Claude Code：`Contents of <root>\CLAUDE.md (project instructions…)` 所在目录；pi：最近一个 `<project_instructions path=…>` 所在目录 |
| cwd | Codex `<environment_context><cwd>`；Claude Code / ZCode ` - Primary working directory:`（以及 `# Environment update` 中的新值）；OpenCode `Working directory:`；pi `<cwd>` 或 `Current working directory:`；dsh `dsh_session_log.session.cwd` 或 `Current working directory: "<path>".` |

- **规范化**：remote URL 中的 `git@host:org/repo.git`、`ssh://git@host/org/repo`、`https://user@host:port/org/repo.git` 一律统一为小写 `host/org/repo`。路径把 `\` 换成 `/`，并且不区分大小写。
- **OpenCode 项目哈希**：管理员配置 `repo_url` 规则时，同时用规范化后的 URL 预先算出 `sha1("git-remote:" + host/org/repo)`，与 `x-opencode-project` 直接比对，不需要解密。只有带 origin 的仓库能这样匹配；以根提交 SHA 或 `global` 作为项目 ID 的，退回按 root/cwd 匹配。
- **文本扫描范围**：cwd 和 root 可能出现在 system、user（含 `<system-reminder>` 包裹的 meta 消息）甚至会话中途插入的 system 消息里，所以提取器扫描全部文本块，同一请求里取**最后出现**的值（对应"环境更新"）。
- **只扫描请求开头和末尾**：完整环境块一般在会话开头注入，随历史一起重发；压缩后可能消失。为控制开销，只扫描前若干条和最后若干条消息。

实现位置：在 insights 词表为每个客户端新增 `project_headers`、`project_body_paths`、`project_text_patterns`（会自动扩展 Header 采集白名单，需加入 `x-codex-turn-metadata`、`x-opencode-project`、`x-agent-project`），并在 analyzer 旁新增提取器。实时路径在 parser worker 内执行。历史回填分两种：**Header 类信号**（Codex、OpenCode、declared）只读 `http_headers` 并解密单个 Header，速度快；**文本类信号**需要请求体，raw 已释放的 OpenAI 记录走已验证的重建，Anthropic 记录依赖 raw 是否还在，否则跳过。

### 5.2 归属（查询时）

- **会话级继承**：同一 Agent 节点（Codex `thread-id`、Claude Code agent-id 或会话、OpenCode/dsh/ZCode 的会话 Header）内，没有标识的请求继承最近一次已识别的标识；整个节点都没有标识时，退回根会话内的多数标识。节点和根会话都按调用者（API Key 指纹）区分：两个调用者碰巧用了同一个会话 ID 时，不会互相继承标识。这是 Claude Code、ZCode 的硬性要求：它们的环境块只在会话开头完整出现一次，标题等附属请求里没有环境块。dsh 子 Agent 继承父目录，OpenCode 子会话继承父项目，与此一致。
- **cwd 到仓库**：cwd 先与同一员工已见过的 root 做最长前缀匹配，归到仓库根；再按规则匹配 `repo_name`（路径任一段）或 `path_glob`。
- **规则匹配**：按指纹对去重后的标识解密，一周只有几百个；再依次匹配用户所在组的项目规则 → 统一项目规则 → 未命中。
- **未命中分两个桶**：“未归属”（有仓库或 cwd 但没有匹配上规则）、“无项目上下文”（聊天类客户端，请求里没有任何路径）。这两个桶也是模块 24 合规模式里“工作相关性”复核的输入（24 §10）。
- 修改规则后，未冻结的周自动重新归属；已冻结的周提供“重新生成”。

## 6. 时长与排名

### 6.1 算法

1. 会话 = Agent 树的根（`agent_root_fpr`）。同一棵树的根 Agent、子 Agent、压缩、标题等附属请求都放进同一条时间线。
2. 每条请求取区间 `[started_at_ns, ended_at_ns]`，按开始时间排序；开始时间不晚于当前块结束 + `idle_gap_seconds` 即并入该块。
3. 根会话时长 = 各块时长之和；**员工时长 = 各根会话时长直接相加**，以鼓励并行。
4. 块内时长按各项目的请求区间时长占比分配给项目。
5. 跨天、跨周的块按区间重叠比例拆分。
6. 并行度：用扫描线统计周内峰值和平均同时进行的根会话数，只数根会话，不数子 Agent。

已知偏差与对策：

- 没有根标识 Header 的三层及以上 Agent 树，可能被拆成两个根（模块 20 §13），从而多算时长。Codex 与 Claude Code 自带根标识，不受影响；OpenCode、dsh 只发直接父节点，深层树需沿父链上溯；自研框架应带 `X-Agent-Session-Id`。
- **没有会话标识的附属请求不单独成根**：pi 的压缩请求、dsh 经 pi-ai 发出的请求，以及 OpenCode 中标题等识别为 `compaction`/`title`/`auxiliary`、却无法关联到会话的请求，只计 Token 和计费，不计时长，也不计根会话数。
- **没有会话标识的主请求**（pi 走 Chat Completions 或 Anthropic、dsh 走 pi-ai）沿用模块 20 的推断会话键（系统提示指纹加首条用户消息）。推断会话可能误合并，周报对这类客户端的时长标注"推断"。
- **pi 的缓存预热**会在会话空闲后最多 60 分钟内持续发刷新请求，会把空闲时间算成活跃。需要先找出这类请求的特征（§11），找到后从时长计算中剔除，只计 Token 和计费。

### 6.2 排名防护

- 默认只有 `ranked_clients` 中的客户端进入时长排名；`unknown` 和聊天类客户端单独展示。
- `principal_class=service` 的用户或 Token 不进排名，在“服务/系统”分区单独展示；NewAPI 管理员账号（`user_id` 为配置中的管理员）默认列为 service 候选，由管理员确认。
- 周内峰值并行或单请求根会话数超过 `anomaly` 阈值时，在该行打上异常标记并说明原因，但不自动排除。
- 每行都显示身份覆盖率（resolved / 全部），提示未识别请求对数字的影响。

## 7. 周报快照与 API

- **作业**：在 parser worker 空闲时运行（与 backfill tick 同一套节奏）。每周结束后为上一周生成快照并 `frozen_at`；手动“重新生成”会覆盖该周快照。快照必须在 retention 删除原始记录之前完成，30 天 retention 下有充足余量。
- **本周至今**：实时用 SQL 加 Go 计算，不落库。
- **管理端点**（需鉴权，`no-store`）：
  - `GET /api/v1/org/weekly?week=&group_id=&metric=hours|tokens|cost`：排名、人 × 项目矩阵、服务分区、异常标记。
  - `GET /api/v1/org/weekly/trend?weeks=N&group_id=`
  - `GET /api/v1/org/projects/{id}/weekly?week=`
  - `GET /api/v1/org/unattributed?week=&limit=`：未归属的仓库或 cwd Top N，按需解密，仅管理员可见。
  - 项目组、项目、成员、主体分类的 CRUD：沿用 `content_policy_rules` 的模式（先持久化，再编译校验，最后原子替换快照）。
- developer 会话：所有 `/api/v1/org/*` 返回 403；只额外开放“我的本周”一行（自己的时长、项目分布），不返回他人数据。

## 8. Web UI

沿用现有 React + recharts，不新增依赖；`org_reports.enabled=false` 时隐藏导航入口。

- **项目周报页**：顶部是周选择器和项目组筛选。主体依次为：排名柱状图（按项目分段堆叠，指标可在时长、Token、计费之间切换，行内显示覆盖率和异常标记）→ 人 × 项目热力矩阵 → 近 N 周趋势 → 服务/系统分区。
- **项目视角**：某个项目的贡献者、时长与成本。
- **管理页**：“项目组与项目”页（2026-11-12 起位于“系统配置”菜单内，见 10 §11）：组、成员、项目规则（含规则命中预览）、主体分类、未归属 Top N（一键生成规则草稿）。

## 9. 非工作用途识别（已移交模块 24）

这一章的设计由[模块 24：会话记录分析](24-session-analysis.md)取代，本文不再维护。要点和修订：

- 模块 24 改用部署方自建的**本地模型**，内容不出机器，所以原先“只把最少内容送给模型”的限制不再是外发问题，而是内部权限问题（24 §9）。
- 原规则“已命中公司项目的会话直接判为工作、不调用 LLM”是为了限制内容外发。改用本地模型后，模块 24 的改进模式会分析全部符合条件的会话，不再按归属跳过。
- 合规模式里的“工作相关性”复核仍然只取“未归属”和“无项目上下文”两个桶（24 §10）。分类枚举、复核队列、证据冻结和影子运行都在 24 §10，属于其 S4，尚未实现。
- 治理前提（员工告知、具名复核人、查看日志）见 24 §13。

## 10. 里程碑

| 里程碑 | 内容 | 主要改动 | 测试 |
| --- | --- | --- | --- |
| P0（前置修复，可独立提交） | 修正词表中 dsh 的父会话路径（`dsh_session_log.session.parentSession`）及相关测试；默认词表新增 `zcode`（UA `ZCode/`，节点头 `x-session-id`，角色按 `x-zcode-session-type` 和 `x-zcode-query-source`）与 `pi`（UA `pi/`，节点头 `session-id`，仅 Responses 协议有）；按 §2.2 更正模块 20 §5.8 和部署指南中的 OpenCode 版本说明；`AnalysisVersion` 加一，让历史记录重算 | `internal/insights/vocabulary_default.yaml`、`agent_test.go`、`insights_e2e_test.go`、doc 20 | dsh 父子按新路径连边；ZCode 与 pi 不再落入 `unknown`；pi 的 `session-id` 不会被误判为 Codex（Codex 识别需要 UA 或 `originator`） |
| M0 | `org_reports` 配置、校验、开关；关闭时零副作用 | `internal/config`、`internal/app` 组装、web 路由守卫 | 关闭时 org API 404 且无 worker；开启但缺依赖时拒绝启动 |
| M1 | 项目标识提取与快速回填，按 §2.2 覆盖全部客户端 | 词表 `project_headers`/`project_body_paths`/`project_text_patterns`、Header 白名单、提取器、`audit_project_identity`、migration 002 | 每个客户端各一个脱敏录制样本：Codex（body、Header、双层 JSON）；OpenCode v1/v2（`<env>`、`x-opencode-project` 哈希比对）；Claude Code 与 ZCode（meta 消息、`# Environment update`、CLAUDE.md 推出仓库根）；pi（`<cwd>` 与旧格式）；dsh 原生与 pi-ai 两条路径。另测：scp/https/带端口的 URL 规范化、Windows 路径、同一请求取最后一个环境值、DB 中没有明文路径、不改变完整性摘要 |
| M2 | 项目组、项目、成员、主体分类 CRUD 与管理页 | storage 层、`internal/web/api.go`、前端管理标签 | 规则编译失败不替换快照；组内规则优先于统一项目；developer 403 |
| M3 | 时长引擎与归属 | 新包 `internal/orgreport`（纯函数：会话切块、继承、分配、跨周拆分、扫描线） | 用合成 fixture 覆盖：并行根会话相加、子 Agent 并集、3 分钟边界（`<=` 合并）、跨零点和跨周按比例拆分、单请求时长、service 排除、异常标记、无会话附属请求不计时长、推断会话标注、缓存预热请求剔除 |
| M4 | 周快照作业、org API、周报页 | `org_weekly_stats`、作业调度、前端页面 | 冻结后修改规则不影响已冻结周、重新生成可覆盖；retention 删除 audit 后快照仍在；用一份生产形态的脱敏样本离线核对口径 |
| M5 | 见[模块 24](24-session-analysis.md) 的 S0–S4：确定性信号、输入包、本地模型 facet、周度聚合已实现；非工作识别、复核队列、证据冻结属于 S4，未开始 | 模块 24 | 见 24 §12 |

建议排期：P0 与本功能无关，现在就可以单独做。M0 等当前未提交的 PostgreSQL 迁移改动合入后再开；M1 和 M2 可以并行；M3 依赖 M1；M4 依赖 M2 和 M3。

### 10.1 推荐的客户端侧配置（可选，提高归属准确率）

自定义 Header 在多数客户端里是按 provider 静态配置的，没法随项目变化，所以 `X-Agent-Project` 只在下面两种情况下值得推广；其余情况靠 cwd 和仓库根自动归属。

| 客户端 | 做法 | 效果 |
| --- | --- | --- |
| pi | `models.json` 的 `headers`：`"X-Agent-Project": "!basename \"$(git rev-parse --show-toplevel)\""`；用全局扩展的 `before_provider_headers` 写入 `x-agent-session-id` | 每次请求动态带项目名；补齐 Chat Completions 和 Anthropic 协议下缺失的会话标识 |
| Claude Code | 托管设置的 `env` 统一下发 `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`；在项目内的 `.claude/settings.json` 写 `ANTHROPIC_CUSTOM_HEADERS: "X-Agent-Project: <name>"` | 拿到请求类别头，附属请求不再靠推断；项目级声明随仓库走 |
| 自研框架 | 每个请求带 `X-Agent-Project` 和 `X-Agent-Session-Id` | 精确归属，三层以上的树也不会断开 |

## 11. 待确认

1. 解密一长一短两条 `x-codex-turn-metadata` 样本，确认长值含 `workspaces`，并查明短值的来源（M1 开工前）。
2. 通过词表覆盖接入的自研客户端（只带 `X-Agent-*`，没有 cwd）需要在请求上带 `X-Agent-Project`，否则其流量只能落到“无项目上下文”。
3. NewAPI 管理员账号及其集成 Token 是否全部标为 service。
4. `work_adjacent` 是否算正常使用：已移到模块 24 §13 第 7 项，在其合规模式（S4）之前确定。
5. ZCode 子 Agent 如何关联父会话：源码显示子 Agent 的 `x-session-id` 很可能是它自己的 ID，需要抓一次真实请求，确认能否用 `x-zcode-trace-id` 或 `metadata.user_id` 关联到父会话。
6. pi 缓存预热请求的特征（`core/cache-warmer.ts`，如 `max_tokens`、消息结构），确认后写入词表的附属请求规则。
7. Claude Code 的 `CLAUDE_CODE_GATEWAY_HINT_HEADERS` 是否通过托管设置统一开启。
8. 上述各客户端的结论来自源码和文档，M1 开工前每个客户端至少用一次真实请求，经本代理的审计详情核对。

## 12. 验收

- 关闭开关时，行为与当前版本完全一致。
- Codex 请求能按 remote URL 归属到项目；同一会话中先于 git 信息到达的请求能继承项目；非 git 目录能按 cwd 规则命中。
- OpenCode v2 能按 `x-opencode-project` 哈希命中 `repo_url` 规则；Claude Code、ZCode 后续请求和标题请求都能从会话开头的环境块继承项目；pi、dsh 能按 cwd 命中；每个客户端的录制样本都归属正确。
- 时长：并行根会话相加，同一棵树内取并集；与 §6.1 的合成 fixture 期望值逐项一致。
- service 主体不进排名；异常行有标记和原因。
- DB/WAL 中没有明文 remote URL、仓库路径或 cwd；派生表变化不改变任何完整性摘要。
- developer 会话看不到他人数据；所有 org 端点都返回 `no-store`。

## 13. 实现记录与偏差

本节记录落地时与上文计划不同或补充的地方；配置、表和 API 的最终定义分别见 [01](01-configuration-and-route-boundary.md)、[04](04-sqlite-storage-and-migrations.md) §3.5、[10](10-query-api-and-minimal-web-ui.md)。

### 13.1 M1 项目标识

- **词表**：每个客户端新增 `project_headers`、`project_body_paths`、`project_text_patterns`（元素分别为 `{header, kind}`、`{path, kind}`、`{kind, pattern}`），另有顶层 `project: {headers, body_paths, text_patterns}` 对**所有**请求生效（包括 `unknown` 客户端）。这样 pi、ZCode 在默认词表还没有它们的客户端条目时也能按 cwd 识别；Claude Code/ZCode、OpenCode、pi、dsh、Codex `<cwd>` 的文本模式都放在共享列表里。`kind` 取值：`declared`、`codex_turn_metadata`、`opencode_project`、`remote`、`root`、`root_file`（捕获的是文件路径，取其目录）、`cwd`。覆盖文件里的列表整体替换默认列表。
- **Header 白名单**：`Vocabulary.HeaderAllowlist()` 不变；新增 `ProjectHeaderAllowlist()`，只有开启 `org_reports` 时才并入 parser 的解密白名单。`audit_analysis` 的结果因此与关闭时逐字节一致，`AnalysisVersion` 未提升；提取器有自己的 `ProjectIdentityVersion`（当前 1）。
- **优先级**：客户端自身的条目先于共享条目；请求体路径先于 Header（Codex 的 Header 只在请求体没有 `workspaces` 时作为回退）；文本模式最后执行，只补空缺字段，同一请求内后出现的匹配覆盖先出现的（环境更新）。只扫描前 8 条与后 8 条消息里的 system/developer/user 文本（含注入块），**从不扫描工具结果、工具调用和 assistant 文本**，避免工具输出里的路径被误认成 cwd。
- **`source` 取值**比计划多了 `declared` 与 `root`：`declared` > `codex_turn_metadata`（remote）> `agent_header`（OpenCode 哈希）> `root` > `cwd` > `none`。另加 `body_scanned` 列，标记该行是否读过请求体（回填时 Header 已有强信号就不读请求体）。
- **OpenCode 哈希**：解密后的身份里保存 Header 原值（40 位十六进制，`global` 等值丢弃）；规则编译时对字面量 `repo_url` 预先计算 `sha1("git-remote:" + host/org/repo)` 比对。OpenCode 自己对 origin 的规范化方式是否与本项目一致仍待真实请求核对（§11）。
- **回填**：parser worker 每个扫描周期（30 秒）在 insights 回填之后执行，按 `started_at_ns` **倒序**、每次最多 50 条，让本周和上周先补齐。先只解密白名单 Header；Header 没有 remote、项目哈希或声明名时才读请求体：raw 仍在则直接读，OpenAI 的 metadata 记录走已验证的重建，Anthropic/Gemini 的 raw 已释放则只保存 Header 结果。
- **迁移**：`002_org_reports.sql` 只在运行时 `migrate()` 中执行，离线导入器的基线仍是 001（见 04 §3.5）。副作用：已被新版代理打开过的空库会多出 org 表，不能再作为离线导入目标；导入应在首次启动前完成。
### 13.2 M2 项目组、项目与主体

- 目录（组、项目、成员、主体分类）的变更先在内存里对**整个候选目录**编译校验，通过后才写库，写库成功后原子替换快照；任一环节失败，数据库与快照都保持原样（测试 `TestServiceCRUDPersistsThenSwapsTheSnapshot`）。这比 `content_policy_rules` 更严格：后者只预编译单条规则。
- 匹配顺序：先用户所在组的项目，再统一项目；每个范围内按信号强弱分层（声明 > remote/项目哈希 > 仓库根 > cwd），同层按项目 id 取第一个命中。停用的项目、停用组的项目都不参与匹配。cwd 先映射到同一用户本周已见过的最长仓库根，再匹配 `repo_name`（路径任一段）和 `path_glob`。
- 通配语义：`*` 不跨 `/`，`**` 跨段，`?` 匹配一个字符，其余字面量；`repo_url` 写成 `https://…`/`git@…` 形式时先按 remote 规则规范化。
- 删除仍有项目或成员的组返回 409（外键 `RESTRICT`），不会级联删除项目。删除项目后，已冻结周的快照仍保留其 id 和名称。
- “规则命中预览”与“未归属 Top N”在 M2 就实现了：它们需要按周加载请求并解密去重后的标识，这部分加载与归属管线（`orgreport.Attribute`）也是 M4 周报的输入。
### 13.3 M3 时长引擎

- 实现在 `internal/orgreport`（`engine.go`、`week.go`、`inherit.go`），全部是纯函数，用合成 fixture 覆盖 §10 M3 列出的每一项。
- 块的活跃时长 = 块内最早开始到最晚结束（块内 ≤ 阈值的空闲间隔计入），与 tokscale 一致；间隔恰好等于阈值时合并。没有结束时间或结束早于开始的请求按时间点处理（不贡献时长）。
- 块按区间重叠拆到周和天；项目按块内各项目请求区间时长的占比分配（全是时间点时按请求数），余数给权重最大的项目，保证分项之和等于块时长。
- **排名行只统计 `ranked_clients` 的根会话**：项目分段、逐日时长、并行度和单请求根会话数都只来自进入排名的客户端；其他客户端的时长合并为 `other_active_ns` 单独显示。Token 与计费按请求开始时间计入该周，不分客户端。
- 没有任何会话标识的请求：附属角色（压缩、标题、review、auxiliary）与缓存预热请求只计 Token/计费；主请求各自成为一个单请求根会话（会进入单请求根会话计数，被异常阈值捕获）。
- 推断会话（`session_link=inferred`）的时长计入 `inferred_ns`，行上带 `inferred_sessions` 说明标记。
- 缓存预热剔除的**机制**已实现（`Request.CacheWarm`），但 pi 缓存预热请求的识别特征尚未确认（§11.6），当前没有任何请求被标记。
- 调用者无法识别（`token_links` 缺失）的请求归到 `user_id=0`，不进排名，在报表里单独汇总。

### 13.4 M4 周快照、API 与页面

- 快照表 `org_weekly_snapshots` + `org_weekly_stats`（见 04 §3.5），没有指向 audit 的外键，retention 删除原始记录后仍可读取；项目名按冻结时保存。
- 冻结作业挂在 parser worker 的空闲任务上（与回填同一 30 秒节奏）：每 10 分钟最多检查一次，只启动一个受保护的后台 goroutine，不阻塞解析。它从旧到新检查最近 5 个已结束的周（覆盖默认 30 天 retention），周结束 2 小时后才冻结；该周仍有待解析的请求或缺当前项目标识的已分析请求时推迟，但周结束 72 小时后无论如何冻结（记录 `org_snapshot_incomplete` 告警），保证在 retention 之前落库。当前周永不冻结。
- 已冻结的周直接读快照，修改规则不影响它；“重新生成”按当前规则和仍保留的证据重算并整体覆盖。本周与未冻结的周实时计算，同一目录快照下 1 分钟内复用结果。
- 每次加载一周时前后各多读 24 小时，用于把跨周的块按重叠拆分；超过 24 小时不间断（每段间隔 ≤ 阈值）的活动会在边界处被截断，这在实际中可以忽略。
- developer 的“我的本周”只返回会话身份（NewAPI 用户 id，来自签名 Cookie）对应的一行；身份未知时返回空行。所有 org 端点都是 `no-store`。
- 页面复用 recharts 与现有设计 token（项目系列颜色复用分类色 `cat-*`，未归属/无上下文用中性色），通过 `design-tokens.test.ts`。

### 13.5 验证范围与未关闭事项

- 本分支的开发环境没有 PostgreSQL：`internal/storage/postgres` 下新增的集成测试（迁移只执行一次且导入基线不建 org 表、身份行往返与级联删除、`TestDerivedOrgTablesStayOutsideTheEvidenceChain`、回填候选倒序、目录 CRUD 与约束、快照往返与 retention 后存活）都会因缺少 `TEST_DATABASE_URL` 跳过，**尚未实际执行**。业务逻辑在纯函数、内存仓库与 HTTP 层测试中覆盖。
  - 更新：合并后，上述 `internal/storage/postgres` 测试已在一次性的 PostgreSQL 18.6 容器上随整个包执行通过（没有跳过）；生产形态数据的口径核对仍未做。
- §10 M4 要求的“用一份生产形态的脱敏样本离线核对口径”未做（需要真实数据，不在本仓库范围）。
- **已知问题：在已有历史的库上首次启用时，旧周会在没有项目标识的情况下冻结。** 项目标识回填每 30 秒最多 50 条、从新到旧；而结束超过 72 小时的周不等回填，启动后第一次检查就冻结（记 `org_snapshot_incomplete`），这些周的归属几乎全是“未归属”。在一份有三周多历史的真实数据副本上试运行时，两个旧周在启动两分钟内以这种状态冻结，上一周也在到期时冻结。现在的补救办法是等回填走过对应的周之后，对该周点“重新生成”。还没有修：可选的做法是首次启用时等回填完成再冻结，或回填完成后自动重新生成带 `org_snapshot_incomplete` 的周。
- §11 第 1–8 项全部仍待确认，尤其：Codex 长/短 `x-codex-turn-metadata` 样本（§11.1）、OpenCode 对 origin 的规范化是否与 `NormalizeRemote` 一致（新增）、ZCode 子 Agent 关联（§11.5）、pi 缓存预热特征（§11.6，确认后需给词表加附属请求规则并让加载器设置 `CacheWarm`）、各客户端真实请求核对（§11.8）。
- 已被新版代理打开过的空 PostgreSQL 库不能再作为 SQLite→PostgreSQL 离线导入目标（导入器会把 org 表视为未知表）；导入应在首次启动前完成。
- 与另一会话的词表修正（dsh 父路径、`zcode`/`pi` 客户端、`AnalysisVersion`）合并时，`vocabulary_default.yaml` 与 `vocabulary.go` 可能有文本冲突；本分支只在各客户端块的 `priority` 行后追加 `project_*` 键，并在文件末尾新增 `project:` 段。合并后 pi/ZCode 有了客户端键，共享文本模式仍然生效。

### 13.6 提供给模块 24 的接口

模块 24（会话记录分析）在 `org_reports` 开启时使用本模块的归属结果，接口都在 `internal/orgreport`，细节见 24 §16“与模块 23 的对接”。

- `Service.ResolveSession(root, apiKey)`：给一个分析会话（同一个 Agent 树根、同一把 Key 的请求）求单一归属，返回项目 id、项目名、命中规则的信号级别、是否 service，以及“尚无结论”标记。
  - 只读该会话自己的请求（`LoadOrgSession`），沿用 §5.2 的会话内继承和规则匹配顺序。
  - cwd 只映射到本会话内出现过的仓库根，不像周报那样使用该员工当周见过的全部仓库根。
  - 身份密文在本服务内解密，调用方拿不到仓库地址和路径。
- `Compiled.ResolveLevel`：`Resolve` 的扩展，同时返回命中规则所在的信号级别（declared / remote / root / cwd）。
- `Compiled.IsService`、`Service.ReportGroups`、`Service.ProjectName`：主体分类、启用的项目组及其成员、项目当前名称。
- 归属规则、成员或主体分类变化后，模块 24 在下一轮批处理里对本周和上周的会话重新求归属；更早的会话不变。
