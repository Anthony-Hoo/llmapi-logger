# 模块 20：上下文分析与用量洞察

> 状态：已实现（首版）。与最初草案不同之处见 §13；用户接入指南见[部署：洞察与 Agent 接入](../deployment/insights-and-agent-headers.md)
> 日期：2026-10-16
> 参考：[bowenliang123/dsh-context](https://github.com/bowenliang123/dsh-context)（Apache-2.0，DeepSeek Harness 插件）
> 文中的配置字段、表和 API 已分别并入 [01](01-configuration-and-route-boundary.md)、[04](04-sqlite-storage-and-migrations.md)、[10](10-query-api-and-minimal-web-ui.md)，以那里为唯一来源；本文保留设计动机与算法。

## 1. 目标与边界

dsh-context 回答三个问题：Agent 的上下文窗口里装了什么、它是怎么一步步长起来的、花了多少 Token 和钱。本项目已经在代理边界上看到每一次完整的 LLM 请求与响应，天然具备回答同样问题的输入，而且比插件更直接：每个请求 Body 本身就是一份完整的上下文快照，不需要像 dsh-context 那样从会话事件日志（`fold.ts`）里重放、补齐被压缩的历史。

本模块新增：

- 用量归一化：缓存读/写、推理 Token，以及按协议统一的计费口径。
- 上下文构成：按类别估算每个请求的 Token 分布，并锚定到上游报告的真实 prompt 总量。
- 会话趋势：逐请求（step）/逐轮（turn）的构成变化，Total/Delta 两种视图和事件标记。
- 用量洞察页：KPI、日用量图、活动热力图和会话卡片。
- 成本估算：内嵌价格快照，可由本地文件覆盖。
- 详情增强：单条请求的上下文浏览器、与上一步的差异、文件活动。

不做：

- 不改写任何请求或响应。dsh-context 的 System Prompt 前后缀注入（`promptInjection.ts`）属于写路径，与本项目“审计失败不得篡改已放行流量”的原则冲突。
- 不新增热路径工作。所有派生指标在异步 parser 中计算，代理字节路径不变。
- 不把消息正文、工具参数、文件路径或系统提示词以明文写入任何汇总表。

## 2. 功能取舍

依据 dsh-context 各模块的输入依赖逐项判断。dsh-context 的输入是 Harness 会话日志；本项目只有 API Body、四阶段时间和 SSE timeline。

| dsh-context 功能 | 依赖 | 结论 | 说明 |
| --- | --- | --- | --- |
| Token Stats、缓存命中率、成本（`cost.ts`/`modelPrices.ts`） | 响应 `usage`、模型、时间 | **移植（P0）** | 输入全部在响应里，需要按协议归一化口径 |
| 上下文构成 + 4 字符/Token 估算 + 锚定（`estimate.ts`/`pricing.ts`/`categories.ts`） | 请求 `system`/`tools`/`messages` + `usage` | **移植（P1）** | 角色直接对应；`inject`/`skill` 只能靠文本标记启发式判断 |
| 上下文趋势 Total/Delta、Step/Turn（`trendChart.tsx`） | 同一会话的连续请求 | **移植（P1）** | step=一次请求；turn 由“最后一条是真实用户消息”判定 |
| 洞察页 KPI / 7 天图 / 热力图 / 会话卡片（`overview.ts`/`activity.ts`/`heatmap.tsx`） | 逐请求用量 + 时间 + 会话标识 | **移植（P1）** | 会话标题、cwd、工作区分组属于 Harness 状态，改为按调用者/Token/模型分组 |
| 上下文浏览器、与上一步差异、助手类型筛选（`browser.tsx`/`assemble.ts`/`browserNodes.tsx`） | 请求消息 + 上一请求 | **移植（P2）** | 用 item hash 代替 dsh 的 `seq` 匹配消息；Thinking/Tools/Answer 三协议都有对应块 |
| 上下文事件（`fold.ts` 中的 compaction/prune/inject/model/mode） | 连续请求 Body | **部分移植（P2）** | 模型切换精确；压缩、清理、注入为启发式；`mode`（计划模式）不可见 |
| 文件活动（`fileOps.ts`/`fileActivity.ts`） | 工具调用名称与参数 | **移植（P2，仅详情）** | 工具词表改为可配置；路径敏感，只在详情解密展示，不进汇总 |
| Timing：TTFT、生成、TPS（`statsTiming.tsx`） | 时间戳 + SSE | **部分移植（P1/P3）** | 模型侧精确；工具耗时只能用请求间隔近似，且混入用户等待 |
| 工具来源标签（`toolSources.ts`） | 工具名 | **部分移植（P2）** | `mcp__server__tool` 语法通用；内置工具映射改为可配置词表 |
| DNA 条带、Treemap（`dna.ts`/`treemap.ts`） | 请求 Body | **移植（P2）** | 纯结构性可视化，复用构成估算的逐条目清单 |
| Agent 树 / Fleet（`agentTree.ts`） | Harness `parentId` | **移植（P2）** | Codex、Claude Code、OpenCode、dsh 官方适配器都在 Header/Body 中显式携带父子标识（§5.8），内容匹配只作兜底 |
| 占用率 / 压缩预留带（`headline.ts`/`reserve.ts`） | 上下文窗口表 + `max_tokens` | **只移植占用率** | 预留带编码的是 dsh 自己的压缩策略（0.8、65536），对其他客户端无意义 |
| `promptInjection.ts`、`attribution.ts`、`stepIdentity.ts`、`fileTokens.ts` | Harness 运行时内部 | **不移植** | 分别是写提示词、劫持插件注册、补消息 ID、dsh 文件句柄计价 |
| DeepSeek 图像 Token 公式（`imageTokens.ts`） | 图片尺寸 | **替换** | 改为各协议自己的图片计价近似（见 §5.2） |

## 3. 核心架构决策

### 3.1 解析时派生、明文数值、汇总不解密

parser worker 已经持有解密后的请求/响应 Body，在同一次解析中顺带计算分析指标。指标只包含数值、计数、枚举和 keyed 指纹，作为明文列写入新的派生表。洞察页和趋势 API 只做 SQL 聚合，不解密任何内容。这延续了列表页“只定向解密 User-Agent”的姿态，也避免了 N 次详情重建。

明文边界：

| 允许明文 | 只能加密（仅详情按需解密） |
| --- | --- |
| 各类别估算 Token 与条目数、字节长度 | 消息正文、推理内容、系统提示词 |
| 归一化用量各桶、模型名、协议、时间 | 工具名称列表、工具参数、工具结果 |
| 停止原因、响应块类型位图、事件标志 | 文件路径、搜索模式、行数变化明细 |
| 工具调用按**类别**计数（file_read/file_write/search/shell/mcp/other） | 逐条目清单与 item 指纹列表 |
| 系统提示词 / 工具集的 keyed 指纹（HMAC，不可反查） | |

工具名称不进明文：MCP 服务名、自定义工具名可能暴露内部系统。汇总层只按工具类别计数，单会话的 Top 工具在会话页上按需解密有限条记录计算。

### 3.2 派生数据在证据链之外，可重算

`parsed_results` 已纳入 `appendParsedResultDigest`（`internal/storage/sqlite/integrity.go:755`），因此**不在 `parsed_results` 上加列**，而是新建 `audit_analysis` 表：

- 不进入任何完整性摘要，与 `api_key_fpr` 的先例一致（[19 §3](19-developer-key-session.md)、`006_developer_key_fingerprint.sql`）。用测试锁定：改动 `audit_analysis` 不得改变任何已签名摘要。
- 带 `analysis_version`。算法升级时后台按版本补算，不触碰 `parse_status`，失败不影响证据和解析结果。
- 随 retention 级联删除。

### 3.3 会话：复用 OpenAI 图，其余协议轻量拼接

“分析会话”是趋势与会话卡片的分组单位，记为 `analysis_session_id`，粒度是**单个 Agent**（主 Agent 与每个子 Agent 各一个会话，父子关系见 §5.8）。三协议统一按以下顺序取第一个可用的键：

1. **客户端显式 Agent 标识**（§5.8 表中的节点 ID，例如 Codex `thread-id`、Claude Code `x-claude-code-agent-id`/会话 ID、OpenCode `x-opencode-session-id`、dsh `x-deepseek-harness-session-id`）。
2. **OpenAI 既有 `turns.conversation_id`**：仅在没有显式标识时使用。注意它的会话键优先取 `prompt_cache_key`，而 Codex 与新版 OpenCode 把根会话 ID 填进这个字段，所以父子 Agent 会落进同一个 conversation（见 §5.8“对现有轮次图的影响”）。
3. **Anthropic / Gemini 的轻量拼接**：不移植完整对象图。依次取：
  1. 通用 `metadata.{session_id, conversation_id, thread_id}`；Claude Code 新版的 `metadata.user_id` 是 JSON，其中有 `session_id`。
  2. 推断键：`HMAC(派生子密钥, protocol ‖ api_key_fpr ‖ system 指纹 ‖ 首条用户消息 item 指纹)`。同一 Agent 会话的请求共享系统提示词和首条用户消息，主 Agent 与子 Agent 的系统提示词通常不同，因此天然分开。

  会话 ID 为 `ses_<hex>`，键里总是带 `api_key_fpr`，不会跨 Key 合并。
- 上一步（prev step）= 同会话、同 `api_key_fpr`（NULL 只匹配 NULL；会话 id 可能被多个 Key 共享）中时间早于本请求、item 指纹序列与本请求公共前缀最长的那一条，候选上限 32，与 `parentCandidateLimit` 一致。

已知限制：

- OpenAI 的父轮次匹配不按调用者过滤（`graph_writer.go:433-493`），会话可能跨 Key。developer 作用域下所有聚合必须逐行套用 `conditionWithAliases`（`scope.go:94`），会话卡片只统计作用域内的步骤。
- retention 物化的 `retention_checkpoint` 会截断链条，趋势序列从截断点开始，UI 标注“更早步骤已过期”。
- 推断键在“同一 Key、同一系统提示词、同一开场白”的并行会话上会误合并，这类会话在趋势图上表现为锯齿。差异计算选公共前缀最长的候选，可以减轻但不能消除，文档与 UI 都按“推断”标注。

## 4. 数据模型（已并入 04 §3.4）

> 实现以 `internal/storage/sqlite/migrations/008_audit_analysis.sql` 为准（含 Agent 树列与 `agent_spawn_hints` 表），下文 SQL 为早期草图。

迁移 `008_audit_analysis.sql`：

~~~sql
CREATE TABLE audit_analysis (
  audit_id              TEXT PRIMARY KEY REFERENCES audit_records(audit_id) ON DELETE CASCADE,
  analysis_version      INTEGER NOT NULL,
  analyzed_at_ns        INTEGER NOT NULL,
  protocol              TEXT NOT NULL,
  model                 TEXT,             -- 请求模型，缺失时用响应模型
  started_at_ns         INTEGER NOT NULL, -- 冗余自 audit_records，便于范围聚合

  -- 归一化用量（§5.1），NULL 表示上游未报告
  u_uncached_input      INTEGER,
  u_cache_read          INTEGER,
  u_cache_write         INTEGER,
  u_output              INTEGER,          -- 含推理
  u_reasoning           INTEGER,
  max_output_tokens     INTEGER,          -- 请求声明的 max_tokens 类字段

  -- 构成估算（§5.2），单位：估算 Token
  est_system INTEGER NOT NULL, est_tools INTEGER NOT NULL,
  est_user INTEGER NOT NULL,   est_injected INTEGER NOT NULL,
  est_assistant INTEGER NOT NULL, est_reasoning INTEGER NOT NULL,
  est_tool_result INTEGER NOT NULL, est_media INTEGER NOT NULL,
  n_items INTEGER NOT NULL, n_tool_defs INTEGER NOT NULL,
  n_tool_results INTEGER NOT NULL, n_media INTEGER NOT NULL,

  -- 本次响应
  stop_reason           TEXT,             -- end_turn/tool_use/length/content_filter/other
  resp_kinds            INTEGER NOT NULL, -- 位图：1 thinking, 2 tool_call, 4 text
  resp_tool_calls       INTEGER NOT NULL, -- 仅本次响应，修正 tool_call_count 的历史累计口径
  tool_kind_counts      TEXT NOT NULL,    -- 紧凑 JSON：{"file_read":2,"shell":1}

  -- 会话与差异（§3.3、§5.4）
  analysis_session_id   TEXT,
  session_link          TEXT,             -- graph/explicit/inferred/root
  prev_audit_id         TEXT,
  turn_start            INTEGER NOT NULL, -- 最后一条输入是真实用户消息
  appended_items        INTEGER, removed_items INTEGER,
  event_flags           INTEGER NOT NULL, -- 位图：model_switch/compaction/prune/system_changed/tools_changed/injected
  system_fpr            BLOB, tools_fpr BLOB, -- keyed 指纹

  -- 时间（§5.6）
  first_event_ns        INTEGER,          -- 相对请求开始
  generation_ns         INTEGER,

  detail_enc            BLOB              -- 加密：逐条目清单、item 指纹、工具名、文件操作
);
CREATE INDEX audit_analysis_time_idx    ON audit_analysis(started_at_ns);
CREATE INDEX audit_analysis_session_idx ON audit_analysis(analysis_session_id, started_at_ns);
CREATE INDEX audit_analysis_model_idx   ON audit_analysis(model, started_at_ns);
~~~

说明：

- 不做日汇总表。单机单用户量级下，按时间索引的 `GROUP BY` 足够；需要时再加 rollup，不提前设计。
- `detail_enc` 使用与其他对象相同的 AES-256-GCM、独立 nonce 和 audit 级 AAD。
- keyed 指纹复用 `CredentialFingerprinter` 的派生模式，换一个域分离标签（`llmapi-logger/analysis-fingerprint-key/v1`）。

## 5. 算法

### 5.1 用量归一化

统一成四个互斥桶，满足 `prompt_total = uncached + cache_read + cache_write`：

| 协议 | uncached_input | cache_read | cache_write | output | reasoning |
| --- | --- | --- | --- | --- | --- |
| OpenAI Chat | `prompt_tokens − prompt_tokens_details.cached_tokens` | `cached_tokens` | 0 | `completion_tokens` | `completion_tokens_details.reasoning_tokens` |
| OpenAI Responses | `input_tokens − input_tokens_details.cached_tokens` | `cached_tokens` | 0 | `output_tokens` | `output_tokens_details.reasoning_tokens` |
| Anthropic | `input_tokens`（本身已不含缓存） | `cache_read_input_tokens` | `cache_creation_input_tokens` | `output_tokens` | 不单独报告，NULL |
| Gemini | `promptTokenCount − cachedContentTokenCount + toolUsePromptTokenCount`（服务端工具结果回填的输入，不含在 `promptTokenCount` 内；下限 0） | `cachedContentTokenCount` | 0 | `candidatesTokenCount + thoughtsTokenCount` | `thoughtsTokenCount` |

- 流式响应取最后一个带 usage 的事件；Anthropic 合并 `message_start` 与 `message_delta` 的 usage。
- 缓存命中率 = `Σcache_read / Σ(uncached + cache_read + cache_write)`。
- 现有 `parsed_results.usage_*` 保持原样，不改语义。Anthropic 的 `usage_input` 在使用缓存时偏低；UI 一律改读 `audit_analysis`。

### 5.2 构成估算

沿用 dsh-context 的固定密度启发式（`estimate.ts`）：文本 `ceil(chars/4)+4`，消息另加 4 的角色开销，工具定义按序列化 JSON `ceil(len/4)+4`。

类别映射：

| 类别 | OpenAI | Anthropic | Gemini |
| --- | --- | --- | --- |
| system | `system`/`developer` 消息、Responses `instructions` | `system` | `systemInstruction` |
| tools | `tools[]` | `tools[]` | `tools[].functionDeclarations` |
| user | user 文本 | user text 块 | user text part |
| injected | user/developer 文本中命中注入标记的部分 | 同左 | 同左 |
| assistant | assistant 文本 + 工具调用参数 | text + `tool_use` 输入 | model text + `functionCall` |
| reasoning | 历史中的 reasoning 内容 | `thinking` 块 | `thought` part |
| tool_result | `tool` 消息 / `function_call_output` | `tool_result` 块 | `functionResponse` |
| media | `image_url`/`input_image`/文件 | `image`/`document` | `inlineData`/`fileData` |

- **注入标记**来自可配置词表（§6），默认包含 `<system-reminder>`、`<environment_context>`、`<user_instructions>`、`<skill_content`、`# AGENTS.md` 等常见客户端约定。命中按 part 计入 injected，不拆分单个 part。这是对 dsh `source` 元数据的启发式替代，UI 标注“推断”。
- **图片近似**：OpenAI 按 tile（`85 + 170 × tiles`）；Anthropic 按 `w × h / 750`，上限 1600；Gemini 每张 258。尺寸未知时按 binary 字节数的保守常数。
- **锚定**在查询时完成，不落库：`category_i = round(est_i × prompt_total / Σest)`，保留估算比例、对齐真实总量，与 dsh `anchoredParts` 相同。无 usage 时展示原始估算并标注。

### 5.3 步与轮

- step = 一次被审计的请求。
- 输入末尾是用户文本（非 tool result、非纯注入）时 `turn_start=1`。turn 序号在查询时按会话内时间序累计。
- Turn 视图把同一 turn 的多步折叠为最后一步（构成是快照，取末值），步数与耗时求和，与 `aggregateByTurn` 一致。
- Delta 视图：逐类别 `this − prev`（有符号）。柱高为 `Σ|Δ|`，提示里给出净值 `ΣΔ`。

### 5.4 差异与事件

`detail_enc` 保存本请求的 item 指纹序列（keyed HMAC）。计算 prev 时只解密 prev 一条记录的 `detail_enc`，成本有界。OpenAI 直接读 `turn_context_ops`，不需要解密。

| 事件 | 判定 | 置信度 |
| --- | --- | --- |
| model_switch | 本请求模型 ≠ prev 模型 | 精确 |
| system_changed / tools_changed | `system_fpr` / `tools_fpr` 变化 | 精确 |
| compaction | 不是 prev 的前缀扩展，且估算总量较 prev 下降 ≥ 30%、prev 不小于 8k | 推断 |
| prune | 公共前缀长度不变但其中 tool_result 条目指纹改变且估算变小 | 推断 |
| injected | 新增条目中含命中注入标记的部分 | 推断 |

### 5.5 成本

- 内嵌 models.dev 价格快照（`internal/insights/prices.json`，构建时更新，**运行时不外联**）。可选本地覆盖文件，按 `provider/model` 精确、大小写不敏感、唯一后缀的顺序匹配，与 dsh `cost.ts` 的查找链相同但去掉跨厂商投票。匹配不到时不计价并显示“未知价格”。
- 成本 = `(uncached·input + cache_read·cache_read_rate + cache_write·cache_write_rate + output·output_rate) / 1e6`，缺失的缓存价回落到 input 价。成本在查询时计算、不落库，覆盖文件更新后即时生效。
- 时段价（DeepSeek 峰谷）以覆盖文件中的通用 `schedules` 表达，不硬编码厂商规则。
- 上下文窗口取 `limit.context`，用于占用率 = `prompt_total / window`。
- 本项目看不到 NewAPI 的实际计费倍率，UI 一律标为“估算成本”。

### 5.6 时间

- 首事件延迟：`stream_timelines.first_event_at_ns − started_at_ns`（明文）。注意 `ttft_ns` 是到 Nginx 的首字节，两者分开展示。
- 生成时长 = 末事件 − 首事件；TPS = `output / 生成时长`。
- 客户端侧间隔：同会话中 prev 以 `tool_use` 结束时，`本请求开始 − prev 结束` 记为“客户端侧时间（工具执行 + 等待）”。它包含用户审批与 Harness 开销，不叫“工具耗时”。
- 按块类型拆分解码时间（thinking/text/tool）需要 SSE 事件类型与 timeline 对齐，放到 P3。

### 5.7 文件活动（仅详情）

从响应中的工具调用解析，规则来自可配置词表：

| 客户端约定 | 映射 |
| --- | --- |
| `Read`/`read_file` | read |
| `Write`/`Edit`/`MultiEdit`/`NotebookEdit` | write，`+lines(new) / −lines(old)` |
| `Grep`/`Glob` | search |
| `apply_patch`（Codex） | write，按 unified diff 的 `+`/`-` 行精确统计 |
| `str_replace_editor` | 按 `command` 区分 view/create/str_replace/insert |
| `shell`/`Bash` | shell，不解析路径 |

错误状态取 Anthropic `tool_result.is_error`；OpenAI 没有该字段，标为未知。路径只存在 `detail_enc`，展示时解密，不进汇总、不进日志。

### 5.8 子 Agent 树

调研结论（2026-10 各客户端当前源码）：主流 Agent 客户端已经在请求上显式标注 Agent 身份和父子关系，目的就是让网关/代理能做会话亲和与归组。因此 Agent 树以读取标识为主，内容匹配只作兜底。

**第一层：显式 Header / Body 标识（精确）**

| 客户端 | 识别 | 根（整棵树） | 节点（单个 Agent） | 父节点 | 请求类别 |
| --- | --- | --- | --- | --- | --- |
| Codex CLI | `originator`、UA `codex_cli_rs/…` | `session-id`（父子相同） | `thread-id` | `x-codex-parent-thread-id`；Body `client_metadata` 同名键；turn metadata 另有 `parent_turn_id` 精确到父轮次 | `x-openai-subagent`：`collab_spawn`/`review`/`compact`/`memory_consolidation`；根 Agent 无此头 |
| Claude Code | UA `claude-cli/…`、`x-app: cli` | `X-Claude-Code-Session-Id`（进程级，父子相同） | `x-claude-code-agent-id`；缺失即主 Agent | `x-claude-code-parent-agent-id`；缺失但有 agent-id 时父节点为主 Agent | 可选 `x-claude-code-request-class`：`main`/`subagent`/`compaction`/`auxiliary`…（客户端需设置 `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`）；Body `system[0]` 计费块中 `cc_is_subagent=true` |
| OpenCode ≥ v1.19.2 / ≥ v2.0.25 | UA `opencode/…`、`x-opencode-client` | 沿父链上溯得到 | `x-opencode-session-id` | `x-opencode-parent-session-id`（或 `x-parent-session-id`），只是直接父节点 | 无 Header；标题请求以固定系统提示词识别，压缩请求以固定尾部用户消息识别 |
| dsh（官方 DeepSeek 适配器） | UA `deepseek-harness/…` | 沿父链上溯得到 | `x-deepseek-harness-session-id`（子 Agent 有自己的 ID） | Body `dsh_session_log.header.parentSession`，附带 `origin: "subagent"`、`delegationDepth` | `x-deepseek-harness-compact: 1` |

各客户端行为随版本变化：Codex 的父线程头约在 2026-04 引入，旧版本只有 `x-openai-subagent`；OpenCode v2.0.0–v2.0.20 期间 `x-opencode-session` 的语义从“自身”改成了“父会话”，只能用 `x-parent-session-id` 判父；Claude Code 的 `x-claude-code-session-id` 自 v2.1.86 起提供。识别规则以**可配置词表**落地（与 §5.7 同一份词表文件），默认内置以上四家，新增客户端或字段改名时只改配置。

**第二层：Body 中的回链（精确，用于补边和交叉验证）**

- 父 Agent 下一次请求中的工具结果往往带子 Agent ID：Codex V1 `spawn_agent` 输出 `{"agent_id": …}`，OpenCode `subagent` 结果 `<subagent sessionID="…">`。
- dsh 经第三方适配器（pi-ai）走自定义网关时没有任何会话 Header，但后台子 Agent 的提示词末尾含 `Your parent agent id is "<id>"`。

**第三层：内容匹配（推断，兜底）**

适用于旧版客户端、dsh 第三方适配器和未知客户端。是否进入内容匹配只看本次请求实际携带了什么：没有父 id，且（角色为子 Agent，或客户端/节点未知）；已知客户端带节点 id 的主 Agent 请求不做内容匹配。旧版 Codex 只发 	hread-id 和 x-openai-subagent: collab_spawn、没有 x-codex-parent-thread-id，因此按此层连边。另外仅限会话内首个请求、非附属角色、同一非空 pi_key_fpr：

1. 父请求的响应中出现派生工具调用：工具名在词表里（`Agent`/`Task`、`spawn_agent`、`subagent`/`task`），取其 `prompt`/`message` 参数。
2. 子候选：同一 `api_key_fpr`、出现新的节点键、首次请求的开始时间落在“父响应结束”到“父请求带回该工具结果”之间。
3. 子候选首条用户文本**包含**该参数文本（Claude Code 会在前面加提醒块，OpenCode 会加固定前缀，所以不要求相等）。比较在 parser 内存中进行，只落 keyed 指纹。
4. 唯一命中才连边，并记 `link_source=content` 和置信度；多个候选时不连边，只在 UI 标“可能的子 Agent”。

`fork` 类派生（Claude Code `subagent_type: fork`、Codex `fork_context`/`fork_turns: all`）的子请求以父历史开头，第三步改为“去掉公共前缀后的首条新增用户消息”。

**附属请求不是 Agent。** 压缩、标题生成、记忆整理、Codex review 等请求挂在发起它的节点下，作为“附属请求”展示，不算子 Agent。

**存储**：在 `audit_analysis` 增加以下列。

| 列 | 内容 |
| --- | --- |
| `agent_client` | `codex`/`claude_code`/`opencode`/`dsh`/`unknown` |
| `agent_role` | `main`/`subagent`/`compaction`/`title`/`review`/`auxiliary` |
| `agent_node_fpr`、`agent_parent_fpr`、`agent_root_fpr` | 客户端原始 ID 的 keyed HMAC 指纹 |
| `agent_link_source` | `header`/`body`/`content` |
| `agent_link_confidence` | 0–100 |

- 原始 ID 只放 `detail_enc`，详情页可显示，便于和客户端日志对照。
- 节点指纹也作为 §3.3 的 `analysis_session_id` 来源。
- 父指纹可能先于父节点出现（乱序完成）。查询时按指纹连接，不在写入时强制外键。

**查询与 UI**：

- `GET /api/v1/insights/agent-trees/{root}` 返回节点列表与边，节点上带聚合用量、构成末值、首末时间、状态、步数。
- developer 作用域下只返回作用域内节点；父节点不在作用域内时显示为“不可见的父节点”占位。
- 布局参考 dsh-context `agentTree.ts`：整洁树、单树最多 40 个节点、按血缘着色。点击节点进入该 Agent 的趋势页。
- 会话卡片按根聚合，显示“含 N 个子 Agent”。

**对现有轮次图的影响**：`conversationKey`（`internal/parser/openai/auditmodel.go:360`）在 `conversation_id` 之后优先取 `prompt_cache_key`；而 `chooseTurnParent`（`graph_writer.go:443-451`）命中会话键后，会强制挂到该会话**最新**的一轮，不比较内容。Codex 的父子 Agent 共享 `prompt_cache_key`（都是根会话 ID），OpenCode v2.0.10 以后在 Responses 协议上也是这样。结果是并发运行的父子 Agent 被串进同一条轮次链，彼此交错成父子关系：

- 重建仍然正确，因为 delta 能表示任意编辑。
- 但 `link_reason=conversation_key` 的血缘是错的，delta 体积也会膨胀，`conversation_turns` 计数偏大。

修正方向（独立于本模块，建议单独做）：会话键命中后仍要比较内容；或者识别到显式 Agent 节点 ID 时，把它作为会话键的一部分。

## 6. 配置（已并入 [01](01-configuration-and-route-boundary.md) §2、§4）

~~~yaml
insights:
  enabled: true          # 关闭后不计算 audit_analysis，页面隐藏
  pricing_file: ""       # 可选：本地价格覆盖 JSON，路径在仓库外
  vocabulary_file: ""    # 可选：工具词表 / 注入标记覆盖 YAML
~~~

默认词表编译进二进制，覆盖文件按键合并，启动时校验，非法时拒绝启动。

## 7. 管理 API（已并入 10 §11）

全部走既有鉴权，响应 `Cache-Control: no-store`，时间范围上限 400 天。JSON 结构以 `internal/insights/apitypes.go` 为唯一契约，前端 `src/types.ts` 与之镜像；另有 `GET /api/v1/insights/agent-trees/{tree_id}` 返回 `TreeResponse`（§5.8）。

| 端点 | 返回 | 作用域 |
| --- | --- | --- |
| `GET /api/v1/insights/overview?from_ns&to_ns&group_by=model\|protocol\|caller\|token` | KPI（请求数、会话数、各用量桶、缓存命中率、估算成本）、按日序列、热力图（近 8 周）、分组小计 | developer 逐行套 `conditionWithAliases`，并禁用 `caller`/`token` 分组 |
| `GET /api/v1/insights/sessions?from_ns&to_ns&sort=recent\|tokens\|context&cursor` | 会话卡片：首末时间、步数/轮数、各用量桶、末步构成、主模型、调用者 | 只统计作用域内步骤；作用域内为空的会话不出现 |
| `GET /api/v1/insights/sessions/{id}/trend` | 逐步序列：构成、usage、事件、时间、turn 标号；最多 2000 步，超出时返回最近一段并标记截断 | 作用域内步骤为 0 时返回 404 |
| `GET /api/v1/audits/{id}/composition` | 解密 `detail_enc`：逐条目清单（类别、估算、标签、摘要）、与 prev 的差异、文件活动 | 经 `authorizeAudit` |

会话卡片不展示 User-Agent 分组，因为那需要逐行解密。

## 8. Web UI

- `Dashboard` 的 `view` 状态新增 `"insights"`，沿用现有页面结构，不引入路由。界面保持中文，不移植 dsh 的 i18n。
- **洞察页**：KPI 栏 → 日用量（Token 与成本成对柱）→ 8 周热力图（点击某天筛选会话）→ 会话卡片（构成环形条、用量、步/轮、模型，可排序与按模型/调用者分组）。点击卡片进入会话趋势。
- **会话趋势**：按类别堆叠的柱状图，支持 Step/Turn、Total/Delta 切换和事件标记。悬停显示锚定值与真实 usage；点击一步打开该审计详情。
- **审计详情**新增“上下文构成”一节：六到八色堆叠条（基于模型窗口）、可展开的类别清单、`+N 项 / ±Nk` 差异徽标、Thinking/Tools/Answer 筛选、文件活动表。现有“解析摘要”中的原始键值保留在折叠区。
- 图表：趋势与日用量使用 `recharts`（与 shadcn 风格一致、体积可接受）；构成条和热力图是简单 SVG，自写即可。

## 9. 回填

已实现为 parser worker 内的后台步骤（`internal/parser/backfill.go`），不新增 writer 并发：

- **触发**：parser 唯一的 worker goroutine 每次扫描 tick（默认 30 秒）在 pending 扫描之后调用；仅当 `insights` 启用（已安装分析器）且实时队列为空时才运行，处理过程中一旦实时队列出现新项立即让出。每个 tick 最多处理 20 条，随 `ctx` 取消，永远不阻塞实时解析。
- **候选**：`parse_status IN ('ok','partial')` 且已结束，`LEFT JOIN audit_analysis` 后缺行或 `analysis_version < AnalysisVersion`，按 `started_at_ns, audit_id` 升序，即**从旧到新**；以 `(started_at_ns, audit_id)` keyset 游标向前推进，游标为空时从最旧的一条开始（`ListAnalysisBackfillCandidates`）。游标走完后暂停 10 分钟再从最旧重扫，避免对同一批不可处理的记录空转。**必须由旧到新**的原因：后继行（`prev_audit_id`、轮次与会话拼接）需要链接到前驱行的分析结果，先分析前驱才能让后继在同一轮回填里拿到正确的链接；若由新到旧，后继会先于前驱落库而缺少前驱链接。
- **正文来源**：raw 分块仍在（`retention_state` 非 metadata）时复用实时路径的 `loadInput`。已转为 metadata 的 OpenAI audit 通过注入的 `parser.Reconstructor`（由 query 服务实现，复用 `ReconstructTurn` 的已验证重建）取得请求与响应 JSON。其余情形（Anthropic/Gemini 的 raw 已被 retention 清除、没有 turn graph 等）跳过。
- **重新解析**：在内存中重跑协议 parser 的 `Parse` 取得 Conversation 与归一化用量，**不**重写 `parsed_results`；再读取白名单 Header，调用与实时路径相同的分析器钩子（`runAnalyzer`），行按 `audit_id` upsert。
- **流式响应的限制**：metadata 保留的 OpenAI 流式响应无法还原成 SSE。回填改用 response envelope 中保存的 usage 摘要与重建的 conversation，因此缓存读/写和推理 Token 拆分不可恢复（只有 uncached input 与 output），停止原因也可能缺失；非流式响应的重建 JSON 保留完整 usage。
- **防空转**：进程内有界（4096）的跳过集合记录跳过或失败的 audit，同一进程不再重试；满后清空重建。日志码 `analysis_backfill_skipped`（附 `reason` 枚举）与 `analysis_backfill_failed`，见[模块 13](13-observability-health-and-lifecycle.md)。暂时性失败（如存储繁忙）也要到进程重启才会再试。
- 已被 retention 删除的记录不在候选里；没有现成的健康计数器，因此未新增 `analysis_backfill_pending` 之类的指标（项目目前无 metrics 面）。
- `AnalysisVersion` 为 4：版本 2 起附属请求（压缩/标题/review/auxiliary）的 `event_flags` 固定为 0；版本 4 起 user 角色的图片/文档计入会话键推断的首条用户项与 `turn_start`，旧行会被回填重算。
- **词表覆盖只影响新分析**：修改 `insights.vocabulary_file` 只对之后新分析的记录生效；已有行保持原有分类，直到 `AnalysisVersion` 变化触发回填重算。

## 10. 阶段与风险

| 阶段 | 内容 | 工作量 | 主要风险 |
| --- | --- | --- | --- |
| P0 | 迁移 008、三协议用量归一化、价格快照与成本计算、详情页用量卡片 | 小 | 各协议 usage 边角（流式分段、缺字段） |
| P1 | 构成估算、会话拼接、overview/sessions/trend API、洞察页与趋势图、回填任务 | 中-大 | 推断会话误合并；developer 作用域漏套 |
| P2a | 子 Agent 树：parser `Input` 增加白名单 Header（当前只有 Body，见 `internal/parser/types.go:62`），三层识别、agent-trees API 与树视图 | 中 | 客户端字段随版本变化，需要靠词表跟进 |
| P2b | composition 端点与上下文浏览器、差异与事件、文件活动、工具来源标签、Treemap/DNA | 中 | 启发式事件误报；词表维护成本 |
| P3 | 解码拆分计时 | 小-中 | 价值相对低，按需再做 |

## 11. 自定义 Agent 接入

自研 Agent 框架只要在发往代理的**每一个** LLM 请求上带以下 Header，就能被精确归入 Agent 树，不需要任何内容推断。这组 Header 属于默认词表的 `custom` 客户端，优先级排在四家内置客户端的原生 Header 之后。

| Header | 必填 | 取值 | 含义 |
| --- | --- | --- | --- |
| `X-Agent-Session-Id` | 推荐 | 不透明字符串，≤ 256 字节，建议 UUID | 整棵 Agent 树的根标识。主 Agent 和它派生的所有子 Agent、孙 Agent 都填**同一个值** |
| `X-Agent-Id` | 是 | 同上 | 当前 Agent 自己的标识。同一 Agent 的所有请求保持不变，不同 Agent 必须不同 |
| `X-Agent-Parent-Id` | 子 Agent 必填 | 同上 | 直接父 Agent 的 `X-Agent-Id`。主 Agent 不带此头 |
| `X-Agent-Role` | 否 | `main` / `subagent` / `compaction` / `title` / `review` / `auxiliary` | 请求类别。缺省时：有 `X-Agent-Parent-Id` 的视为 `subagent`，否则视为 `main` |
| `X-Agent-Name` | 否 | ≤ 64 字节的可读名，如 `researcher` | 只在详情页展示 |

规则：

- **缺 `X-Agent-Session-Id`** 时，根由父链上溯得到；父 Agent 的请求晚到或已过期时，这棵子树会暂时显示为独立树，补齐后自动合并。
- **附属请求**（压缩、生成标题、总结）带发起它的那个 Agent 的 `X-Agent-Id`，并把 `X-Agent-Role` 设为对应类别。这样它们挂在该节点下，不会被当成子 Agent。
- **透明转发**：代理不删除、不改写这些 Header，NewAPI 和上游会照常收到。上游若对未知 Header 敏感，请在 Nginx 之后、NewAPI 之前自行处理；代理本身不提供剥离功能。
- **安全**：Header 值与其他 Header 一样逐个 AES-256-GCM 加密存储。明文列中只出现 keyed HMAC 指纹，指纹不可反查，所以填 UUID 或业务 ID 都可以。但不要放密钥、Token 或个人信息。
- **`prompt_cache_key` 的副作用**：若同时把根会话 ID 写进 OpenAI 的 `prompt_cache_key`，现有 OpenAI 轮次图会把父子 Agent 串进同一个 conversation（§5.8“对现有轮次图的影响”）。建议每个 Agent 用自己的 `X-Agent-Id` 作 `prompt_cache_key`，或者干脆不填。
- **识别优先级**：内置客户端的原生 Header → 本节通用 Header → Body 回链 → 内容推断。框架若本身就是 Codex/Claude Code 等客户端的封装，无需重复设置。

示例：主 Agent 派生一个子 Agent，子 Agent 再触发一次压缩。

~~~http
POST /v1/chat/completions            # 主 Agent
X-Agent-Session-Id: 7d0c…-root
X-Agent-Id: 7d0c…-root
X-Agent-Name: planner

POST /v1/chat/completions            # 子 Agent
X-Agent-Session-Id: 7d0c…-root
X-Agent-Id: 51a9…-child
X-Agent-Parent-Id: 7d0c…-root
X-Agent-Name: researcher

POST /v1/chat/completions            # 子 Agent 的压缩请求
X-Agent-Session-Id: 7d0c…-root
X-Agent-Id: 51a9…-child
X-Agent-Parent-Id: 7d0c…-root
X-Agent-Role: compaction
~~~

Header 名称可以在词表覆盖文件中改成你框架已有的名字（`configs/insights-vocabulary.example.yaml`），不必修改框架。

## 12. 验收

- 三协议流式/非流式样本的四个用量桶与 §5.1 表一致；Anthropic 缓存场景的 prompt_total 等于三桶之和。
- 锚定后各类别之和等于上游 prompt_total（舍入误差 ≤ 类别数）。
- Delta 模式在压缩样本上出现负值；Turn 视图折叠后的步数与原始步数一致。
- 同一 Key 的两段不同开场白会话得到两个 `ses_` ID；不同 Key 的相同对话不合并。
- developer 作用域：共享 OpenAI conversation 中他人 Key 的步骤不出现在 overview、会话卡片和趋势中；他人会话 ID 返回 404。
- `audit_analysis` 的增删改不改变任何完整性摘要，启动链校验通过（参照 `TestAPIKeyFingerprintStaysOutsideTheEvidenceChain`）。
- DB/WAL 中没有测试 secret、消息正文、工具名、文件路径的明文；`detail_enc` 可正常解密。
- 洞察相关 API 不触发 Body/对象解密（composition 端点除外），用查询计数或打桩验证。
- 回填任务可取消、幂等；版本升级后只重算旧版本行。
- 价格未知的模型不报错，显示“未知价格”；运行时没有外联请求。
- 用四家客户端的录制样本（脱敏）构造父子与孙级请求：显式标识层还原的树与真实结构一致；附属请求（压缩、标题）不出现为子 Agent。
- 去掉全部 Header 后，内容匹配层只在唯一命中时连边，并标为推断；两个子 Agent 使用相同 prompt 时不连边。
- 原始 Agent ID 不以明文出现在 DB/WAL 中。

## 13. 实现偏差与已知限制

- **合成节点指纹**：没有客户端 Agent ID 的会话（普通 OpenAI/Anthropic 客户端）也会得到一个由 `analysis_session_id` 派生的合成 `agent_node_fpr`（`SyntheticAgentFPR`），使会话链接、根聚合和 Agent 树查询走同一条路径。合成指纹不带 `agent_link_source`。
- **真实树规则**：因此 `agent_root_fpr` 非空并不代表这是一棵 Agent 树。查询层只在根满足以下任一条件时才视为真实树：作用域内有 ≥ 2 个不同的 `agent_node_fpr`，或该根的任一行带非空 `agent_parent_fpr`。`agent_link_source` 不参与判定：只带节点头的主 Agent 也会记 `link_source=header`，不能据此认定为树。`OverviewResponse.trees`、`SessionCard.tree_id`（非树为空）与 `subagents` 都按此判定；`agent-trees` 端点仍可读取单节点根。总览按所选时间窗口内的行判定，会话卡片与趋势按作用域内全部行判定。
- **卡片取值口径**：会话卡片的角色、末步构成/prompt 总量取最新的 main/subagent 步骤；附属请求不开始 turn（`turn_start` 在统计和趋势序号中被忽略），其 `event_flags` 为 0（`prev_audit_id`/增删条目数仍保留）。
- **趋势估算保持原始值**：`/trend` 返回未锚定的构成估算与真实 usage，锚定到 prompt 总量由前端完成（会话卡片与树节点由服务端锚定）。
- **价格表**：内嵌快照 `internal/insights/pricing/prices.json`，可由 `insights.pricing_file` 覆盖。JSON 顶层为 `snapshot`、`note`、`models`、`schedules`，禁止未知字段。`models` 的键为小写 `provider/model`（或裸模型名），值为每百万 Token 美元价：`input`、`output` 必填，`cache_read`、`cache_write` 缺省回落到 `input`，`context` 为上下文窗口（0 表示未知）。`schedules` 是按 UTC 时段的成本倍率（`model` glob、`weekdays` 0=周日、`start`/`end` 为 `HH:MM`、`multiplier` ∈ (0,100]），首个匹配生效，跨午夜的窗口按开始日计星期。覆盖文件的同键条目替换内嵌条目，`schedules` 追加。查找链：完整 id（大小写不敏感）→ 去掉厂商前缀后的裸名（唯一才命中）→ 最长的已知族名加 `-`/`@`/`:` 后缀（带日期的发行版本，跨厂商共享则视为未知）→ 未知价格，不计价并计入 `unpriced_requests`。
- **请求体被多次解析**：一次 audit 的请求体会被协议 parser、OpenAI normalizer、insights 分析器（`Analyze`、`IdentifyAgent`、`SpawnPrompts`、`OpeningUserHints`）各自反序列化一次。输入受 `MaxDecodedBodyBytes`（64 MiB）限制且全部在异步 worker 中，不影响代理字节路径；合并为一次解码是后续优化，目前不做。
- **回填速率**：每个扫描 tick 最多 20 条，历史量大时需要数小时到数天，期间洞察页展示的是已分析部分。