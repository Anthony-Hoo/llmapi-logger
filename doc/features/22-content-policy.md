# 模块 22：关键词/模型请求拦截与上游策略拒绝识别

## 1. 目标与边界

本模块在既有入站拦截链上增加一个动态配置的 `content_policy` 拦截器：管理员按模型范围和关键词表配置规则，命中后在代理访问 NewAPI 之前本地拒绝请求。它用于减少会触发上游安全策略（例如 OpenAI `cyber_policy`）的高风险提示词，不把本代理扩展成通用内容安全网关。

同时记录上游返回的安全策略拒绝：parser 从已解密的响应错误字段派生一个不参与完整性签名的 `upstream_error_class`，列表 API 和 UI 支持筛选与展示。

边界：

- 只作用于 Matcher 精确命中的 LLM API route；passthrough、404、管理面和健康检查不执行策略。
- 只做本地拒绝，不修改请求 Method/URL/Header/Body，不做响应改写或响应侧拦截。
- 规则命中判断是启发式前置过滤，不是安全边界：gzip 请求体、超过扫描上限的 Body、无法解析的 JSON 和未知 parser 都放行。
- 不按用户、NewAPI Token、分组或渠道细分；这些身份或信息在请求时不可见或仅异步回填。
- 不扫 OCR/ASR/文件正文，不展开 `previous_response_id` 或外部会话历史。

## 2. 拦截点与执行顺序

~~~text
data-plane dispatcher -> Matcher -> BeginAudit -> require_credential
  -> ... route chain ... -> user_agent_policy -> content_policy
  -> allow: audited ReverseProxy -> NewAPI
  `-> reject: 框架固定 JSON（NewAPI 零调用）
~~~

`content_policy` 由 app 在所有已匹配 route 的 chain 末尾注入（位于动态 UA 策略之后）。规则快照只读，`Check` 不访问网络、DB、文件或子进程。模块返回的决策、error 和 panic 仍遵循拦截链统一语义：显式 reject 只允许 400–499，error/panic 固定 503 fail-closed。

## 3. 规则模型

规则持久化在 `content_policy_rules`，并通过管理面 CRUD 热更新。

| 字段 | 约束 | 语义 |
| --- | --- | --- |
| id | 正整数 | 规则标识；服务在启动时按现有最大 id+1 分配 |
| name | 1–128 字节，禁 NUL | 管理员描述 |
| enabled | 0/1 | 单规则启停 |
| action | `block` / `dry_run` | block 命中拒绝；dry_run 只写安全日志并继续；省略时默认 `block` |
| model_pattern | 0–2048 字节 RE2；空表示全部模型 | 模型来自请求顶层 `model`，Gemini template route 回退 `{model}` PathParam |
| scan_scopes | 非空子集，JSON 数组 | 要扫描的文本类别；新建规则默认全部 7 类 |
| keywords | 1–500 条，每条 1–200 字节，总 JSON ≤64 KiB | 字面量、大小写不敏感、连续子串 |
| created_at_ns / updated_at_ns | 单调时间戳 | 与动态 UA 规则一致 |

模型缺失时：`model_pattern` 为空的规则仍然适用；非空规则跳过，不扩大阻断范围。多条规则按 id 升序评估，首个 `block` 命中立即拒绝；`dry_run` 命中只记录 `content_policy_dry_run` 安全日志并继续评估。命中响应只使用框架固定 `request_rejected` 正文，不返回规则 id、关键词或命中位置。

## 4. 扫描范围

| scope | 内容 |
| --- | --- |
| `latest_user` | 最后一条 user 消息的文本 |
| `user_history` | 更早的 user 消息文本 |
| `system` | system/developer、Responses `instructions`、Anthropic `system`、Gemini `systemInstruction` |
| `assistant` | assistant 历史文本与 reasoning/thinking |
| `tool_calls` | 历史工具调用名称与参数 |
| `tool_results` | 工具返回内容 |
| `tool_definitions` | 请求中的 tools/functions 定义（名称、描述、参数 schema 文本） |

规则默认扫描全部类别（管理员已明确选择）。这比 new-api 的全局 `CombineText` 更明确：不把 role 字符串、模型名、JSON 字段名、metadata、图片/音频/文件字节当成正文。需要低误报时可以只勾 `latest_user`。

文本提取器按 `RequestView.Parser` 分派，支持默认的 OpenAI chat/completions/responses/responses_compact、Anthropic messages、Gemini generate_content/stream_generate_content。未知 parser 不猜测、不扫描，直接放行并记录稳定日志。

## 5. 匹配算法

- 字面量关键词，`strings.ToLower` 后做连续子串匹配；大小写不敏感。
- 不支持正则、通配符、词边界、NFKC/全半角/繁简/拼音/同音字归一化。
- 每个规则快照编译一个字节级 Aho–Corasick 自动机，扫描复杂度与文本长度线性相关；命中即停，不记录具体关键词。
- 规则关键词在服务层 trim、去空、按大小写不敏感去重；模型正则和关键词编译失败会让整条规则校验失败，绝不替换当前生效快照。
- 扫描主体上限 8 MiB（解码前字节）；超过时跳过策略并记录 `content_policy_body_too_large`。
- 只支持未编码 JSON 请求体。`Content-Encoding` 存在时跳过（`content_policy_encoded`）；非法 JSON 跳过（`content_policy_unparseable`）。这些是明确 fail-open，不属于框架级 503。

## 6. 拒绝与审计语义

命中 `action=block`：

- 返回 HTTP 400，正文固定为 `{"error":{"code":"request_rejected","message":"request rejected"}}`。
- audit 记录 `forward_status=rejected`、`blocked_by=content_policy`、`block_code=content_policy_blocked`、`status_code=400`、`parse_status=skipped`。
- 不创建 `request_sent_to_newapi`、两个响应阶段或 NewAPI request id。
- 进程日志只包含 audit_id（由代理完成日志）、route_id、blocked_by、block_code 和规则 id；不包含关键词、匹配文本、Header 或 Body。
- 新 block code 不在开发者可见白名单内，因此开发者会话默认看不到被策略拒绝的记录。

`dry_run` 命中只写 `content_policy_dry_run` 日志，不改变转发和审计结果；当前没有“允许但审计标记”的通道，因此 dry-run 命中不会出现在审计列表中。

## 7. 持久化

migration `010_content_policy_rules.sql` 创建 `content_policy_rules`，不写入任何种子规则：空表等于不拦截。

Store 通过既有单 writer 提供 `ListContentPolicyRules`、`CreateContentPolicyRule`、`UpdateContentPolicyRule`、`DeleteContentPolicyRule`；`contentpolicy` 领域包定义 `Repository`、`RuleSet` 和编译快照。保存顺序固定为：校验/编译 → 持久化 → 重编译整份快照 → 原子发布。DB 不可用（available 模式）时 service 得到空快照，全部放行；管理 API 返回 503。

## 8. 管理 API 与 UI

管理员专属端点：

~~~text
GET    /api/v1/content-policy-rules
POST   /api/v1/content-policy-rules
PUT    /api/v1/content-policy-rules/{id}
DELETE /api/v1/content-policy-rules/{id}
~~~

规则请求体单独限制为 96 KiB，避免与 16 KiB 的 UA 规则上限混用。错误映射沿用动态 UA 规则：`invalid_rule` 400、`not_found` 404、`content_policy_unavailable`/`content_policy_timeout` 503。开发者会话对这些端点一律 403。

React 管理页增加“关键词拦截”入口：规则列表、启停、编辑/删除、动作选择、模型正则、关键词逐行编辑、扫描范围复选（默认全选）。保存后立即生效，无需重启。

## 9. 上游策略拒绝识别（Phase 2）

parser 在解析响应错误 envelope（非流式 JSON、SSE `error` / `response.failed` 帧）时，除现有 `error_type`/`error_code` 外，派生稳定分类 `upstream_error_class`：

| 分类 | 触发 |
| --- | --- |
| `cyber_policy` | `error.code=cyber_policy`，或错误 message 命中 cyber 精确短语 |
| `misalignment_policy` | `error.code=misalignment_policy_violation` |
| `content_policy` | `error.code=content_policy_violation` |
| `content_filter` | `content_filter` / Azure `ResponsibleAIPolicyViolation` / `content_filter` innererror |
| `moderation_blocked` | `moderation_blocked` |
| `safety_policy` | 错误 message 出现安全策略精确短语但没有更具体 code |

分类只在 parser 内存中判断，不保存 `error.message`；`parsed_results.upstream_error_class` 是不进入完整性摘要的派生列（migration 011），旧记录为 NULL。列表 API 增加 `parsed_error_type`、`parsed_error_code`、`upstream_error_class` 字段和 `upstream_error_class` 精确筛选；详情解析摘要展示分类；UI 列表显示“上游安全拒绝”短标签并提供筛选。

该识别只能看到代理边界上 NewAPI 实际返回的响应；NewAPI 二次包装、Azure `innererror`、Gemini 200+SAFETY 等形态按能解析到的字段尽量归类，不能保证覆盖全部厂商错误。

## 10. 测试

- 匹配语义：大小写、子串、中文、首命中、空词表/非法规则拒绝、未做全角与繁简归一化。
- 提取器：OpenAI chat/completions/responses/compact、Anthropic、Gemini 的 latest/历史/system/assistant/tool 各类别；role 名、模型名、媒体 base64 不进入文本。
- 模型范围、规则顺序、dry_run、block 返回 400、NewAPI 零调用和审计字段。
- 规则 CRUD 跨重启、无效规则不替换快照、删除不存在规则不污染 writer 批次、DB 不可用降级为空策略。
- gzip/非法 JSON/超 8 MiB/未知 parser 的 fail-open 和稳定日志 code；日志不含关键词或文本。
- migration 010/011 新库与旧库升级、版本计数与表/列断言。
- 上游分类：cyber/misalignment/content filter/Azure/新 API 包装/未知错误；分类列不改变任何完整性摘要。
- Web：管理员 CRUD、开发者 403、请求体上限、错误映射、no-store；前端类型/API/panel 测试与 `pnpm build`。
- 集成：在真实数据/管理 listener 下创建规则 → 命中拦截且 NewAPI 零调用 → 审计记录 block 字段；上游返回 cyber_policy 错误后，parser 分类可通过 `upstream_error_class` 列表筛选读取。

## 11. 实现边界

`routing` 决定哪些请求进入链；`interceptor` 只产生 allow/reject；`contentpolicy` 只读请求快照并返回决策；`app` 负责注入；`storage` 负责规则持久化；`parser` 负责上游拒绝分类；`query`/`web` 负责展示。任一层都不能让策略扩大路由或把受保护路径降级为 passthrough。
