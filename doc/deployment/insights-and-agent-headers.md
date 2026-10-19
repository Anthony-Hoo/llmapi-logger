# 上下文洞察与 Agent 接入指南

本文面向部署者和客户端使用者：怎样开关上下文洞察、实际计费从哪里来、怎样覆盖上下文窗口与词表、各客户端需要做什么，以及自研 Agent 框架怎样通过 Header 被精确归入 Agent 树。设计与算法见[模块 20](../features/20-context-insights.md)，API 与页面见[模块 10](../features/10-query-api-and-minimal-web-ui.md) §11。

洞察是只读的派生功能：它在异步 parser 中从已审计的请求/响应计算用量、上下文构成、会话和 Agent 树，不改写任何转发字节，失败也不影响审计与解析结果。

## 1. 开关与配置

配置块（字段定义以[模块 01](../features/01-configuration-and-route-boundary.md)为准）：

~~~yaml
insights:
  enabled: true          # 默认 true；false 时不计算、不回填，洞察页与端点隐藏（404）
  vocabulary_file: ""    # 可选：工具词表 / 注入标记 / Agent 标识覆盖 YAML，路径放在仓库外
  context_windows: {}    # 可选：按模型覆盖上下文窗口（Token）
~~~

- **关闭**：设 `insights.enabled: false` 并重启。已有的 `audit_analysis` 行保留但不再更新，也不会被读取。重新开启后，后台回填会补齐关闭期间缺失的记录。
- **开启**：默认即开启。启动后新请求在解析成功后立即分析；历史记录由后台回填逐步补齐（队列空闲时每个扫描周期最多 20 条，已被 retention 清除原始正文且无法重建的记录会跳过）。
- `insights.enabled` 为 true 时，非空的 `vocabulary_file` 必须在启动时已存在且是普通文件；内容非法时拒绝启动。
- 旧配置中的 `insights.pricing_file` 已废弃：仍可解析，不会导致启动失败，但不再生效，启动时输出一次警告。可以直接删除这一行。

## 2. 实际计费

洞察中的成本是 NewAPI 对每个请求的实际扣费，不是按价格表估算（设计见[模块 21](../features/21-newapi-billing.md)）。

- **前提**：配置了 `newapi.access_token` 与 `newapi.user_id`（[部署说明](README.md)中的 NewAPI 管理凭证）。不配置时洞察页说明“未配置 NewAPI 管理凭据，无法获取实际计费”，Token 用量照常统计。
- **来源**：调用者识别查询 NewAPI 日志时，同时读取消费日志的 `quota`；换算系数 `quota_per_unit` 来自 NewAPI 公开的 `/api/status`，启动时读取并每 5 分钟刷新。成本（美元）= `quota / quota_per_unit`，写入时保存当时的系数，之后修改 NewAPI 设置不会改写历史成本。
- **未计费**：没有消费日志的请求（上游失败、NewAPI 日志已清理、调用者未识别等）只计数，页面显示“含 N 条未计费”，不做估算。退款不会体现在成本中。
- **升级前的记录**：升级后，已识别调用者的旧记录由后台逐条补查计费（最新优先，每条间隔至少 500ms，失败 3 次后记为未计费），不影响新请求。NewAPI 已清理的旧日志无法补回。

## 3. 上下文窗口覆盖

占用率需要模型的上下文窗口。常见模型的窗口编译在二进制中；网关别名或内嵌表没有的模型，可以在 `insights.context_windows` 中按模型 id 指定：

~~~yaml
insights:
  context_windows:
    my-gateway-alias: 200000
    example-provider/example-large: 1000000
~~~

键的匹配方式与内嵌表相同：完整 id（大小写不敏感）→ 去掉厂商前缀后的唯一裸名 → 最长的已知族名加 `-`/`@`/`:` 后缀（带日期的发行版本）→ 未知。同名键替换内嵌条目；值必须是正整数，键不能为空或含空白，仅大小写不同的两个键视为重复，均在启动时校验。窗口未知的模型不显示占用率。
## 4. 词表覆盖

工具分类、注入标记和各客户端的 Agent 标识 Header 来自编译进二进制的默认词表。要调整，复制 [`configs/insights-vocabulary.example.yaml`](../../configs/insights-vocabulary.example.yaml)，只保留要改的键，把 `insights.vocabulary_file` 指向它。覆盖按键合并，示例文件头部列有合并规则；非法时拒绝启动。典型用途：自研框架已经有自己的 Header 名，直接在词表里给 `custom` 客户端改名，而不用改框架；或者按 User-Agent 前缀为自研框架单列一个客户端（§6.4）。修改词表覆盖只影响之后新分析的记录；已有行保持原有分类，直到 `AnalysisVersion` 变化才会被回填重算（回填用当时生效的覆盖文件）。

每个客户端规则可以带可选的 `label`（≤ 64 字节的显示名，超长拒绝启动）。它只影响展示：洞察页、会话卡片、Agent 树和审计详情里用它代替客户端键，总览 `group_by=client` 的分组名也用它；写入数据库的 `agent_client` 仍是客户端键，改 `label` 不需要重算。内置四家客户端与 `custom` 在页面上有固定中文名，没有 `label` 的新客户端按键名原样显示。

## 5. 各客户端

| 客户端 | 需要做什么 | 说明 |
| --- | --- | --- |
| Claude Code | 设置环境变量 `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`（可选） | 会话、Agent 与父 Agent 标识 Header 默认就有；该开关额外发送 `x-claude-code-request-class`（`main`/`subagent`/`compaction`/`auxiliary`…），用于把压缩等附属请求准确挂到发起它的 Agent 下，不开则靠 Body 里的标记推断 |
| Codex CLI | 不需要 | `session-id`、`thread-id`、`x-codex-parent-thread-id`、`x-openai-subagent` 默认携带 |
| OpenCode | 不需要 | `x-opencode-session-id` 与父会话头默认携带（较旧版本的头语义不同，识别规则可在词表中调整） |
| dsh（官方 DeepSeek Harness 适配器） | 不需要 | 默认携带 `x-deepseek-harness-session-id`，压缩请求带 `x-deepseek-harness-compact` |
| dsh 经第三方 pi-ai 适配器 | 无法改善 | 该路径没有任何会话 Header，只能靠内容推断：用同一 Key、系统提示词与首条用户消息拼会话，子 Agent 仅在子 Agent 提示词里带 `Your parent agent id` 时才能连边。会话和树会标为“推断”，并行且开场白相同的会话可能被合并 |
| 基于 pi-ai SDK 的框架 | 自动压缩无需设置 | pi-ai / pi-coding-agent 自动压缩请求的系统提示词以 `You are a context summarization assistant.` 开头，默认词表据此把它识别为 `compaction` 附属请求（对任何客户端生效，包括未识别的客户端）；Agent 身份仍按 §6 加 Header |
| 其他/自研 | 见 §6 | 在每个请求上加 `X-Agent-*` Header；可选按 §6.4 单列为一个客户端 |

这些 Header 由客户端本身发送，代理只读取不改写，原样转发给 NewAPI 与上游。它们与其他 Header 一样被逐个 AES-256-GCM 加密存储，明文列里只有不可反查的 keyed 指纹。

## 6. 自研 Agent 的 Header 约定

在发往代理的**每一个** LLM 请求上带下列 Header，即可被精确归入 Agent 树，不依赖任何内容推断（`custom` 客户端，优先级低于四家内置客户端的原生 Header）：

| Header | 必填 | 取值 | 含义 |
| --- | --- | --- | --- |
| `X-Agent-Session-Id` | 推荐；三层及以上的树必填 | 不透明字符串，≤ 256 字节，建议 UUID | 整棵 Agent 树的根标识：主 Agent 和它派生的所有子/孙 Agent 都填**同一个值** |
| `X-Agent-Id` | 是 | 同上 | 当前 Agent 自己的标识：同一 Agent 的所有请求不变，不同 Agent 必须不同 |
| `X-Agent-Parent-Id` | 子 Agent 必填 | 同上 | 直接父 Agent 的 `X-Agent-Id`；主 Agent 不带 |
| `X-Agent-Role` | 否 | `main` / `subagent` / `compaction` / `title` / `review` / `auxiliary` | 请求类别；缺省时有 `X-Agent-Parent-Id` 视为 `subagent`，否则 `main`；pi-ai 自动压缩请求即使不带此头也会按系统提示词识别为 `compaction` |
| `X-Agent-Name` | 否 | ≤ 64 字节的可读名，如 `researcher` | 在审计详情和 Agent 树节点上展示（节点取其最新一条非附属请求的值；压缩等附属请求可以不带） |

规则：

- 带 `X-Agent-Session-Id` 时，整棵树的根直接来自该值，请求到达和分析的先后顺序无关紧要。
- 缺 `X-Agent-Session-Id` 时，根在分析时由父链上溯得到，分析结果一旦写入不再改写。两层树（主 Agent + 子 Agent）在任何顺序下都能合并；三层及以上的树里，孙 Agent 的请求若先于中间 Agent 被分析，这棵孙子树会一直显示为独立的树，不会自动合并（只有将来 `AnalysisVersion` 升级触发的回填重算才会修正）。父 Agent 的请求尚未分析、已过期或不在当前身份可见范围内时，树里显示一个占位父节点。所以三层及以上的框架请总是带 `X-Agent-Session-Id`。
- **附属请求**（压缩、生成标题、总结）带发起它的那个 Agent 的 `X-Agent-Id`，并把 `X-Agent-Role` 设为对应类别。它们挂在该节点下，不被当成子 Agent，也不开启新 turn。
- 代理不删除、不改写这些 Header。上游若对未知 Header 敏感，请在 Nginx 之后、NewAPI 之前自行处理。
- 不要在 ID 里放密钥、Token 或个人信息；UUID 或业务 ID 都可以。
- **`prompt_cache_key` 的影响**：若把根会话 ID 写进 OpenAI 的 `prompt_cache_key`，OpenAI 轮次图会把父子 Agent 归入同一个 conversation，按内容各成一条链，`conversation_turns` 计数包含子 Agent。Agent 树与洞察统计按上面的 Header 区分，不受影响。

没有客户端 Agent ID 的普通会话不算 Agent 树：只有同一根下出现 ≥ 2 个不同 Agent，或存在 Header/Body/内容连边时才会显示为树。

### 6.1 curl

主 Agent、子 Agent，以及子 Agent 的一次压缩（把 `AUDIT_PROXY` 和密钥换成你自己的；域名 `example.com` 仅为占位）：

~~~bash
AUDIT_PROXY="https://audit.example.com"
ROOT="7d0c1f2e-0000-4000-8000-000000000001"
CHILD="51a9c3d4-0000-4000-8000-000000000002"

# 主 Agent
curl -sS "$AUDIT_PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -H "X-Agent-Session-Id: $ROOT" -H "X-Agent-Id: $ROOT" -H "X-Agent-Name: planner" \
  -d '{"model":"example-model","messages":[{"role":"user","content":"plan the work"}]}'

# 子 Agent：父是主 Agent
curl -sS "$AUDIT_PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -H "X-Agent-Session-Id: $ROOT" -H "X-Agent-Id: $CHILD" \
  -H "X-Agent-Parent-Id: $ROOT" -H "X-Agent-Name: researcher" \
  -d '{"model":"example-model","messages":[{"role":"user","content":"research the parser"}]}'

# 子 Agent 的压缩请求：同一个 X-Agent-Id，角色为 compaction
curl -sS "$AUDIT_PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -H "X-Agent-Session-Id: $ROOT" -H "X-Agent-Id: $CHILD" \
  -H "X-Agent-Parent-Id: $ROOT" -H "X-Agent-Role: compaction" \
  -d '{"model":"example-model","messages":[{"role":"user","content":"summarize the conversation so far"}]}'
~~~

### 6.2 Python

OpenAI SDK 用 `default_headers`（整个客户端）或 `extra_headers`（单次请求），Anthropic SDK 同名：

~~~python
import uuid
from openai import OpenAI
from anthropic import Anthropic

ROOT = str(uuid.uuid4())
CHILD = str(uuid.uuid4())
BASE = "https://audit.example.com"  # 占位域名


def agent_headers(agent_id, parent_id=None, role=None, name=None):
    headers = {"X-Agent-Session-Id": ROOT, "X-Agent-Id": agent_id}
    if parent_id:
        headers["X-Agent-Parent-Id"] = parent_id
    if role:
        headers["X-Agent-Role"] = role
    if name:
        headers["X-Agent-Name"] = name
    return headers


# 每个 Agent 一个客户端：default_headers 对其所有请求生效
main_client = OpenAI(base_url=f"{BASE}/v1", api_key="YOUR_KEY",
                     default_headers=agent_headers(ROOT, name="planner"))
child_client = OpenAI(base_url=f"{BASE}/v1", api_key="YOUR_KEY",
                      default_headers=agent_headers(CHILD, parent_id=ROOT, name="researcher"))

main_client.chat.completions.create(
    model="example-model", messages=[{"role": "user", "content": "plan the work"}])

# 子 Agent 的压缩请求：单次请求覆盖角色（extra_headers）
child_client.chat.completions.create(
    model="example-model",
    messages=[{"role": "user", "content": "summarize the conversation so far"}],
    extra_headers={"X-Agent-Role": "compaction"},
)

# Anthropic SDK：同样的 default_headers / extra_headers
anthropic_child = Anthropic(base_url=BASE, api_key="YOUR_KEY",
                            default_headers=agent_headers(CHILD, parent_id=ROOT, name="researcher"))
anthropic_child.messages.create(
    model="example-model", max_tokens=256,
    messages=[{"role": "user", "content": "summarize the conversation so far"}],
    extra_headers={"X-Agent-Role": "compaction"},
)
~~~

### 6.3 TypeScript

~~~typescript
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { randomUUID } from "node:crypto";

const ROOT = randomUUID();
const CHILD = randomUUID();
const BASE = "https://audit.example.com"; // 占位域名

const agentHeaders = (agentId: string, parentId?: string, role?: string, name?: string) => ({
  "X-Agent-Session-Id": ROOT,
  "X-Agent-Id": agentId,
  ...(parentId ? { "X-Agent-Parent-Id": parentId } : {}),
  ...(role ? { "X-Agent-Role": role } : {}),
  ...(name ? { "X-Agent-Name": name } : {}),
});

// 原生 fetch：子 Agent 的一次压缩请求
await fetch(`${BASE}/v1/chat/completions`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${process.env.API_KEY}`,
    "Content-Type": "application/json",
    ...agentHeaders(CHILD, ROOT, "compaction"),
  },
  body: JSON.stringify({
    model: "example-model",
    messages: [{ role: "user", content: "summarize the conversation so far" }],
  }),
});

// OpenAI SDK：defaultHeaders 对整个客户端生效，单次请求用 headers 选项覆盖
const child = new OpenAI({
  baseURL: `${BASE}/v1`,
  apiKey: process.env.API_KEY,
  defaultHeaders: agentHeaders(CHILD, ROOT, undefined, "researcher"),
});
await child.chat.completions.create(
  { model: "example-model", messages: [{ role: "user", content: "research the parser" }] },
  { headers: { "X-Agent-Role": "subagent" } },
);

// Anthropic SDK
const anthropicChild = new Anthropic({
  baseURL: BASE,
  apiKey: process.env.API_KEY,
  defaultHeaders: agentHeaders(CHILD, ROOT, undefined, "researcher"),
});
await anthropicChild.messages.create(
  { model: "example-model", max_tokens: 256, messages: [{ role: "user", content: "hello" }] },
  { headers: { "X-Agent-Role": "compaction" } },
);
~~~

### 6.4 为自研框架单列一个客户端

默认情况下带 `X-Agent-*` Header 的请求都归入 `custom` 客户端。如果希望自研框架在总览里独立成列、有自己的显示名，可以在词表覆盖文件里按 User-Agent 前缀新增一个客户端（占位名 `my-agent`，Header 配置与 `custom` 相同）：

~~~yaml
clients:
  my-agent:
    label: "My Agent"                 # 可选显示名，≤ 64 字节
    detect:
      user_agent_prefixes: ["MyAgent/"]
      headers_present: [x-agent-id]
    root_headers: [x-agent-session-id]
    node_headers: [x-agent-id]
    parent_headers: [x-agent-parent-id]
    name_headers: [x-agent-name]
    role_headers:
      - header: x-agent-role
        values:
          main: main
          subagent: subagent
          compaction: compaction
          title: title
          review: review
          auxiliary: auxiliary
~~~

框架侧只需把 User-Agent 设为 `MyAgent/<版本>`（如 `MyAgent/1.2.0`），其余 Header 不变。效果：

- 这些请求的 `agent_client` 写成 `my-agent`，总览 `group_by=client` 中单独一列，列名、会话卡片、Agent 树和详情页显示 `label`（没有 `label` 时显示 `my-agent`）。
- 新客户端未填 `priority` 时默认 50：排在四家内置客户端之后、`custom`（100）之前，所以同一请求不会再落入 `custom`。
- User-Agent 前缀匹配是**大小写不敏感的开头匹配**：`myagent/2`、`MyAgent/1.0 (linux)` 都命中，`node MyAgent/1.0` 不命中。User-Agent 识别优先于 Header 识别。
- 漏发 `X-Agent-Id` 的请求（例如预热或视觉等附属调用）仍按 User-Agent 归入该客户端，但没有节点标识，会话退回按内容推断（同一 Key、系统提示词与首条用户消息），也不会挂进 Agent 树。
- `detect.headers_present: [x-agent-id]` 会让**任何**带 `X-Agent-Id` 的请求都归入 `my-agent`，不只是该 User-Agent 的请求。如果同一个代理后面还有别的框架也用 `X-Agent-*` Header 并且应留在 `custom`，就去掉这一行，只靠 User-Agent 前缀识别。
- 改动只对之后新分析的记录生效；已有记录保持 `custom`，直到 `AnalysisVersion` 升级触发回填（回填用当时生效的词表）。

## 7. 验证与排错

1. 发几个带 Header 的请求后打开管理页“洞察”视图：会话卡片应显示“含 N 个子 Agent”，点击进入 Agent 树能看到父子关系。
2. 压缩/标题请求应出现在对应节点的“附属请求”计数里，而不是新的子 Agent。
3. 树没有出现：确认 `X-Agent-Id` 在同一 Agent 内保持不变、`X-Agent-Session-Id` 在整棵树内相同；只有一个节点的会话不是树。树被拆成几棵、或树里出现“父 Agent 不在范围内或尚未分析”的占位节点：通常是缺 `X-Agent-Session-Id` 且三层以上的树乱序到达（§6），或父 Agent 的请求尚未分析、已过期、不在当前身份可见范围内。
4. 节点没有名字：确认该 Agent 的非附属请求带 `X-Agent-Name`（≤ 64 字节）；名字从节点最新一条非附属请求读取，只在压缩请求上带名字不会显示。
5. 洞察页为空：检查 `insights.enabled`，以及日志中是否出现 `analysis_failed`、`analysis_save_failed`、`request_headers_load_failed`（见[模块 13](../features/13-observability-health-and-lifecycle.md)）。历史记录由后台回填补齐，大库需要一段时间。
6. 成本为空或大量“未计费”：确认已配置 `newapi.access_token`/`user_id`，并检查日志中的 `newapi_status_refresh_failed`、`caller_lookup_failed`、`billing_rate_missing`；占用率为空时按 §3 补充 `context_windows`。
