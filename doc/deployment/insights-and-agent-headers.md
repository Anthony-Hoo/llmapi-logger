# 上下文洞察与 Agent 接入指南

本文面向部署者和客户端使用者：怎样开关上下文洞察、怎样覆盖价格与词表、各客户端需要做什么，以及自研 Agent 框架怎样通过 Header 被精确归入 Agent 树。设计与算法见[模块 20](../features/20-context-insights.md)，API 与页面见[模块 10](../features/10-query-api-and-minimal-web-ui.md) §11。

洞察是只读的派生功能：它在异步 parser 中从已审计的请求/响应计算用量、上下文构成、会话和 Agent 树，不改写任何转发字节，失败也不影响审计与解析结果。

## 1. 开关与配置

配置块（字段定义以[模块 01](../features/01-configuration-and-route-boundary.md)为准）：

~~~yaml
insights:
  enabled: true          # 默认 true；false 时不计算、不回填，洞察页与端点隐藏（404）
  pricing_file: ""       # 可选：本地价格覆盖 JSON，路径放在仓库外
  vocabulary_file: ""    # 可选：工具词表 / 注入标记 / Agent 标识覆盖 YAML，路径放在仓库外
~~~

- **关闭**：设 `insights.enabled: false` 并重启。已有的 `audit_analysis` 行保留但不再更新，也不会被读取。重新开启后，后台回填会补齐关闭期间缺失的记录。
- **开启**：默认即开启。启动后新请求在解析成功后立即分析；历史记录由后台回填逐步补齐（队列空闲时每个扫描周期最多 20 条，已被 retention 清除原始正文且无法重建的记录会跳过）。
- 非空的 `pricing_file` / `vocabulary_file` 必须在启动时已存在且是普通文件；内容非法时拒绝启动。

## 2. 价格覆盖

内嵌价格快照只是一份手写的公开标价估算，**不包含**网关倍率、折扣和长上下文阶梯，运行时不联网刷新。要使用自己的价格，复制 [`configs/insights-pricing.example.json`](../../configs/insights-pricing.example.json)，把 `insights.pricing_file` 指向它。文件中的价格都是占位示例，请换成你要估算的费率。

格式：

| 字段 | 说明 |
| --- | --- |
| `models` | 键为小写模型 id（`provider/model` 或网关里实际使用的别名），值为每百万 Token 的美元价 |
| `models.*.input`、`output` | 必填，非负 |
| `models.*.cache_read`、`cache_write` | 可选，缺省回落到 `input` |
| `models.*.context` | 可选，上下文窗口 Token 数，用于占用率；0 或缺省表示未知 |
| `schedules` | 可选，按 UTC 时段对匹配模型的成本乘以倍率，如夜间折扣 |
| `schedules.*.model` | 模型 glob（大小写不敏感），首个匹配的时段生效 |
| `schedules.*.weekdays` | 0=周日 … 6=周六；空表示每天，跨午夜的窗口按开始日计 |
| `schedules.*.start`、`end` | `HH:MM`（UTC），结束不晚于开始表示跨午夜，两者不能相等 |
| `schedules.*.multiplier` | (0, 100] |

覆盖文件按键并入内嵌快照：同名条目替换，`schedules` 追加。文件禁止未知字段，最大 4 MiB。查找模型价格的顺序：完整 id → 去掉厂商前缀后的唯一裸名 → 最长的已知族名加 `-`/`@`/`:` 后缀（带日期的发行版本）→ 未知（不计价，页面显示“未知价格”）。成本在查询时计算、不落库，修改文件并重启后立即对历史数据生效。

## 3. 词表覆盖

工具分类、注入标记和各客户端的 Agent 标识 Header 来自编译进二进制的默认词表。要调整，复制 [`configs/insights-vocabulary.example.yaml`](../../configs/insights-vocabulary.example.yaml)，只保留要改的键，把 `insights.vocabulary_file` 指向它。覆盖按键合并，示例文件头部列有合并规则；非法时拒绝启动。典型用途：自研框架已经有自己的 Header 名，直接在词表里给 `custom` 客户端改名，而不用改框架。

## 4. 各客户端

| 客户端 | 需要做什么 | 说明 |
| --- | --- | --- |
| Claude Code | 设置环境变量 `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`（可选） | 会话、Agent 与父 Agent 标识 Header 默认就有；该开关额外发送 `x-claude-code-request-class`（`main`/`subagent`/`compaction`/`auxiliary`…），用于把压缩等附属请求准确挂到发起它的 Agent 下，不开则靠 Body 里的标记推断 |
| Codex CLI | 不需要 | `session-id`、`thread-id`、`x-codex-parent-thread-id`、`x-openai-subagent` 默认携带 |
| OpenCode | 不需要 | `x-opencode-session-id` 与父会话头默认携带（较旧版本的头语义不同，识别规则可在词表中调整） |
| dsh（官方 DeepSeek Harness 适配器） | 不需要 | 默认携带 `x-deepseek-harness-session-id`，压缩请求带 `x-deepseek-harness-compact` |
| dsh 经第三方 pi-ai 适配器 | 无法改善 | 该路径没有任何会话 Header，只能靠内容推断：用同一 Key、系统提示词与首条用户消息拼会话，子 Agent 仅在子 Agent 提示词里带 `Your parent agent id` 时才能连边。会话和树会标为“推断”，并行且开场白相同的会话可能被合并 |
| 其他/自研 | 见 §5 | 在每个请求上加 `X-Agent-*` Header |

这些 Header 由客户端本身发送，代理只读取不改写，原样转发给 NewAPI 与上游。它们与其他 Header 一样被逐个 AES-256-GCM 加密存储，明文列里只有不可反查的 keyed 指纹。

## 5. 自研 Agent 的 Header 约定

在发往代理的**每一个** LLM 请求上带下列 Header，即可被精确归入 Agent 树，不依赖任何内容推断（`custom` 客户端，优先级低于四家内置客户端的原生 Header）：

| Header | 必填 | 取值 | 含义 |
| --- | --- | --- | --- |
| `X-Agent-Session-Id` | 推荐 | 不透明字符串，≤ 256 字节，建议 UUID | 整棵 Agent 树的根标识：主 Agent 和它派生的所有子/孙 Agent 都填**同一个值** |
| `X-Agent-Id` | 是 | 同上 | 当前 Agent 自己的标识：同一 Agent 的所有请求不变，不同 Agent 必须不同 |
| `X-Agent-Parent-Id` | 子 Agent 必填 | 同上 | 直接父 Agent 的 `X-Agent-Id`；主 Agent 不带 |
| `X-Agent-Role` | 否 | `main` / `subagent` / `compaction` / `title` / `review` / `auxiliary` | 请求类别；缺省时有 `X-Agent-Parent-Id` 视为 `subagent`，否则 `main` |
| `X-Agent-Name` | 否 | ≤ 64 字节的可读名，如 `researcher` | 只在详情页展示 |

规则：

- 缺 `X-Agent-Session-Id` 时，根由父链上溯得到；父 Agent 的请求晚到或已过期时，该子树暂时显示为独立树，补齐后自动合并。
- **附属请求**（压缩、生成标题、总结）带发起它的那个 Agent 的 `X-Agent-Id`，并把 `X-Agent-Role` 设为对应类别。它们挂在该节点下，不被当成子 Agent，也不开启新 turn。
- 代理不删除、不改写这些 Header。上游若对未知 Header 敏感，请在 Nginx 之后、NewAPI 之前自行处理。
- 不要在 ID 里放密钥、Token 或个人信息；UUID 或业务 ID 都可以。
- **`prompt_cache_key` 的副作用**：若同时把根会话 ID 写进 OpenAI 的 `prompt_cache_key`，OpenAI 轮次图会按它把父子 Agent 串进同一个 conversation，导致血缘和 delta 体积失真（重建仍然正确）。建议每个 Agent 用自己的 `X-Agent-Id` 作 `prompt_cache_key`，或者不填。

没有客户端 Agent ID 的普通会话不算 Agent 树：只有同一根下出现 ≥ 2 个不同 Agent，或存在 Header/Body/内容连边时才会显示为树。

### 5.1 curl

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

### 5.2 Python

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

### 5.3 TypeScript

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

## 6. 验证与排错

1. 发几个带 Header 的请求后打开管理页“洞察”视图：会话卡片应显示“含 N 个子 Agent”，点击进入 Agent 树能看到父子关系。
2. 压缩/标题请求应出现在对应节点的“附属请求”计数里，而不是新的子 Agent。
3. 树没有出现：确认 `X-Agent-Id` 在同一 Agent 内保持不变、`X-Agent-Session-Id` 在整棵树内相同；只有一个节点的会话不是树。
4. 洞察页为空：检查 `insights.enabled`，以及日志中是否出现 `analysis_failed`、`analysis_save_failed`、`request_headers_load_failed`（见[模块 13](../features/13-observability-health-and-lifecycle.md)）。历史记录由后台回填补齐，大库需要一段时间。
5. 成本显示“未知价格”：模型名不在价格表里，按 §2 添加覆盖条目。
