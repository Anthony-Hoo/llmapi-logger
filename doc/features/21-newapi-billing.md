# 21. NewAPI 实际计费

## 1. 目标与取舍

用量洞察里的成本改为直接采用 NewAPI 对每个请求的实际扣费，本服务不再维护价格表。

- **唯一成本来源是 NewAPI 消费日志。** 没有消费日志的请求是“未计费”，不做本地估算，也不和估算值混合求和。
- **删除本地价格机制。** 内嵌价格快照 `prices.json`、`insights.pricing_file` 覆盖文件、按时段计价的 `schedules`（以及为它存在的 30 分钟时间槽聚合）全部移除。它们只是在近似 NewAPI 的计费，拿到实际扣费后没有保留价值。
- **上下文窗口与价格拆开。** 占用率仍需要模型的上下文窗口，这是模型元数据而不是计费配置，改由独立的内嵌表 `internal/insights/models` 提供，可在 YAML 中按模型覆盖。
- **一次查询，一条记录。** 模块 11 已经按 request ID 查询 NewAPI 全站日志来回填调用者；计费来自同一次查询的同一批日志行，写入同一条 `token_links` 记录，不新增第二条查询链路。

## 2. NewAPI 日志契约

查询仍为 `GET /api/log/?p=0&size=10&request_id=<X-Oneapi-Request-Id>`（管理员凭据）。本模块额外读取每个日志项的：

| 字段 | 用途 |
| --- | --- |
| `type` | 只有 `2`（consume）计费；`5`（error）只用于身份 |
| `quota` | 该行实际扣除的额度，整数，必须 ≥ 0 |
| `prompt_tokens` / `completion_tokens` | NewAPI 计费所用的 Token 数，仅用于展示与核对 |

规则：

- 同一 request ID 的多条 consume 行，`quota` 与 Token 数求和。
- 只有 error 行时：若审计记录的响应状态是 2xx，说明 consume 行可能尚未落库，按“未找到”进入模块 11 的重试；重试耗尽或响应非 2xx，则身份照常写入，计费状态为 `unbilled`。
- 身份一致性校验（所有行用户与 Token 相同）不变，覆盖 consume 与 error 行。
- **不读取、不保存 `other`。** 管理员读取到的 `other` 含渠道与诊断信息，超出本服务需要。`content`、`ip`、`channel` 同样不读取。
- 退款日志（type 6）在 NewAPI 中不携带原请求 ID，无法关联，退款不会体现在成本中。

额度换算：

- `GET /api/status`（无需认证）返回 `quota_per_unit`，即 1 美元对应的额度（NewAPI 默认 500000）。客户端启动时读取，并随用户目录每 5 分钟刷新。
- 成本（美元）= `quota / quota_per_unit`。`usd_exchange_rate`、`quota_display_type` 等只是 NewAPI 的显示设置，本服务统一以美元展示。
- 查询成功但尚未得到有效的 `quota_per_unit`（> 0 且有限）时，按临时错误重试，不写入缺少换算系数的计费行。
- 写入时保存当时的 `quota_per_unit` 快照，运营方日后修改该值不会改写历史成本。

兼容性：`type`、`quota`、`request_id` 是 one-api 系列长期稳定的字段。NewAPI 版本过旧、日志不含 `request_id` 时，模块 11 本身就无法回填，计费同样不可用。

## 3. 存储

迁移 `009_newapi_billing.sql` 为 `token_links` 增加：

| 列 | 说明 |
| --- | --- |
| `billing_state TEXT NOT NULL` | `unchecked`（迁移前已有的链接，等待补查）、`billed`、`unbilled` |
| `quota INTEGER` | consume 行 `quota` 之和；仅 `billed` 时非空，≥ 0 |
| `quota_per_unit REAL` | 写入时的换算系数；仅 `billed` 时非空，> 0 |
| `billed_prompt_tokens`、`billed_completion_tokens INTEGER` | consume 行 Token 之和；仅 `billed` 时非空 |
| `billing_attempts INTEGER NOT NULL DEFAULT 0` | 历史补查次数 |

CHECK 约束保证 `billing_state='billed'` 当且仅当 `quota` 与 `quota_per_unit` 非空。迁移把已有行设为 `unchecked`，新写入的行只会是 `billed` 或 `unbilled`。

与 `token_links` 一样，计费数据不进入 HMAC 完整性证据链，随 retention 级联删除。

## 4. 历史补查

迁移前已解析调用者的记录没有计费。NewAPI worker 在处理完到期的调用者查询后，以低优先级补查 `billing_state='unchecked'` 的行：

- 从最新的记录开始，每次 1 条，间隔 500ms；有新的调用者查询到期时优先处理新查询。
- 补查只更新计费列，**不改变** `caller_status` 和身份字段，补查失败不会把已解析的调用者降级。
- 找到 consume 行写 `billed`，只有 error 行或日志已不存在写 `unbilled`；请求失败或缺少 `quota_per_unit` 时 `billing_attempts + 1`，满 3 次写 `unbilled`。连续失败时本轮补查暂停 1 分钟。
- NewAPI 已清理的旧日志无法补回，这些记录显示为未计费。

## 5. 查询与 API

成本在 SQL 中按 `LEFT JOIN token_links` 求和：`SUM(CASE WHEN billing_state='billed' THEN quota / quota_per_unit END)`，作用域沿用 `audit_records` 上已有的条件。Go 侧不再按模型逐行计价。

`UsageTotals`（overview KPI、分组小计、会话卡片等所有出现处）字段调整：

| 旧字段 | 新字段 |
| --- | --- |
| `estimated_cost_usd` | `cost_usd`：已计费请求的实际成本之和；没有已计费请求时为 `null` |
| `unpriced_requests` | `unbilled_requests`：没有计费结果的请求数（未查询、查询中、未识别、`unchecked`、`unbilled`） |
| — | `billed_requests`：`billing_state='billed'` 的请求数 |

- 会话趋势每一步的 `cost_usd` 取该审计自身的计费，未计费为 `null`。
- Agent 树节点如有成本字段，同样来自计费求和。
- overview 与 sessions 响应新增 `billing_enabled`：配置了 `newapi.access_token`/`user_id` 时为 `true`。为 `false` 时前端说明“未配置 NewAPI 管理凭据，无法获取实际计费”，而不是把所有请求显示为未计费。
- 审计详情返回 `billing_state`、`newapi_quota`、`cost_usd`、`billed_prompt_tokens`、`billed_completion_tokens`，在调用者信息旁展示。
- developer 作用域照常生效：开发者只能看到自己 Key 记录的计费。

前端把“估算成本”改为“实际计费”，并在有未计费请求时显示其数量（如“含 12 条未计费”）。

## 6. 配置

```yaml
insights:
  enabled: true
  vocabulary_file: ""
  context_windows:          # 可选：按模型覆盖上下文窗口（Token）
    my-gateway-alias: 200000
```

- `insights.pricing_file` 已废弃：仍可解析以免旧配置启动失败，但不再生效，启动时输出一次警告。下一个次版本移除。
- `context_windows` 的键按内嵌表相同规则匹配（精确 id、去掉厂商前缀、唯一的日期后缀族），值必须为正整数。
- 计费依赖模块 11 的 `newapi.access_token` 与 `newapi.user_id`，不新增配置项。

## 7. 验收

- 假 NewAPI 返回 `/api/status` 与带 `type`/`quota` 的日志：overview 的 `cost_usd` 等于 Σ`quota`/`quota_per_unit`，`billed_requests`/`unbilled_requests` 正确。
- 响应 2xx 但只有 error 行时会重试，consume 行出现后写为 `billed`；非 2xx 且只有 error 行时为 `unbilled`。
- 缺少 `quota_per_unit` 时不写计费行并重试。
- 迁移后的旧链接逐条补查为 `billed`/`unbilled`，`caller_status` 不变；补查失败 3 次停止。
- 未配置 NewAPI 凭据时 `billing_enabled=false`，旧配置中的 `pricing_file` 只产生警告。
- 上下文窗口与占用率结果与改造前一致；`context_windows` 覆盖生效。
- developer 作用域下看不到他人计费。
