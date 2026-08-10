# 模块 12：保留与可选单条 JSON 导出

## 1. 目标与范围

阶段 4 只计划两项个人单机能力：

1. 按 `retention_days` 小批量清理已经终结的旧审计。
2. 如果实际使用确有需要，再增加单条 audit 的 JSON 导出。

不计划 ZIP、筛选结果/批量导出、批量删除、导出任务队列、gaps UI 或项目内 VACUUM 管理功能。SQLite 的备份、完整性检查和 VACUUM 可以由用户停机后使用标准工具完成。

## 2. 数据边界

本模块只处理 LLM API 白名单产生的 audit。Nginx 直连 NewAPI 的 health/login/admin/models/UI 和其他路径没有可清理或导出的记录。

`audit_records` 是父记录。retention 只删除已终结父记录，并依靠模块 04 定义且经过测试的外键级联清理子表。`audit_gaps` 是进程级记录，可按自身时间字段清理，但不伪装成单条 audit 的一部分。

## 3. Retention

直接使用[模块 01](01-configuration-and-route-boundary.md)的 `retention_days`：默认 30，设置为 0 表示关闭，负数配置无效。cutoff 按审计开始时间计算，只选择 `ended_at_ns IS NOT NULL` 的记录。

实现保持简单：

- 启动后延迟一次执行，随后每天执行一次，不引入 cron 或调度表。
- 每个 writer 事务最多删除约 200 条最旧记录，批次间短暂让出执行权。
- 单次运行设置合理总量上限，剩余积压留给下一次运行。
- 清理不读取或解密 Body，也不影响活动记录。
- SQLite busy 或删除失败时回滚当前批次、记录 warning，等待下次运行。

阶段 3 不提供手工 DELETE API；retention 是计划中的唯一自动删除入口。

## 4. 可选单条 JSON 导出

单条 JSON 导出是阶段 4 的可选项，不作为阶段 3 验收条件。若实现，候选接口为：

~~~http
GET /api/v1/audits/{audit_id}/export?format=json
~~~

该端点属于管理面，即使监听在 loopback 也必须携带与其他管理 API 相同的 Bearer token。导出只处理一个 audit，在当前 HTTP 请求中完成，不创建后台任务。

JSON 以现有详情摘要为主体，可附带 Base64 编码的 raw request/response Body 和完整性标记。未发生的阶段保持缺失/null，不伪造空响应；不尝试重建完整对话、SSE 时间线或 NewAPI 后方不可见数据。

导出是解密后的敏感数据，响应必须设置 `Cache-Control: no-store`。客户端取消、解密认证失败或大小超过固定安全上限时立即停止；不返回看似完整的截断 JSON。

## 5. 明确不做

- ZIP 导出及自定义归档布局。
- 按筛选条件导出数组或批量文件。
- 后台导出任务、进度查询和重试。
- 单条/批量删除管理端点。
- gaps 页面或把 gap 关联到具体 audit。
- 运行中的 VACUUM API 或项目专用维护命令。

## 6. 最少测试

- retention cutoff 正确，未终结记录不删除，批次失败完整回滚。
- 删除父记录后所有审计子表无孤儿行，执行期间普通查询仍可用。
- 关闭 retention 时不启动清理；SQLite busy 时不中断代理。
- 如果实现单条 JSON 导出：Bearer 鉴权、单条范围、Body Base64、完整性标记、取消和大小上限均有测试。
- 日志不包含导出明文、Header value、Body、admin token 或主密钥。

## 7. 实施步骤

1. 实现共用的 retention 批量删除事务。
2. 实现简单每日清理循环、批次上限和故障回滚测试。
3. 根据个人使用反馈决定是否实现单条 JSON 导出；若没有明确需求，阶段 4 可以只交付 retention。
