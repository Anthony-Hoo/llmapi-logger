# 模块 12：保留、同步导出与维护

## 1. 目标

本模块为个人单机部署提供三项最小能力：按天数清理旧审计、同步导出 ZIP/JSON、停机执行 VACUUM。

首版范围固定为按天数清理、当前请求内导出和人工停机维护。

## 2. 配置

直接使用[模块 01](01-configuration-and-route-boundary.md)的 retention_days，默认 30，以审计开始时间计算。设置为 0 表示关闭自动保留清理；负数配置无效并导致启动失败。

导出的记录数、字节数和超时上限使用[模块 10](10-query-api-and-minimal-web-ui.md)的固定值，不在本模块增加配置。

## 3. 数据范围

本模块只处理明确 LLM API 白名单产生的 audit；Nginx 直连 NewAPI 的 health/login/admin/models/UI/其他路径没有可清理或导出的记录。单条审计的删除和导出涉及 audit_records、http_stages、http_headers、body_streams、body_chunks、parsed_results 和 token_links。audit_gaps 是独立的进程级时间区间，只参与按时间清理和缺口查询，不放进单条审计导出。

audit_records 是父记录。删除只提交父记录，由模块 04 定义并经过测试的 ON DELETE CASCADE 清理全部审计子表。

## 4. 每日保留任务

进程启动一分钟后运行一次，此后每 24 小时运行一次；不引入 cron 表达式或独立调度器。

删除条件固定为 `ended_at_ns IS NOT NULL AND started_at_ns < :cutoff_ns`。

活动、未终结或刚完成但仍在保留窗口内的记录不得删除。

## 5. 小批量删除算法

每个事务最多处理 200 个 `audit_id`：

1. 按 `started_at_ns ASC, audit_id ASC` 选择最旧的 200 条父记录。
2. 在同一 writer 事务中删除父表 audit_records，由外键级联删除全部审计子表。
3. COMMIT 后让出执行权至少 100 ms。
4. 重复直到无到期记录，或本次运行已删除 5000 条。

单次运行达到 5000 条后停止，剩余积压留到下一天，避免个人设备上长时间占用 SQLite writer。

清理不读取、不解密 Body，也不创建临时导出。删除计数只写普通日志和低基数 metric。

模块 10 的单条 DELETE API 与 retention 共用同一个 writer 事务删除函数。记录已不存在时，API 返回 `404`，后台清理直接跳过。

## 6. 同步导出格式

管理 API 支持：

~~~http
GET /api/v1/audits/{audit_id}/export?format=zip
GET /api/v1/audits/{audit_id}/export?format=json
GET /api/v1/audits/export?format=json&from_ns=...&to_ns=...
~~~

导出在当前 HTTP 请求中同步完成，不持久化任务状态，也不后台重试。

## 7. ZIP 布局

单条 ZIP 固定包含 audit.json、headers.json、request.body、response.body 和 parsed.json。audit.json 包含 forward_status、blocked_by、block_code 和 parse_status；rejected audit 保留 skipped，未触发的 NewAPI/响应阶段保持缺失。时间使用 RFC3339Nano 展示，同时保留原始 Unix ns 字段。Body 按 chunk 顺序解密并流式写入 ZIP entry。

## 8. JSON 布局

单条 JSON 是一个完整 audit 对象；筛选导出是对象数组。对象包含 forward_status、blocked_by、block_code、parse_status、解密后的 Request-URI、Header/Trailer、实际存在的请求与响应 Body、阶段摘要、parsed result 和 token link；Body 使用 Base64 字段，空 Body 使用空字符串，未触发阶段使用缺失/null 而不是伪造空阶段。

若导出总量超过固定 max_bytes，整个同步导出失败；不输出截断但看似完整的 JSON。

ZIP 和 JSON 都是解密后的敏感数据。服务端设置下载文件名和 `Cache-Control: no-store`，但不尝试为导出再包一层项目专有加密格式。

## 9. 一致性与资源控制

- 开始导出时开启只读事务，保证筛选结果和各子表来自同一 SQLite snapshot。
- 先按索引读取目标 `audit_id`，再逐条读取子表，禁止一次加载所有 Body。
- 达到 `max_records` 或 `max_bytes` 返回 `413`，超时返回 `504`。
- 客户端取消后立即 rollback 只读事务并停止解密。

HTTP 响应一旦开始流式写出后发生错误，只能中断连接并记录错误；不得把不完整文件标记为成功。

## 10. 手动 VACUUM

提供停机命令：

~~~text
llmapi-logger maintenance vacuum --db ./data/audit.db
~~~

命令要求代理已停止。它以 busy_timeout=0 打开数据库；若仍有其他连接导致 busy，立即退出。执行前运行 PRAGMA integrity_check，成功后执行普通 VACUUM，结束后再次检查数据库可打开。

运行中的管理 API 不提供 VACUUM 端点，避免长时间阻塞 writer。首版不自动判断碎片率，也不自动执行 VACUUM。

## 11. 故障行为

- retention 遇到 SQLite busy：当前批次 rollback，warning 后结束，下一天重试。
- 任一子表删除失败：整个批次 rollback，不留下孤儿或半删记录。
- 解密认证失败：导出失败；HTTP 已开始输出时中断响应。
- 输出磁盘空间不足：导出失败，不影响代理主数据库。
- VACUUM 无法取得独占锁：立即退出并提示先停止代理。
- 主数据库或输出盘空间不足时返回实际写入错误，不在本模块内改变代理 admission。

## 12. 可观测性

日志只记录耗时、条数、字节数和错误类别。若启用 metrics，只增加 retention_deleted_total 和 export_total 两个计数器。

## 13. 测试

- 默认 30 天 cutoff 正确；未终结记录不删除；每个事务和每日运行上限生效。
- 删除后所有审计子表无孤儿行，中途故障完整 rollback。
- 列表查询与 retention 并发时不出现损坏或错误分页。
- ZIP 文件结构、chunk 顺序和 hash 信息正确。
- 单条和数组 JSON 可解析，Body Base64 可还原。
- 记录数、字节数、超时和取消限制生效。
- 代理运行时 VACUUM 拒绝，停机后可成功回收空间。
- 搜索日志确认未输出导出明文或主密钥。

## 14. 实施步骤

1. 实现共享的单条/批量事务删除函数。
2. 实现启动后一分钟、随后每 24 小时运行的清理循环和小批量上限。
3. 实现基于只读事务的同步导出遍历器。
4. 实现 ZIP 与 JSON 流式编码器。
5. 接入模块 10 的 API。
6. 实现停机 VACUUM、文件锁和完整性检查。
7. 完成并发、空间不足、解密失败和回滚测试。
