# 模块 12：保留清理

## 1. 目标与边界

本模块只实现个人单机需要的自动保留清理。它只处理 LLM API route 产生的审计；passthrough 的登录、管理、模型列表、页面、健康检查和其他安全非 LLM 请求没有对应记录。

首版不提供导出端点、DELETE API、后台维护任务、gaps 页面或自动 VACUUM。原始请求/响应仍通过模块 10 的单条 raw 接口读取，备份使用标准 SQLite 工具。

## 2. 选择规则

直接使用模块 01 的 `retention_days`：

- `0`：关闭 retention runner。
- `1..3650`：按当前时间减去天数计算 cutoff。
- 负数或更大值：配置无效，拒绝启动。

只删除同时满足以下条件的 `audit_records`：

- `ended_at_ns IS NOT NULL`；
- `started_at_ns < cutoff`；
- `parse_status != processing`。

删除父记录后依靠 SQLite 外键级联删除 HTTP 阶段、Header、Body、解析结果和 Token 名称关联。清理过程不读取或解密敏感内容，也不触碰活动记录。

`audit_gaps` 没有父 audit，按自身 `ended_at_ns < cutoff` 独立清理。

## 3. 执行方式

- 应用启动后异步执行一轮，此后每 24 小时执行一次。
- 每个 writer 事务最多删除 200 条 audit，并在同一事务最多删除 200 条过期 gap。
- 单轮最多分别删除 5000 条 audit 和 5000 条 gap；两类独立推进，一类已经清空不会阻断另一类。
- 每批都通过现有单 writer 执行，不增加第二个写连接。
- SQLite busy 或事务失败时回滚本批，只输出稳定 `retention_failed` warning，等待下一轮。

retention 或 gap 清理失败不改变代理 readiness，也不阻断转发。

## 4. 最少测试

- cutoff 边界正确，未终结和 `processing` 记录不删除。
- audit/gap 每批各不超过 200，单轮各不超过 5000。
- 父记录删除后审计子表没有孤儿行。
- gap 按同一 cutoff 独立清理。
- `retention_days=0` 时不启动 runner。
- 事务失败完整回滚，安全日志不包含 Header、Body、Query、token、key 或数据库错误原文。

## 5. 运维

数据库与主密钥必须一起备份；运行中的数据库必须通过 SQLite `.backup` 创建一致性快照。详见 [部署备份说明](../deployment/backup-and-restore.md)。

项目不自动执行 VACUUM。确需收缩文件时先停机并备份，再使用标准 SQLite CLI 手工处理。
