# 模块 12：保留清理

## 1. 目标与边界

本模块只实现个人单机需要的自动保留清理。它删除过期 HTTP audit 和不再可达的 conversation/content/binary 对象，同时保证仍在保留期内的分支轮次不依赖已经删除的父历史。

不提供单条 DELETE API、在线导出、gaps 页面或自动 VACUUM。完整性事件使用全局 append-only 链，不随普通 audit retention 删除中间事件。

## 2. 选择规则

直接使用 `retention_days`：

- `0`：关闭 runner；
- `1..3650`：按当前时间减去天数计算 cutoff；
- 其他值：配置无效，拒绝启动。

只选择同时满足以下条件的 `audit_records`：

- `ended_at_ns IS NOT NULL`；
- `started_at_ns < cutoff`；
- `parse_status <> processing`。

未终结 audit 和正在写语义图的 processing audit 不能删除。`audit_gaps` 没有父 audit，按 `ended_at_ns < cutoff` 独立清理。

## 3. 轮次检查点

直接级联删除父 audit 会被 `turns.parent_turn_id ON DELETE RESTRICT` 阻止，也会破坏保留子轮次的重建。因此每批删除前必须：

1. 找出目标 audit 对应 turns；
2. 找出 parent 位于删除集合、但自身不在删除集合的边界子轮次；
3. 沿现有 parent/delta 链恢复其完整 request refs；
4. 删除原 delta，改写为从空序列开始的 root insert 操作；
5. 设置 `parent_turn_id=NULL`、`parent_base=root`、`link_reason=retention_checkpoint`、`link_confidence=100`；
6. 立即重建并比较 sequence hash；验证失败则回滚整批。

这样会牺牲该边界节点的一次 delta 压缩，但保留期内的后代继续准确重建，且不会为了删除旧历史而复制 content/binary 对象本体。

## 4. 删除与可达性 GC

同一 writer 事务按以下顺序执行：

1. 创建必要的 retention checkpoints；
2. 在删除集合内按叶到根删除 turns；
3. 删除目标 audit_records，由外键级联清理 HTTP、parsed result、token link 和 turn 子表；
4. 删除不再包含 turn 的 conversations；
5. 删除不再被 turn envelope、context op 或 response item 引用的 content objects；
6. 删除不再被 content object 引用的 binary objects；
7. 删除本批过期 audit_gaps。

对象 GC 使用 `NOT EXISTS` 和专用引用索引，不使用手工 ref_count。`content_binary_refs` 随 content object 级联删除，binary object 只有在没有任何引用后才删除。

## 5. 执行方式

- 应用启动后异步执行一轮，此后每 24 小时执行一次。
- 每个 writer 事务最多删除 200 条 audit，并最多删除 200 条 gap。
- 单轮最多分别删除 5000 条 audit 和 5000 条 gap。
- 所有写入经过既有单 writer，不增加第二个写连接。
- 任意 checkpoint、删除或 GC 失败都回滚整批，只记录稳定 `retention_failed`，等待下一轮。

retention 失败不改变 data-plane admission；数据库 writer 本身不健康时，原有 available/strict 语义仍然适用。

## 6. 最少测试

- cutoff 边界正确，未终结和 processing 记录不删除。
- audit/gap 每批和单轮上限正确，两类互不阻塞。
- 删除简单 audit 后不存在 HTTP/parsed/token/turn 孤儿行。
- 删除父轮次但保留子轮次时，子轮次成为 `retention_checkpoint`，provider request/response 仍可精确重建。
- 多层删除集合按叶到根完成，不触发 parent RESTRICT，也不会形成循环。
- 仅由过期 turns 引用的 content/binary objects 被清理，共享对象继续保留。
- 事务中任何一步失败完整回滚。
- 日志不包含 Header、Body、Query、Token、主密钥或底层数据库错误原文。

## 7. 运维

数据库与主密钥必须联合备份；运行中的数据库必须通过 SQLite backup API 创建一致性快照。项目不自动执行 VACUUM。确需收缩主库文件时先停机并备份，再使用标准 SQLite CLI；WAL 增长先检查长读事务和 checkpoint，不要在进程运行时删除 `-wal` 或 `-shm`。
