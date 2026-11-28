# 模块 12：保留清理

## 1. 目标与边界

本模块只实现个人单机需要的自动保留清理。它删除过期 HTTP audit 和不再可达的 conversation/content/binary 对象，同时保证仍在保留期内的分支轮次不依赖已经删除的父历史。

不提供单条 DELETE API、在线导出、gaps 页面或自动 VACUUM。完整性事件使用全局 append-only 链，不随普通 audit retention 删除中间事件。把到期记录导出到归档目录的冷归档是另一个模块（[模块 26](26-cold-archive.md)），开启时本模块不运行（§2）。

## 2. 选择规则

直接使用 `retention_days`：

- `0`：关闭 runner；
- `1..3650`：按当前时间减去天数计算 cutoff；
- 其他值：配置无效，拒绝启动。

**开启冷归档时不直接删除。** `archive.mode` 不为 `off`（`export_only` 或 `archive_then_delete`，[模块 26](26-cold-archive.md)）时，本模块的 runner 不组装：audit 和 gap 都不再被直接删除，到期判定（同一个 cutoff 算法）改由每天一次的归档运行使用。这是决策 5.7 的第 2 条护栏：启用归档以后，任何情况下都不会跳过归档直接删。`export_only` 从不删除；`archive_then_delete` 下唯一的删除是归档的校验后移除（模块 26 §18.7），它与本模块共用批量策略（`retention.Batcher`：从 1 条起，翻倍、按比例缩小、慢失败降到 1，每批后暂停同样长、至多 5 秒）和同一段删除代码（检查点、叶到根删除、派生明细修剪、对象回收），只是输入换成了“包已核对、变更戳没变”的成员。移除只作用于格式版本不低于 1 的包，内置格式版本是 0，所以这个版本里两种开启的模式下热库都持续增长。

- 开启归档要求 `retention_days > 0`，否则配置校验拒绝（第 1 条护栏）。
- **暂停归档**而不恢复直接删除：把 `retention_days` 设为 0。把 `archive.mode` 改回 `off` 而 `retention_days > 0`，本模块的直接删除立刻恢复，没有归档就删；以前运行过归档（目录表里有运行记录）时启动日志 Warn 一条 `archive_direct_delete_resumed`（第 3 条护栏）。

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

1. 读出候选对象：目标 turns 的 conversation、request/response envelope、response item，以及目标 turns 和其直接子轮次的 context op 引用的 content object；
2. 创建必要的 retention checkpoints；
3. 在删除集合内按叶到根删除 turns；
4. 读出本批 audit 的 `audit_analysis.detail_root`，再删除目标 audit_records，由外键级联清理 HTTP、parsed result、token link、turn 子表以及派生的 `audit_analysis` 与 `agent_spawn_hints` 行（上下文洞察，不在完整性链内）；
5. 从上一步读出的 detail root 出发裁剪 `analysis_detail_objects`（见下文）；
6. 在候选中删除不再包含 turn 的 conversations；
7. 先读出候选 content object 引用的 binary，再在候选中删除不再被 turn envelope、context op 或 response item 引用的 content objects；
8. 在上一步读出的 binary 中删除不再被 content object 引用的 binary objects；
9. 删除本批过期 audit_gaps。

对象 GC 使用 `NOT EXISTS` 和专用引用索引，不使用手工 ref_count，也不做全表扫描：每条语句只检查本批候选（每条最多 500 个参数），引用检查分别走 `turns_conversation_created_idx`、`turns_request_envelope_idx`、`turns_response_envelope_idx`、`turn_context_ops_object_idx`、`turn_response_items_object_idx` 和 `content_binary_refs_binary_idx`，开销随本批删除量而不是表大小增长。全表 `NOT EXISTS` 放在唯一 writer 事务里，库一大就会超过语句超时并拖垮同批审计写入。`content_binary_refs` 随 content object 级联删除，binary object 只有在没有任何引用后才删除。只有 retention 会删除 turn 或改写 context op，所以候选覆盖了所有可能被释放的对象；早期版本遗留、与本批无关的孤儿对象不会被顺带清理。

`analysis_detail_objects` 是共享前缀树，不做全表可达性扫描，而是定向裁剪：从被释放的 detail root 开始，删除既没有子节点（`analysis_detail_parent_idx`）、也不再是任何 `audit_analysis.detail_root`（`audit_analysis_detail_root_idx`）的节点，再对被删节点的父节点重复，直到遇到仍被共享的节点为止。开销只与被释放的链长度有关，与表大小无关。全表递归扫描放在唯一 writer 事务里，表一大就会超过语句超时并拖垮同批审计写入，因此禁止使用。

重新分析替换 detail root 时，`SaveAnalysis` 在同一事务里按旧 root 裁剪，所以没有过期 audit 的 retention 轮次不处理 analysis detail。定向裁剪只覆盖被释放的链；早期版本遗留的、不在任何被释放链上的孤儿节点不会被自动清理（属于可重算的派生数据，不影响证据）。

会话分析的派生表（`session_signals`、`session_packs` 等，[模块 24](24-session-analysis.md)）与 audit 没有外键，不在 retention 批次里清理：会话分析的每日批处理按同样的约束分页清理（候选只取早于 retention 截止时间的行，每页最多 500 个、各自一次 writer 操作，见 24 §16）。`audit_project_identity`（模块 23）随 audit 外键级联删除。

## 5. 执行方式

- 应用启动后异步执行一轮；已追平时每小时检查一次。
- 每个 writer 事务最多删除 200 条 audit，并最多删除 200 条 gap。
- 单轮最多分别删除 5000 条 audit 和 5000 条 gap；任一类别达到上限时，暂停一分钟后继续下一轮，直到追平，再回到每小时检查。
- 所有写入经过既有单 writer，不增加第二个写连接。
- 任意 checkpoint、删除或 GC 失败都回滚本批，记录稳定 `retention_failed` 和安全的 `storage_error` 类别，一分钟后重试。延迟从本轮结束时计算，不重叠运行，也不在单轮里无限追赶。

retention 失败不改变 data-plane admission；数据库 writer 本身不健康时，原有 available/strict 语义仍然适用。

### 5.1 对 writer 的占用

`BeginAudit` 同步等待 writer 提交，所以 retention 占住 writer 多久，正在进来的请求就多等多久。删除一条 audit 要级联它的 Header、Body、解析结果和派生行，在慢盘上是秒级，而且各条相差很大（长对话、带图的请求），事先算不出来。固定每批 200 条时，慢盘上一批会超过 30 秒语句超时，回滚后一分钟再原样重试，永远删不掉。因此：

- **单独成批**：retention 请求在 writer 里独占一个事务，不与排在它前后的审计写入合批。存储级错误按 writer 规则整批失败，合批时 retention 的一次失败（例如语句超时）会把同批的审计写入一起回滚。
- **按耗时定批量**：每批删多少条 audit 由 runner 根据上一批的实际耗时决定，目标是一批占用 writer 约 1 秒（`targetBatchTime`）。从 1 条开始；装满且耗时不超过目标一半的批让下一批翻倍（上限 200）；耗时超过目标的批让下一批按超出的比例缩小（下限 1）。批量在各轮之间保留。store 侧不变：每个事务仍是一次完整的 §3–§4 流程，不取消语句，也不为守时间回滚。
- **失败后退到单条**：量出来的成本预见不了“便宜的后面跟着一段昂贵的”。按便宜的定出的大批撞上昂贵段可能超过语句超时而失败。多于一条、且耗时超过目标才失败的批，批量退到 1（记一条 `retention batch reduced to one audit`），并在本轮剩余和下一轮里保持为 1；此后每完成一轮，允许的批量上限翻倍，直到回到 200。立刻失败的批（连接抖动、队列满）与批量无关，不触发。只含一条 audit 的批是能前进的最小单位。
- **批间让路**：一轮里每两批之间，runner 暂停与前一批耗时相等的时间，最长 5 秒。耗时从提交请求算到拿到结果，包含在 writer 队列里等待的时间，所以审计写入繁忙时 retention 会自己退让；排队本身就稳定超过半秒时批量长不上去，清理会很慢，但那时 `BeginAudit` 也在等同样久，问题不在 retention。单批不超过 5 秒时，retention 至多占用 writer 一半的时间。

这些措施限制的是单次占用和连带失败，不改变删除一条 audit 的成本：

- 一条 audit 的删除不可分割。它要花几秒，赶上的请求就要等几秒。
- 批量是按过去估的。一批里混进一条远比平均昂贵的 audit 时，这一批会超出目标，超出的就是那条的耗时；一批的耗时不超过它所含的那些连续记录（至多 200 条）的成本之和。批的边界不再落在 200 的整数倍上，所以固定 200 条时恰好被分在两批的一簇昂贵记录，可能被装进同一批：那一批更久，总和超过语句超时时失败一次。
- 上面说的大批失败每次占用 writer 到撞上语句超时为止，之后一分钟重试；成本突变一次，失败一次。语句超时按语句计（30 秒），一批由多条语句组成，所以这次占用可以超过 30 秒。
- 在每条都要花数秒的盘上，批量停在 1，积压按“每条耗时的两倍”消化；到期速度超过它时积压会增长，但 retention 仍在前进，也不会让审计写入失败。
- 批越小，批的边界越多，而每个边界都要给“父轮次在本批、自己不在”的轮次做 §3 的检查点，即使它下一批就被删除。一条长对话逐条删除时，每条都要重写一遍完整上下文的引用，写入的 `turn_context_ops` 行数约为对话轮数的平方：实测 160 轮的单链，批量 200 时写 0 行、60 ms，批量 1 时写约 2.56 万行、3.3 秒。这是小批的固有代价，在批量被迫缩小时出现（慢盘，或一次慢失败之后的两轮），进程启动后从 1 爬升到 200 的那几批也有少量（同一条链约 500 行）；批量为 200 时与原先相同。
- 批间暂停与批的耗时相等，追赶积压时清理的吞吐因此低于不暂停时。
- 要降低单条成本，只能减少每条 audit 的数据量或换更快的盘。

## 6. 最少测试

- cutoff 边界正确，未终结和 processing 记录不删除。
- audit/gap 每批和单轮上限正确，两类互不阻塞。
- retention 批因存储错误失败时，与它一同到达 writer 的审计写入不被回滚，无论谁排在前面。
- 批量从 1 起步，按耗时翻倍或按比例缩小，在各轮之间保留；被单轮上限截短或没删满的批不触发翻倍。
- 多于一条的批失败后退到单条，且不在剩余的便宜记录上长回去；之后每完成一轮上限翻倍。取消不改变批量。
- 成本不均匀时没有批被放弃，占用等于实际工作量，单批不超过固定 200 条的一批。
- 每批之后按耗时暂停，上限 5 秒；取消在暂停期间生效。
- 超过单轮上限的积压会自动继续处理；失败不等待空闲检查周期，追平后恢复空闲周期。
- 删除简单 audit 后不存在 HTTP/parsed/token/turn 孤儿行。
- 删除父轮次但保留子轮次时，子轮次成为 `retention_checkpoint`，provider request/response 仍可精确重建。
- 多层删除集合按叶到根完成，不触发 parent RESTRICT，也不会形成循环。
- 仅由过期 turns 引用的 content/binary objects 被清理，共享对象继续保留；候选超过单条语句上限时分批完成，本批释放的 content object 和 conversation 全部被回收。
- 事务中任何一步失败完整回滚。
- 日志不包含 Header、Body、Query、Token、主密钥或底层数据库错误原文。
- 删除 audit 后不残留 `audit_analysis` 与 `agent_spawn_hints` 行。
- 重新分析替换 detail root 后，旧链上不再被共享的节点在保存时即被删除，仍被其他 audit 共享的前缀保留。
- retention 只裁剪本批被删 audit 的 detail 链，长链逐层裁剪完成，仍保留 audit 的节点不受影响；一次释放的根超过单条语句上限时分批完成。

## 7. 运维

数据库与主密钥必须联合备份；运行中的数据库必须通过 SQLite backup API 创建一致性快照。项目不自动执行 VACUUM。确需收缩主库文件时先停机并备份，再使用标准 SQLite CLI；WAL 增长先检查长读事务和 checkpoint，不要在进程运行时删除 `-wal` 或 `-shm`。
