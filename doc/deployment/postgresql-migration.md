# PostgreSQL 运行与离线迁移

本版本运行时只使用 PostgreSQL（CI 与本地验证为 18.6）。不再接受 YAML `db_path`；必须显式配置 `database_url`。旧 SQLite 文件不会被自动打开、转换或删除。`audit.key` 仍在本地受限文件中。

## 新部署

1. 创建专用数据库和最小权限角色。角色需要在专用 schema 内创建/升级表并读写数据；不要让其他应用共享同一 schema。
2. 在私有 YAML 中设置 PostgreSQL URL 和 `key_path`。URL 中密码需百分号编码；不要把真实 URL、密码或密钥提交仓库。
3. 远程数据库使用 `sslmode=verify-full` 及可信 CA。示例中的 `sslmode=disable` 仅适用于受控本机或 Compose 私有网络，不是互联网部署建议。
4. Compose 的 PostgreSQL 18 数据卷挂载在 `/var/lib/postgresql`。设置 `POSTGRES_PASSWORD`，并将相同密码写入私有代理配置的 URL。Compose 不会自动替换挂载 YAML 中的占位符。
5. 运行 `audit-proxy --config <私有配置> --validate-config`，再启动。空数据库初始化独立 PostgreSQL schema 版本；它不沿用 SQLite migration 版本号。

每个数据库/schema 仅允许一个代理写者。代理在固定数据库连接上持有 session advisory lock；第二个实例不可写入。连接丢失后不能换连接无锁继续写，必须重新启动。数据库端不要终止锁连接后继续保留旧服务；按正常服务停止、启动流程操作。只读查询的多语句证据快照使用 repeatable read。

## 从 v0.6.0 SQLite 迁移

迁移是显式停机操作，不是在线双写。先在副本演练，并保留旧版本可执行文件/镜像。

1. 停止旧代理，确认没有任何写者。保留完整 SQLite 备份与其匹配 `audit.key`。活动 WAL 数据库不能只复制主 `.db`；应使用 SQLite backup API，或干净关闭后保存完整一致副本。
2. 源必须是 SQLite schema 12，且证据完整性可验证。更老数据库先按旧版受支持升级路径处理，不直接跳过。
3. 准备空 PostgreSQL 目标，确认目标无审计、用户规则或其他业务数据。迁移不会覆盖已有数据或提供 force 选项。
4. 构建导入工具 `go build -o audit-import ./cmd/audit-import`。通过环境变量 `AUDIT_IMPORT_DATABASE_URL` 提供目标 URL，避免把密码写入进程参数。先执行：

```sh
./audit-import --source /backup/audit.db --key-file /backup/audit.key --service-stopped --dry-run
```

5. dry-run 成功后使用相同参数去掉 `--dry-run`。导入读取只读源快照，复制原密文/ID/完整性事件，检查行数、引用、摘要和 ID 高水位；目标事务失败时回滚，源不改变。已成功导入的目标不能重复导入。
6. 切换私有 YAML 至 `database_url`，保留同一 `audit.key`，启动新服务。检查 readiness、规则、样本详情与完整性结果后恢复流量。

派生 insights 旧明细仍可读取；分析版本 8 的后台空闲扫描按既有有界批次逐步重算为共享前缀表示，不在导入事务内执行。失败保留原明细，后续扫描重试。历史量较大时需要时间，不保证导入后立即减少物理数据库文件。

## 回滚

先停止新服务并备份 PostgreSQL，再用 v0.6.0 与原 SQLite 备份及匹配密钥启动。PostgreSQL 切换后的新写入不会自动回灌 SQLite；有新流量时必须先决定如何保留这段审计数据，不能宣称无损直接回退。不要用旧版本打开新格式数据库，也不要删除旧备份来腾空间。

## 验证边界

四阶段原始 hash、字节长度、内容对象身份、AES-GCM AAD、HMAC 完整性链和作用域隔离保持不变。PG WAL/事务提交之前的进程内 capture 缓冲仍会因强制退出丢失。共享对象减少重复内容存储；数据库空页与 WAL 的物理回收受 PostgreSQL 维护机制影响，不等于逻辑泄漏。
