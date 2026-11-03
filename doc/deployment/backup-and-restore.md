# 备份与恢复

当前运行时使用 PostgreSQL。数据库与对应的本地 `audit.key` 必须作为一个匹配备份集保存；密钥丢失不能恢复已加密证据。

- 使用 PostgreSQL 的 `pg_dump`/`pg_restore` 或经过验证的物理备份与 WAL 归档流程；不要直接复制运行中数据库的数据目录。
- 最容易验证的一致备份窗口是停止代理、完成备份、保护密钥副本，再恢复服务。在线快照备份的时点与 WAL 恢复策略应由数据库运维明确管理。
- 密钥、备份与连接凭据只进入受限存储。不要写入仓库、公开 Actions 产物或日志。
- 在隔离数据库定期演练恢复：恢复后检查 readiness、完整性链/载荷、规则、审计总量以及样本原始证据和重建会话。恢复使用同一密钥，不重新生成密钥来绕过验证。
- PostgreSQL schema/version 不得用 SQLite migration 数字解释。旧 SQLite schema12 只通过显式离线导入工具迁移；源文件与密钥备份在迁移成功后仍保留。

详细切换、dry-run 与回滚步骤见 [PostgreSQL 迁移](postgresql-migration.md)。SQLite 旧备份若仍有 WAL，必须使用 backup API 或完整一致快照，不能只拿 `.db` 文件。
