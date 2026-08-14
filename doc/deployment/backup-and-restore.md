# SQLite 与主密钥备份

## 1. 必须一起保存的文件

一个可恢复的备份至少包含：

~~~text
audit.db   # SQLite 一致性快照
audit.key  # 32-byte AES-256-GCM 主密钥
~~~

只保存数据库没有意义：key 丢失后，Header、raw Body、Request-URI、fallback conversation、content/binary object 和 stream timeline 无法解密，HMAC 完整性链也无法验证。只保存 key 也不能恢复审计记录。`audit.db-wal` 和 `audit.db-shm` 不是数据库备份，也不能代替 `audit.db`。

备份目录应使用与原数据相同或更严格的访问权限；不要把 key 上传到日志、工单或未加密的公共存储。

## 2. 在线备份

进程运行时，数据库处于 WAL 模式。此时必须通过 SQLite backup API 创建一致性快照，不能直接 `cp`/`Copy-Item` 正在使用的 `audit.db`。

在能同时读取数据目录和备份目录的主机上执行：

~~~bash
umask 077
data_dir="${AUDIT_DATA_DIR:?set AUDIT_DATA_DIR}"
backup_root="${AUDIT_BACKUP_DIR:?set AUDIT_BACKUP_DIR}"
backup_dir="${backup_root}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"

sqlite3 "$data_dir/audit.db" \
  ".timeout 5000" \
  ".backup '$backup_dir/audit.db'"

install -m 600 "$data_dir/audit.key" "$backup_dir/audit.key"
sqlite3 "$backup_dir/audit.db" "PRAGMA quick_check;"
~~~

期望 `PRAGMA quick_check` 输出 `ok`。主密钥在首启后不会自动轮换，因此可以在 `.backup` 前后复制；关键是数据库文件必须来自 `.backup`。

distroless 运行镜像故意不包含 `sqlite3`。Docker volume 部署需要从宿主机或一个固定版本、可信的临时 SQLite 工具容器执行同样的 `.backup`，并把备份输出到独立挂载目录；不要为了备份把 SQLite CLI 安装进运行容器。

## 3. 停机备份

可以接受停机时，先正常停止 audit-proxy，确认没有进程再打开数据库，然后 checkpoint 并复制数据库与 key：

~~~bash
data_dir="${AUDIT_DATA_DIR:?set AUDIT_DATA_DIR}"
backup_dir="${AUDIT_BACKUP_DIR:?set AUDIT_BACKUP_DIR}/offline"
mkdir -p "$backup_dir"
sqlite3 "$data_dir/audit.db" "PRAGMA wal_checkpoint(TRUNCATE);"
cp "$data_dir/audit.db" "$backup_dir/audit.db"
cp "$data_dir/audit.key" "$backup_dir/audit.key"
~~~

不要在进程仍运行时使用这套复制步骤。

## 4. 恢复

1. 停止 audit-proxy。
2. 保留当前数据目录的离线副本。
3. 把同一备份集中的 `audit.db` 和 `audit.key` 放入配置指定路径。
4. 不要从在线备份复制旧的 `-wal` 或 `-shm` 文件。
5. 使用支持该备份 schema generation 的程序版本；不要让旧二进制直接打开 generation 2 数据库，也不要把新版本的破坏性 migration 当成历史恢复工具。
6. 恢复运行账户的只读 key 权限和数据目录写权限；Compose 镜像中的运行 UID/GID 是 `65532:65532`。
7. 启动程序，通过带 Bearer token 的 `/readyz`、一条历史 reconstructed request/response 和完整性链启动检查验证数据库及 key 匹配；若备份中存在 `full` 异常记录，再抽查一条 raw。正常 `metadata` 记录的 raw 返回 410 是预期行为。

如果 key 与数据库不匹配，GCM 认证或 HMAC 链验证会失败。不要让程序为已有数据库生成替代 key；应停止服务并换回正确的备份集。

## 5. 不包含的维护功能

项目不提供在线导出、DELETE API、自动 VACUUM、在线 key rotation 或专用备份任务。需要收缩 SQLite 文件时，停机后使用标准 SQLite 工具，并在操作前先完成数据库与 key 的联合备份。需要更换主密钥时，应保留旧数据库/旧 key 联合备份，并以新 key 创建新的空审计库。
