# PostgreSQL 运行与离线迁移

本版本运行时只使用 PostgreSQL（CI 与本地验证为 18.6）。不再接受 YAML `db_path`；必须显式配置 `database_url`。旧 SQLite 文件不会被自动打开、转换或删除。`audit.key` 仍在本地受限文件中。

## 新部署

1. 创建专用数据库和最小权限角色。角色需要在专用 schema 内创建/升级表并读写数据；不要让其他应用共享同一 schema。
2. 在私有 YAML 中设置 PostgreSQL URL 和 `key_path`。URL 中密码需百分号编码；不要把真实 URL、密码或密钥提交仓库。
3. 远程数据库使用 `sslmode=verify-full` 及可信 CA。示例中的 `sslmode=disable` 仅适用于受控本机或 Compose 私有网络，不是互联网部署建议。
4. Compose 的 PostgreSQL 18 数据卷挂载在 `/var/lib/postgresql`。设置 `POSTGRES_PASSWORD`，并将相同密码写入私有代理配置的 URL。Compose 不会自动替换挂载 YAML 中的占位符。
5. 运行 `audit-proxy --config <私有配置> --validate-config`，再启动。空数据库初始化独立 PostgreSQL schema 版本；它不沿用 SQLite migration 版本号。

每个数据库/schema 仅允许一个代理写者。代理在固定数据库连接上持有 session advisory lock；第二个实例不可写入。连接丢失后不能换连接无锁继续写，必须重新启动。数据库端不要终止锁连接后继续保留旧服务；按正常服务停止、启动流程操作。只读查询的多语句证据快照使用 repeatable read。

## 数据库参数

PostgreSQL 的默认值是按很小的机器定的。本项目的负载有三个特点：大的加密 Body 先写入、请求结束和解析通过后再删掉；只有一个写者；WAL 持续不断地产生。一个实测部署库约 74 GB，按 5 分钟窗口推算每天约 20 GB WAL，而当时全部用默认值。

`compose.yaml` 给 PostgreSQL 显式传了下面几项。**这些只是起点，没有在本项目上测过效果**，不保证会更快或更省；改动后按本节末尾的方法观察，再按自己的机器调整。宿主机自建的 PostgreSQL 可以把同样的值写进 `postgresql.conf`。

| 参数 | 默认值 | Compose 起点 | 覆盖用的变量 |
| --- | --- | --- | --- |
| `shared_buffers` | 128MB | 1GB | `LLMAPI_PG_SHARED_BUFFERS` |
| `maintenance_work_mem` | 64MB | 256MB | `LLMAPI_PG_MAINTENANCE_WORK_MEM` |
| `max_wal_size` | 1GB | 4GB | `LLMAPI_PG_MAX_WAL_SIZE` |
| `checkpoint_timeout` | 5min | 15min | `LLMAPI_PG_CHECKPOINT_TIMEOUT` |
| `wal_compression` | off | lz4 | `LLMAPI_PG_WAL_COMPRESSION` |
| `autovacuum_vacuum_scale_factor` | 0.2 | 0.05 | `LLMAPI_PG_AUTOVACUUM_VACUUM_SCALE_FACTOR` |

变量在运行 `docker compose` 的 shell 环境或项目目录的 `.env` 里设置，不设时用表里的起点。容器另外设了 `shm_size: 256mb` 和 `stop_grace_period: 60s`，原因见下。这些值在 PostgreSQL 18.6 上都能被接受（`wal_compression=lz4` 需要编译时带 lz4，官方镜像带了）。

每一项的作用和缩放方法：

- **`shared_buffers`**：PostgreSQL 自己的页缓存。回填和候选查询反复扫 `audit_records`、`audit_analysis` 这类表，放得进缓存就不用每次向内核要页。起点 1GB 按约 8 GB 内存、同一台机器上还跑 NewAPI 和代理来定；独占数据库的机器一般取内存的 25%，和其他服务共用时取 10% 到 15%。超过几个 GB 后收益通常变小。
- **`maintenance_work_mem`**：`VACUUM`、`VACUUM FULL` 重建索引和建索引时可用的内存。下面的 `audit_analysis` 回收和大表的清理都靠它。autovacuum 默认也用这个值（`autovacuum_work_mem` 为 -1），最多 3 个 worker 同时运行，最坏约占 3 倍；PostgreSQL 17 起死元组记录是按需分配的，平时用不满。内存小于 4 GB 时降到 128MB。
- **`max_wal_size`** 与 **`checkpoint_timeout`**：一起决定检查点多久发生一次。检查点之后每个页面第一次被修改时，WAL 里要写一份整页镜像；检查点越密，整页镜像越多。按平均速率，每天 20 GB 约合每 5 分钟 70 MB，默认的 1 GB 平时并不会先到；但每个请求约写 2.5 MB WAL，一阵密集的请求就会让 WAL 量提前触发检查点（实际触发点约为 `max_wal_size / (1 + checkpoint_completion_target)`，默认约 540 MB）。4 GB 给这类突发留出余量，让检查点主要按 15 分钟的时间触发。代价是两样：`pg_wal` 目录平时可能涨到接近 `max_wal_size`（它是软上限，偶尔会超过），磁盘要留出这么多空间；崩溃后启动要重放上一个检查点以来的 WAL，最长约 15 分钟的量。磁盘紧张时先把 `max_wal_size` 降到 2GB，而不是缩短 `checkpoint_timeout`。
- **`wal_compression`**：只压缩 WAL 里的整页镜像，不压缩普通 WAL 记录。这里大部分 WAL 是加密的 Body 本身，加密后的页压不动，所以收益只来自索引页和普通表页的镜像，可能很小；lz4 的 CPU 开销低，所以默认打开。CPU 紧张时可以设回 `off`。
- **`autovacuum_vacuum_scale_factor`**：表里死元组超过行数的这个比例（加 50 行）才触发自动清理。`body_chunks` 留着大量异常请求的 raw，正常请求的块又不断被删掉，`audit_records` 每行平均被非 HOT 更新两三次；默认 0.2 意味着这类表要先攒下约五分之一的死空间才清理，之后才能复用。0.05 让清理更早、每次更小。它是全局设置，也作用于这些表的 TOAST 表；本项目不在表上单独设存储参数。
- **`shm_size`**（容器设置，不是 PostgreSQL 参数）：并行查询和手工 `VACUUM` 的并行索引清理在 `/dev/shm` 里分配共享内存，容器默认只给 64 MB，调大内存参数后可能不够用而报错。
- **`stop_grace_period`**（容器设置）：快速关闭时 PostgreSQL 要把全部脏页写进最后一个检查点。`shared_buffers` 变大、检查点间隔变长以后，这一步可能超过 Compose 默认的 10 秒而被强制杀掉；数据不会丢，但下次启动要重放 WAL。60 秒给它留出时间。

没有改的：

- `effective_cache_size`（默认 4GB）只是给查询规划器的估计，不分配内存。约 8 GB 内存的机器上默认值合适；内存明显更大或更小时，设为内存的一半左右。
- `checkpoint_completion_target` 的默认值已经是 0.9，即把检查点的写入摊到整个间隔里，不需要改。
- **不要**为了速度关闭 `fsync`、`full_page_writes` 或 `synchronous_commit`。这是审计库，这几项任何一个关掉，断电或崩溃后都可能丢掉已经确认提交的证据，或者让库损坏。代理自己的连接固定 `synchronous_commit=on`。`wal_level` 也保持默认的 `replica`，改成 `minimal` 会让基于 WAL 的备份不可用。

改完之后观察这些（需要超级用户或 `pg_monitor` 角色）：

- 检查点是按时间还是按 WAL 量触发的：`SELECT num_timed, num_requested FROM pg_stat_checkpointer;`。`num_requested` 占大头，说明 `max_wal_size` 仍然偏小。默认开启的 `log_checkpoints` 也会在日志里写出每次的原因（`time` 或 `wal`）和耗时。
- WAL 量与整页镜像：`SELECT wal_records, wal_fpi, wal_bytes FROM pg_stat_wal;`，隔一段时间取两次求差。
- `pg_wal` 的大小：`SELECT pg_size_pretty(sum(size)) FROM pg_ls_waldir();`，与磁盘剩余空间对照。
- 缓存命中：`SELECT blks_hit, blks_read FROM pg_stat_database WHERE datname = current_database();`，同样取差值看。
- 清理是否跟得上：`SELECT relname, n_live_tup, n_dead_tup, last_autovacuum FROM pg_stat_all_tables WHERE relname IN ('body_chunks', 'audit_records', 'http_headers') ORDER BY n_dead_tup DESC;`，以及各表总大小是否在没有新增保留数据时持续上涨。
- 容器内存（`docker stats` 或 `podman stats`）不应接近宿主机上限。

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
