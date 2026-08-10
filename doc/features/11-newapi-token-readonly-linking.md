# 模块 11：NewAPI Token 只读关联

## 1. 目标

本模块是可选增强：从 NewAPI 的 SQLite 数据库只读加载 tokens(id, key, name)，在内存中建立 token key 到名称的映射，为已通过 interceptor 并准备发往 NewAPI 的 LLM API 审计记录附加 newapi_token_id 和 token_name。

关联结果只用于查询展示，不参与鉴权、配额、路由或流量放行。NewAPI 的实际响应始终是鉴权结果的唯一依据。

首版数据源固定为 NewAPI SQLite，并使用精确 token key 的内存 map 完成关联。

## 2. 配置

只使用[模块 01](01-configuration-and-route-boundary.md)的顶层 newapi_token_db_path。路径为空时关闭功能；非空时启动加载 goroutine。reload 固定为 5 分钟，SQLite busy timeout 固定为 2 秒，不增加调优项。

## 3. 数据源约束

加载器使用只读 SQLite 连接，并执行：

~~~sql
PRAGMA query_only = ON;
SELECT id, key, name FROM tokens
WHERE key IS NOT NULL AND key <> '';
~~~

连接必须使用 `mode=ro`，不得执行 migration、写 PRAGMA、锁表或修改 NewAPI 文件。不要使用 `immutable=1`，因为运行中的 NewAPI 会更新 token。

启动和每次 reload 前，通过 `PRAGMA table_info(tokens)` 检查 `id`、`key`、`name` 三列存在。表或列不匹配即视为 schema 不兼容。

## 4. 内存索引

成功加载后构建不可变 map：

~~~go
type TokenInfo struct {
    ID   int64
    Name string
}

type Snapshot map[string]TokenInfo // key 是 NewAPI token 明文，仅存在内存
~~~

新 map 完整构建后再通过 `atomic.Value` 一次替换，转发 goroutine 不等待数据库 I/O，也不持有 reload 锁。

原始 token key 不写入本项目 SQLite、日志或错误消息。旧 snapshot 被替换后不再引用，交给 Go 运行时回收。

若数据源中同一个 key 对应多个不同 id，该 key 视为歧义并从 map 中移除，同时记录不含 key 的 warning 计数。

## 5. 请求凭据选择

只从 interceptor 已放行、即将创建 request_sent_to_newapi 阶段的请求快照中选择一个凭据：

1. `Authorization: Bearer <token>`。
2. `x-api-key: <token>`。
3. `x-goog-api-key: <token>`。
4. Gemini 请求的 Query 参数 `key=<token>`。

仅去除协议语法要求的前缀和首尾空白，不改变大小写、不 hash、不做历史兼容归一化。

若同一请求出现多个受支持入口，按以上顺序选择，并记录不含凭据内容的 warning。首版不尝试同时关联多个 token。

forward_status=rejected 的 audit、没有 request_sent_to_newapi 阶段的请求，以及由 Nginx 直连的 NewAPI health/login/admin/models/UI/其他路径均不执行关联。

## 6. 热路径接口

~~~go
type TokenLinker interface {
    LookupFromRequest(req *http.Request) (TokenInfo, bool)
}
~~~

`LookupFromRequest` 只能读取当前内存 snapshot，目标是 O(1) map lookup；不得访问 NewAPI DB、等待 reload 或调用外部服务。

找到匹配后，审计流水线异步写入 `token_links`：

- `audit_id`。
- `newapi_token_id`。
- `token_name`。
- `linked_at_ns`。

找不到匹配、功能关闭或 snapshot 为空时不插入行，也不把请求标记为失败。

## 7. Reload 生命周期

- 启动后立即尝试加载一次，此后每 5 分钟加载。
- 每次使用独立短连接，查询完成后立即关闭。
- 加载成功才替换 snapshot。
- schema 不兼容时清空 snapshot、关闭关联能力并输出 warning。
- 文件不存在、busy、权限错误或查询失败时清空 snapshot 并 warning；下一周期自动重试。
- 后续 reload 恢复成功后自动重新启用，不需要重启代理。

warning 只在状态变化时输出，避免每个请求或每个周期刷屏。健康信息只需展示 enabled、当前条目数和最近一次 reload 是否成功。

## 8. 与主库的边界

本模块只向本项目的 `token_links(audit_id,newapi_token_id,token_name,linked_at_ns)` 写关联快照，不修改 audit_records，也不创建凭据索引表。

当 NewAPI token 改名或删除后，既有审计记录保留当时的 newapi_token_id 和 token_name，不做历史回填。新的 snapshot 只影响后续请求。

删除审计记录时，由同一事务删除对应 `token_links` 行。

## 9. 故障行为

- token 关联任何失败都不得阻断代理转发。
- NewAPI schema 不匹配时功能关闭并 warning，不猜测列名或备用表。
- NewAPI DB 长时间 busy 时每周期最多等待 2 秒，随后放弃本次加载。
- 内存查找 panic 或异常必须被上层隔离，审计继续但不写 token link。
- 日志不得输出 SQL 行内容、token key 或带敏感 Query 的完整 DSN。

## 10. 可观测性

健康信息只展示 enabled、当前条目数和最近一次 reload 是否成功；状态变化写一条 warning。首版不单独建设一组 Token 关联指标。

## 11. 测试

- 使用含 `id,key,name` 的 SQLite fixture 成功加载并命中内存 map。
- 请求热路径测试中禁止出现 NewAPI DB 打开或 SQL 查询。
- 缺表、缺列、路径错误和只读权限错误会清空 snapshot、warning 且不影响转发。
- reload 构建期间并发 lookup 始终看到完整旧 map 或完整新 map。
- 重复 key 不关联，且日志不包含该 key。
- 四种凭据入口及优先级符合约定。
- rejected audit、缺少 request_sent_to_newapi 的 audit 和 Nginx 直连路径均不查询内存 map、不写 token_links。
- 搜索本项目 DB 和日志，确认没有 NewAPI token key。
- token 改名后新请求使用新名称，历史 `token_links` 不变。

## 12. 实施步骤

1. 实现配置、只读连接和最小 schema 检查。
2. 实现 `SELECT id,key,name`、歧义处理和不可变 snapshot。
3. 实现 5 分钟 reload goroutine 与原子替换。
4. 实现四种凭据选择和纯内存 lookup。
5. 接入 `token_links` 异步写入与审计删除事务。
6. 增加状态变化 warning 和健康摘要。
7. 完成并发、schema mismatch、busy 和敏感数据泄漏测试。
