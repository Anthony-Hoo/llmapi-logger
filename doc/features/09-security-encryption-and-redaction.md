# 模块 09：本地加密、脱敏与管理面保护

## 1. 目标

本模块面向个人单机部署，解决三个问题：审计敏感数据落盘加密、普通日志和列表脱敏、管理面始终使用静态 token 保护明文详情与 raw 证据接口。

首版按单用户单机模型设计，只保留一套管理面访问规则和一把活动主密钥。

## 2. 安全边界

- 管理面默认监听 `127.0.0.1:8081`。
- `admin_token` 在任何 `admin_listen` 上都必填，包括 loopback；为空或包含空白字符时启动失败。
- 受保护的 `/api/v1/*`、`/healthz` 和 `/readyz` 全部要求 Bearer token 或有效的管理 Cookie。
- 只有本审计代理不含数据的静态管理 UI shell 和其 CSS/JS/font 资源可以免 token 加载。

本节的 health、ready、API 和 UI 都属于审计代理的独立管理 listener，不是 NewAPI 自身路径。NewAPI health、login、admin、models、UI 和其他安全非 LLM 请求可经数据面的 passthrough 转发，但不进入 interceptor、audit 或 parser。
- SQLite、WAL、备份中的 Request-URI、Header、Body chunk 和 parsed JSON 必须是密文。
- 普通运行日志、错误响应和列表 API 不得包含凭据、Body 或 conversation 内容；受保护详情和 raw API 是用户显式读取明文证据的唯一入口。
- 同时取得进程权限、主密钥和数据库的本机管理员不在首版威胁模型内。

## 3. 配置

本模块不增加独立配置。直接使用模块 01 的 `admin_listen`、`admin_token` 和 `key_path`；配置校验必须拒绝空值和包含空白字符的 `admin_token`，不因监听地址是 loopback 而放宽。可选的 `newapi.access_token` 与 `newapi.user_id` 只用于读取 NewAPI 全站安全用户目录和按 request ID 查询全站日志，必须成对配置；access token 是配置 secret，只保留在进程内存和受限配置文件中，不进入管理 API、审计库或普通日志。

日志固定脱敏 Authorization、Proxy-Authorization、X-API-Key、x-goog-api-key，以及 Query 中的 key、api_key、access_token；首版不把这组规则做成可配置策略。admin_token 和主密钥不得通过普通日志或配置回显返回。

## 4. 管理面鉴权

除本审计代理的静态管理 UI shell 和登录端点外，管理 listener 上的 API、health 和 ready 请求都必须携带：

~~~text
Authorization: Bearer <configured-token>
~~~

服务使用常量时间比较 token。缺失或不匹配返回 `401`，不说明哪一部分错误。规则对 loopback 和非 loopback 完全相同。Bearer 方式保留给 curl/CLI。

Web UI 通过 `POST /api/v1/session` 提交一次 admin token。验证成功后，服务返回只含版本、绝对过期时间和 HMAC 的 Cookie；Cookie 不保存原始 admin token，固定七天过期，并设置 `HttpOnly`、`SameSite=Strict`、`Path=/`、`Max-Age` 和 `Expires`，HTTPS 请求额外设置 `Secure`。`DELETE /api/v1/session` 清除 Cookie。登录、注销、鉴权错误和其他管理响应均禁止缓存。

管理 JSON 与 raw Body 响应统一设置 `Cache-Control: no-store`。错误响应不能包含底层数据库/解密错误、Header、Query、Body、token 或密文。

本审计代理的静态管理 UI shell 只能提供 HTML/CSS/JS/font，不能内嵌审计数据、运行状态、配置 secret 或 token。React 页面只在登录请求的受控输入中短暂持有 admin token，不写入 localStorage、sessionStorage、IndexedDB、URL 或 Service Worker cache；后续请求只使用浏览器自动携带、JavaScript 无法读取的 HttpOnly Cookie。

首版只有一个静态 token，不区分接口权限，也不记录单独的敏感访问事件。

## 5. 主密钥

- 主密钥固定为 32 个随机字节，算法为 AES-256-GCM。
- 首次运行且数据库尚未包含审计数据时，可以原子创建 key 文件。
- POSIX 创建权限设为 `0600`；Windows 使用当前用户私有数据目录的 ACL。
- key 文件已存在时只读取，不覆盖、不自动修复内容。
- 数据库已有审计数据但 key 文件缺失时禁止生成新 key。
- key 长度错误或文件不可读时，审计能力标记为不可用：available 仍可转发但不落敏感证据，strict 返回 `503`。

进程只在内存中持有一份主密钥，不把它写入 SQLite、诊断包或普通日志。

## 6. 密文格式

每个敏感值独立调用 AES-GCM，并为每次加密生成新的 12-byte 随机 nonce。

数据库 BLOB 使用简单布局：

~~~text
nonce[12] || ciphertext_and_tag
~~~

首版只有一个活动主密钥，密文 BLOB 不携带额外密钥或版本元数据。

AAD 使用 NUL 分隔的受控字段，防止密文被移动到另一条记录：

- Request-URI：audit_id、request_uri。
- Header/Trailer：audit_id、header、stage、kind、name、value_index。
- Body chunk：audit_id、body_chunk、stage、seq。
- Parsed JSON：audit_id、parsed_json、parser_name。

解密端必须按同一顺序重建，调用方不得自行拼接其他变体。

独立加密单位：

- `audit_records.request_uri_enc`。
- `http_headers.value_enc` 的每个 Header/Trailer value。
- `body_chunks.data_enc` 的每个 chunk。
- `parsed_results.parsed_json_enc`，其中可包含 parser 紧凑 envelope 和协议无关 conversation。

不得复用 nonce，也不得把多个 chunk 合并后共享一次加密。

## 7. 存储接口

security 包提供最小接口：

~~~go
type Cipher interface {
    Encrypt(aad, plaintext []byte) ([]byte, error)
    Decrypt(aad, blob []byte) ([]byte, error)
}
~~~

调用方只把返回的完整 BLOB 写入上述四类 `*_enc` 字段。`audit_records` 和 `token_links` 只保存 NewAPI request ID、用户 ID/用户名、Token ID/名称和重试状态，不存在用户 API Key 字段。audit_gaps 只保存非敏感时间范围、原因和计数。

## 8. 管理证据与脱敏规则

- 列表 API 返回紧凑摘要，并为每条候选记录只读取、认证解密入站 User-Agent 供展示和筛选；它不读取其他 Header、Request-URI、Body chunk、parsed JSON 或 conversation 全文。
- 详情 API 在 Admin Token 鉴权后解密并返回原始 Request-URI、parser conversation，以及每个已保存 Header/Trailer 的 `stage`、`kind`、`name`、`value_index`、`value_length` 和 `value`。同名多值不会合并。
- conversation 只接受当前 schema version、连续 message/part index、受控 role/phase/direction/type；密文能解密但结构非法时也视为完整性错误，不能把任意 JSON 透传给前端。
- 原始 request/response Body 只在用户显式请求对应 raw API 时逐块认证解密；UI 不自动加载大 Body。
- React 页面可用详情字段重建应用层 HTTP 起始行和 Header/Trailer 视图，但不宣称恢复 TCP、TLS、HTTP/2 frame、原始 Header 大小写/顺序或 chunk framing。
- Query 中配置为敏感的键在日志中只保留键名。
- 调用者关联只落 `newapi_request_id`、`newapi_user_id`、`username`、`newapi_token_id`、`token_name` 和状态/时间；用户 API Key 与 NewAPI 管理 access token 均不得出现在响应、数据库或日志中。
- 错误日志只记录 `audit_id`、组件和错误类别，不记录明文或密文 BLOB。

## 9. 故障行为

- 启动阶段无法加载主密钥：不以明文降级；available 继续代理并报告审计不可用，strict 保持 not ready。
- 随机数源或加密失败：本条证据不写入；strict 模式拒绝新请求，available 模式继续转发并记录 `audit_gaps`。
- Request-URI、Header、Body 或 parsed JSON 解密认证失败，Header 明文长度不匹配，或 conversation schema 校验失败：返回通用 `500 evidence_unavailable`；错误文本不包装底层密码库错误，也不返回部分详情。
- admin token 配置为空：无论监听地址为何，配置校验都失败。
- 不允许忽略 GCM tag 错误，也不返回部分解密内容。

## 10. Key 备份

数据库与 key 文件必须一起备份。首版不提供轮换、重写或多 key 兼容工具；key 丢失后已有密文无法恢复。确需更换时，保留旧数据库与旧 key 的完整备份，再创建新的空数据库和 key。在线数据库必须使用 SQLite `.backup`，详见[部署备份说明](../deployment/backup-and-restore.md)。

## 11. 测试

- 首次启动生成 32-byte key，文件权限符合平台要求。
- loopback 和非 loopback 下，空 token 都导致启动失败；正确和错误 token 分别得到成功与 `401`。
- 未携带 token 时本审计代理的静态管理 UI shell 可加载，但 API、health 和 ready 均返回 `401`。
- 登录响应设置七天过期的 HttpOnly、SameSite=Strict Cookie；刷新后会话仍可使用，注销或到期后重新要求输入 token；Cookie 值不包含原始 admin token。
- 管理列表只允许出现预期的入站 User-Agent 明文，扫描不到测试 Request-URI、其他 Header、Body 或 conversation 明文；正确 Token 下详情能读取 conversation、逐项 Header/Trailer 值和 Request-URI，raw API 能还原请求/响应 Body。
- 详情、错误 JSON 和 raw 响应均带 `Cache-Control: no-store`；未授权请求不返回任何明文证据。
- 相同明文重复加密得到不同 BLOB，且都可解密。
- 篡改 nonce、ciphertext、tag 或 AAD 后解密失败。
- 扫描 DB、WAL、日志确认没有测试凭据和 Body 明文。
- NewAPI 用户目录只暴露安全用户字段，调用者解析只暴露 request ID 与用户/Token 元数据；配置 access token 和用户 API Key 不出现在管理 API、审计库、错误或日志中。
- 删除 key 后不得生成替代 key；available 只做代理，strict 返回 `503`。
- available 加密失败只产生 gap，不影响已开始的字节转发。
- 备份同时包含数据库、WAL 状态处理方式和 key 文件。

## 12. 实现边界

security 只提供 key 管理、AAD 和 AES-GCM；storage 为普通列表只定向返回入站 User-Agent 密文，为详情返回其余所需密文证据；query 是管理面唯一允许解密列表 User-Agent、Request-URI、Header/Trailer、conversation 和 raw Body 的层。web 只映射稳定错误，不记录或拼接敏感错误细节。
