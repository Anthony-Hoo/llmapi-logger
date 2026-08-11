# 模块 09：本地加密、脱敏与管理面保护

## 1. 目标

本模块面向个人单机部署，解决三个问题：审计敏感数据落盘加密、普通日志和列表脱敏、管理面始终使用静态 token 保护明文详情与 raw 证据接口。

首版按单用户单机模型设计，只保留一套管理面访问规则和一把活动主密钥。

## 2. 安全边界

- 管理面默认监听 `127.0.0.1:8081`。
- `admin_token` 在任何 `admin_listen` 上都必填，包括 loopback；为空或包含空白字符时启动失败。
- `/api/v1/*`、`/healthz` 和 `/readyz` 全部要求静态 Bearer token。
- 只有本审计代理不含数据的静态管理 UI shell 和其 CSS/JS/font 资源可以免 token 加载。

本节的 health、ready、API 和 UI 都属于审计代理的独立管理 listener，不是 NewAPI 自身路径。NewAPI health、login、admin、models、UI 和其他安全非 LLM 请求可经数据面的 passthrough 转发，但不进入 interceptor、audit 或 parser。
- SQLite、WAL、备份中的 Request-URI、Header、Body chunk 和 parsed JSON 必须是密文。
- 普通运行日志、错误响应和列表 API 不得包含凭据或 Body 内容；受保护详情和 raw API 是用户显式读取明文证据的唯一入口。
- 同时取得进程权限、主密钥和数据库的本机管理员不在首版威胁模型内。

## 3. 配置

本模块不增加独立配置。直接使用模块 01 的 `admin_listen`、`admin_token` 和 `key_path`；配置校验必须拒绝空值和包含空白字符的 `admin_token`，不因监听地址是 loopback 而放宽。

日志固定脱敏 Authorization、Proxy-Authorization、X-API-Key、x-goog-api-key，以及 Query 中的 key、api_key、access_token；首版不把这组规则做成可配置策略。admin_token 和主密钥不得通过普通日志或配置回显返回。

## 4. 管理面鉴权

除本审计代理的静态管理 UI shell 资源外，管理 listener 上的 API、health 和 ready 请求都必须携带：

~~~text
Authorization: Bearer <configured-token>
~~~

服务使用常量时间比较 token。缺失或不匹配返回 `401`，不说明哪一部分错误。规则对 loopback 和非 loopback 完全相同。

管理 JSON 与 raw Body 响应统一设置 `Cache-Control: no-store`。错误响应不能包含底层数据库/解密错误、Header、Query、Body、token 或密文。

本审计代理的静态管理 UI shell 只能提供 HTML/CSS/JS/font，不能内嵌审计数据、运行状态、配置 secret 或 token。React 页面由用户输入 token，token 只保存在当前页面的 JavaScript 内存中；不得写入 localStorage、sessionStorage、Cookie、IndexedDB、URL 或 Service Worker cache。

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
- `parsed_results.parsed_json_enc`。

不得复用 nonce，也不得把多个 chunk 合并后共享一次加密。

## 7. 存储接口

security 包提供最小接口：

~~~go
type Cipher interface {
    Encrypt(aad, plaintext []byte) ([]byte, error)
    Decrypt(aad, blob []byte) ([]byte, error)
}
~~~

调用方只把返回的完整 BLOB 写入上述四类 `*_enc` 字段。token_links 只保存 NewAPI token id/name，不保存 token key；audit_gaps 只保存非敏感时间范围、原因和计数。

## 8. 管理证据与脱敏规则

- 列表 API 只返回非敏感摘要，不读取 Request-URI、Header 密文、Body chunk 或 parsed JSON 全文。
- 详情 API 在 Admin Token 鉴权后解密并返回原始 Request-URI，以及每个已保存 Header/Trailer 的 `stage`、`kind`、`name`、`value_index`、`value_length` 和 `value`。同名多值不会合并。
- 原始 request/response Body 只在用户显式请求对应 raw API 时逐块认证解密；UI 不自动加载大 Body。
- React 页面可用详情字段重建应用层 HTTP 起始行和 Header/Trailer 视图，但不宣称恢复 TCP、TLS、HTTP/2 frame、原始 Header 大小写/顺序或 chunk framing。
- Query 中配置为敏感的键在日志中只保留键名。
- Token 关联只落 `newapi_token_id`、`token_name`，不落 NewAPI token key。
- 错误日志只记录 `audit_id`、组件和错误类别，不记录明文或密文 BLOB。

## 9. 故障行为

- 启动阶段无法加载主密钥：不以明文降级；available 继续代理并报告审计不可用，strict 保持 not ready。
- 随机数源或加密失败：本条证据不写入；strict 模式拒绝新请求，available 模式继续转发并记录 `audit_gaps`。
- Request-URI、Header 或 Body 解密认证失败，以及 Header 明文长度不匹配：返回通用 `500 evidence_unavailable`；错误文本不包装底层密码库错误，也不返回部分详情。
- Bearer token 配置为空：无论监听地址为何，配置校验都失败。
- 不允许忽略 GCM tag 错误，也不返回部分解密内容。

## 10. Key 备份

数据库与 key 文件必须一起备份。首版不提供轮换、重写或多 key 兼容工具；key 丢失后已有密文无法恢复。确需更换时，保留旧数据库与旧 key 的完整备份，再创建新的空数据库和 key。在线数据库必须使用 SQLite `.backup`，详见[部署备份说明](../deployment/backup-and-restore.md)。

## 11. 测试

- 首次启动生成 32-byte key，文件权限符合平台要求。
- loopback 和非 loopback 下，空 token 都导致启动失败；正确和错误 token 分别得到成功与 `401`。
- 未携带 token 时本审计代理的静态管理 UI shell 可加载，但 API、health 和 ready 均返回 `401`。
- 页面刷新后 token 消失，浏览器持久化存储、Cookie、URL 和静态资源中均无 token。
- 管理列表扫描不到测试 Request-URI、Header 或 Body 明文；正确 Token 下详情能读取逐项 Header/Trailer 值和 Request-URI，raw API 能还原请求/响应 Body。
- 详情、错误 JSON 和 raw 响应均带 `Cache-Control: no-store`；未授权请求不返回任何明文证据。
- 相同明文重复加密得到不同 BLOB，且都可解密。
- 篡改 nonce、ciphertext、tag 或 AAD 后解密失败。
- 扫描 DB、WAL、日志确认没有测试凭据和 Body 明文。
- 删除 key 后不得生成替代 key；available 只做代理，strict 返回 `503`。
- available 加密失败只产生 gap，不影响已开始的字节转发。
- 备份同时包含数据库、WAL 状态处理方式和 key 文件。

## 12. 实现边界

security 只提供 key 管理、AAD 和 AES-GCM；storage 只返回密文证据；query 是管理面唯一允许解密 Request-URI、Header/Trailer 和 raw Body 的层。web 只映射稳定错误，不记录或拼接敏感错误细节。
