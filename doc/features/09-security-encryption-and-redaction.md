# 模块 09：本地加密、完整性与脱敏

## 1. 目标

本模块解决四件事：敏感审计数据落盘加密、内容对象的认证与哈希校验、append-only 防篡改事件链，以及管理面/普通日志的明文边界。

项目仍按单用户单机模型设计：一把 32-byte 主密钥、一个 SQLite 数据库和一个静态管理 token。取得主机管理员权限、数据库和主密钥的攻击者不在首版防护范围内。

## 2. 管理面边界

- `admin_token` 在任何 `admin_listen` 上都必填，包括 loopback。
- `/api/v1/*`、`/healthz`、`/readyz` 要求 Bearer token 或有效管理 Cookie。
- 只有不含数据的 `/ui/` shell、CSS 和 JS 可以匿名加载。
- Cookie 固定七天过期，包含版本、绝对过期时间和 HMAC，不包含原始 admin token；设置 `HttpOnly`、`SameSite=Strict`、`Path=/`、`Max-Age/Expires`，HTTPS 请求额外设置 `Secure`。
- 管理 JSON、错误、raw、reconstructed 和 timeline 响应全部 `Cache-Control: no-store`。

前端不把 token 写入 localStorage、sessionStorage、IndexedDB、URL 或 Service Worker。缺失或错误凭证统一返回通用 `401`。

## 3. 主密钥

- 固定 32 个随机字节，AES-256-GCM。
- key 文件存在时只读，不覆盖。
- 数据库没有 audit 时允许原子创建；数据库已有 audit 且 key 缺失时禁止生成替代 key。
- POSIX 建议 `0600`；Windows 使用仅维护账户可读的 ACL。
- key 长度错误、不可读或 GCM 初始化失败时不允许明文降级；available 只做代理，strict 返回 `503`。

schema generation 2 的破坏性 migration 会清除旧 audit 数据；若升级时旧库已被清空且 key 缺失，程序可以为新空库创建新 key。运维上仍应显式保存或轮换，不依赖这种隐式结果。

## 4. 压缩后加密

顺序固定为：plaintext/canonical bytes -> 可选 gzip -> AES-GCM。

- 文本、JSON、SSE timeline 和可压缩 raw chunks 使用确定性 gzip；只有节省超过固定开销时才保留 gzip。
- PNG、JPEG、GIF、WebP、ZIP、GZIP、PDF 等按 magic 判定为已压缩，不重复 gzip。
- binary object 的压缩决策只由实际字节决定，不能由调用者可伪造的 MIME 标签改变。
- 每个加密单位使用独立随机 12-byte nonce。

数据库 BLOB 格式：

~~~text
nonce[12] || ciphertext_and_tag
~~~

## 5. AAD

AAD 使用 NUL 分隔的受控字段，禁止调用方随意拼接不同格式。主要域如下：

| 数据 | AAD 绑定 |
| --- | --- |
| Request-URI | audit id、`request_uri` |
| Header/Trailer value | audit id、`header`、stage、kind、name、value index |
| raw Body chunk v2 | audit id、`body_chunk_v2`、owning stage、seq、compression |
| parsed JSON | audit id、`parsed_json`、parser name |
| content object | `content_object`、object hash、kind、compression |
| binary object | `binary_object`、binary hash、compression |
| external ref | `external_ref`、content hash、JSON pointer、ref kind |
| stream timeline | audit id、`stream_timeline_v1`、stage、compression |

解密后还必须校验 plaintext/encoded length、object hash、semantic hash、binary hash、sequence hash 和 reconstruction hash。GCM 成功不代表结构自动可信。

## 6. 内容寻址与密文随机性

内容地址在压缩和加密前计算：

~~~text
content hash        = domain-separated SHA-256(canonical object)
binary hash         = domain-separated SHA-256(decoded raw bytes)
sequence hash       = domain-separated SHA-256(ordered slot/hash refs)
reconstruction hash = domain-separated SHA-256(canonical rebuilt provider value)
~~~

相同 plaintext 每次 AES-GCM 密文不同，但 SQLite 以 plaintext 内容 hash 作为对象主键，所以只保存首次插入的认证密文。冲突插入必须比较 kind、semantic hash、compression 和长度；不能仅因主键已存在就静默接受不一致对象。

data URL 先严格 Base64 解码，再按原始字节寻址。实际媒体类型和 data URL header 属于 occurrence reference，binary object 本身不以 MIME 作为身份。

## 7. 防篡改事件链

从主密钥通过 HMAC-SHA-256 域分离派生 integrity key。每个 event MAC 绑定：

- 上一个 event MAC；
- audit id；
- event type；
- 当前 capture/semantic payload 的 canonical digest；
- event 时间。

事件类型：

- `capture_finalized`：audit 终结或 process-exit recovery 后；
- `semantic_compacted`：verified turn、对象和 retention 状态原子保存后；
- `reconstruction_failed`：normalization/reconstruction 无法验证时。

启动时按 sequence 验证整条链；对仍存在的 audit 还会重新计算当前 payload digest。终结 audit 缺少 capture event、turn 缺少 semantic event、MAC/previous MAC/payload 不一致都会使审计存储 not-ready。

该链能发现事件或受保护 payload 被修改、重排或删除，但无法单独证明数据库尾部从某个历史备份整体截断；需要外部备份或锚点解决该威胁。

`audit_records.api_key_fpr` 刻意留在链外：它是访问控制索引而非证据，且把它并入 capture payload digest 会改变旧库中每条历史记录的重算摘要，令既有数据库无法通过启动校验。代价是作用域归属不具备防篡改性，被捕获的字节仍然具备。

## 7.1 凭据指纹

同样从主密钥用 HMAC-SHA-256 域分离（`llmapi-logger/credential-fingerprint-key/v1\x00`）派生独立子密钥，对规约后的入站凭据生成 32 字节标签，用于把开发者会话限定在自己 Key 的记录上（[模块 19](19-developer-key-session.md)）。

规约逐字复刻 NewAPI 的 token 解析：去 `Bearer ` 前缀、去 `sk-` 前缀、取首个 `-` 之前的片段。指纹是 keyed 标签，无主密钥不可验证也不可反查，且不出现在任何 API 响应、日志或错误文本中。系统仍不保存完整或打码的 API Key。

## 8. 明文边界

- 普通日志不记录 Query value、Header value、Body、conversation、Token、key、密文或底层错误文本。
- 列表只定向解密入站 User-Agent；不读取其他 Header、Request-URI、Body 或 content objects。
- 详情在鉴权后解密 Request-URI、Header/Trailer、窄 parsed result 和 verified turn 所需对象。
- OpenAI verified conversation 从对象重建；没有 normalizer 或异常记录可以使用 `parsed_json_enc` 内的加密回退 conversation。
- raw API 只对 `retention_state=full` 开放；metadata 返回 `410 raw_not_retained`。
- reconstructed API 返回 verified provider JSON；timeline API 返回认证后的逻辑 SSE 时间点。
- NewAPI 调用者只保存 request ID、用户 ID/用户名、Token ID/名称和状态，不保存完整或打码 API Key。
- 入站 Key 指纹只用于开发者会话的作用域判定，不进入任何 DTO、日志或错误；开发者登录提交的 Key 只作为一次上游校验请求的凭据，不落库也不回显。
- 开发者会话看不到被本地策略拦截的记录，`blocked_by`/`block_code` 属管理员可见信息。

详情能解密但 schema、枚举、连续 index、marker 或 hash 非法时，整条请求返回通用完整性错误，不返回部分明文。

## 9. 故障行为

- 随机数源、AES-GCM、压缩、对象写入或 integrity signer 失败：不写明文或半成品；writer 事务回滚。
- normalizer 或重建失败：parse 变为 partial，raw 保持 full，写稳定错误码和完整性事件。
- query 解密、长度、hash、sequence 或 reconstruction 校验失败：返回通用 `evidence_unavailable`，不包装底层密码库或 SQLite 错误。
- integrity chain 启动验证失败：不启动可写审计 runtime；available/strict 按原有审计依赖故障语义处理。
- 不允许忽略 GCM tag 或 hash 错误，也不返回“尽量解出的部分对象”。

## 10. 备份与 key

数据库与 key 必须作为同一备份集。在线数据库使用 SQLite backup API；不能只复制 `audit.db`、`-wal` 或 `-shm`。恢复后启动过程会同时验证数据库结构、GCM、对象 hash 和事件链。

项目不提供在线 key rotation 或多 key 解密。更换 key 时应保留旧数据库/旧 key 的联合备份，再创建新的空审计库和新 key。

## 11. 测试

- key 创建、权限、缺失、错误长度和错误 key 行为。
- 管理 Bearer/Cookie、七天过期、注销、匿名 shell 和 `no-store`。
- 相同明文随机密文、nonce/ciphertext/tag/AAD 篡改。
- content/binary/external/timeline AAD、长度、compression 和 hash 篡改。
- integrity event MAC、previous MAC、payload、缺 capture/semantic event 和尾部顺序测试。
- verified OpenAI parsed JSON 不重复保存 conversation；fallback conversation 只存在于密文。
- raw metadata/full/pending 状态与 410/409/正常下载语义。
- DB/WAL、日志、Git diff 和构建产物扫描不到测试凭据、Body、二进制或主密钥明文。
- 用户 API Key、NewAPI access token、admin token 不进入数据库、管理响应或普通日志。
