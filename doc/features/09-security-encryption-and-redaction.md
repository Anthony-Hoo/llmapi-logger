# 模块 09：本地加密、完整性与脱敏

## 1. 目标

本模块解决四件事：敏感审计数据落盘加密、内容对象的认证与哈希校验、append-only 防篡改事件链，以及管理面/普通日志的明文边界。

项目仍按单用户单机模型设计：一把 32-byte 主密钥、一个 SQLite 数据库和一个静态管理 token。管理 token 不再是唯一的管理面凭据：网页会话 Cookie 由它登录换取，可选的开发者登录（[模块 19](19-developer-key-session.md)）与 Agent 接入（[模块 25](25-agent-access.md)，默认关闭）另有自己的凭据，但三者的签名或摘要密钥都由 `admin_token` 按用途标签派生，轮换 `admin_token` 仍是让它们全部失效的总开关。取得主机管理员权限、数据库和主密钥的攻击者不在首版防护范围内。

## 2. 管理面边界

- `admin_token` 在任何 `admin_listen` 上都必填，包括 loopback。短于 24 字节时启动日志给出一条 `weak_admin_token` 告警，不拒绝启动。
- 错误的 Bearer 令牌按来源地址限流（5 分钟 10 次），与登录接口的限流分开计数。
- `/api/v1/*`、`/healthz`、`/readyz` 要求 Bearer token 或有效管理 Cookie。
- 只有不含数据的 `/ui/` shell、CSS 和 JS 可以匿名加载。
- Cookie 固定七天过期，包含版本、绝对过期时间和 HMAC，不包含原始 admin token；设置 `HttpOnly`、`SameSite=Strict`、`Path=/`、`Max-Age/Expires`，HTTPS 请求额外设置 `Secure`。
- 管理 JSON、错误、raw、reconstructed 和 timeline 响应全部 `Cache-Control: no-store`。

前端不把 token 写入 localStorage、sessionStorage、IndexedDB、URL 或 Service Worker。缺失或错误凭证统一返回通用 `401`。

**Agent 令牌**（模块 25，`agent_access.enabled` 默认关闭；关闭时下面的路径都不存在）：

- 第三种凭据，只能调用 `/api/agent/v1/*`；`/api/v1/*` 不接受它，门面也不接受管理 token 与 Cookie。格式为 `lla_` 加 32 字节随机数，库里只存 `HMAC-SHA-256(K, token)`，`K` 由 `admin_token` 加用途标签派生；明文只在兑换响应里出现一次，由命令行存进本机仅本人可读的凭据文件。
- 令牌由网页会话经授权确认页签发，身份与可见范围同签发它的会话（开发者令牌只能是只读档），不续期；可在“Agent 接入”页撤销。校验失败按来源地址单独限流。
- 两条匿名路径：`POST /api/agent/v1/token`（以一次性授权码加 PKCE 校验串兑换令牌，失败另行限流）与 `GET /api/agent/v1/dl/<签名>/<文件名>`（凭 30 分钟有效的签名链接下载 Skill 安装包，签名密钥同样由 `admin_token` 派生，每条链接最多下载 30 次，只能取清单与清单里列出的包）。两者都不返回任何审计数据。
- 门面输出里凭据类 Header 与查询参数的值一律不输出，只给名称和长度；分析模型的 API Key 只能由用户在终端里不回显地输入，不经过 Agent。细节见[接口合同](25-agent-access-contract.md)。

## 3. 主密钥

- 固定 32 个随机字节，AES-256-GCM。
- key 文件存在时只读，不覆盖。
- 数据库里既没有 audit 记录、也没有完整性事件时，才允许原子创建；两者有其一而 key 缺失时，禁止生成替代 key。完整性事件不会被 retention 删除：retention 删光 audit 后事件仍要用原来的 key 校验，换成新 key 会让链校验失败、审计存储不可用，所以这时同样不生成新 key，启动按 key 不可用处理。
- POSIX 建议 `0600`；Windows 使用仅维护账户可读的 ACL。
- key 长度错误、不可读或 GCM 初始化失败时不允许明文降级；available 只做代理，strict 返回 `503`。

schema generation 2 的破坏性 migration 会清除旧 audit 数据；若升级时旧库已被清空且 key 缺失，程序可以为新空库创建新 key。运维上仍应显式保存或轮换，不依赖这种隐式结果。

## 4. 压缩后加密

顺序固定为：plaintext/canonical bytes -> 可选 gzip -> AES-GCM。

- 文本、JSON、SSE timeline 和可压缩 raw chunks 使用 gzip，只有节省超过固定开销时才保留 gzip；gzip 输出字节随工具链版本可变，解码一律以存储行自身的 `compression` 与其绑定的 AAD 为准。
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
| Header 块（`capture_version=2`） | audit id、`header_block_v1`、compression |
| 入站 User-Agent（`capture_version=2`） | audit id、`user_agent_v1` |

解密后还必须校验 plaintext/encoded length、object hash、semantic hash、binary hash、sequence hash 和 reconstruction hash。GCM 成功不代表结构自动可信。

### 5.1 parsed JSON 的存储形式

`parsed_results.parsed_json_enc` 没有 compression 列，AAD 也不含 compression。解密后的字节自带格式：

- 以 gzip magic `1f 8b` 开头的是 gzip 流，解压后才是 JSON；
- 其他情况就是 JSON 本身。早期写入的行全部是这种形式，原样可读。

JSON 文本不可能以 `0x1f` 开头，两种形式不会混淆。写入端（`auditmodel.SealParsedResult`）只在明文不小于 4 KiB、压缩后确实变小（沿用 `bodycodec` 的判定），并且不超过 128 MiB 时才压缩，所以窄摘要行仍是明文 JSON。读取端统一走 `auditmodel.OpenParsedResult`，包括详情、会话分析读取和离线导入校验。

解压有上限：先读 gzip 尾部的 ISIZE，超过 128 MiB 直接拒绝，再按 ISIZE 精确限长读取，产出长度必须正好等于 ISIZE。128 MiB 是 parser 单个 Body 解码上限（64 MiB）的两倍，覆盖一份由完整请求和完整响应拼出的回退 conversation。更大的结果写入端不压缩，照旧存明文，因此这个上限不会让任何已写入的行变得不可读。截断、校验和错误、尾随数据、ISIZE 不符或超限，都按解密失败处理，返回同一个通用完整性错误。

完整性事件摘要取的是落库密文的 SHA-256。压缩行按自己的密文签名，摘要格式不变；旧行不回头重写。

### 5.2 Header 块与入站 User-Agent

`internal/headerblock` 实现第 3 阶段设计（`doc/design/issue-59-stage3-write-path.md` C.3 到 C.8）的存储格式。PostgreSQL 上的新记录按它写（`capture_version=2`，迁移 007）；SQLite 存储照旧逐值加密写 `http_headers` 行（`capture_version=1`），已删去的 legacy 写入路径留下的旧记录也是版本 1。两种记录并存，读取方一律按 `capture_version` 分派。

- **块明文：** `"LLHB" 0x01`，之后每个已写入的阶段一段：阶段码（1 到 4，按阶段顺序严格递增），header 段，trailer 段。每段是 `u32be(名称数)`，每个名称是 `u32be(长度) 名称 u32be(值数) (u32be(长度) 值)+`，整数都是大端。名称按字节序严格递增，值数至少为 1，明文不超过 64 MiB。解码逐条校验这些规则和长度，不允许尾随字节，所以一段明文只有一种解码。
- **存储：** 明文经 `bodycodec` 按 `application/x-llmapi-header-block` 判定是否 gzip，再 AES-GCM 加密，存 `compression`、`plaintext_length` 和密文三项。读取时依次认证解密、按 `plaintext_length` 解压核对长度、严格解码。
- **残缺块：** 块里只含到那时为止已写入的阶段；读取时块里的阶段集合必须等于该 audit 的阶段行集合，否则按完整性错误处理。`capture_status` 为 `failed` 或被启动恢复以 `interrupted` 终结的 audit 例外，见 §8 末尾。
- **User-Agent：** `0x01 (u32be(长度) 值)+`，取 `request_received` 中名称与 `user-agent` 不区分大小写相等的全部值，不压缩。没有这个 Header 时存 NULL，与“有一个空值”区分。
- **读取入口：** `headerblock.Expand` 按 `capture_version` 分派：1 用上表的逐值 AAD 解密各行，2 打开整块；两者输出同一个扁平列表（阶段顺序、header 先于 trailer、名称字节序、value index）。
- **测试向量：** `internal/headerblock/testdata/vectors.json` 固定块明文、拒绝样例、两个 AAD、User-Agent 编码，以及用合成密钥封好的块和 User-Agent，供另一份实现对照。
- **何时写：** `BeginAudit` 写 `user_agent_enc` 和只含入站阶段的块；之后每次插入阶段行的写（两个检查点、`CommitAudit`）都覆盖写一次整块，含到那时为止已写入的全部阶段，所以块里的阶段集合始终等于阶段行集合。trailer 到达后，下一次写也会带上新块；`CommitAudit` 时块与最后一次检查点写的相同（没有响应 trailer）就不再写。崩溃或终结失败的记录留下最后一次成功写入的块，恢复时对它签名（D.4）。

### 5.3 加密列与明文列（`capture_version=2` 之后）

与采集有关的密文列：

| 列 | 内容 | 版本 |
| --- | --- | --- |
| `audit_records.request_uri_enc` | Request-URI | 1、2 |
| `audit_records.user_agent_enc`（新） | 入站 User-Agent 的全部值 | 2；版本 1 恒为 NULL |
| `http_headers.value_enc` | 一个 Header 或 Trailer 值 | 1；版本 2 没有这张表的行 |
| `http_header_blocks.block_enc`（新） | 全部阶段的 Header 和 Trailer，压缩后整块加密 | 2 |
| `body_chunks.data_enc`、`stream_timelines.timeline_enc`、`parsed_results.parsed_json_enc` | Body 块、SSE 时间线、解析结果 | 不变 |

迁移 007 新增的明文列，不用密钥就能读到：

- `audit_records.capture_version`：1 或 2。
- `http_stages.content_type`、`content_encoding`：版本 2 每个阶段 parser 选用的 Content-Type 和 Content-Encoding（该阶段 header 里名称小写后匹配的第一个非空值）。这两个值原来只在密文里，现在随阶段行明文存放，parser 和回填扫描判断内容类型时不必解密块（设计 C.6、K 第 6 项）。其余 Header 的值仍只在块里。
- `http_header_blocks.compression`、`plaintext_length`：块的压缩方式和明文长度，即一条 audit 全部 Header 的总字节数。

版本 2 的 `capture_finalized` 摘要按设计 D.2 计算：在版本 1 的字段之外覆盖 `user_agent_enc`、两个内容列和块的三列（密文取数据库算的 SHA-256），不覆盖 `http_headers`。域字符串是 `llmapi-logger/capture-payload/v2\x00`，`capture_version` 不单独作为字段，由域字符串绑定；校验按 `capture_version` 选版本，改成别的值都会让载荷校验失败。固定测试向量和它描述的夹具在 `internal/storage/postgres/integrity_capture_v2_test.go`。

### 5.4 本地暂存文件

采集会话把超出内存预算的 Body 块写到 `audit.staging.dir`（模块 03 §13.4）。文件里只有密文和块的元数据，不加任何新的密钥或密码学结构：

- 每个块就是 `body_chunks.data_enc` 那份密文，AAD 同上表的 raw Body chunk v2，所以可以原样插入库里；
- 明文的元数据是文件头里的 audit id，以及每块的阶段码、seq、offset、明文长度、编码长度、观察时间和压缩方式，与库里同一行的非密文列相同；
- 每条记录的 CRC-32C 只用来发现写了一半的尾部记录，真实性靠 AEAD：启动导入逐块按它自己的 AAD 认证解密后才插入（模块 03 §13.6）。

放在哪里由配置和启动检查约束（模块 01 §4 第 18 项）：必须是绝对路径，不能是主密钥所在的目录、包含它或位于其中，这样同一个卷、同一份备份里不会同时有密文和打开它的密钥；目录以 0700、文件以 0600 创建，Unix 上要求目录属主是进程用户、组和其他用户没有权限，Windows 交给目录 ACL。目录里的文件是证据的一部分，备份和权限按审计数据对待；部署见[部署说明](../deployment/README.md) 3.2。

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
- 列表只定向解密入站 User-Agent；不读取其他 Header、Request-URI、Body 或 content objects。版本 2 的行直接解密列表查询已经带回的 `user_agent_enc`，版本 1 的行照旧每行查一次 `http_headers`。
- 详情在鉴权后解密 Request-URI、Header/Trailer、窄 parsed result 和 verified turn 所需对象。两个版本都经 `headerblock.Expand` 得到同一个扁平列表，Web、Agent 门面的凭据掩码和导出看到的完全相同。
- parser 读白名单内的入站 Header（洞察和项目标识用）时，版本 1 在 SQL 里按名称过滤、只解密名单内的值；版本 2 的 Header 是一段密文，parser 在进程内解密整块，按白名单过滤后立即清掉其余的值。这是维护者接受的明文边界变化（第 3 阶段设计决定 2）：这是内网的内部工具，parser 进程本来就持有主密钥。parser 判断内容类型不打开块，读阶段行上的两个明文列。
- 采集会话在内存里持有明文，比已删去的 legacy 写入路径久：Body 明文在单阶段和全局预算之内，从观察到它直到写库，以及交给 parser 的那一份（模块 03 §13.4、§13.8）；版本 2 的 Header 字段从阶段开始深拷贝，直到 `CommitAudit` 得到应答后清零。版本 2 的交接作业还带着两个接收阶段的 Header 字段明文（凭据类 Header 也在其中），在 parser 内存里直到作业的 `Release`；版本 1 的作业带的是密文行。这些明文都只在进程内存里，不写日志、不落盘；超出预算的部分落暂存时已经加密（§5.4）。与压缩器的私有缓冲一样，释放后的内存不声称安全擦除。
- OpenAI 与 Anthropic verified conversation 从对象重建；没有 normalizer 或异常记录可以使用 `parsed_json_enc` 内的加密回退 conversation。
- raw API 只对 `retention_state=full` 开放；metadata 返回 `410 raw_not_retained`。
- reconstructed API 返回 verified provider JSON；timeline API 返回认证后的逻辑 SSE 时间点。
- NewAPI 调用者只保存 request ID、用户 ID/用户名、Token ID/名称和状态，不保存完整或打码 API Key。
- 入站 Key 指纹只用于开发者会话的作用域判定，不进入任何 DTO、日志或错误；开发者登录提交的 Key 只作为一次上游校验请求的凭据，不落库也不回显。
- 开发者会话看不到被本地策略拦截的记录，`blocked_by`/`block_code` 属管理员可见信息。

详情能解密但 schema、枚举、连续 index、marker 或 hash 非法时，整条请求返回通用完整性错误，不返回部分明文。版本 2 的块不能认证、解不开、不满足严格解码规则，或者（capture 没有失败、也不是被恢复终结的 interrupted 时）块里的阶段集合与阶段行集合不等，同样按完整性错误处理。

块里的阶段集合与阶段行集合必须相等。这一条是完整性检查，例外只有两种 audit：已存 `capture_status` 为 `failed` 的，以及被启动恢复以 `forward_status = 'interrupted'` 终结的。写失败时会话并不知道，块与阶段行就可能对不上：

- **检查点被可隔离的错误拒绝（约束、触发器）。** 整个检查点回滚，audit 当场被标为 `failed`；它插入的阶段行不存在，之后的块仍含那个阶段的段，存储没有密钥，无法打开块去掉它。
- **`BeginAudit` 的入站块被拒绝，入站阶段行保留。** audit 当场被标为 `failed`。之后插入阶段行或带上 trailer 的写会重新写整块；没有这样的写时（拦截器拒绝，或在检查点 1 之前崩溃），这条 audit 有入站阶段行而没有块。
- **检查点所在的批次存储级失败。** 失败标记先只记在 writer 的内存恢复表里，最多一个恢复周期（5 秒）或在该 audit 的 `CommitAudit` 之前才写进库，把 audit 标为 `failed`。之后的检查点可能已经写了含缺行阶段的块。进程在标记写入前退出时，恢复表随之丢失，启动恢复把 audit 终结为 `interrupted`、`partial`、`process_exit`（`TestCaptureV2LostCheckpointMarkReadsAfterRestart`）。

`forward_status = 'interrupted'` 只由启动恢复（`RecoverInterruptedAudits`）写入，会话的终结从不使用它；`capture_status` 为 `partial` 时 `error_code` 恒为 `process_exit`，而失败的 audit 保留自己的错误码，所以取 `forward_status` 作为标记，两种情形都能覆盖。

这两种 audit 照常可读，与 legacy 写入路径上同样的写失败时一致（`headerblock.Expand` 是唯一的判定处，详情、Agent 门面、导出和 parser 的白名单读取都经过它）：

- 有阶段行、块里没有它的段，或者根本没有块：这个阶段的 Header 不显示，等同 legacy 上 Header 写失败时没有行。
- 块里有段、却没有阶段行：照常显示。legacy 在这种情形下没有 Header 行，只是因为它的 Header 写依赖阶段行；块用这条 audit 的 AAD 认证过，又被签名的摘要覆盖，是已存且真实的证据，隐藏它没有理由。

认证、解压、严格解码和阶段集合本身的合法性（已知阶段、不重复）都不放宽。其余 audit 上阶段集合不等照旧是完整性错误。`capture_status` 和 `forward_status` 都是版本 1 和版本 2 capture 摘要的字段，把一条已终结的健康 audit 改成 `failed` 或 `interrupted`（单独改，或者为了掩盖删掉的块）都会让载荷校验失败，读取方的放宽借此不能被用来掩盖篡改；测试 `TestCaptureV2TamperIsDetected` 覆盖了这几种改法。还在进行中的 audit 没有签名，它的任何列本来就不受链保护。

规则之外仍有一个短暂的窗口：批次存储级失败之后、恢复表写入标记之前（最多一个恢复周期），进程没有退出时，进行中的 audit 既不是 `failed` 也不是 `interrupted`，读 Header 报完整性错误；标记写入后它按失败的 capture 读取（`TestCaptureV2LostCheckpointIsUnreadableUntilMarked`）。

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
- Header 块和 User-Agent 的测试向量；版本 2 摘要的固定向量；改动 `capture_version`、`user_agent_enc`、块、内容列、`capture_status`、`forward_status` 都让载荷校验失败；failed 与 interrupted 的 audit 按 §8 的规则可读，其余 audit 阶段集合不等时报完整性错误。
- 暂存文件尾部截断、中间 CRC 或 AEAD 失败、文件头指向别的 audit 时按模块 03 §13.6 处理，不导入未通过认证的块。
- verified OpenAI parsed JSON 不重复保存 conversation；fallback conversation 只存在于密文。
- raw metadata/full/pending 状态与 410/409/正常下载语义。
- DB/WAL、日志、Git diff 和构建产物扫描不到测试凭据、Body、二进制或主密钥明文。
- 用户 API Key、NewAPI access token、admin token 不进入数据库、管理响应或普通日志。
