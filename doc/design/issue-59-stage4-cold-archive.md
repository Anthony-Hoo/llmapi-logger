# Issue #59 第 4 阶段详细设计：只导出（P3）与校验后移除（P4）

状态：设计稿，等第 0 节的决定。基线提交 `8df5ea3`（第 1 到 3 阶段已落地，schema 版本 7）。

本阶段对应方案 `doc/design/issue-59-unified-write-cold-archive.md` 第 6 节的 P3、P4 两行：4.3 的批量读取、4.4 的归档格式、4.5 的归档与移除、4.6 的三层证明、4.7 的读取工具，以及决策 5.2 到 5.5、5.7 的补充要求与护栏。方案第 5 节优先于本文；本文与方案其他各节不同的地方在 0.2 列出。

记号：

- 〔核〕：作者在 `8df5ea3` 上读代码直接核对过，给出文件与函数。
- 〔推〕：推断，没有测试或实测证实。
- 〔设〕：本文的设计。

文中路径都相对仓库根目录。

---

## 0. 需要维护者决定的问题

下面十四项都涉及证据语义、摘要与签名格式、归档里省略什么，或者库表结构，方案和决策 5.2 到 5.7 都没有定下来。每项给出选项、代价和推荐。正文按推荐写成；推荐被否决时，只需改对应的正文小节。纯机械的选择不在这里，见 P 节。

### 0.0 答复（2026-11-28）

维护者在实施会话里答复：“只保留 unified，归档版本确定为 1，现在开始做第四阶段。”据此：

- **Q14 取乙**：本地验收（4.6 的三层检查与 N 节的全部用例）通过后，格式定为版本 1，对象放在包内。`archive_then_delete` 随之真正移除。以后若真实分布显示 5.4 的膨胀比超过界限，改用共享对象库要出版本 2。
- **Q1 到 Q13** 没有逐项答复。按“开始做”实施正文里的推荐；这不是逐项确认，维护者对任何一项有异议时改对应的小节。
- **只保留 unified 写入路径**不是本文的问题，但影响本文两处：M.1 第 18 行（legacy 的逐操作写）随 legacy 路径一起删去；新写入的记录在 PostgreSQL 上都是采集版本 2，版本 1 只剩旧数据，归档仍要能表达两种（Q5）。

### 0.1 问题清单

**Q1 变更戳怎么构成（决定 P4 能不能安全地删）**

方案 4.5 列的变更戳是：`audit_records` 的解析状态与调用者状态及更新时间、`parsed_results.parsed_at_ns`、`token_links` 的条数与最大 `linked_at_ns`、各阶段 `retention_state`、turn 的父引用。按 M.1 逐条核对，它漏了两条已有的写：

- `updateTokenLinkBilling`（`postgres/token_writer.go`）在 `linked_at_ns` 不变的情况下改写 `billing_state`、`billing_attempts`、`quota`、`quota_per_unit` 和两个计费 token 数〔核〕；
- `saveProjectIdentity`（`postgres/org_writes.go`，由 `insights/project.go` 的回填调用）对 `audit_project_identity` 做 upsert，`identity_version` 升级时会重写已有行〔核〕。

此外，legacy 的异步写（`insertStage`、`insertHeaders`、`insertBody`、`insertChunk`、`finishStage`）在 SQL 里没有“audit 已终结就不写”的守卫，只是会话按构造在 `FinishAudit` 之前发出它们〔核：`postgres/writer.go`；顺序保证是〔推〕〕。

- 甲：方案的字段清单，补上计费列、项目标识行和完整性事件条数。代价：清单靠人工枚举，以后新增一条写语句而忘了补，就会在源记录已变的情况下删掉热库数据。
- 乙：每张按 audit 归档的表，取该 audit 每一行的主键和系统列 `xmin`，加上各表的行数，按固定顺序编码后求 SHA-256。PostgreSQL 的任何 UPDATE 都会生成新的行版本，`xmin` 随之改变；DELETE 和 INSERT 改变行集合。代价：`xmin` 是 32 位事务号，理论上存在 2^32 个事务后恰好重合的情形；`pg_dump` 加恢复会让全部成员变成 `stale`（只多占空间，方向安全）；冻结和 `VACUUM FULL` 是否保留 `xmin` 依据的是 PostgreSQL 文档，本库没有实测〔推〕。
- 丙：甲加乙。代价：两套都要维护，但甲只是可读的补充。

推荐乙。它不依赖枚举，覆盖今后新增的任何写；M.1 的枚举仍然保留，作为测试清单（N.3）。

**Q2 凭据指纹 `value_fpr` 的输入；`api_key_fpr` 是否归档**

决策 5.5 要求同一个凭据在入站和出站阶段得到相同的指纹，并且能拿已知的 Key 核对归属，但没有定输入是什么。

- 甲：原值的全部字节，不含名称。入站与出站同一个 Header 的指纹逐字节可比。代价：同一个 Key 在 `Authorization: Bearer sk-…`、`x-api-key: sk-…`、`?key=sk-…` 下指纹不同；核对时读取工具要对已知 Key 算几种候选（D.4）。
- 乙：先按 `security.NormalizeNewAPIKey` 归一化再算。不同传输方式的同一个 Key 指纹相同。代价：证明不了两个阶段的原值逐字节相同；`Cookie`、`Basic`、`Set-Cookie` 这类不是 NewAPI Key 的凭据，归一化没有意义，要另定规则。
- 丙：两者都存。代价：每个凭据项多一个字段，归一化规则仍要为非 Key 类凭据另定。

`audit_records.api_key_fpr` 已经是按 `NormalizeNewAPIKey` 归一化、用另一个主密钥子密钥算的 keyed 指纹（`security/fingerprint.go`、`audit/manager.go` 的 `Begin`）〔核〕。它不是凭据值。

推荐甲，同时把 `api_key_fpr` 原样归档。甲证明阶段间一致，`api_key_fpr` 提供跨传输方式的归一化核对，两者合起来覆盖了乙的用途，而不需要为非 Key 类凭据发明归一化。

**Q3 Request-URI 的投影形式，以及解不开的查询参数**

决策 5.5 说判定“复用 Request-URI 查询参数的掩码规则”。这套规则是 `internal/web/agent_requests.go` 的 `agentRequestURIOf`，它不在 `agentapi` 里，而且是有损的〔核〕：

- 名称和值都经 `url.QueryUnescape` 解码后输出，原始的百分号编码没有了；
- `#` 之后的部分和空的 `&&` 段被丢掉；
- 解码失败的参数一律不输出值，原因写 `unparsed`，这是凭据以外的第二种省略。方案不变量 7 只允许凭据省略。

两种做法：

- 甲：按原始字节保留 Request-URI 的结构，见 D.3。路径原样；查询串按 `&` 切成原始分段，空段也保留；每段按 `=` 切开，判定时用解码后的名称和值（解码失败就用原始字节），是凭据的段只把值换成投影项，其余分段原样。凭据以外的部分能逐字节还原。代价：解码失败、名称和值又都不像凭据的参数会原样进入归档。
- 乙：与 Agent 门面一致，解码失败的值一律省略，省略原因 `unparsed`。代价：多一种省略，和不变量 7 冲突，归档比热库少了非凭据内容。

推荐甲。NewAPI 自己也是用 Go 的查询解析读 `key` 参数，解码失败的参数它同样读不出来，所以甲漏掉的只可能是不会被当作凭据使用的值〔推〕。

**Q4 决策 5.5 没有覆盖到的凭据位置**

5.5 只说了 Header 和查询参数。D.2 列出了热库里所有可能放着凭据值的地方，其中下面几处 5.5 没有提到：

- `full` 记录的 raw 请求体和响应体（上游错误信息可能回显部分 Key）；
- 内容对象（请求 envelope 里的工具定义、用户粘贴进对话的 Key）；
- `parsed_json_enc` 里的兜底会话和 `partial_response_messages`；
- `content_external_refs` 的值（`file_id` 一类，见 D.2）。

三协议本身只在 Header 和查询参数里传递 Key（`security/credential.go` 列出的四种传输）〔核〕，上面这些位置出现凭据是内容层面的，不是传输层面的。

- 甲：不处理，原样归档，在格式文档和部署说明里写明“凭据省略只针对 Header、User-Agent 和 Request-URI 的查询参数”。代价：归档盘上可能存在内容里出现的 Key，加密开启时它们和对话内容同样在密文里。
- 乙：按 `IsCredential` 的值前缀规则扫描并替换。代价：raw 的 SHA-256、内容对象的内容地址、重建哈希全部对不上，等于改写证据；`sk-` 这样的前缀在普通文本里误报很多。
- 丙：发现疑似 Key 时整条记录不归档、留在热库。代价：这些记录永远删不掉，而误报率高。

推荐甲。乙改写了证据，丙让保留策略失效。

**Q5 Header 用一种逻辑形式还是两种**

热库里有两种形态：采集版本 1 每个值一行（`http_headers`），版本 2 每条 audit 一个密封块（`http_header_blocks`），外加 `user_agent_enc` 和 `http_stages` 上的两个内容头列。

- 甲：一种逻辑形式。归档写 `headerblock.Expand` 给出的扁平列表（阶段、kind、名称、序号、值），版本 2 另记“是否有块”和“块里有段的阶段集合”。两种版本都能无损还原：版本 2 的块明文是 `headerblock.Encode` 对这两项的确定输出（C.3 规定了名称严格递增、值按序，解码时逐条校验〔核：`headerblock/headerblock.go`〕），版本 1 的 `value_length` 就是值的长度。`expandBlock` 对失败或中断记录放宽的两种情形（有阶段行没有段、有段没有阶段行）由段集合表达。读出等价可以直接比 `query.Detail.Headers`。代价：版本 2 块的存储元数据（压缩方式、明文长度）不进归档，见 Q7。
- 乙：两种形式，版本 1 写逐值行，版本 2 写解码后的块结构。代价：读取工具和摘要都要处理两套结构，凭据投影要写两遍。

推荐甲。无论哪种，凭据投影都作用在值上，块的明文从不写进归档：块里有 `Authorization`。

**Q6 血缘与请求上下文：摘要覆盖什么**

方案 4.4 要求父轮次在本分段时存原样的增量操作，不在时存物化后的完整引用，并单独保留原始的 `parent_turn_id`、`parent_base`、`link_reason`。现有的 `semantic_compacted` 摘要覆盖的是物化后的请求引用，不覆盖 `turn_context_ops`，也不覆盖 `parent_turn_id`、`parent_base`、`link_reason`、`link_confidence`〔核：`postgres/integrity.go` 的 `semanticPayloadDigest`〕。而 retention 的 `checkpointRetainedChildren` 会把留下的子轮次改写成根：父字段改成 `NULL`、`root`、`retention_checkpoint`、`100`，增量操作整段重写，物化结果不变〔核：`postgres/maintenance.go`〕。

- 甲：记录摘要覆盖物化引用和四个血缘字段，不覆盖增量操作本身。增量操作的正确性由“按包内父轮次重算出的引用等于物化引用、序列哈希相符”来核对（J.2）。被检查点改写过的轮次，血缘字段变了，摘要随之变化，按 `stale` 重新收录。代价：一条 audit 在“父轮次已移除之前”和“之后”各有一个归档版本，两个修订号的血缘不同。
- 乙：摘要连增量操作一起覆盖。代价：增量操作的形态取决于父轮次是否在同一分段，同一条记录在不同分段里摘要不同，热库一侧算不出可比的值。
- 丙：摘要只覆盖物化引用，不覆盖血缘。代价：检查点改写不会让成员变 `stale`，归档里的血缘可能与移除时热库里的不同而无人发现。

推荐甲。被移除的 audit 的原始血缘保存在它自己的归档行里，不需要新的库表。

**Q7 列覆盖：归档哪些表、省略哪些列**

方案 4.4 列了 10 张表。代码里一条 audit 的证据还分布在 `http_header_blocks`、`turn_context_ops`、`conversations`、内容对象四张表和 `body_chunks` 上（E.3 列出全部）。需要确认的省略：

| 列 | 推荐 | 理由 |
| --- | --- | --- |
| 各表的 `*_enc` 密文列 | 不写密文，写明文（凭据按 D 投影） | 方案 3.1 |
| `content_objects`、`binary_objects`、`body_chunks`、`stream_timelines` 的 `compression`、`encoded_length`；`http_header_blocks` 的 `compression`、`plaintext_length` | 不归档 | 只描述密文容器的存储编码；明文和明文长度都在归档里 |
| `parsed_results.parsed_json_enc` 里是明文 JSON 还是 gzip 流 | 不归档 | 同上；归档写解开后的 JSON |
| `conversations.updated_at_ns` | 不归档 | 每有新轮次就变（`persistTurn` 的 `UPDATE conversations`）〔核〕，不是任何一条 audit 的属性；等于该会话轮次 `created_at_ns` 的最大值 |
| `conversations` 的其余列（`protocol`、`key_hash`、`created_at_ns`） | 归档 | `key_hash` 是无密钥的域哈希（`auditmodel.ConversationKeyHash`）〔核〕，会话 ID 本身就由它得出 |
| `content_objects.created_at_ns`、`binary_objects.created_at_ns` | 写进对象文件，不进记录摘要 | 首次写入时间，被多条 audit 共享 |
| `audit_records.api_key_fpr` | 归档 | 见 Q2 |
| `audit_records.parse_save_failures`、`parse_next_at_ns`、`caller_attempts`、`caller_next_at_ns` | 归档 | 运行状态，但与其他列同样在行里；省略它们没有收益 |
| `audit_project_identity` | 归档（方案已定“有则带”） | 它是派生数据（迁移 002 的注释）〔核〕，版本升级时会被重写，按 Q1 会让成员变 `stale` |
| `audit_analysis`、`agent_spawn_hints`、`analysis_detail_objects` | 不归档（方案已定） | 可重算 |

推荐按上表。E.3 的排除清单就是这张表，列覆盖测试照它执行。

**Q8 尚未到终态的记录是否推迟归档**

现在的 retention 只跳过 `parse_status = 'processing'`，`pending` 的记录照删（`selectExpiredAuditIDs`）〔核〕。归档后再变化的记录会变成 `stale`，但如果它在变化之前就被移除，变化永远不会发生：一条 `pending` 的记录在解析之前被移除，它的轮次和对象就不会再产生（raw 仍在归档里）。

- 甲：`parse_status` 为 `pending` 或 `processing`，或 `caller_status = 'pending'` 的记录推迟到终态之后再归档。`billing_state = 'unchecked'` 不等：计费回填可能永远不会运行（没有配置 NewAPI 管理凭据时）。代价：这些记录在热库里多留，超过 `retention_days` 加一天。
- 乙：照常归档，之后变化的按 `stale` 重新收录。代价：上面说的“在变化之前被移除”。
- 丙：甲，再加一个上限：到期后超过 N 天（例如 7 天）仍未到终态的照常归档。代价：卡住的记录在 P4 下会在解析之前被移除，等于对这些记录退回到乙。

推荐甲，不设上限，每次运行在运行记录和日志里报告推迟的条数。解析失败满 5 次会以 `error` 终结（`releaseProcessingParse`）〔核〕，调用者查找最终会变成 `resolved` 或 `unresolved`〔推〕，所以正常情况下推迟是有界的；推迟的条数一直增长，说明解析或调用者查找卡住了，应当去修那里，而不是让归档绕过去。

**Q9 记录摘要的编码**

E 节给出完整的字节序列。其中需要确认的取舍：

1. NULL 与空串区分。现有的 `digestEncoder` 里 NULL 文本写成 `F(nil)`，与 `''` 无法区分〔核：`postgres/integrity.go` 的 `nullableText`〕。推荐新摘要用一个前导字节区分：NULL 为 `0x00`，有值为 `0x01` 后接编码。
2. 明文哈希的口径。推荐对“归档里写的那个明文”求哈希：`parsed_json_enc` 取解开 gzip 之后的 JSON；Header 取 D 节投影之后的项；时间线取解密解压后的明文。
3. raw 块的覆盖。方案 4.6 说“`full` 记录的 raw 字节对回 `body_streams` 里记的 SHA-256 和长度”，但残缺的 Body 的 `sha256` 是 NULL（`finalizeIncompleteCapture` 把它置空）〔核〕，异常记录最要紧的那部分 raw 没有任何哈希可比。推荐记录摘要逐块覆盖 `body_chunks`：阶段、序号、偏移、明文长度、观察时间、明文的 SHA-256。这超出了“比照现有两个摘要”的范围，但只有这样残缺 raw 才受保护。
4. 对象只取内容地址（方案已定），对象明文不进摘要：内容地址本身就是对明文的哈希，重读时重算（J.2）。
5. 域字符串带格式版本：试行期为 `llmapi-logger/archive-record/v0\x00`，格式定为版本 1 时改为 `…/v1\x00`。试行包不作为删除依据（方案 4.4），所以版本切换时旧摘要作废不影响任何删除。

推荐按 E 节。

**Q10 清单签名的规范编码与密钥指纹**

- 甲：签名覆盖清单各字段按 F 节固定顺序的长度前缀编码，与 JSON 的书写方式无关。读取方从解析出的值重建字节序列。代价：格式文档要写清每个字段的顺序。
- 乙：签名覆盖清单文件里某个 JSON 对象的原始字节。代价：第三方实现要拿到未经重新序列化的原始字节，大多数 JSON 库做不到。
- 丙：RFC 8785（JCS）规范化 JSON。代价：要在仓库里实现 JCS；Go 的 `encoding/json` 默认转义 `<>&`，与 JCS 不同。

密钥指纹推荐 `HMAC-SHA-256(归档签名密钥, "llmapi-logger/archive-key-fingerprint/v1\x00")`，加密与不加密的包都有。推荐甲。

**Q11 整包加密：仓库内实现还是用库**

方案 4.4 把这件事留到 P3。`go.mod` 里没有任何密码学依赖（只有 pgx、yaml、sqlite 及其间接依赖）〔核〕。G 节比较了两条路。

- 甲：在仓库内用标准库的 AES-256-GCM 实现 STREAM 构造，帧格式见 G.2。代价：新增约两三百行密码学代码，需要单独评审，配固定测试向量和篡改测试。
- 乙：用库。可选的是 `filippo.io/age`（ChaCha20-Poly1305 的 STREAM，64 KiB 一帧，依赖 `golang.org/x/crypto`，要为主密钥派生的对称密钥写一个自定义 recipient）和 Tink 的 streaming AEAD（依赖树大，含 protobuf）。代价：新增依赖，测试容器没有网络，要随仓库带上模块；`age` 的文件格式自带 recipient 头，读取工具要理解它。

推荐甲。

**Q12 目录表（迁移 008）的结构**

I 节给出完整的 SQL。需要确认的结构选择：

1. 分段多一个过渡状态 `publishing`：先在目录表登记意向（含各成员的记录摘要和变更戳），再 rename 发布，然后改为 `sealed`。方案 4.5 的顺序是先发布、后登记，崩溃后靠扫描归档目录补登记；但补登记时变更戳已经无从得知（它必须取自导出时的快照）。先登记意向，变更戳就始终在库里，崩溃后的对账只需要看文件在不在（H.6）。
2. 成员状态沿用方案的 `sealed`、`hot_removed`、`stale`。对账时发现的、目录表里没有记录的包（例如数据库从备份恢复），它的成员登记为 `stale`：可以列出、可以读取，但永远不作为删除依据，到期记录会被重新收录。
3. 变更戳列在 P3 的迁移里就加上，P3 起就计算并保存，P4 不需要第二个迁移。
4. 另加三张小表：
   - `archive_gap_members`：已导出的 gap。gap 只插入不更新〔核：`postgres/gaps.go` 只有 `insertAuditGaps`〕，所以不需要变更戳；
   - `archive_runs`：每次运行的开始、结束、状态和计数，以及选取水位（B.1），供补跑判断、水位和排障；
   - `archive_deferred`：在水位之后被推迟或复核不过、需要回头再看的 audit（B.1）。没有它，就只能每趟对全部已导出的记录做一次反连接，`export_only` 下随表线性变慢（方案附录 A.4 的同类问题）。
5. 同一 audit 至多一个非 `stale` 的成员（部分唯一索引）。重新收录时，登记新行的同一个操作先把旧行改为 `stale`（H.2 第 4 步）。
6. 对账登记的包，分段行的 `run_id` 记为执行对账的那次运行（H.6）。

推荐按 I 节。

**Q13 行格式（C 节）**

C 节的选择大多是机械的，但它们决定了第三方能否不依赖本仓库代码解析归档（方案 4.4），所以列出来请一并确认：

1. 64 位整数写十进制字符串；文本列不是合法 UTF-8 时写 `{"b64": …}`；NULL 写 `null`，不允许省略键（C.1）。
2. 内容对象、`parsed_json`、项目标识的明文写成 JSON 字符串，不作为嵌套 JSON 嵌入，以保住内容地址所依赖的原始字节（C.1）。
3. 凡是进记录摘要的都在行里，包括对象的元数据、引用行、raw 块的元数据和哈希；对象文件只放大块字节（C.2）。
4. 时间线写解密解压后的明文（base64），不写解码后的点列表。代价：格式文档要写清 `internal/streamtimeline` 的编码，模块文档里目前只有一句“offset/time delta 序列”（模块 04 §3.3）〔核〕，要从代码补全；好处：逐字节无损，与摘要的口径一致。另一种做法是写点列表、摘要也按点列表算，可读但要求编码是双射，没有核对过。
5. 解开后超过 1 MiB 的 `parsed_json` 分段放进对象文件（C.2），使单行有界。

推荐按 C 节。

**Q14 格式何时从版本 0 定为版本 1（决定 P4 是否真的会删）**

方案 4.4 规定试行包（版本 0）不作为删除热库数据的依据，第 6 节规定 P3 验收通过后定为版本 1。`archive_then_delete` 只移除版本不低于 1 的分段里的成员（M.2 第 1 步），所以在版本 0 之下 P4 的代码不会删除任何东西。而两件与格式有关的事要靠真实分布来定，这份数据还没有：桶包阈值（5.3），以及对象放在包内还是按月共享（5.4 的 3 到 5 倍界限；改用共享对象库是格式改动）。

- 甲：本阶段停在版本 0。P4 的代码与测试照做，测试里把格式版本强制为 1 来走完移除路径；发布出去的二进制在 `archive_then_delete` 下只导出、不移除，并在启动日志里说明。等真实库上的 `audit-bench dist` 结果确认 5.4 的膨胀比在界限以内，再用单独一个提交定为版本 1。代价：P4 在生产上暂时不生效。
- 乙：本地验收（4.6 的三层检查与 N 节的全部用例）通过就定为版本 1，包内自足。代价：如果以后真实分布显示膨胀比超过界限，改用共享对象库就要出版本 2，而版本 1 的包按兼容承诺必须永远可读。
- 丙：定为版本 1，但 `archive_then_delete` 另加一个显式的确认开关，默认关闭。代价：多一个配置项；格式仍然先冻结。

推荐甲。冻结格式是一个不能撤回的承诺，而缺的只是一次只读的测量。

### 0.2 方案与代码不符之处

逐条对照 `8df5ea3` 的代码，方案里下面这些前提不成立或不完整。正文已按代码处理。

1. **5.2 的“`session_analysis.run_at` 加 `timezone`”。** `session_analysis` 段只有 `run_at`（默认 `02:00`），没有时区键。会话分析的时区取 `org_reports.timezone`，而且只在组织报告开启时；否则用进程的 `time.Local`〔核：`app/app.go` 的 `assembleSessionAnalysisWith`，`sessionanalysis/runner.go` 的 `untilNextRun`〕。归档另设 `archive.timezone`（L.1）。
2. **4.5 的变更戳清单漏了两条写**，见 Q1。
3. **4.6 的 raw 核对对残缺 Body 不起作用**，见 Q9 第 3 点。
4. **4.4 的“行内容”是第 2 阶段之前写的。** 它列的是 `http_headers`；版本 2 的记录没有这张表的行，而有 `http_header_blocks`、`user_agent_enc` 和 `http_stages` 的两个内容头列。它也没有列 `conversations` 和 `turn_context_ops`。见 Q5、Q7。
5. **4.5 “离线导入器和 `audit-stage` 的白名单要同步更新”对迁移 008 不成立。** 导入目标只建 001 基线（`InitializeImportSchema`），并拒绝基线以外的任何表（`migrate/importer.go` 的 `known` 集合）〔核〕。它不会遇到迁移 008 的表，与第 3 阶段对 007 的结论相同。`cmd/audit-stage` 不在仓库里〔核：`cmd/` 下只有 `audit-bench`、`audit-import`、`audit-proxy`、`llmaudit`〕。
6. **4.5 第 5 步“输入从按截止时间选换成给定 id 列表”。** `deleteAuditBatch` 本来就接收 id 列表〔核：`postgres/maintenance.go`〕，要改的不是它，而是在它之前加变更戳比对和目录表更新，以及调用方的排序（M.2）。
7. **“复核原完整性事件”证明不了所有列。** 没有轮次的 audit，`parsed_results` 只在错误码为 `reconstruction_failed` 或 `normalization_failed` 时被 `reconstruction_failed` 事件覆盖（`saveParsedAudit`）〔核〕；其余情况下它不在任何事件里。`token_links`、`audit_project_identity`、`audit_records` 的 `parse_status`、`caller_*`、`api_key_fpr` 也不在任何事件里（第 3 阶段设计 D.1）。归档签名对这些列的含义只是“归档那一刻热库里是这个值”。格式文档按 E.4 标出每列的来源类别。
8. **`HasAudits` 的隐患现在就存在。** retention 删光 audit 后完整性事件仍在（载荷校验只看还有 audit 行的事件）〔核：`verifyIntegrityPayloadsTransaction`〕；这时密钥文件丢失，启动会新建密钥，随后 `EnableIntegrity` 的链校验失败，审计存储不可用。所以 L.3 的修复不依赖归档，排在第一个提交（O.1）。
9. **5.2 第 2 点只说了代价。** 按变更戳覆盖血缘（Q6 甲），顺序错误还会制造假的 `stale`：先删父轮次，检查点改写了同一批成员里的子轮次，子轮次的血缘与归档时不同。见 M.2。

---

## A. 现状

### A.1 retention 的删除路径

**调度**〔核：`internal/retention/runner.go`〕：

- 只在 `retention_days > 0` 时组装（`app/app.go`），默认 30 天（`config/types.go` 的 `DefaultRetentionDays`）。
- 每小时一轮。截止时间是 `now - retention_days × 24h`。
- 每轮最多删 5000 条 audit 和 5000 条 gap。gap 每批 200 条；audit 每批从 1 条起：
  - 整批且耗时不超过 0.5 秒时翻倍，上限 200（`storage.RetentionBatchLimit`）；
  - 超过 1 秒时按比例缩小；
  - 多条的一批慢失败后降到 1 条并把上限也设为 1，之后每完成一轮上限翻倍。
- 每批之后暂停与该批相同的时长，最多 5 秒。失败或有积压时 1 分钟后再跑。

**一批里做什么**〔核：`postgres/maintenance.go`〕：`DeleteExpired` 以 `writeDeleteExpired` 同步提交。这个操作独占一个 writer 事务（`writer.go` 的 `alone()`）。`deleteExpired` 依次：

1. `selectExpiredAuditIDs`：`ended_at_ns IS NOT NULL AND started_at_ns < cutoff AND parse_status <> 'processing'`，按 `started_at_ns, audit_id` 升序取一批。
2. `deleteAuditBatch(ids)`：
   1. `selectTurnIDsForAudits` 取这些 audit 的轮次。
   2. `selectRetentionObjectCandidates` 在改写之前收集候选：会话、两个 envelope、过期轮次和它们子轮次的上下文操作引用的对象、过期轮次的响应条目。
   3. `checkpointRetainedChildren`：父轮次在这一批里、自己不在的子轮次，先用 `loadRequestRefs` 物化出完整请求引用，删掉它的 `turn_context_ops`，把 `turns` 的父字段改成 `NULL`、`root`、`retention_checkpoint`、`100`，写入 `BuildDelta(nil, refs)`，再读回核对序列哈希。
   4. `deleteTurnsLeafFirst`：循环删除没有子轮次的轮次，直到这一批删完；删不动就报错。
   5. 读出派生明细的根，`DELETE FROM audit_records`（各表级联），核对删除条数，修剪派生明细链。
   6. `garbageCollectConversationObjects`：只在候选范围内，删掉不再有轮次的会话、不再被四处引用的内容对象、不再被引用的二进制对象，每条语句至多 500 个参数。
3. gap：`DELETE FROM audit_gaps WHERE ended_at_ns < cutoff`，按 `ended_at_ns, id` 取一批。

`audit_gaps` 只插入，不更新〔核：`postgres/gaps.go`〕。

### A.2 `HasAudits` 与密钥文件

〔核〕：

- `postgres/reader.go` 的 `HasAudits` 只查 `EXISTS (SELECT 1 FROM audit_records)`。SQLite 的同名方法形状相同。
- 唯一的调用方是 `app/app.go` 的 `assembleAuditWithStore`：`security.LoadOrCreateKey(key_path, !hasAudits)`，然后 `NewAESGCM`，再 `EnableIntegrity` 校验整条事件链。
- `security/key.go` 的 `createKey`：目录 0700；写临时文件（0600）、fsync，再用 `os.Link` 原子发布，已存在就读已有的。从不覆盖已有密钥。
- 隐患见 0.2 第 8 条。

### A.3 查询层给出什么（“读出等价”的比较对象）

`internal/query` 只依赖 `storage` 的类型、`auditmodel`、`headerblock`、`parser/builtin`、`security` 等，不依赖 PostgreSQL 驱动〔核：`go list -deps ./internal/query`〕。对外的输出：

| 方法 | 输出 | 关键规则〔核〕 |
| --- | --- | --- |
| `Service.Get` | `Detail`：`Audit`、`RequestURI`、`Stages`、`Headers`、`Bodies`、`ParsedResult`、`Conversation`、`Turn`、`TokenLink` | Request-URI 用 AAD `(audit_id, "request_uri")` 解密，原样输出；Header 一律经 `headerblock.Expand`，版本 1、2 得到同样的扁平列表；`Conversation` 先取 `parsed_json_enc` 的兜底会话，有轮次时由重建结果替换；计费字段只在 `billed` 时给出 |
| `Service.GetMetadata` | 只有 `Audit`、`Stages`、`Bodies` | raw 和时间线导出用它，不依赖派生记录 |
| `Service.ReconstructTurn` | `Turn`、provider 的 `Request`、`Response`、`Conversation` | `reconstructTurnGraph`：逐个打开对象并核对语义哈希；`Assemble(layout, envelope, items)`；核对序列哈希和重建哈希；`RestoreBinaries`；`builtin.Registry().RebuildConversation`。响应 layout 为 `none` 时经 `MergePartialResponse` 接上半截回答（`query/partial_response.go`） |
| `Service.Timeline(side)` | `StreamTimeline` | 选阶段的规则与 raw 相同（请求侧先 `request_sent` 后 `request_received`，响应侧先 `response_received` 后 `response_sent`）；AAD `(audit_id, "stream_timeline_v1", stage, compression)`；至多 100,000 个点 |
| `Service.RawMeta`、`StreamRaw(side)` | 长度、SHA-256、完整与否；raw 字节 | `pending` 回 `ErrNotReady`，`metadata` 回 `ErrNotRetained`；块按序号与偏移连续，只有 `capture_chunk_missing` 允许跳过；完整时核对 SHA-256；AAD `body_chunk_v2`，回退到旧的 `body_chunk` |
| `Service.SessionConversation` | 会话 | 有轮次用重建，没有用兜底会话 |
| `Service.List` | `AuditSummary` 列表 | 每行只解密 User-Agent：版本 1 逐行查 Header，版本 2 解 `user_agent_enc` |

导出接口（`web/agent_requests.go` 的 `agentExportKinds`）是这几个方法的组合：`conversation`、`headers`、`request`、`response`、`raw-request`、`raw-response`、`timeline-request`、`timeline-response`。管理端的重建路由在响应 layout 为 `none` 时回 `404 not_available`，不回 `null`（`web/api.go` 的 `serveReconstructed`）〔核〕。

不能拿来比较的字段〔核〕：

- `AuditSummary.ConversationTurns` 是查询时对整个会话的 `COUNT(*)`（`query_reader.go` 的 `queryAuditDetail`），随会话后续的轮次变化；
- `DisplayName` 由 web 层另行填写（`addCallerDisplayNames`）。

### A.4 现有的凭据判定

〔核〕：

- `agentapi.IsCredential(name, value)`（`internal/agentapi/mask.go`）有三条规则：
  1. 名称不区分大小写地等于 `authorization`、`proxy-authorization`、`cookie`、`set-cookie`、`x-api-key`、`x-goog-api-key`、`api-key`、`key`，或者等于 `token`，或以 `-token`、`_token` 结尾；
  2. 小写名称包含 `secret`、`password`、`passwd`、`credential`、`signature`、`api-key`、`apikey`、`api_key`；
  3. 值去掉前导空白后不区分大小写地以 `bearer `、`basic `、`sk-`、`lla_` 开头。
- 判定按单个值做，同名多值的 Header 逐值判断（`web/agent_requests.go` 的 `agentHeadersOf`）。
- User-Agent 按 `IsCredential("User-Agent", value)` 判定，命中时输出 `null`（`agentUserAgentOf`）。
- Request-URI 由 `agentRequestURIOf` 切分。它的有损之处见 Q3。
- 入站凭据的传输方式由 `security/credential.go` 枚举：`Authorization`、`X-Api-Key`、`X-Goog-Api-Key`、查询参数 `key`。`api_key_fpr` 是 `NormalizeNewAPIKey` 之后的 keyed 指纹，在 `Begin` 时写入，早于拦截器。
- `audit_records.path` 是 `URL.EscapedPath()`，不含查询串；完整的 Request-URI 只在 `request_uri_enc` 里（`audit/manager.go` 的 `Begin`）。

### A.5 每日定时的现有模式

〔核：`config/session_analysis.go`，`sessionanalysis/runner.go`〕：

- `run_at` 是 `HH:MM`，由 `ParseRunAt` 校验。
- `untilNextRun` 在给定的 `time.Location` 里取当天该时刻，已过就取次日。
- 设置变更通过 `reschedule` 通道立即重排。
- 没有补跑：进程在那一刻不在，就等下一天。
- 时区来源见 0.2 第 1 条。`config/org_reports.go` 引入了 `time/tzdata`，容器里没有系统时区库也能解析 IANA 名称。

### A.6 子密钥与完整性事件

**子密钥派生**〔核〕：三处都是 `HMAC-SHA-256(主密钥, 域字符串)`，取全部 32 字节，派生后清除中间值：

- `security/integrity.go`：`llmapi-logger/integrity-key/v1\x00`
- `security/fingerprint.go`：`llmapi-logger/credential-fingerprint-key/v1\x00`
- `security/analysis_fingerprint.go`：`llmapi-logger/analysis-fingerprint-key/v1\x00`

**三种事件摘要覆盖什么**〔核：`postgres/integrity.go`、`integrity_capture_v2.go`；第 3 阶段设计 D.1、D.2〕：

| 事件 | 覆盖 | 不覆盖 |
| --- | --- | --- |
| `capture_finalized` v1/v2 | `audit_records` 的终态列；`request_uri_enc`、Header 值（v1）或块（v2）、`user_agent_enc`（v2）各自密文的 SHA-256；`http_stages` 各列（v2 含两个内容头列）；`body_streams` 的长度、哈希、状态、时间和错误码 | `stored_length`、`chunk_count`、`retention_state`、事件计数；`body_chunks`、`stream_timelines`；`parse_status`、`caller_*`、`api_key_fpr` 等 |
| `semantic_compacted` | `parsed_results` 各列与 `parsed_json_enc` 密文的 SHA-256；轮次的布局、哈希、计数、`response_id`、`created_at_ns`；物化后的请求引用与响应引用；每个引用对象的内容地址、语义哈希、kind、压缩、两个长度和密文 SHA-256；二进制引用与外部引用行；二进制对象；各阶段的 `retention_state` 与时间线密文 SHA-256 | 血缘字段（`parent_turn_id`、`parent_base`、`link_reason`、`link_confidence`）；`turn_context_ops` |
| `reconstruction_failed` | `parsed_results` 同上；各阶段长度、哈希、状态、`retention_state`、错误码 | 其余 |

“密文的 SHA-256”都是数据库里求的 `CASE WHEN octet_length(col) > 0 THEN sha256(col) END`。

**事件与 audit 的关系**〔核〕：

- 事件按 `audit_id` 关联，没有外键，从不删除。
- 启动校验检查整条链的 MAC 链接，并要求每条已终结的 audit 有 `capture_finalized`、每个轮次有 `semantic_compacted`。
- 后台载荷校验只核对仍有 audit 行的事件（`JOIN audit_records`），按会话分组，复用一个 `integrityGraphCache`。
- 单条事件的载荷摘要由 `integrityPayloadDigestFor(ctx, tx, cache, auditID, eventType, schemaLive)` 重算，MAC 由 `IntegritySigner.Verify` 核对。归档复核直接复用这两个函数（H.3）。

---

## B. 选取与分组〔设〕

### B.1 到期与推迟

一条 audit 在某次运行里“到期可归档”，要求同时满足：

1. `ended_at_ns IS NOT NULL`。仍在进行的 audit 不选，与 retention 相同。崩溃留下的在途记录由启动恢复终结为 `interrupted`，之后按普通记录处理。
2. `started_at_ns < cutoff`，`cutoff` 的算法与 retention 相同（5.2 甲）。
3. `parse_status NOT IN ('pending', 'processing')`，且 `caller_status <> 'pending'`（Q8 甲）。
4. 目录表里没有它“当前有效”的成员行。当前有效指状态为 `sealed` 或 `hot_removed`，且所在分段的格式版本是当前版本。`stale` 的成员，以及只在试行格式（版本 0）分段里出现过的成员，在 `archive_then_delete` 模式下重新收录，修订号加一。

`capture_status = 'failed'` 的 audit 照常归档：它已终结、有 `capture_finalized` 事件，Header 按 `expandBlock` 的宽松规则读出（A.3）。没有轮次的 audit、只有请求的轮次（响应 layout 为 `none`）也照常归档，后者的半截回答在 `parsed_results` 里（C.2）。

**水位。** 方案附录 A.4 量到过两个没有水位的回填查询：全部处理完以后每一轮仍要扫一遍整张表。`export_only` 下已导出的记录永远留在热库，“到期且没有当前成员”这个反连接也会随表线性变慢。所以选取分两部分：

- **新范围**：`(started_at_ns, audit_id)` 大于水位、`started_at_ns < cutoff`，沿 `audit_records_started_idx` 升序取〔核：迁移 001 的索引〕。这一趟检查过的最后一行就是新水位，不论其中有多少条被推迟或跳过。
- **回头的部分**：
  - `archive_deferred` 里登记的记录（被推迟的、仍在进行的、复核不过的，见 I.1），现在满足 B.1 的就收录，否则留着；
  - 状态为 `stale`、audit 还在热库、又没有当前成员的成员。

  两者都是小集合，走主键或部分索引。

水位存在 `archive_runs`，随格式版本记录。格式版本变化时（试行版 0 定为 1）水位归零，于是版本 0 的成员按 B.1 第 4 条全部重新收录。

### B.2 一次运行分几趟

一次运行可能面对很大的积压：例如在一个未开过 retention 的库上首次开启归档。一个覆盖全部到期记录的长 REPEATABLE READ 快照会挡住 VACUUM 的清理水位。所以一次运行分若干“趟”，每趟一个快照：

- 每趟按 `started_at_ns, audit_id` 升序取至多 `archive.pass_audits`（默认 5000，与 retention 的每轮上限相同）条到期 audit；
- 再把这些 audit 所在会话里其余的到期 audit 补齐，使一个会话的到期轮次总在同一趟；
- 一趟写完、核对、登记之后才开下一趟；
- 一次运行最长 `archive.run_deadline`（默认 4 小时），到点停在趟与趟之间，下次运行接着做。

### B.3 分组与装包

每趟内：

1. 有轮次的 audit 按 `turns.conversation_id` 分组；没有轮次的 audit 不属于任何会话。
2. 一个会话在本趟的到期轮次数达到 `archive.conversation_min_turns`（默认 16），或这些轮次的归档明文字节（行加对象，C 节）达到 `archive.conversation_min_bytes`（默认 16 MiB），这个会话写成独立的会话包（`bundle_kind = "conversation"`）。
3. 其余会话和没有轮次的 audit 按 `audit_records.protocol` 装进本趟的桶包（`bundle_kind = "bucket"`），每个协议一组。
4. 包内的行按会话、`turns.created_at_ns`、`audit_id` 排序；没有轮次的 audit 排在桶包末尾，按 `started_at_ns`。父轮次总在子轮次之前，读取时可以一遍顺序处理增量操作。

默认值的依据：附录 A 的部署平均每轮约 220 个上下文条目、请求体约 1.1 MB，一个持续工作一天的编码 Agent 会话通常有几十到几百轮〔推〕，会独立成包；没有 key 的一次性请求和短会话进桶包。方案要求用 P0 量出的分布来定阈值，但 `audit-bench dist` 没有在任何真实库上运行过（附录 B.1），所以这里只能给推测的默认值，并做成配置。格式版本 0 期间可以随时调整，调整不影响已写的包：读取工具按清单建索引，不靠文件名或包的划分。

### B.4 按大小滚动

一个包（会话包或桶包）累计的明文字节超过 `archive.segment_max_bytes`（默认 256 MiB）时，在下一条 audit 之前切到同名的下一个分段（`_s0002`……）。计数取行文件与对象文件压缩前的字节，与压缩率无关，测试可以确定地复现。

一条 audit 从不跨分段，所以单个分段可能超出上限一条 audit 的量。同一个会话被切进两个分段时，后一个分段里第一个父轮次在前一个分段的轮次，存物化引用（C.4）。

### B.5 归档之后会话又活跃

- 新轮次不在快照里，也还没到期，不受影响。它们之后到期时进入新的分段或桶包，旧包不动。同一会话因此可能分布在多个会话包和桶包里，读取工具按清单建索引（K.2）。
- 新轮次可以选一个已归档、还未移除的轮次做父轮次（`chooseTurnParent` 只看 `turns`）〔核：`postgres/graph_writer.go`〕。这不改父轮次的任何行，只在 `conversations.updated_at_ns` 上留下变化（Q7）。之后移除父轮次时，由检查点把新轮次改写成根（M.2）。

---

## C. 行格式（格式版本 0）〔设〕

### C.1 文件与编码规则

一个分段由三个文件组成：

| 文件 | 内容 |
| --- | --- |
| `<名称>.jsonl.gz.enc` | 行文件：每行一条 audit |
| `<名称>.objects.jsonl.gz.enc` | 对象文件：本分段引用到的对象和 raw 块，各存一次；为空时不产生 |
| `<名称>.manifest.json` | 明文清单（F 节） |

`archive.encrypt: false` 时去掉 `.enc`。gap 包是 `gaps/gaps-<first_id>-<last_id>.jsonl.gz(.enc)` 加清单。

JSON 编码规则：

- **整数**：64 位整数、纳秒时间戳一律写成十进制字符串，如 `"started_at_ns": "1764300000123456789"`。
- **浮点**（只有 `token_links.quota_per_unit`）：写成 `strconv.FormatFloat(v, 'g', -1, 64)` 的字符串，能精确还原。
- **哈希和 keyed 指纹**：小写十六进制。
- **二进制内容**（图片、raw 块、时间线明文）：带填充的标准 base64。
- **文本列**：合法 UTF-8 时写 JSON 字符串；否则写 `{"b64": "…"}`。Header 值、Request-URI 分段、User-Agent 都可能不是合法 UTF-8；Go 的 `encoding/json` 会把非法字节替换成 U+FFFD，所以编码器必须先判断。
- **NULL 与缺省**：SQL 的 NULL 写 `null`；每一列都必须出现，不允许省略键。
- **内容对象的明文**：写成 JSON 字符串，内容是存储的规范 JSON 原文。不作为嵌套 JSON 嵌入：读取方重新序列化会改变字节，内容地址就对不上了。`parsed_json` 和项目标识的明文同理。

### C.2 一行的结构

一行是一个 JSON 对象，键按下面的顺序写出（顺序只为便于阅读，读取方不得依赖）：

```json
{
  "type": "audit",
  "audit_id": "…",
  "conversation_id": "conv_…",
  "protocol": "openai",
  "started_at_ns": "…",
  "ended_at_ns": "…",
  "revision": "1",
  "audit_records": { "…": "全部列，见 E.3；request_uri 与 user_agent 是投影形式（D 节）" },
  "http_stages": [ { "stage": "request_for_newapi_received_from_nginx", "…": "…" } ],
  "headers": {
    "capture_version": "2",
    "block_present": true,
    "block_stages": ["request_for_newapi_received_from_nginx", "…"],
    "values": [
      { "stage": "…", "kind": "header", "name": "content-type", "value_index": "0", "value": "application/json" },
      { "stage": "…", "kind": "header", "name": "Authorization", "value_index": "0",
        "value_omitted": "credential", "length": "51", "value_fpr": "…" }
    ]
  },
  "body_streams": [ { "stage": "…", "source_stage": "…", "…": "全部列" } ],
  "raw_chunks": [ { "stage": "…", "seq": "0", "offset": "0", "plaintext_length": "1048576",
                    "observed_at_ns": "…", "sha256": "…" } ],
  "stream_timelines": [ { "stage": "…", "event_count": "…", "first_event_at_ns": "…", "last_event_at_ns": "…",
                          "timeline_complete": "1", "plaintext_length": "…", "timeline_b64": "…" } ],
  "parsed_results": { "…": "全部列", "parsed_json": "<解开后的 JSON 原文；超过 1 MiB 时为 null>",
                      "parsed_json_ref": null },
  "token_links": { "…": "全部列" },
  "turn": {
    "turns": { "…": "全部列，含原始血缘" },
    "request_context": { "form": "delta", "ops": [ { "op_index": "0", "operation": "retain", "item_count": "12", "slot": null, "object_hash": null, "semantic_hash": null } ] },
    "response_items": [ { "ordinal": "0", "slot": "…", "object_hash": "…", "semantic_hash": "…" } ],
    "objects": [ { "object_hash": "…", "semantic_hash": "…", "object_kind": "…", "plaintext_length": "…" } ],
    "binary_refs": [ { "object_hash": "…", "json_pointer": "…", "binary_hash": "…", "media_type": "…", "encoding": "base64" } ],
    "external_refs": [ { "object_hash": "…", "json_pointer": "…", "ref_kind": "file_id", "value_hash": "…", "value": "…" } ],
    "binaries": [ { "binary_hash": "…", "media_type": "…", "plaintext_length": "…" } ]
  },
  "conversation": { "conversation_id": "…", "protocol": "…", "key_hash": "…", "created_at_ns": "…" },
  "audit_project_identity": { "…": "全部列", "identity": "<身份明文 JSON>" },
  "integrity_events": [ { "sequence": "…", "event_type": "capture_finalized", "previous_mac": "…",
                          "payload_digest": "…", "event_mac": "…", "created_at_ns": "…" } ],
  "record_digest": "…"
}
```

规则：

- **行首字段**（`audit_id` 到 `revision`）与行内各表的值必须一致，重读时比对（J.2）。没有轮次时 `conversation_id` 为 `null`。
- **可选部分**：没有对应行的表写 `null`（`parsed_results`、`token_links`、`turn`、`conversation`、`audit_project_identity`），列表为空写 `[]`。
- **Header**：`headers.values` 是 `headerblock.Expand` 的扁平顺序（阶段顺序、header 先于 trailer、名称的字节序、`value_index`）〔核：`headerblock/expand.go`〕。版本 1 的 `block_present` 为 `false`、`block_stages` 为 `null`；版本 2 写块是否存在、块里有段的阶段集合（Q5 甲）。值的投影见 D.3。
- **记录摘要只凭这一行就能重算**（E.2）。凡是进摘要的东西都在行里；对象文件只放大块的字节，由行里记的哈希核对（J.2）。
- **raw**：`raw_chunks` 是每个 `full` 阶段每一块的元数据和明文的 SHA-256，块的字节在对象文件里（C.5）。`source_stage` 指向另一阶段的 Body（成对合并）没有自己的块，读取时按 `source_stage` 取来源阶段的块〔核：`deduplicateEquivalentBodyPair`；`postgres/query_reader.go` 的 `StreamBodyChunks` 先查 `source_stage` 再按它取块〕。
- **`parsed_json`**：`parsed_json_enc` 解密后，若以 gzip 魔数开头就解开（`auditmodel.OpenParsedResult` 的规则）〔核〕，写出的是 JSON 原文。
  - 兜底会话 `conversation` 和 `partial_response_messages` 都在其中，读取工具同样经 `query.MergePartialResponse` 合并（K.3）。
  - 解开后超过 1 MiB 时，`parsed_json` 为 `null`，正文按至多 1 MiB 一段放进对象文件（C.5 的 `parsed_json_part`），行里写 `parsed_json_ref = {"sha256", "length", "parts"}`。所以任何一行都不超过几 MiB；读取工具要导出这种记录的会话时，在内存里拼回整段，上界是 `auditmodel.MaxParsedResultBytes`（128 MiB）〔核〕。
  - `parsed_json_enc` 为 NULL 时两者都是 `null`。
- **`turn.objects`、`binaries`、两种引用行**：
  - `objects` 是这一轮引用的全部内容对象（两个 envelope、物化请求引用和响应引用里的对象），去重后按字节序排序，与 `readTurnGraph` 读取的集合相同〔核：`postgres/graph_reader.go`〕；
  - `binaries` 是这些对象经 `content_binary_refs` 引用的二进制对象；
  - 两种引用行是这些对象的 `content_binary_refs`、`content_external_refs` 行。
  这些都是很小的元数据，重复出现在共享同一对象的各行里；对象的明文和字节只在对象文件里存一次。
- **原完整性事件**：该 audit 的全部事件，按 `sequence` 排序，原样抄录（方案 4.4）。

### C.3 两种采集版本与 `parsed_json_enc` 的两种形态

| 热库形态 | 归档 |
| --- | --- |
| 采集版本 1：`http_headers` 逐值行，`user_agent_enc` 为 NULL，两个内容头列为 NULL | `headers.capture_version = "1"`，扁平列表；`audit_records.user_agent` 为 `null`；`http_stages` 两列为 `null` |
| 采集版本 2：`http_header_blocks` 一块，`user_agent_enc`，两个内容头列 | `headers.capture_version = "2"`，扁平列表加块的段集合；`user_agent` 投影；两列原样 |
| `parsed_json_enc` 明文 JSON 或 gzip 流 | 都写解开后的 JSON |
| 旧的 Anthropic、Gemini 记录：没有轮次，会话在 `parsed_json_enc` 里，raw 为 `full` | 行里 `turn` 为 `null`，`parsed_json` 带会话，raw 块进对象文件 |
| 旧的 OpenAI 流式 layout、新的紧凑 SSE layout | layout 名照抄，对象照抄；装配由 `auditmodel.Assemble` 的数据表完成（方案 4.1 第 2 条的调整说明），读取工具不需要 parser 注册 |

### C.4 请求上下文

- 父轮次在同一分段、且排在前面时：`request_context = {"form": "delta", "ops": [...]}`，是 `turn_context_ops` 的原样行。`parent_base = 'post_turn'` 时，基底是父轮次的请求引用接它的响应引用，所以父轮次的响应条目也必须在本分段里；父轮次在本分段时自然满足。
- 其他情形（根轮次之外，父轮次在别的分段、已移除或还在热库），写 `{"form": "materialized", "refs": [{"slot": "…", "object_hash": "…", "semantic_hash": "…"}]}`，由导出时的 `loadRequestRefs` 物化。
- 根轮次（`parent_turn_id` 为 NULL，包括检查点改写过的）写 `delta`：它的增量操作本身就是全量插入。
- 原始血缘（`parent_turn_id`、`parent_base`、`link_reason`、`link_confidence`）在 `turn.turns` 里，与 `request_context` 的形式无关。

### C.5 对象文件

每行一个对象，`type` 区分：

| `type` | 字段 |
| --- | --- |
| `content_object` | `object_hash`、`semantic_hash`、`object_kind`、`plaintext_length`、`created_at_ns`、`data`（规范 JSON 原文的字符串） |
| `binary_object` | `binary_hash`、`media_type`、`plaintext_length`、`created_at_ns`、`data_b64` |
| `raw_chunk` | `audit_id`、`stage`、`seq`、`data_b64` |
| `parsed_json_part` | `audit_id`、`part`、`data`（JSON 原文的一段，按 UTF-8 字符边界切分） |

引用行（`content_binary_refs`、`content_external_refs`）在行里（C.2），不在对象文件里。

- 对象在本分段里第一次被引用时写出，之后不再重复。写入器只在内存里保留已写对象的哈希集合。
- raw 块一块一行。块至多 1 MiB：legacy 攒满 1 MiB 才 flush（方案 2.1），unified 离开内存的块也是整 1 MiB（`config/audit.go` 的 `MinAuditMemoryStageBytes` 注释）〔核：注释；unified 的块大小上限没有逐行读代码〕。所以单行至多约 1.4 MB。

### C.6 gap 文件

每行一条 `audit_gaps`：`{"type": "gap", "id", "started_at_ns", "ended_at_ns", "reason", "request_count", "detail", "created_at_ns"}`。gap 不在完整性链里，只受清单签名保护。

---

## D. 凭据投影〔设，判定规则〔核〕〕

### D.1 判定

一个值是否是凭据，一律由 `agentapi.IsCredential(name, value)` 判定（A.4），逐值进行：

| 位置 | `name` | `value` |
| --- | --- | --- |
| Header 与 Trailer 的每个值（四个阶段，版本 1 与 2） | Header 名称 | 该值 |
| 入站 User-Agent 的每个值（`user_agent_enc`） | `"User-Agent"` | 该值 |
| Request-URI 查询串的每个分段 | 解码后的名称；解码失败时用原始字节 | 解码后的值；解码失败时用原始字节 |

### D.2 热库里凭据值可能在哪里

| 位置 | 是否可能有凭据值 | 归档怎么处理 |
| --- | --- | --- |
| `http_headers.value_enc`（版本 1） | 是：`Authorization`、`x-api-key`、`x-goog-api-key`、`Cookie`、响应的 `Set-Cookie` 等〔核：`audit/session.go` 的 `addHeadersLocked` 对 map 的全部键取值，不按名称过滤；它的三条分支里读了逐值加密的那一条，另两条（`addHeaderGroupLocked`、`snapshotHeadersLocked`）没有逐行读，方案 2.1 的结论相同〕 | 投影 |
| `http_header_blocks.block_enc`（版本 2） | 是，同上，在块的明文里 | 块不写进归档；扁平列表逐值投影 |
| `audit_records.user_agent_enc` | 只在值形如凭据时（例如以 `sk-` 开头） | 逐值投影 |
| `audit_records.request_uri_enc` | 是：Gemini 的 `?key=` | 按 D.3 投影 |
| `audit_records.api_key_fpr` | 不是值，是 keyed 指纹 | 原样（Q2） |
| `audit_records.path` | 否：只有路径，不含查询串〔核〕 | 原样 |
| `body_chunks`（`full` 的 raw） | 协议上不传 Key；内容里可能有 | 原样（Q4 甲） |
| `content_objects`、`binary_objects` | 同上 | 原样（Q4 甲） |
| `content_external_refs.value_enc` | 是 `file_id`、`image_file_id`、`attachment_id`、`asset_id` 的值，同时也在对象明文里〔核：`auditmodel/binary.go`〕 | 原样 |
| `parsed_results.parsed_json_enc` | 只有统计摘要、兜底会话和半截回答，没有 Header〔核：三个 parser 的 `ParsedJSON` 只有协议、端点、状态和三个计数；`parser/worker.go` 的 `parsedResultPlaintext` 只在其上加 `conversation` 或 `partial_response_messages`，`compactResultJSON` 只有解析结果的字段〕；会话内容里可能有 | 原样（Q4 甲） |
| `audit_project_identity.identity_enc` | 否：远端地址经 `NormalizeRemote` 归一化为 `host/path`，用户名部分被去掉〔核：`orgreport/identity.go`〕 | 原样 |
| `stream_timelines.timeline_enc` | 否：只有偏移和时间 | 原样 |
| `token_links` | 否：用户名与 Token 名称，不是 Key | 原样 |
| `audit_analysis`、会话分析各表 | 不归档 | — |

### D.3 投影形式

**Header 与 User-Agent 的值**：非凭据写 `"value": <文本>`；凭据写

```json
{ "value_omitted": "credential", "length": "<原值字节数>", "value_fpr": "<64 位十六进制>" }
```

两者互斥。`name`、`stage`、`kind`、`value_index` 照常写。`audit_records.user_agent` 是这样的值的数组，Header 缺失时为 `null`（与 `user_agent_enc` 的 NULL 对应，`[]` 不会出现）〔核：`headerblock/useragent.go` 要求至少一个值〕。

**Request-URI**（Q3 甲）：

```json
"request_uri": {
  "path": "<第一个 ? 之前的原始字节>",
  "has_query": true,
  "segments": [
    { "raw": "alt=sse" },
    { "raw_name": "key", "has_equals": true, "value_omitted": "credential", "length": "<解码后的值的字节数>", "value_fpr": "…" }
  ]
}
```

- 查询串按 `&` 切分，空段也保留（`{"raw": ""}`），所以非凭据的段能逐字节拼回原串。`#` 不特殊处理：服务端的 Request-URI 不含片段〔推〕，出现时就是最后一段的一部分。
- 凭据段只保留原始名称和是否带 `=`；`length` 和 `value_fpr` 按解码后的值计算，使 `?key=` 与 Header 里的同一个 Key 在归一化之外也能直接比对；解码失败时按原始字节计算。
- 没有 `?` 时 `has_query` 为 `false`，`segments` 为 `[]`。

### D.4 指纹

```
value_fpr = HMAC-SHA-256(K_fpr, "llmapi-logger/archive-credential-value/v1\x00" || value)
```

- `value` 是 D.3 说的那串字节（Q2 甲：不含名称，不归一化）。域字符串是固定常量，后面只有一个变长字段，不需要长度前缀，与 `security/fingerprint.go` 的写法相同〔核〕。
- `K_fpr` 见 F.3。
- `audit-archive fpr` 子命令（K.1）从终端读入一个已知的 Key，输出它的三种候选：原样、`Bearer ` 加 Key、归一化后的 Key（与 `api_key_fpr` 比对）。

### D.5 投影在哪里做

投影是 `internal/archive` 里的一个纯函数，三处共用：

1. 导出时作用在解密出的热库值上，产生要写的行；
2. 热库一侧算记录摘要时（摘要只吃投影之后的值，E.2）；
3. 读出等价测试里作用在 `query.Detail` 上（J.3）。

块的明文、`user_agent_enc` 和 Request-URI 的明文只在投影函数内部出现，用完即清零，从不进入摘要编码器、行编码器或日志。

---

## E. 记录摘要〔设〕

### E.1 编码记号

沿用第 3 阶段设计 D.1 的记号，再加区分 NULL 的一种（Q9 第 1 点）：

- `B(x) = u64be(len(x)) || x`
- `T(s) = B(s 的字节)`。文本列不是合法 UTF-8 时就是那些原始字节，与 JSON 里写成 `{"b64": …}` 无关。
- `I(v) = B(i64 按补码的 8 字节大端)`，与现有 `digestEncoder.integer` 相同
- `N(e)`：NULL 时为一个字节 `0x00`；否则为 `0x01 || e`
- `H(p) = B(SHA-256(p))`，`p` 是明文
- `L(n) = I(n)`，后面跟 n 个元素
- `V(value)`：非凭据为 `0x00 || H(value)`；凭据为 `0x01 || I(length) || B(value_fpr)`
- `M(s) = T(s)`，表名或段名标记

Request-URI 的投影 `U`：

```
U = M("request_uri") T(path) I(has_query) L(n) 段*
段 = 0x00 T(raw)                                         ; 非凭据段
   | 0x01 T(raw_name) I(has_equals) I(length) B(value_fpr) ; 凭据段
```

### E.2 字节序列

记录摘要是 SHA-256 作用在下面这个序列上：

```
"llmapi-logger/archive-record/v0\x00"                 ; 原样写入，没有长度前缀
T(audit_id)
M("audit_records")
  I(schema_generation) I(started_at_ns) I(ended_at_ns)
  T(route_id) T(protocol) T(parser_name) T(method) T(path)
  U
  T(mode) N(I(status_code)) N(I(ttft_ns))
  T(forward_status) T(capture_status) T(parse_status)
  N(T(blocked_by)) N(T(block_code)) N(T(error_code)) N(T(newapi_request_id))
  T(caller_status) I(caller_attempts) N(I(caller_next_at_ns)) N(I(caller_updated_at_ns))
  N(B(api_key_fpr)) I(parse_save_failures) N(I(parse_next_at_ns))
  I(capture_version)
  N(L(k) V(ua_1) … V(ua_k))                            ; user_agent
M("http_stages") L(n)，每行按阶段顺序：
  T(stage) T(state) T(proto) T(method) T(host)
  N(I(status_code)) N(I(content_length)) I(started_at_ns) N(I(ended_at_ns))
  N(T(error_code)) N(T(content_type)) N(T(content_encoding))
M("headers") I(capture_version) I(block_present) N(L(k) T(stage)*)   ; block_stages
  L(n)，每个值按 Expand 的扁平顺序：
  T(stage) T(kind) T(name) I(value_index) V(value)
M("body_streams") L(n)，每行按阶段顺序：
  T(stage) T(source_stage) I(observed_length) I(stored_length) N(B(sha256))
  I(hash_complete) I(eof_seen) T(state) T(retention_state)
  N(I(first_observed_at_ns)) N(I(last_observed_at_ns))
  I(chunk_count) I(stream_event_count) I(stream_timeline_complete) N(T(error_code))
M("body_chunks") L(n)，每块按（阶段顺序, seq）：
  T(stage) I(seq) I(offset) I(plaintext_length) I(observed_at_ns) H(块明文)
M("stream_timelines") L(n)，每行按阶段顺序：
  T(stage) I(event_count) N(I(first_event_at_ns)) N(I(last_event_at_ns))
  I(timeline_complete) I(plaintext_length) N(H(时间线明文))
M("parsed_results") N(
  T(parser_name) T(parser_version) T(status)
  N(T(request_model)) N(T(response_model)) N(I(requested_stream)) N(I(observed_stream))
  N(T(response_id)) N(I(usage_input)) N(I(usage_output)) N(I(usage_total))
  N(T(error_type)) N(T(error_code)) N(T(upstream_error_class))
  N(I(message_count)) N(I(tool_call_count)) N(I(has_tool_call))
  N(H(解开后的 parsed_json)) I(parsed_at_ns) )
M("token_links") N(
  I(newapi_user_id) T(username) I(newapi_token_id) T(token_name) I(linked_at_ns)
  T(billing_state) N(I(quota)) N(B(quota_per_unit 的 IEEE-754 位，8 字节大端))
  N(I(billed_prompt_tokens)) N(I(billed_completion_tokens)) I(billing_attempts) )
M("turn") N(
  T(turn_id) T(conversation_id) N(T(parent_turn_id)) T(parent_base) T(link_reason) I(link_confidence)
  T(request_layout) T(response_layout) B(request_envelope_hash) B(response_envelope_hash)
  I(request_item_count) I(response_item_count) B(request_sequence_hash) B(response_sequence_hash)
  B(request_reconstruction_hash) B(response_reconstruction_hash) T(reconstruction_status)
  N(T(previous_response_id)) N(T(response_id)) I(created_at_ns)
  M("request_refs") L(n)，物化后的请求引用按序：T(slot) B(object_hash) B(semantic_hash)
  M("response_items") L(n)，按 ordinal：I(ordinal) T(slot) B(object_hash) B(semantic_hash)
  M("content_objects") L(n)，按 object_hash 的字节序：B(object_hash) B(semantic_hash) T(kind) I(plaintext_length)
  M("binary_refs") L(n)，按（object_hash, json_pointer, binary_hash）：
    B(object_hash) T(json_pointer) B(binary_hash) T(media_type) T(encoding)
  M("external_refs") L(n)，按（object_hash, json_pointer, ref_kind）：
    B(object_hash) T(json_pointer) T(ref_kind) B(value_hash) H(value)
  M("binary_objects") L(n)，按 binary_hash 的字节序：B(binary_hash) T(media_type) I(plaintext_length) )
M("conversation") N( T(conversation_id) T(protocol) N(B(key_hash)) I(created_at_ns) )
M("audit_project_identity") N(
  I(identity_version) I(extracted_at_ns) T(source) I(body_scanned)
  N(B(identity_fpr)) N(B(remote_fpr)) N(B(repo_root_fpr)) N(B(cwd_fpr)) N(H(身份明文)) )
M("integrity_events") L(n)，按 sequence：
  I(sequence) T(event_type) N(B(previous_mac)) B(payload_digest) B(event_mac) I(created_at_ns)
```

几点说明：

- **范围。** 把 `capture_finalized` 与 `semantic_compacted` 里“密文的 SHA-256”换成了“明文的 SHA-256”（方案 4.4），再补上两者不覆盖、而归档行里有的列：
  - `audit_records` 的解析与调用者状态、`api_key_fpr`、`schema_generation`；
  - `stored_length`、`chunk_count`、`retention_state` 和两个时间线计数；
  - `body_chunks` 逐块（Q9 第 3 点）；
  - `stream_timelines` 的元数据；
  - `token_links`；
  - 血缘（Q6 甲）；
  - 会话行；
  - 项目标识；
  - 原事件本身。
- **对象只进内容地址**（Q9 第 4 点）。对象的明文、二进制的字节都不进摘要。内容地址就是对明文的哈希：`ContentHash` 作用在规范 JSON 原文上，`BinaryHash` 作用在解码后的字节上〔核：`auditmodel/canonical.go`，`codec.go` 的 `openContent`、`openBinary`〕。重读时逐个重算（J.2）。
- **凭据**以投影形式进入（`V`、`U`），两侧可比，加密包与非加密包相同（5.5）。
- **不在摘要里的：**
  - `revision`：同一内容的不同修订号摘要相同，修订号只在内容变了时才加；
  - 行首的检索字段：它们与表里的值逐项比对；
  - 存储编码列（Q7）；
  - 增量操作（Q6 甲）。
- **只凭行就能重算。** 上面每一项都在行里（C.2）：raw 块和大的 `parsed_json` 以它们明文的 SHA-256 出现，对象以内容地址和元数据出现。对象文件不参与摘要计算，只在 J.2 里与行里的哈希核对。所以重算摘要只需要逐行读，内存只有一行。
- **热库一侧的计算。** 导出时从快照里解密出的值构造投影后的记录结构，用它同时算摘要、写行。重读时从解析出的 JSON 行重新构造同一个结构、重算摘要（J.2）。两条路共用摘要函数，但输入一个来自数据库行，一个来自 JSON 文本，序列化和解析的错误都会在比对时暴露。

### E.3 列覆盖清单

这张表就是列覆盖测试（J.1）执行的规格。在 `internal/archive` 里写成一份数据表（表名、列名、归档字段、是否进摘要、排除理由），测试和编码器都从它读。

| 表 | 进归档且进摘要 | 进归档、不进摘要 | 不进归档（排除理由） |
| --- | --- | --- | --- |
| `audit_records` | 全部列；`request_uri_enc` 以 `U`，`user_agent_enc` 以 `V` 列表 | — | — |
| `http_stages` | 全部列 | — | — |
| `http_headers` | `stage`、`kind`、`name`、`value_index`；`value_enc` 以 `V`；`value_length` 由值长度给出（凭据项为 `length`） | — | — |
| `http_header_blocks` | 块的段集合与是否存在；块内容以扁平列表 | — | `compression`、`plaintext_length`（存储编码） |
| `body_streams` | 全部列 | — | — |
| `body_chunks` | `stage`、`seq`、`offset`、`plaintext_length`、`observed_at_ns`、明文哈希 | 明文（对象文件） | `compression`、`encoded_length`（存储编码） |
| `stream_timelines` | 除 `compression` 外全部；明文哈希 | 明文 | `compression`（存储编码） |
| `parsed_results` | 全部列；`parsed_json_enc` 以解开后的明文哈希 | 明文 | 存储形态（明文或 gzip） |
| `token_links` | 全部列 | — | — |
| `turns` | 全部列 | — | — |
| `turn_context_ops` | — | 全部列（`request_context` 为 `delta` 时） | 以物化引用进摘要（Q6 甲） |
| `turn_response_items` | 全部列 | — | — |
| `conversations` | `conversation_id`、`protocol`、`key_hash`、`created_at_ns` | — | `updated_at_ns`（随后续轮次变化） |
| `content_objects` | `object_hash`、`semantic_hash`、`kind`、`plaintext_length` | 明文、`created_at_ns` | `compression`、`encoded_length` |
| `binary_objects` | `binary_hash`、`media_type`、`plaintext_length` | 字节、`created_at_ns` | `compression`、`encoded_length` |
| `content_binary_refs` | 全部列 | — | — |
| `content_external_refs` | 全部列；`value_enc` 以明文哈希 | 明文 | — |
| `audit_project_identity` | 全部列；`identity_enc` 以明文哈希 | 明文 | — |
| `integrity_events` | 全部列 | — | — |
| `audit_gaps` | — | 全部列（gap 文件，受清单签名保护） | — |

表级的清单：

- 上面 20 张表是“归档表”。
- `audit_analysis`、`agent_spawn_hints`、`analysis_detail_objects` 是“派生表”，不归档（方案已定）。
- 测试同时要求：每张以外键引用 `audit_records`、`turns`、`content_objects`、`binary_objects` 或 `conversations` 的表，要么是归档表，要么在派生表清单上（J.1）。现在这样的表有 `http_stages`、`parsed_results`、`turns`、`token_links`、`audit_analysis`、`agent_spawn_hints`、`audit_project_identity`、`http_header_blocks`，以及经它们间接引用的各表〔核：迁移 001、002、007 的外键〕。

### E.4 每列的来源类别

清单签名只证明“归档那一刻热库里是这些值，并且复核通过”（方案 4.4）。格式文档为每列标出它在热库里本来受什么保护，给读者判断证据强度用：

| 类别 | 含义 | 列 |
| --- | --- | --- |
| 甲 | 原完整性事件的载荷摘要覆盖（经密文哈希或直接） | A.6 表里“覆盖”一栏的列 |
| 乙 | 只有 AEAD 认证：没有密钥伪造不了，但不在任何事件里 | 残缺 Body 的块明文（完整的 Body 经 `body_streams.sha256` 属于甲）、无轮次时 `stream_timelines` 的明文、`identity_enc`，以及无轮次且错误码不是那两种的记录的 `parsed_json_enc` |
| 丙 | 热库里没有任何密码学保护 | `token_links`；`audit_records` 的 `parse_status`、`caller_*`、`api_key_fpr`、`parse_*`；`body_streams` 的 `stored_length`、`chunk_count`；`audit_project_identity` 的明文列；血缘字段；`turn_context_ops`；`conversations`；`audit_gaps` |

---

## F. 清单、签名与密钥派生〔设，派生方式〔核〕〕

### F.1 清单

`<名称>.manifest.json`，明文 JSON，不含任何内容：

```json
{
  "format": "llmapi-logger-archive",
  "format_version": "0",
  "source_schema_version": "8",
  "segment_id": "<32 位十六进制，随机>",
  "run_id": "<32 位十六进制>",
  "bundle_kind": "conversation",
  "protocol": "openai",
  "conversations": ["conv_…"],
  "first_started_at_ns": "…",
  "last_ended_at_ns": "…",
  "created_at_ns": "…",
  "encrypted": true,
  "key_fingerprint": "<64 位十六进制>",
  "tables": { "audit_records": ["audit_id", "schema_generation", "…"], "…": ["…"] },
  "files": [
    { "role": "lines", "name": "<文件名>", "bytes": "…", "sha256": "…" },
    { "role": "objects", "name": "<文件名>", "bytes": "…", "sha256": "…" }
  ],
  "line_count": "…",
  "object_count": "…",
  "raw_chunk_count": "…",
  "members": [
    { "audit_id": "…", "revision": "1", "conversation_id": "conv_…", "started_at_ns": "…",
      "ended_at_ns": "…", "record_digest": "…" }
  ],
  "gaps": null,
  "mac": "<64 位十六进制>"
}
```

- `bundle_kind` 是 `conversation`、`bucket` 或 `gaps`；会话包的 `protocol` 是该会话的协议；gap 包的 `protocol` 和 `conversations` 为 `null` 与 `[]`，`gaps` 是 `{"first_id", "last_id", "count"}`，`members` 为 `[]`。
- `tables` 是 E.3 里“进归档”的列，按格式文档的顺序，供以后的读取工具解释旧包（方案 4.4 的兼容策略）。
- `files[].sha256` 是落盘字节的 SHA-256，不拿密钥也能核对文件是否完整。
- `members` 按行在文件里的顺序列出。

### F.2 签名

```
mac = HMAC-SHA-256(K_sign, "llmapi-logger/archive-manifest/v0\x00" || 清单编码)
```

清单编码（Q10 甲）用 E.1 的记号，字段顺序固定：

```
T(format) T(format_version) T(source_schema_version) T(segment_id) T(run_id)
T(bundle_kind) N(T(protocol)) L(n) T(conversation_id)*
I(first_started_at_ns) I(last_ended_at_ns) I(created_at_ns) I(encrypted) B(key_fingerprint)
L(表数) ( T(表名) L(列数) T(列名)* )*                ; 按表名字节序
L(n) ( T(role) T(name) I(bytes) B(sha256) )*        ; 按 files 的顺序
I(line_count) I(object_count) I(raw_chunk_count)
L(n) ( T(audit_id) I(revision) N(T(conversation_id)) I(started_at_ns) I(ended_at_ns) B(record_digest) )*
N( I(first_id) I(last_id) I(count) )                ; gaps
```

签名的含义：这些文件的字节、这些成员的记录摘要，在归档那一刻对应热库里通过了原完整性复核的行（方案 4.4）。行文件内容由文件哈希和逐行的记录摘要两层绑定；对象文件由文件哈希绑定，对象内容由内容地址自证。

### F.3 三把派生密钥

现有子密钥都是 `HMAC-SHA-256(主密钥, 域字符串)`（A.6）〔核〕，归档沿用同一构造：

| 密钥 | 派生 |
| --- | --- |
| 归档加密密钥 `K_enc` | `HMAC-SHA-256(主密钥, "llmapi-logger/archive-encryption-key/v1\x00")` |
| 归档签名密钥 `K_sign` | `HMAC-SHA-256(主密钥, "llmapi-logger/archive-signing-key/v1\x00")` |
| 凭据指纹密钥 `K_fpr` | `HMAC-SHA-256(主密钥, "llmapi-logger/archive-credential-fingerprint-key/v1\x00")` |
| 密钥指纹（清单里） | `HMAC-SHA-256(K_sign, "llmapi-logger/archive-key-fingerprint/v1\x00")` |

- 三个域字符串互不相同，也不同于现有的三个，所以这几把密钥两两独立，也独立于完整性签名密钥（方案 4.4）。
- 新增 `security.ArchiveKeys`：像 `IntegritySigner` 一样只持有派生结果，不暴露主密钥；在 `assembleAuditWithStore` 里与其他子密钥一起派生，主密钥随后清除〔核：`app/app.go` 的 `defer clear(key)`〕。
- `audit-archive` 读主密钥文件，用同一个函数派生。
- 读取工具先比对 `key_fingerprint`，不符就报“密钥不匹配”，不尝试解密。

---

## G. 整包加密

### G.1 两条路的比较

方案 4.4 的要求：分帧的认证加密；每帧独立认证；帧序号和末帧标记参与认证，截断、重排、拼接都能检出；文件头带格式版本和随机盐。

| | 甲：仓库内，STREAM 构造加 AES-256-GCM | 乙：库 |
| --- | --- | --- |
| 依赖 | 只用标准库：`crypto/aes`、`crypto/cipher`、`crypto/hmac`、`crypto/sha256`；仓库已经在用 AES-256-GCM（`security/aesgcm.go`）〔核〕 | `filippo.io/age` 需要 `golang.org/x/crypto`；Tink 的 streaming AEAD 依赖更多，含 protobuf〔推：外部资料，没有在本仓库核对〕。`go.mod` 里两者都没有〔核〕 |
| 测试环境 | 无影响 | 测试容器没有网络，新模块要预先进模块缓存或随仓库带上 |
| 与需求的贴合 | 只做需要的部分：一把派生出的对称密钥加盐 | `age` 的文件头是 recipient 列表，要为“主密钥派生的对称密钥”写自定义 recipient；Tink 要用它的密钥集格式 |
| 评审负担 | 约两三百行新的密码学代码，必须单独评审 | 库本身已经过评审，但接入代码和文件头的处理仍要评审 |
| 测试向量 | 自己定，钉在 testdata | 用库的向量，另加接入层的向量 |

推荐甲（Q11）。这个构造就是 `age` 和 Tink 用的 STREAM（Hoang、Reyhanitabar、Rogaway、Vizár 2015）〔推：外部资料〕：每个文件一把用随机盐派生的密钥，nonce 由帧序号和末帧标记组成。不同文件之间没有 nonce 复用的可能，同一文件内序号不重复。

### G.2 帧格式〔设〕

文件头，共 40 字节：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | 魔数 `LLAR`（`0x4C 0x4C 0x41 0x52`） |
| 4 | 1 | 格式版本 `0x01` |
| 5 | 1 | 帧大小的以 2 为底的对数，固定 `0x10`（64 KiB） |
| 6 | 2 | 保留，必须为 `0x00 0x00` |
| 8 | 32 | 随机盐 |

文件密钥：

```
K_file = HMAC-SHA-256(K_enc, "llmapi-logger/archive-file-key/v1\x00" || 文件头全部 40 字节)
```

文件头的每个字节都进了密钥派生，所以改动文件头的任何一位，后面所有帧都解不开。

帧：

- 明文按 65,536 字节切成帧 `P_0 … P_n`。除最后一帧外每帧恰好 65,536 字节，最后一帧 0 到 65,536 字节。只有整个明文为空时，最后一帧（也是唯一一帧）才是空的。
- 第 i 帧的 nonce 是 12 字节：前 11 字节为 i 的大端编码，最后 1 字节在最后一帧为 `0x01`，其余帧为 `0x00`。
- `C_i = AES-256-GCM-Seal(K_file, nonce_i, P_i, AAD = 空)`，长 `len(P_i) + 16`。
- 文件 = 文件头 `|| C_0 || … || C_n`，没有帧长字段：除最后一帧外每帧密文都是 65,552 字节。

写入方攒满一帧且还有后续数据时才发出非末帧；`Close` 时把手里剩下的（可能是整帧）作为末帧发出。所以写入方从不需要预先知道总长度。

读取方：

1. 读 40 字节文件头，核对魔数、版本、帧大小、保留字节。
2. 每次读至多 65,552 字节：
   - 读满且后面还有字节：按非末帧解；
   - 读满且后面恰好是文件尾：按末帧解；
   - 不满 65,552 字节：必须是文件尾，按末帧解；
   - 不足 16 字节：错误。
3. 解开末帧之后还有字节就是错误。

任何一帧认证失败都中止，不输出这一帧的明文。

能检出的篡改：

| 篡改 | 为什么能检出 |
| --- | --- |
| 在帧边界截断 | 新的最后一帧是按非末帧加密的，用末帧 nonce 解不开 |
| 在帧中间截断 | 最后一帧的认证标签不对 |
| 帧重排、删除中间一帧 | 序号进了 nonce |
| 从另一个文件拼接帧 | 盐不同，文件密钥不同 |
| 在末尾追加 | 原来的末帧变成了非末帧位置，解不开；或者末帧之后还有字节 |
| 改文件头 | 文件密钥变了 |

### G.3 固定测试向量

`internal/archive/stream/testdata/vectors.json`，仿照 `internal/headerblock/testdata/vectors.json` 的做法〔核：该文件存在〕。

- **输入**：固定的 32 字节 `K_enc`（测试常量，不是任何真实密钥）、固定的 32 字节盐，明文长度 0、1、65,535、65,536、65,537、200,000（内容为确定的伪随机序列）。
- **期望值**：完整密文的 SHA-256、前 64 字节的十六进制、文件长度。
- **篡改用例**（对 200,000 字节的那一个）：在每个帧边界截断、交换第 0 帧和第 1 帧、去掉第 1 帧、拼入另一个盐的第 1 帧、追加 1 字节、翻转文件头每一位、翻转每帧最后一字节。每一种都要求读取失败，认证失败的那一帧的明文不交出。

流式读取时，失败之前的帧已经交给了上层（gzip 解压、逐行解析）。所以上层把任何一个读取错误都当作整个文件作废：`verify` 和运行时的重读核对读完全文件才下结论；`cat` 和 `export` 先完整核对一遍，再从头输出（K.1）。

主密钥到 `K_enc` 的派生也钉一个向量（F.3）。

---

## H. 一次运行〔设，复用的函数〔核〕〕

### H.1 调度

- 新包 `internal/archive/runner`，结构照搬 `sessionanalysis.Runner`：`run_at` 用 `config.ParseRunAt` 校验，`untilNextRun` 的算法相同，同一时间只有一次运行。
- 时区取 `archive.timezone`（L.1）。
- **补跑**：启动时读 `archive_runs` 里最近一次 `completed` 的开始时间，早于 24 小时前（或者没有）时，在启动校验结束后排一次运行。现有的每日任务没有补跑（A.5），但归档漏跑一天，热库就多留一天，而 5.2 承诺的是“最多一天”。

### H.2 一趟的步骤

一次运行先对账（H.6），然后一趟接一趟（B.2）。每一趟：

1. **快照。** 在只读连接池上开 `READ ONLY, REPEATABLE READ` 事务，按 B.1 选出本趟的 audit 并分组（B.3）。不占用 writer。
2. **逐个包、逐条 audit 读与写。** 包内的行顺序见 B.3。对每条 audit：
   1. 在同一个快照里读出它在各归档表里的行，密文原样读出。读法复用 `readTurnGraph`、`readHeaderEvidence`、`readHeaderBlockEvidence`、`readBodies` 等现有函数，外加一个按 audit 读 `body_chunks`、`stream_timelines`、`token_links`、`audit_project_identity`、`conversations`、`integrity_events` 的函数。物化请求引用用 `loadRequestRefs`，每个会话一个 memo。
   2. **复核原完整性事件（H.3）。** 不通过就跳过这条 audit。
   3. 解密并校验：
      - 每段密文用它原来的 AAD 认证解密；
      - 对象重算内容地址和语义哈希；
      - 完整的 Body 把块明文依次求 SHA-256，与 `body_streams.sha256` 比对；
      - 时间线按 `query.Timeline` 的规则检查边界。
      任何一项失败同样跳过，记 `archive_integrity_failed`。
   4. 凭据投影（D 节），构造记录结构，算记录摘要（E 节），在快照里算变更戳（M.1）。
   5. 写一行；本分段还没写过的对象和 raw 块写进对象文件。
3. **关文件。** 依次关 gzip、关加密写入器（发出末帧）、`fsync`、关文件。
4. **登记意向。** 一个 writer 操作，在目录表插入 `publishing` 状态的分段行和全部成员行（记录摘要、变更戳、修订号），以及 gap 成员行（I 节）。
   - 重新收录的成员（B.1 第 4 条）如果还有一个非 `stale` 的旧行（只在试行格式分段里的 `sealed` 成员会这样），同一个操作先把旧行改为 `stale`，再插入新行，满足 `archive_members_current_idx`。
   - 同一个操作在事务内重算这些成员的变更戳，与快照里算出的比对：不同的成员直接登记为 `stale`（快照之后它已经变了），下次运行重新收录。目录表与清单的成员列表因此始终一一对应。
5. **发布。**
   1. 数据文件从临时名改为正式名。用 `os.Link` 加删除临时名，正式名已存在时失败，不覆盖。这与 `security/key.go` 发布密钥的做法相同〔核〕。
   2. 写清单的临时文件、`fsync`，同样以 link 发布。
   3. `fsync` 目录。Windows 上目录 `fsync` 是空操作，暂存目录也是如此〔核：`audit/staging/platform_windows.go`〕；部署目标是 Linux 容器。
6. **重读核对。** 重新打开已发布的文件做 J.2 的全部检查，再按 `archive.verify_sample` 抽样做 J.3 的读出等价比对。
7. **定稿。** 一个 writer 操作把分段改为 `sealed`。

移除不在这里做。一次运行的全部趟都结束（或到了期限）之后，`archive_then_delete` 模式下才统一进入 M 节，对象是全部 `sealed` 分段里格式版本不低于 1 的 `sealed` 成员。原因：同一个会话可能被滚动切进同一趟的 `_s0001` 和 `_s0002`，先移除 `_s0001` 里的父轮次会让检查点改写 `_s0002` 里的子轮次，子轮次随之变成 `stale`（0.2 第 9 条）。等全部分段都定稿后再按 M.2 的全局顺序删，子轮次总在父轮次之前。

某个分段在第 6 步作废时，它的成员仍是热库里的普通 audit，不是成员；移除别的分段里它们的父轮次，由检查点照常处理，它们下次以检查点之后的形态重新收录。

第 6 步任何一项不过：

- 这个包作废：三个文件改名加 `.rejected` 后缀。清单也改名，所以读取工具不会再索引到它们。文件不删除，留作诊断。
- 目录表里的意向行删掉。
- 成员留在热库，下一次运行重新收录。

### H.3 复核原完整性事件

对每条 audit：

1. 它的事件必须齐全：有 `capture_finalized`；有轮次就有 `semantic_compacted`。
2. 每个事件：
   - 用 `integrityPayloadDigestFor(ctx, tx, cache, auditID, eventType, schemaLive)` 在同一个快照里重算载荷摘要，与存储的 `payload_digest` 比对；
   - 用 `store.integrity.Load()` 的 `IntegritySigner.Verify(previous_mac, audit_id, event_type, payload_digest, event_mac, created_at_ns)` 核对 MAC〔核：两个函数都在 `postgres/integrity.go`、`security/integrity.go`〕。
3. `cache` 是 `newIntegrityGraphCache()`，按会话重置，与后台载荷校验相同。

复核读的密文哈希和第 2.3 步解密的密文来自同一个快照，所以“事件绑定的密文”和“写进归档的明文”是同一份。

链的连续性（`previous_mac` 等于上一个事件的 MAC）不在这里核对：启动时 `EnableIntegrity` 已经核对过整条链。单个事件的 MAC 足以证明它没有被伪造。

### H.4 失败

| 情形 | 处理 |
| --- | --- |
| 复核不过或解密失败的 audit | 不归档、不删除，留在热库；登记进 `archive_deferred`（`integrity_failed`），之后每次运行再试一次；计入本次运行的 `integrity_failed_audits`；日志 `error_category=archive_integrity_failed`。存储的载荷校验状态置为失败，与后台载荷校验发现损坏时相同（P 节第 4 条） |
| 磁盘满、写失败、`fsync` 失败 | 删掉本趟的临时文件（只删本次运行自己创建、自己记下名字的临时文件），不登记；本次运行以 `archive_failed` 结束，日志带 `error_category=archive_failed`；10 分钟后重试，直到 `run_deadline` |
| 登记意向失败（writer 不可用） | 同上：临时文件删掉，未发布 |
| 发布后、定稿前崩溃 | 下次运行对账（H.6） |
| 定稿后、移除前崩溃 | 下次运行对账时继续 M 节 |

启用归档后，任何情况下都不会跳过归档直接删（方案 4.5）：retention 的直接删除在 `archive.mode != off` 时不组装（L.2）。

### H.5 日志与状态

- 日志只写稳定的状态码、计数、字节数和耗时（`AGENTS.md`）。不写路径、文件名、会话 ID 以外的内容，不写底层错误原文；存储错误照现有做法只给 `storage.ErrorClass`。
- 每次运行在 `archive_runs` 留一行（I 节）。管理界面和 Agent 门面本阶段不展示它，只供补跑判断和排障时查库。
- 启动日志：`export_only` 提示热库会持续增长（5.7 第 2 条）；L.2 的回切提示。

### H.6 对账

每次运行开始时：

1. **`publishing` 的分段**：清单已发布且通过 J.2 → 继续 H.2 第 6 步；否则删掉意向行，已发布的数据文件改名加 `.orphan`。
2. **归档目录里有清单、目录表里没有的包**（数据库从备份恢复之类）：用密钥核对 J.2，通过的登记为 `sealed` 的分段，成员一律登记为 `stale`（Q12 第 2 点）：可以读，永远不作为删除依据。
   - 分段行的 `run_id` 记为执行这次对账的运行，清单里原来的 `run_id` 只留在文件里，所以 `archive_runs` 的外键成立。
   - 某个成员在目录表里已有非 `stale` 的行时，只登记分段，不登记这个成员。
3. **残留的临时文件**：文件名形如 `.<名称>.tmp-<随机>`，只有归档器会这样命名，删除。**没有清单的数据文件**：改名加 `.orphan`，不删除。
4. **`sealed` 分段里仍为 `sealed` 的成员**：`archive_then_delete` 模式下继续移除（M 节）。

对账只读、只改名，唯一删除的是第 3 步的临时文件。

### H.7 内存上界

- 一次只在内存里持有一条 audit 的行，以及当前处理的一个对象或一个 raw 块（至多 1 MiB）。
- 每个分段一个“已写对象”的哈希集合（每个 32 字节）。
- 每个会话一个 `integrityGraphCache` 和一个 `loadRequestRefs` 的 memo，上界与后台载荷校验相同：最大的单个会话〔核：`integrity.go` 的注释，`loadRequestRefs` 的 `memoEndpointLimit`、`memoReferenceLimit`〕。
- 解开后的 `parsed_json` 最大 128 MiB（`auditmodel.MaxParsedResultBytes`）〔核〕，一行至多这么大。这只出现在没有轮次、解析不完整的旧记录上。
- gzip 和加密都是流式的，各自只有一帧（64 KiB）的缓冲。

---

## I. 目录表（迁移 008）〔设〕

### I.1 SQL

新文件 `internal/storage/postgres/migrations/008_archive_catalog.sql`：

```sql
-- Cold archive catalog (doc/design/issue-59-stage4-cold-archive.md, I).
-- Management data only: no table here is part of the integrity event chain,
-- none references audit_records (an archived audit is later removed), and the
-- SQLite offline importer never sees them.
CREATE TABLE archive_runs (
    run_id TEXT COLLATE "C" PRIMARY KEY CHECK (length(run_id) = 32),
    mode TEXT COLLATE "C" NOT NULL CHECK (mode IN ('export_only', 'archive_then_delete')),
    cutoff_ns BIGINT NOT NULL CHECK (cutoff_ns > 0),
    started_at_ns BIGINT NOT NULL CHECK (started_at_ns > 0),
    finished_at_ns BIGINT,
    status TEXT COLLATE "C" NOT NULL CHECK (status IN ('running', 'completed', 'archive_failed', 'interrupted')),
    exported_audits BIGINT NOT NULL DEFAULT 0 CHECK (exported_audits >= 0),
    integrity_failed_audits BIGINT NOT NULL DEFAULT 0 CHECK (integrity_failed_audits >= 0),
    stale_audits BIGINT NOT NULL DEFAULT 0 CHECK (stale_audits >= 0),
    removed_audits BIGINT NOT NULL DEFAULT 0 CHECK (removed_audits >= 0),
    removed_gaps BIGINT NOT NULL DEFAULT 0 CHECK (removed_gaps >= 0),
    deferred_audits BIGINT NOT NULL DEFAULT 0 CHECK (deferred_audits >= 0),
    segments BIGINT NOT NULL DEFAULT 0 CHECK (segments >= 0),
    disk_bytes BIGINT NOT NULL DEFAULT 0 CHECK (disk_bytes >= 0),
    -- Selection watermark (B.1) after the last completed pass, for this format.
    format_version BIGINT NOT NULL CHECK (format_version >= 0),
    watermark_started_at_ns BIGINT,
    watermark_audit_id TEXT COLLATE "C",
    CHECK ((watermark_started_at_ns IS NULL) = (watermark_audit_id IS NULL))
);

-- Audits a pass looked at behind the watermark but did not export, which the
-- next passes check again (B.1).
CREATE TABLE archive_deferred (
    audit_id TEXT COLLATE "C" PRIMARY KEY,
    reason TEXT COLLATE "C" NOT NULL CHECK (reason IN ('open', 'parse_pending', 'caller_pending', 'integrity_failed', 'export_failed')),
    first_seen_at_ns BIGINT NOT NULL CHECK (first_seen_at_ns > 0),
    last_checked_at_ns BIGINT NOT NULL CHECK (last_checked_at_ns >= first_seen_at_ns)
);

CREATE TABLE archive_segments (
    segment_id TEXT COLLATE "C" PRIMARY KEY CHECK (length(segment_id) = 32),
    run_id TEXT COLLATE "C" NOT NULL REFERENCES archive_runs(run_id) ON DELETE RESTRICT,
    bundle_kind TEXT COLLATE "C" NOT NULL CHECK (bundle_kind IN ('conversation', 'bucket', 'gaps')),
    format_version BIGINT NOT NULL CHECK (format_version >= 0),
    -- Relative to archive.dir, forward slashes; never an absolute path.
    manifest_name TEXT COLLATE "C" NOT NULL UNIQUE
        CHECK (length(manifest_name) BETWEEN 1 AND 1024 AND left(manifest_name, 1) <> '/'),
    manifest_sha256 BYTEA CHECK (manifest_sha256 IS NULL OR length(manifest_sha256) = 32),
    key_fingerprint BYTEA NOT NULL CHECK (length(key_fingerprint) = 32),
    encrypted BIGINT NOT NULL CHECK (encrypted IN (0, 1)),
    member_count BIGINT NOT NULL CHECK (member_count >= 0),
    disk_bytes BIGINT NOT NULL CHECK (disk_bytes >= 0),
    first_started_at_ns BIGINT,
    last_ended_at_ns BIGINT,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('publishing', 'sealed', 'hot_removed')),
    created_at_ns BIGINT NOT NULL CHECK (created_at_ns > 0),
    sealed_at_ns BIGINT,
    removed_at_ns BIGINT,
    CHECK (state = 'publishing' OR (manifest_sha256 IS NOT NULL AND sealed_at_ns IS NOT NULL))
);

CREATE TABLE archive_members (
    audit_id TEXT COLLATE "C" NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    segment_id TEXT COLLATE "C" NOT NULL REFERENCES archive_segments(segment_id) ON DELETE CASCADE,
    record_digest BYTEA NOT NULL CHECK (length(record_digest) = 32),
    -- NULL only for members registered from an unrecorded bundle (stale).
    change_stamp BYTEA CHECK (change_stamp IS NULL OR length(change_stamp) = 32),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('sealed', 'hot_removed', 'stale')),
    started_at_ns BIGINT NOT NULL,
    -- turns.created_at_ns at export; NULL for an audit without a turn. Removal
    -- deletes in descending order of it (M.2).
    turn_created_at_ns BIGINT,
    state_changed_at_ns BIGINT NOT NULL CHECK (state_changed_at_ns > 0),
    PRIMARY KEY (audit_id, revision),
    CHECK (state = 'stale' OR change_stamp IS NOT NULL)
);

-- At most one current (not stale) member per audit.
CREATE UNIQUE INDEX archive_members_current_idx
    ON archive_members (audit_id) WHERE state <> 'stale';
CREATE INDEX archive_members_segment_idx ON archive_members (segment_id);
CREATE INDEX archive_members_removal_idx
    ON archive_members (segment_id, turn_created_at_ns DESC, audit_id) WHERE state = 'sealed';

CREATE TABLE archive_gap_members (
    gap_id BIGINT PRIMARY KEY,
    segment_id TEXT COLLATE "C" NOT NULL REFERENCES archive_segments(segment_id) ON DELETE CASCADE,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('sealed', 'hot_removed'))
);
CREATE INDEX archive_gap_members_segment_idx ON archive_gap_members (segment_id);
```

- **状态迁移。** 分段 `publishing → sealed → hot_removed`，`publishing` 的意向行可以被对账删除（级联删掉成员行）。成员 `sealed → hot_removed`，或 `sealed → stale`。
- **锁与耗时。** 全是新表，不改已有的表，迁移不扫描任何数据。
- **索引。** `archive_members_current_idx` 同时服务 B.1 第 4 条的 `NOT EXISTS`。

### I.2 新迁移版本还要改的地方

照迁移 006、007 的先例〔核〕：

| 位置 | 改动 |
| --- | --- |
| `postgres/migrate.go` | `derivedMigrations` 加 `{8, "migrations/008_archive_catalog.sql"}`，`latestSchemaVersion = 8`；迁移文件经 `//go:embed migrations/*.sql` 自动嵌入 |
| PostgreSQL 的迁移测试 | `migration_semantic_index_test.go`、`migration_turns_created_index_test.go`、`migration_header_block_test.go` 里断言“全部已应用”的 `requireVersions(…, 1, 2, 3, 4, 5, 6, 7)` 都要加上 8；新增 `migration_archive_catalog_test.go`：首次打开、重复打开、从 7 升到 8、回滚 SQL 之后再升级 |
| `doc/features/04-sqlite-storage-and-migrations.md` | 新增 §3.10 |
| `doc/deployment/postgresql-migration.md` | 新增“回滚到 schema 版本 7”（I.3） |
| 离线导入器、`audit-stage` | 不用改（0.2 第 5 条） |
| SQLite 存储 | 不加迁移：归档只在 PostgreSQL 上（第 3 阶段 H.2 的先例）。`HasAudits` 同步改为也检查 `integrity_events`（L.3），两个存储语义一致〔核：SQLite 的 `HasAudits` 与 PostgreSQL 的形状相同，`integrity_events` 由 SQLite 迁移 005 建立〕 |

旧版本打开 schema 8 的库时，因版本过新（`errSchemaTooNew`）而审计存储不可用：`available` 模式照常转发、不留 audit，`strict` 模式回 `503`（方案 4.5 的更正）。旧版本的配置加载用 `KnownFields(true)`〔核：`config/load.go`〕，配置里有 `archive:` 段会拒绝启动。

### I.3 回滚

```sql
-- 仅在回滚到不含迁移 008 的版本时执行；先把 archive.mode 设为 off 并停止新版本
BEGIN;
DROP TABLE archive_gap_members;
DROP TABLE archive_deferred;
DROP TABLE archive_members;
DROP TABLE archive_segments;
DROP TABLE archive_runs;
DELETE FROM schema_migrations WHERE version = 8;
COMMIT;
```

部署说明要写明三点：

1. 归档目录里的包不受回滚影响，读取工具照常可读。
2. 目录表是“哪些成员已从热库移除”的唯一库内记录。回滚前先 `pg_dump` 这五张表，留作对照；清单里也有同样的成员列表。
3. 旧版本的 `HasAudits` 不看目录表。所以回滚后密钥文件绝不能缺失，否则会落进 0.2 第 8 条的隐患。

---

## J. 三层证明

### J.1 列覆盖〔设〕

**规格。** E.3 的数据表 `archive.Columns`，每项是 `{表, 列, 归档字段, 进摘要, 排除理由}`。派生表清单 `archive.DerivedTables`。

**PostgreSQL 上的测试** `internal/storage/postgres/archive_columns_test.go`：

1. 在自己的 schema 里打开存储（应用全部迁移），从 `information_schema.columns` 读出全部归档表与派生表的列：`table_schema = current_schema()`。
2. 与 `archive.Columns` 逐列比对：
   - 库里有、规格里没有的列 → 失败，消息给出 `表.列`；
   - 规格里有、库里没有的 → 失败；
   - 排除项必须有非空理由。
3. 从 `pg_constraint`（`contype = 'f'`）读出所有外键，求出直接或间接引用 `audit_records`、`turns`、`content_objects`、`binary_objects`、`conversations` 的表。每张都必须是归档表或派生表。
4. **证明它真的会失败**（方案第 7 节）：同一测试的第二部分执行 `ALTER TABLE http_stages ADD COLUMN archive_probe TEXT`，调用同一个检查函数，断言返回的错误恰好点名 `http_stages.archive_probe`；再 `CREATE TABLE archive_probe_child (audit_id TEXT REFERENCES audit_records(audit_id))`，断言点名这张表。检查函数是导出给测试用的普通函数，正式测试与“证明会失败”的部分调用的是同一个。

**主机上的测试**（不需要数据库）`internal/archive/digest_test.go`：

- **摘要敏感性**：构造一条每列都非空的合成记录。对 `archive.Columns` 里每个“进摘要”的列，只改这一列（文本加一个字节、整数加一、哈希翻一位），断言摘要变化；可空列另测 NULL 与 `''`（或 0）的摘要不同。
- **行往返**：编码成行再解析回来，记录结构逐字段相等，摘要相等；每个“进归档”的列都在行里出现。
- 测试向量：一条固定记录的摘要钉在 testdata，格式文档引用它。

### J.2 数据一致（每次重读核对）〔设〕

对一个包依次做，任何一项不过整个包作废（H.2）：

1. 清单：
   - 解析，核对 `format`、`format_version`；
   - 比对 `key_fingerprint`；
   - 重算 `mac`；
   - 每个文件的落盘字节数与 SHA-256 等于清单。
2. 解密（G.2）、解压、逐行解析：
   - 行数等于 `line_count`，行的顺序与 `members` 相同；
   - 对象文件的对象数、raw 块数等于清单。
3. 每一行：
   - 行首字段与行内各表一致；
   - `audit_id`、`revision` 与成员项一致；
   - 从行重算记录摘要，等于行尾的 `record_digest`、清单的成员项，以及导出时从热库算出的值（H.2 第 2.4 步）。运行时的重读核对比对内存里的值；对账时比对目录表的意向行。
4. 对象：
   - `content_object`：`ContentHash(data)` 等于 `object_hash`；解析出的值用 `auditmodel.SemanticHash(kind, value)` 重算，等于 `semantic_hash`；明文长度相符；
   - `binary_object`：`BinaryHash(bytes)` 等于 `binary_hash`，长度相符；
   - 行里 `turn.objects`、`turn.binaries` 的每一项（语义哈希、kind、长度、媒体类型）与对象文件里同一哈希的那一项相同；
   - 行里的 `external_refs`：`ExternalValueHash(ref_kind, value)` 等于 `value_hash`〔核：`auditmodel/canonical.go`〕。
5. raw 与大的 `parsed_json`：
   - 对象文件里每个 `raw_chunk` 的字节，SHA-256 和长度等于行里同一 `(stage, seq)` 的那一项；`parsed_json_part` 按序拼起来等于 `parsed_json_ref` 的长度和 SHA-256；
   - 每个 `full` 阶段的块按 `seq`、`offset` 连续，只有 `capture_chunk_missing` 允许前向跳过（与 `query.StreamRaw` 相同）；
   - 块数和字节数等于 `body_streams` 的 `chunk_count`、`stored_length`；
   - 完整的 Body 拼接后的 SHA-256 与长度等于 `sha256`、`observed_length`；
   - 残缺的 Body 由记录摘要逐块覆盖（第 3 步）。
6. 引用闭合：
   - 每行 `turn.objects`、`turn.binaries`、`request_context`、`response_items`、`raw_chunks`、`parsed_json_ref` 里出现的东西都在本包的对象文件里；
   - `delta` 形式的轮次，父轮次在本分段且排在它前面，用 `auditmodel.ApplyDelta`（`post_turn` 时基底接上父轮次的响应引用）重建出的引用条数与 `SequenceHash` 等于 `request_item_count`、`request_sequence_hash`；
   - `materialized` 形式直接核对同样两项；
   - 包内没有任何指向热库的引用：每个被引用的东西要么在行里，要么在对象文件里。
7. 原完整性事件的 MAC：用主密钥派生的 `IntegritySigner` 逐个核对。载荷摘要绑定的是密文，从明文算不出来（方案 2.1），这一步证明的是事件本身是真的。

### J.3 读出等价〔设〕

**比较的东西。** 设 `P` 是 D.5 的投影函数在查询层输出上的作用：Header 的值换成 `V` 形式、`ValueLength` 换成凭据项的 `length`、`RequestURI` 换成 D.3 的结构、User-Agent 逐值投影。对每条成员 audit，下面每一对在 `P` 之后逐项相等：

| 热库（`query.Service`） | 读取工具（`archive.Reader`） |
| --- | --- |
| `Get` 的 `Detail`，去掉 `Audit.ConversationTurns` | `Detail` |
| `List` 的那一行 `AuditSummary`（含 User-Agent），去掉 `ConversationTurns` | 同一个摘要 |
| `ReconstructTurn` 的 `Turn`、`Request`、`Response`、`Conversation`（`Request`、`Response` 比 `auditmodel.CanonicalJSON` 的字节） | 同 |
| `SessionConversation` | 同 |
| `Timeline(request)`、`Timeline(response)` | 同 |
| `RawMeta`、`StreamRaw` 的两侧（元数据和全部字节） | 同 |

- 出错时比较错误的类别（`ErrNotFound`、`ErrNotRetained`、`ErrNotReady`、`ErrNoTurnGraph`、`ErrIntegrity`），不比消息。
- `DisplayName` 不在查询层的输出里，不比（A.3）。

**测试**（需要 PostgreSQL，放在 `tests/integration`）：

- `protofixture.Catalog()` 的全部用例：四个协议 × 流式与非流式 × 正常与异常场景，经真实的代理、解析 worker 和存储写入。legacy（采集版本 1）与 unified（采集版本 2）各跑一遍。
- 再加旧形态的行：
  - 旧的 OpenAI 流式 layout；
  - 没有轮次、会话在 `parsed_json_enc`、raw 为 `full` 的 Anthropic 与 Gemini 记录；
  - 四阶段全 `full` 的异常记录。

  这些按现有测试的做法替换 `rawRetentionDecision` 等钩子写出〔核：`graph_writer.go` 的 `rawRetentionDecision` 变量〕。
- 导出之后，对每条成员逐对比较上表。

**运行时**按 `archive.verify_sample`（默认 0.05，且每个包至少一条）抽样：

- 发布之后，用正常的 `query.Service` 读热库，与读取工具从刚发布的包读出的比较。
- 热库一侧这时已不在导出快照里：比较不等时，先在 writer 里重算这条成员的变更戳。
  - 与快照时的不同：这条成员改记 `stale`，不算包的错误；
  - 相同：包作废。

---

## K. `cmd/audit-archive`〔设〕

### K.1 子命令

只读归档目录，不连数据库（方案 4.7）。

| 子命令 | 需要密钥 | 做什么 | 输出 |
| --- | --- | --- | --- |
| `list` | 否 | 按清单列出包：种类、协议、时间范围、成员数、会话、是否加密、格式版本。可按 `--conversation`、`--audit` 过滤。给了 `--key` 时顺带核对清单签名 | 表格，或 `--json` 的 JSON 行 |
| `verify` | 不给只做无密钥的一层，给了做全部 | 不给密钥：清单可解析、文件字节数和 SHA-256 与清单一致。给密钥：J.2 的全部检查，包括事件 MAC。对一个包或整个目录 | 每个包一行结果码（`ok`、`file_mismatch`、`mac_mismatch`、`key_mismatch`、`decrypt_failed`、`digest_mismatch`、`object_mismatch`、`reference_open` 等）；有失败时退出码非零 |
| `cat` | 是 | 先对涉及的包做完整的 J.2，再把明文 JSONL 写到标准输出。按 `--conversation`、`--audit` 过滤；同一 audit 默认只输出最高修订号，`--all-revisions` 全部输出；`--with-objects` 附带对象行 | JSONL，凭据只有投影形式 |
| `export` | 是 | 把一条 audit 导出成单条导出的某一种形态：`--what` 取值与 Agent 门面的 `agentExportKinds` 相同（`conversation`、`headers`、`request`、`response`、`raw-request`、`raw-response`、`timeline-request`、`timeline-response`）；给 `--conversation` 时按轮次顺序输出该会话全部轮次的 `conversation` | 与门面导出相同的 JSON，raw 为原始字节；`headers` 是投影形式 |
| `fpr` | 是 | 从终端不回显地读入一个已知的 Key，输出 D.4 的三种候选指纹 | 三行十六进制 |

- 加密关闭的包（`.jsonl.gz`），`cat` 和 `export` 在没有密钥时拒绝，除非加 `--unauthenticated`。这时不核对签名，在标准错误上提示输出未经认证。
- 帮助文本写明：`cat`、`export` 的输出是明文对话内容，没有凭据值，去向由使用者负责（方案第 8 节）。

### K.2 索引

1. 递归遍历归档目录，取全部 `*.manifest.json`；跳过带 `.rejected`、`.orphan` 后缀的。
2. 逐个解析清单。有密钥时核对 `mac` 和 `key_fingerprint`，不通过的清单报告后跳过。
3. 建两张索引：`audit_id → [(修订号, 分段)]`，同一 audit 取最高修订号；`conversation_id → [分段]`。
4. 按会话或 audit 查找时只靠这两张索引，从不按文件名匹配（5.3）。

一个会话的全部轮次可能分布在多个包里，`export --conversation` 按 `turns.created_at_ns` 合并排序。

### K.3 与查询层共用代码

查询层不依赖 PostgreSQL（A.3），可以直接被 `cmd/audit-archive` 引入。问题在于它的重建函数吃的是密文：`reconstructTurnGraph` 自己调 `OpenObject`、`OpenBinary`，`Get` 自己解 Request-URI 和 Header，`Timeline` 和 `StreamRaw` 自己解密〔核〕。归档里只有明文。

做法：把查询层拆成“解密”与“从明文组装”两段，组装那段导出。

1. `internal/query/plain.go`（新）定义 `PlainDetail`：与 `storage.AuditQueryDetail` 同样的行，密文列换成明文；轮次图的对象换成解开的 `DecodedObject` 和二进制字节。
2. 导出的组装函数：
   - `BuildDetail(PlainDetail) (Detail, error)`：今天 `Get` 里除解密以外的部分；
   - `ReconstructPlainTurn(parserName string, graph PlainTurnGraph) (ReconstructedTurn, error)`：今天 `reconstructTurnGraph` 里除 `OpenObject`、`OpenBinary` 以外的部分，含语义哈希、序列哈希、重建哈希的核对、`Assemble`、`RestoreBinaries`、`RebuildConversation`；
   - `TimelineFromPlain(meta, plaintext) (StreamTimeline, error)`；
   - `VerifyRaw(meta, chunks)`：`StreamRaw` 的连续性和哈希核对，以块的明文迭代器为输入。
3. 热库路径改为“解密成 `PlainDetail` → 组装”，行为不变；现有的查询测试全部照跑。
4. 读取工具把归档行解析成 `PlainDetail`，调同一组组装函数。两边只在“明文从哪里来”上不同，读出等价测试（J.3）比的就是这一段。

凭据投影不进查询层：读取工具给出的 `Detail` 里，Header 和 Request-URI 是投影形式，由 `internal/archive` 定义的投影类型承载（D.5）。

依赖守卫：一个测试对 `cmd/audit-archive` 跑 `go list -deps`，断言其中没有 `internal/storage/postgres` 和 `github.com/jackc/pgx`。

---

## L. 配置与护栏

### L.1 `archive` 段〔设〕

```yaml
archive:
  mode: off                       # off | export_only | archive_then_delete
  dir: ""                         # 绝对路径；mode 不为 off 时必填
  encrypt: true
  run_at: "03:00"                 # 本地时间 HH:MM
  timezone: ""                    # IANA 名称；空则取 org_reports.timezone
  segment_max_bytes: 268435456    # 256 MiB，行与对象的未压缩字节
  conversation_min_turns: 16
  conversation_min_bytes: 16777216
  pass_audits: 5000
  run_deadline_minutes: 240
  verify_sample: 0.05             # 每个包至少一条
```

校验（`internal/config/archive.go`，由 `validate.go` 的 `Validate` 调用）：

- `mode` 取三个值之一；`mode != off` 时 `dir` 必填且为绝对路径；
- `run_at` 用 `ParseRunAt`；`timezone` 非空时用 `time.LoadLocation`，`time/tzdata` 已经嵌入（A.5）；
- 各数值有上下界：`segment_max_bytes` 在 16 MiB 到 4 GiB 之间；`verify_sample` 在 0 到 1 之间；其余为正。

配置文件之外不提供运行时修改，本阶段不进管理界面的设置页。

### L.2 五条护栏（5.7）

| # | 护栏 | 落在哪里 |
| --- | --- | --- |
| 1 | `archive.mode != off` 而 `retention_days == 0`：拒绝 | `config` 校验 |
| 2 | `export_only` 不做任何直接删除，启动日志提示热库会持续增长 | `app` 组装：`archive.mode != off` 时不组装 `retention.Runner`〔核：现在只看 `retention_days > 0`，`app/app.go`〕。归档 runner 在 `export_only` 下不调用移除。移除的 writer 操作再自查：分段必须 `sealed` 且格式版本不低于 1（M.2）。启动日志 `archive export only: hot store keeps growing`，带稳定码 `archive_export_only` |
| 3 | 从 `archive_then_delete` 切回 `off` 而 `retention_days > 0`：启动日志醒目提示直接删除已经恢复 | `app` 启动：`mode = off`、`retention_days > 0`，且目录表里有 `hot_removed` 的成员或 `mode = 'archive_then_delete'` 的运行记录时，Warn 一条，稳定码 `archive_direct_delete_resumed`。回滚文档写明想暂停归档应当把 `retention_days` 设为 0 |
| 4 | `archive.dir` 与 `key_path` 的目录相同或互相包含：拒绝 | `config` 校验，复用 `config/audit.go` 的 `within`〔核：暂存目录已经这样校验〕 |
| 5 | `HasAudits` 同时看 `audit_records`、`integrity_events` 和目录表 | L.3 |

### L.3 `HasAudits` 的修复〔设〕

```sql
SELECT EXISTS (SELECT 1 FROM audit_records)
    OR EXISTS (SELECT 1 FROM integrity_events)
    OR EXISTS (SELECT 1 FROM archive_segments)
```

- `HasAudits` 在 `Open` 之后调用，迁移已应用，三张表都存在〔核：`app/app.go` 的调用顺序〕。
- 在迁移 008 之前的提交里先只加 `integrity_events`（O.1 第 1 个提交）。
- SQLite 的 `HasAudits` 同样加上 `integrity_events`。

---

## M. P4：校验后移除

### M.1 可能改动已归档行的全部语句

范围：仓库里所有对归档表做 INSERT、UPDATE、DELETE 或 upsert 的语句〔核：对 `UPDATE`、`DELETE FROM`、`INSERT INTO`、`ON CONFLICT` 在整个仓库检索，`internal/storage/postgres` 里的逐一读了上下文〕。

`internal/storage/postgres` 之外只有两处：

- `internal/storage/sqlite`：旧格式的离线导入验证与兼容测试用，生产不打开它（`app/storage.go` 只打开 PostgreSQL）〔核〕，归档也不在它上面运行；
- `internal/storage/migrate` 的离线导入器：只写入一个只有 001 基线表、而且必须为空的目标库（0.2 第 5 条），碰不到已归档的成员。

下表只列 PostgreSQL 的语句。“已归档成员”指按 B.1 选出、已终结、解析与调用者状态都已到终态的 audit。

| # | 语句 | 位置 | 能否作用于已归档成员 | 方案的戳 | Q1 乙 |
| --- | --- | --- | --- | --- | --- |
| 1 | `UPDATE token_links SET billing_state, billing_attempts, quota, …` | `token_writer.go` 的 `updateTokenLinkBilling` | 能：条件只是 `billing_state = 'unchecked'` | 不覆盖 | 覆盖 |
| 2 | `INSERT … ON CONFLICT DO UPDATE audit_project_identity` | `org_writes.go` 的 `saveProjectIdentity`，由 `insights/project.go` 回填调用 | 能：首次提取或 `identity_version` 升级 | 不覆盖 | 覆盖 |
| 3 | `DELETE FROM turn_context_ops`、`UPDATE turns SET parent_turn_id = NULL …`、重新插入上下文操作 | `maintenance.go` 的 `checkpointRetainedChildren` | 能：成员的父轮次先被移除时 | 覆盖（父引用） | 覆盖 |
| 4 | `UPDATE conversations SET updated_at_ns` | `graph_writer.go` 的 `persistTurn` | 能：会话里有任何新轮次 | 不在戳里 | 不在戳里：该列不归档（Q7） |
| 5 | `INSERT INTO turns`、`turn_context_ops`、`turn_response_items`，指向成员的子轮次 | `persistTurn` | 新行属于另一条 audit，不改成员的行 | — | — |
| 6 | `INSERT … ON CONFLICT DO NOTHING` 内容对象、二进制对象、引用行 | `graph_writer.go` | 已存在的行不变 | — | — |
| 7 | GC 删除会话、内容对象、二进制对象 | `garbageCollectConversationObjects` | 不能：成员还引用着，外键 `RESTRICT` 挡住 | — | — |
| 8 | `UPDATE audit_records SET parse_status = 'processing'` | `parser_writer.go` 的 `claimPendingParse` | 不能：只作用于 `pending`，B.1 不选 `pending` | 覆盖 | 覆盖 |
| 9 | `releaseProcessingParse`、`resetProcessingParses` | `parser_writer.go` | 不能：只作用于 `processing` | 覆盖 | 覆盖 |
| 10 | `saveParsedAudit` 的全部写（`parsed_results` upsert、轮次、`applySideRetention` 删块与改 `body_streams`、`parse_status`、事件） | `graph_writer.go` | 不能：要求 `parse_status = 'processing'`（`requireOneRow`） | 覆盖 | 覆盖 |
| 11 | `upsertTokenLink` 与 `UPDATE audit_records SET caller_*` | `token_writer.go` | 不能：要求 `caller_status = 'pending'` | 覆盖 | 覆盖 |
| 12 | `retryCallerLookup` | `token_writer.go` | 不能：同上 | 覆盖 | 覆盖 |
| 13 | `finishAudit`、`loadFinishedOutcome`、`finalizeIncompleteCapture`、`deduplicateEquivalentBodyStages` | `writer.go` | 不能：`finishAudit` 先读 `ended_at_ns`，已终结只读回 | — | 覆盖 |
| 14 | `applyCheckpoint`、`applyCommit`（含 `UPDATE body_streams SET source_stage`、Header 块 upsert） | `checkpoint_writer.go`、`commit_writer.go` | 不能：已终结时直接返回或只读回 | — | 覆盖 |
| 15 | `recoverInterruptedAudits` | `recovery.go` | 不能：只作用于 `ended_at_ns IS NULL` | — | 覆盖 |
| 16 | `recoverCaptureEntry`、`markCaptureWriteFailed`、`markMissingChunk`、`prepareFinalization` 的溢出标记 | `write_recovery.go`、`writer.go` | 不能：都有 `ended_at_ns IS NULL` 条件或先读 `ended_at_ns` | — | 覆盖 |
| 17 | `restoreStagedChunks` | `staged_restore.go` | 不能：已终结的 audit 从不改动 | — | 覆盖 |
| 18 | `insertAudit`、`insertStage`、`insertBody`、`insertHeaders`、`insertChunk`、`finishStage`、`saveStreamTimeline`（legacy 的逐操作写） | `writer.go` | SQL 里没有守卫；会话按构造只在 `FinishAudit` 之前发出〔推〕 | 不覆盖 | 覆盖 |
| 19 | `insertAuditGaps` | `gaps.go` | 只插入新 gap | — | — |
| 20 | `saveAnalysis`、会话分析与组织报告的派生写 | `analysis_writer.go`、`session_*.go`、`org_*.go` | 只写派生表，不写归档表 | — | — |
| 21 | retention 的 `deleteExpired` | `maintenance.go` | 归档开启时不组装（L.2 第 2 条） | — | — |

结论：

- 方案的戳在第 1、2、18 行有缺口（0.2 第 2 条）。
- Q1 乙对表中每一行都成立，对以后新增的语句也成立：任何 UPDATE 都换掉行版本，任何 INSERT、DELETE 都改变行集合。

**Q1 乙的确切构成：**

```
change_stamp = SHA-256(
  "llmapi-logger/archive-change-stamp/v1\x00"
  对下列每张表，按这个顺序：
    T(表名) L(n)，每行按主键排序：B(主键的编码) I(xmin)
)
```

- 表与行：
  - `audit_records`、`http_stages`、`http_headers`、`http_header_blocks`、`body_streams`、`body_chunks`、`stream_timelines`、`parsed_results`、`token_links`、`audit_project_identity`、`integrity_events`：按 `audit_id` 取该 audit 的行；
  - `turns`：该 audit 的那一行；
  - `turn_context_ops`、`turn_response_items`：按 `turn_id` 取。
- 主键的编码是各主键列按 E.1 的 `T`、`I` 依次拼接。`xmin` 取 `xmin::text::bigint`。
- 内容对象、二进制对象和引用行不进戳：它们按内容寻址，只插入不更新（第 6 行），成员存在时也删不掉（第 7 行）。
- 读取都走主键或 `audit_id` 开头的索引；`xmin` 在行头里，不读 TOAST，所以 `body_chunks` 的密文不会被取出。

### M.2 按 id 列表删除

**新的 writer 操作 `writeRemoveArchived`**，与 `writeDeleteExpired` 一样独占事务（`alone()` 加上这个 kind）。输入是一批 `(segment_id, audit_id, revision, change_stamp)`，至多 200 条（`RetentionBatchLimit`）。事务内依次：

1. `SELECT … FROM archive_members … FOR UPDATE`，只留下状态仍为 `sealed`、所在分段为 `sealed` 且格式版本不低于 1 的成员。其余跳过，这是重复执行的幂等点。
2. 对每条成员：
   - audit 已不在热库：只把成员改为 `hot_removed`；
   - 否则按 M.1 在事务内重算变更戳：与成员行的不同，改为 `stale`；相同，进入删除列表。
3. 对删除列表调用现有的 `deleteAuditBatch(transaction, ids)`，不改动它：检查点、叶到根删除、派生明细修剪、对象 GC 照旧（A.1）。
4. 删除列表的成员改为 `hot_removed`，写 `state_changed_at_ns`；分段里不再有 `sealed` 成员时，分段改为 `hot_removed`。

gap 的移除是另一个同样独占事务的操作：按 `archive_gap_members` 里 `sealed` 的 id 删 `audit_gaps`，改为 `hot_removed`。

`deleteAuditBatch` 不需要改，因为它本来就接收 id 列表（0.2 第 6 条）。现有的 `deleteExpired` 也不改，`archive.mode = off` 时行为与现在逐字节相同。

**顺序（5.2 第 2 点）。** 一次运行里，所有可移除的成员（跨分段）按 `turn_created_at_ns DESC NULLS FIRST, audit_id DESC` 排序，再按批切分。

- 为什么是 `turns.created_at_ns`：按会话 key 和无 key 两种方式找父轮次时，候选只取 `created_at_ns` 严格小于本轮的轮次（`chooseTurnParent` 的两条候选查询都有 `t.created_at_ns < $n`）〔核〕。所以按它降序，子轮次排在父轮次之前，每一批都不会是自己之后某一批成员的父轮次。
  - 例外是 `previous_response_id` 的强制链接：`loadCandidateByResponseID` 按 `response_id` 取，SQL 里没有时间条件〔核〕。父轮次总是先被解析、先写入，在单个解析 worker 和单调的墙上时钟下它的 `created_at_ns` 更小〔推〕。
  - 时钟回拨时这条可能不成立。后果只是那一对父子在跨批时触发一次检查点，子轮次被记为 `stale`、下次重新收录，不会删错。
- 为什么不能用 `started_at_ns`：`created_at_ns` 是解析时间，不是请求开始的时间。例如 A 在 0 秒开始、100 秒结束，B 在 10 秒开始、20 秒结束。B 先解析，A 的父轮次可以是 B，而按 `started_at_ns` 降序 B 排在 A 前面。
- 删 B 时，`checkpointRetainedChildren` 把 A 改写成根。随后：
  1. A 的变更戳变了，A 被误记为 `stale`（Q6 甲的后果，0.2 第 9 条）；
  2. 自适应缩批反复切开这样的父子对，检查点的重写随批数增长（5.2 的原话）。
- 没有轮次的成员（`NULLS FIRST`）与图无关，排在最前。
- `turn_created_at_ns` 在导出时记进成员行（I.1），排序不必再关联 `turns`。

**批量与让路。** 沿用 PR #55 的规则：从 1 条起，整批且不超过 0.5 秒时翻倍，超过 1 秒按比例缩小，慢失败降到 1；每批之后暂停同样的时长，至多 5 秒（A.1）。这段逻辑从 `retention.Runner` 抽成一个小的导出类型 `retention.Batcher`，retention 与归档移除共用，retention 的行为不变（它现有的测试照跑）。

### M.3 崩溃与重复执行

| 崩溃点 | 之后 |
| --- | --- |
| 移除事务提交之前 | 整批回滚，成员仍为 `sealed`；下次运行对账后继续（H.6 第 4 步） |
| 两批之间 | 已提交的批是 `hot_removed`，其余是 `sealed`；下次继续 |
| 所有批之后、运行记录写完之前 | 运行记录留在 `running`，下次启动改为 `interrupted`；成员状态已经完整 |

删除和目录表更新在同一个事务里，所以不存在“热库删了、目录表没记”或者反过来的状态。重复执行时，第 1 步只挑 `sealed` 的成员，已移除的不会再处理。

### M.4 `stale` 之后

- `stale` 的成员不删。它仍是热库里的 audit，到期条件不变，下一次运行的 B.1 第 4 条会重新选中它，以“已有最大修订号加一”写进新的分段。
- 旧的 `stale` 行保留。`archive_members_current_idx` 保证同一 audit 至多一个非 `stale` 的成员。
- 读取工具按最高修订号取（K.2），旧修订号仍可用 `cat --all-revisions` 看到。

### M.5 移除之后的完整性链

- 被移除 audit 的事件留在 `integrity_events` 里（方案不变量 8），表里的事件从不删除。
- 启动校验：
  - 链的 MAC 照常通过；
  - “每条已终结 audit 有 `capture_finalized`”只看还存在的 audit；
  - “每个轮次有 `semantic_compacted`”只看还存在的轮次〔核：`verifyIntegrityChainTransaction`〕。
- 后台载荷校验跳过没有 audit 行的事件〔核〕。
- 被检查点改写的留存轮次：语义摘要覆盖的是物化引用，检查点保证物化结果不变；血缘不在语义摘要里（A.6），所以它们的载荷校验照常通过。这一点 `tests/integration/retention_shapes_test.go` 已经对 retention 验证过（方案附录 C.6），移除走同一段代码。
- 被移除 audit 的载荷校验从此只能在归档里做一半：
  - 事件的 MAC 可以用主密钥核对（J.2 第 7 步）；
  - 载荷摘要绑定的是密文，从明文算不出来（方案 2.1）。
  这一半由清单签名补上：它说明归档那一刻复核通过。
- `HasAudits` 因 `integrity_events` 和目录表非空而返回真，密钥文件缺失时不会新建密钥（L.3）。

---

## N. 测试与验收

“PG”表示需要 PostgreSQL，没有 DSN 时会被跳过，验收报告要分别写明在真实库上跑过哪些（方案第 7 节）。

### N.1 方案第 7 节“归档完整性”

| 方案的条目 | 测试 | PG |
| --- | --- | --- |
| 列覆盖测试通过，并用“给被归档的表加一列”验证它会失败 | J.1 的两部分；外加主机上的摘要敏感性与行往返 | 是（前者）、否（后者） |
| 四类协议的全部夹具读出等价，含旧格式的行 | J.3，legacy 与 unified 各一遍 | 是 |
| 跨分段的会话，父轮次所在分段已不在时后一分段仍能单独读出 | 一个会话分两天导出成两个分段；删掉第一个分段的三个文件，读取工具只凭第二个分段导出全部轮次，与热库相同 | 是（导出）；读取部分不需要 |
| 截断、帧重排、清单改动、对象文件缺一个对象都能检出 | G.3 的向量与篡改用例；包级用例：改清单一个字段、删对象文件一行（重新加密使帧本身有效）、交换两行、换一个成员的记录摘要 | 否 |
| 原事件复核不过的 audit 不进归档 | 绕过 writer 用 SQL 改一段密文或一个事件的载荷摘要，运行归档：该 audit 留在热库，`integrity_failed_audits` 为 1，载荷校验状态为失败 | 是 |
| 扫描归档目录和临时文件：加密时扫不到测试正文，两种配置下都扫不到凭据值 | 夹具的请求体带唯一标记串，`Authorization`、`x-api-key`、`x-goog-api-key`、`?key=`、`Cookie`、`Set-Cookie` 各带唯一的合成凭据。用测试钩子在临时文件写完、发布之前暂停并扫描；发布后扫描整个目录，非加密配置下先解开 gzip 再扫 | 是 |
| 凭据指纹：入站出站相同；已知 Key 算出同一个；换主密钥算不出 | 主机测试 | 否 |
| 冻结夹具包 | `internal/archive/testdata/frozen/v0/` 一个小包，当前读取工具读一遍；格式定为 1 时再冻结一个 v1 包 | 否 |

### N.2 第 6 节 P3 的门槛

| 门槛 | 测试 | PG |
| --- | --- | --- |
| 磁盘满 | 包写入器的文件系统经一个接口；注入第 n 次写返回“空间不足”：临时文件被删除，目录表没有意向行，运行记录为 `archive_failed`，热库不变 | 是 |
| 损坏包 | N.1 的包级用例，经 `verify` 和运行时重读两条路 | 否、是 |
| 重复执行 | 同一截止时间连跑两次：第二次不产生新包，成员不重复 | 是 |
| 归档期间会话活跃 | 在快照之后、登记之前，经测试钩子插入同一会话的新轮次：新轮次不在包里、不进目录表，下次到期后进新分段 | 是 |
| 归档盘上扫不到明文和凭据 | N.1 的扫描 | 是 |
| 对账 | 分别在登记意向后、发布数据文件后、发布清单后、定稿前中止，再运行：每种情形都收敛到“定稿”或“干净回退” | 是 |

### N.3 方案第 7 节“移除”

| 方案的条目 | 测试 | PG |
| --- | --- | --- |
| 磁盘满、包损坏、归档后删除前崩溃、重复执行都不丢数据，重试幂等 | N.2 的对应用例，模式改为 `archive_then_delete`，加上 M.3 每个崩溃点 | 是 |
| 源记录在归档后变化时不删除，下一分段以新修订号出现 | 定稿后分别执行 M.1 第 1、2、3 行的写：成员变 `stale`、留在热库；下次运行出现修订号 2，读取工具取到修订号 2 | 是 |
| 归档期间会话继续活跃，边界轮次靠检查点保留 | 新轮次以已归档的轮次为父；移除后它成为 `retention_checkpoint` 的根，详情、重建导出与删除前逐字节相同 | 是 |
| 删除之后链校验与载荷校验通过 | 移除后重新 `EnableIntegrity`、`VerifyIntegrityPayloads` | 是 |

另外：

- **变更戳覆盖**（PG）：对 M.1 表里“能作用于已归档成员”的每一行执行一次那条写，断言戳变化；对“不能”的每一行，构造一条已终结的 audit 执行那条写，断言它是空操作。每多一条写语句，这张表和这个测试一起加一行。
- **顺序**（PG）：一组构造出“开始顺序与解析顺序相反”的父子轮次，按 `turn_created_at_ns` 降序移除时检查点改写 0 次、`stale` 0 条；按 `started_at_ns` 降序（测试里的对照实现）时两者都大于 0。
- **`archive.mode = off` 不变**（PG）：现有的 retention 测试照跑，并加一条断言 `deleteExpired` 的语句序列与改动前相同。

### N.4 其他

| 测试 | PG |
| --- | --- |
| `HasAudits`：只有事件、只有目录表、三者皆空 | 是；SQLite 版本否 |
| 配置护栏 1、4，各字段的校验 | 否 |
| 护栏 2、3 的组装与日志 | 否（用假存储） |
| 调度：`untilNextRun`、补跑判断，用假时钟 | 否 |
| `cmd/audit-archive` 的依赖守卫 | 否 |
| 查询层拆分不改行为：现有 `internal/query` 测试全部照跑 | 否 |
| 迁移 008：首次打开、重复打开、从 7 升级、回滚 SQL 后再升级 | 是 |

---

## O. 工作拆分

### O.1 提交顺序（每个提交都能单独验证）

P3：

| # | 提交 | 验证 |
| --- | --- | --- |
| 1 | `fix(storage)`：`HasAudits` 也看 `integrity_events`（PostgreSQL 与 SQLite） | N.4 第一行；与归档无关，可以先合 |
| 2 | `feat(security)`：`ArchiveKeys` 派生与向量 | 主机单元测试 |
| 3 | `feat(archive)`：分帧加密 `internal/archive/stream` | G.3 |
| 4 | `refactor(query)`：解密与组装拆开（K.3），行为不变 | 现有查询测试；`internal/app`、`tests/integration` 在 PG 上照跑 |
| 5 | `feat(archive)`：格式类型、列规格、凭据投影、记录摘要、行与清单的编解码 | J.1 的主机部分、D.4 的指纹测试 |
| 6 | `feat(postgres)`：迁移 008、目录表操作、`HasAudits` 加目录表；迁移测试与版本清单更新；部署回滚一节 | 迁移测试（PG） |
| 7 | `feat(postgres)`：导出快照读取（行、物化、事件复核、变更戳）与列覆盖测试 | J.1 的 PG 部分；复核不过的用例 |
| 8 | `feat(archive)`：包写入器（两个文件、滚动、临时文件与发布）、包读取与 J.2 核对、索引 | 包级篡改用例（主机） |
| 9 | `feat(archive)`：runner（调度、分趟、分组、登记、抽样核对、对账、gap 导出）、`archive` 配置段与护栏、`app` 组装（`export_only`）、日志 | N.2（PG） |
| 10 | `feat(cmd)`：`audit-archive` 的五个子命令与依赖守卫 | 子命令测试（主机，用第 8 步写出的包） |
| 11 | `test(integration)`：J.3 全量、扫描、对账与故障用例 | N.1、N.2（PG） |
| 12 | `docs`：归档格式文档（版本 0）、模块 04、09、18、`AGENTS.md` 的加密边界、部署说明、配置示例 | — |

P3 验收通过后：格式定为版本 1（域字符串 `v0 → v1`，冻结 v1 夹具包），单独一个提交。

P4：

| # | 提交 | 验证 |
| --- | --- | --- |
| 13 | `refactor(retention)`：抽出 `Batcher`，行为不变 | retention 现有测试 |
| 14 | `feat(postgres)`：`writeRemoveArchived`、gap 移除、事务内重算变更戳 | M.3 各崩溃点、变更戳覆盖测试（PG） |
| 15 | `feat(archive)`：`archive_then_delete` 模式、排序、版本门槛、启动提示 | N.3（PG） |
| 16 | `docs`：P4 的模式说明、回切警告、回滚 | — |

### O.2 并行拆分与文件归属

| 包 | 拥有的文件 | 依赖 |
| --- | --- | --- |
| W-sec | `internal/security/archive_keys.go` 及测试 | 无 |
| W-stream | `internal/archive/stream/*` | 无（只用 `K_enc` 的字节） |
| W-query | `internal/query/{service.go, turn.go, timeline.go, raw.go, plain.go(新)}` 及其测试 | 无 |
| W-format | `internal/archive/{columns.go, project.go, digest.go, record.go, line.go, manifest.go}`、`internal/archive/testdata/*` | W-sec 的接口（可以先约定）；W-query 的 `PlainDetail`（先约定字段） |
| W-pg | `internal/storage/postgres/{migrate.go, migrations/008_archive_catalog.sql, archive_catalog.go(新), archive_snapshot.go(新), archive_stamp.go(新), reader.go, writer.go, types.go}` 及测试，含已有迁移测试里的版本清单；`internal/storage/{types.go, archive_types.go(新)}`；`internal/storage/sqlite/reader.go` 及测试 | W-format 的列规格与记录结构 |
| W-bundle | `internal/archive/bundle/*` | W-format、W-stream |
| W-runner | `internal/archive/runner/*`、`internal/config/{archive.go(新), validate.go, types.go}` 及测试、`internal/app/*`（含 `app/storage.go` 的 `runtimeStore` 接口） | W-pg、W-bundle |
| W-cli | `cmd/audit-archive/*`；终端不回显读取从 `internal/agentcli/term*.go` 移到 `internal/termio`（新），`agentcli` 改为引用它 | W-bundle、W-query |
| W-it | `tests/integration/archive_*_test.go` | 以上全部 |
| W-doc | `doc/features/*`、`doc/deployment/*`、`AGENTS.md`、`configs/*.yaml`、`compose.yaml`（归档卷） | 以上全部 |
| W-p4 | `internal/retention/*`、`internal/storage/postgres/archive_remove.go(新)`、`internal/archive/runner/remove.go(新)` 及测试 | P3 验收；必须顺序做 |

- W-sec、W-stream、W-query 可以立刻并行，W-format 在约定接口后与它们并行。
- W-pg 与 W-bundle 可以并行。
- W-runner、W-cli 在它们之后，W-it、W-doc 最后。
- W-p4 整体在 P3 验收之后，内部按 O.1 第 13 到 16 个提交顺序做。
- 共享文件的归属：
  - `internal/storage/postgres/{writer.go, types.go}` 的 `alone()`、`applyWrite` 分派和 writer 操作类型，P3 归 W-pg（目录表操作），P4 归 W-p4（移除操作），两者不同时进行；
  - `internal/storage` 的共享类型归 W-pg，W-format 只引用、不修改，新增的跨包类型先在 W-pg 的第一个提交里约定；
  - `app/storage.go` 归 W-runner。

---

## P. 实施时按推荐做的小选择

下面这些不等维护者决定，实施者按推荐做，阶段结束时在小结里逐项报告。

1. **时区默认值**：`archive.timezone` 为空时取 `org_reports.timezone`（其默认值 `Asia/Shanghai`，与组织报告是否开启无关），不取进程的 `time.Local`。容器里的进程时区通常是 UTC，`03:00` UTC 落在东八区的白天，与 5.2 选本地低峰的理由相反。
2. **补跑**：H.1。
3. **分趟与期限**：每趟 5000 条，一次运行至多 4 小时，失败后 10 分钟重试（B.2、H.4）。
4. **复核不过时**：载荷校验状态置为失败，与后台载荷校验发现损坏时相同（存储因此不健康）〔核：`open.go` 里健康检查看这个状态〕。发现了损坏而不报告，与现有行为不一致。
5. **阈值与分段大小**：16 轮或 16 MiB 独立成包，分段 256 MiB 未压缩字节（B.3、B.4）。
6. **文件名**：
   - 时间写成 `20261128T030000Z`（UTC），取包内最早的 `started_at_ns` 和最晚的 `ended_at_ns`；
   - 桶包写成 `bucket-<protocol>-<run_id 前 8 位>`，保证同一天的几次运行不重名；
   - 目录按最早 `started_at_ns` 的 UTC 年月；
   - 从不覆盖已有文件（H.2 第 5 步）。
7. **推迟的计数**：Q8 推迟的记录不设上限（Q8 的推荐），每次运行把条数写进 `archive_runs.deferred_audits` 和完成日志。
8. **`export_only` 下每条到期记录只导出一次**，不检测 `stale`。切到 `archive_then_delete` 后，移除时的变更戳比对会把之后变化过的成员标成 `stale` 重新收录。
9. **抽样**：`verify_sample` 默认 0.05，每个包至少一条（J.3）。
10. **非加密包没有密钥时**：`cat`、`export` 要加 `--unauthenticated`（K.1）。
11. **作废的包和孤儿文件只改名，不删除**；唯一删除的是归档器自己命名的临时文件（H.2、H.6）。
12. **新建密钥的额外检查**：`archive.mode != off` 且归档目录里有任何清单时，也拒绝新建密钥。5.7 只要求查三张表；数据库整个丢失、只剩归档目录时，这一条防止新密钥让旧包全部打不开。
13. **`archive.dir` 与 `audit.staging.dir` 不得相同或互相包含**，理由与第 4 条护栏相同：暂存目录也放着密文。
14. **终端不回显读取**移到 `internal/termio`，`llmaudit` 与 `audit-archive` 共用（O.2）。
15. **移除的批量上限** 200 条，与 retention 相同（M.2）。
16. **同一次运行里先移除 audit，再移除 gap。**
17. **归档格式文档**放在 `doc/features/26-cold-archive.md`，写到不读本仓库代码也能解析的程度（方案 4.4），包括 E、F、G 三节的字节序列和 G.3 的向量。
18. **`archive_runs` 不进管理界面**（H.5）。以后要展示时，走现有的设置或健康接口，另行设计。

---

## 附：残余风险

1. **长快照。** 每趟一个 REPEATABLE READ 快照，至多 5000 条 audit 加上补齐的会话。一个极长的会话会让单趟变长、挡住 VACUUM 的清理水位。没有在大库上量过。
2. **`xmin` 的前提**（Q1 乙）。在 PostgreSQL 18.6 上用一张临时表试过：`VACUUM (FREEZE)` 和 `VACUUM FULL` 之后各行的 `xmin` 不变；值不变的 `UPDATE` 也会换掉 `xmin`；`SELECT … FOR UPDATE` 不改变它。实施时把这几条固定成 PG 测试。没有试过的：`pg_upgrade`、逻辑复制到另一个库（都按“可能全部变 `stale`”对待，方向安全）。
   变更戳是否收敛：会让已终结记录的行再变的写只有三种，都有终点。计费回填至多 `MaxBillingAttempts` 次后置为终态；项目标识只在 `identity_version` 升级时重写一遍；检查点改写只在父轮次被移除时发生一次。所以一条记录至多被重新收录有限次。
3. **阈值是猜的**（B.3）。真实分布没有量过，格式版本 0 期间可以改。
4. **新增的密码学代码**（G 节）要单独评审（方案第 8 节）。
5. **每个分段重复一份上下文。** 跨天的会话，每个分段都要带边界轮次的物化引用和它引用的全部对象（5.4 已接受，由膨胀比兜底）。共享对象库的切换条件仍按 5.4。
6. **Windows 上目录 `fsync` 是空操作**（H.2 第 5 步），与暂存相同；部署目标是 Linux。
7. **内容里的凭据**（Q4 甲）会随对话内容进入归档。加密开启时它们在密文里，关闭时是明文。
8. **暂存目录里留下的文件不进归档。** 第 3 阶段的启动导入会把接不上的暂存文件改名为 `.orphan` 或 `.corrupt` 留在 `audit.staging.dir`，它们可能是某条已终结 audit 的一部分 raw 的唯一副本。归档只读数据库：这样的 audit 按库里的样子（raw 残缺、`full`）归档和移除，暂存目录里的文件既不读也不删，移除之后仍在原处，需要人工处理。归档运行不检查暂存目录。
9. **调用者查找被关掉时，`caller_status = 'pending'` 的记录会一直被推迟**（Q8 甲）。查找有终态（`resolved`、`unresolved`），但只有 NewAPI 集成开着时才会走到。集成关掉之后遗留的 `pending` 记录不会被归档，表现为每次运行报告的推迟条数不降。
10. **Header 采集的另外两个分支没有逐一读过**（D.2 依据的是 `addHeadersLocked` 这一个入口）。

---

## 实施记录

下面是代码与正文不同、或正文没有写到的地方，随实施补充。

### R.1 查询层的拆分（O.1 第 4 个提交）

组装的一半在 `internal/query/plain.go`，不需要 cipher 和存储，`internal/query` 的依赖里没有任何一个存储包。入口：`BuildDetail`、`BuildMetadata`、`BuildSummary`、`ReconstructPlainTurn`、`PlainSessionConversation`、`TimelineFromPlain`、`RawMetadataFromPlain`、`RawStages`、`VerifyRaw`；输入类型 `PlainDetail`、`PlainParsedResult`、`PlainTurnGraph`、`PlainObject`、`PlainBinary`、`PlainChunk`。与 K.3 不同的地方：

1. **热路径没有先拼出 `PlainDetail`。** K.3 第 3 步设想热路径解密后构造 `PlainDetail` 再组装。这样会改变行为：现在只解密被引用到的对象和二进制，并且各方法只打开自己需要的部分（`ReconstructTurn` 只在只有请求的轮次上打开解析结果，`SessionConversation` 不打开 Header 和 Request-URI），出错时报的阶段名也取决于打开的顺序。所以两条路共用的是同一组不导出的核心函数，它们接收“按需打开”的函数；错误值和文案不变。
2. **`ReconstructPlainTurn` 的入参是 `PlainDetail`**，不是 K.3 写的解析器名加图：只有请求的轮次要用解析结果合并 `partial_response_messages`。
3. **对象以规范化 JSON 文本交给组装的一半**，每次打开都按内容地址、长度、schema 版本和 kind 核对，与 `OpenObject` 解密之后做的检查相同。`RestoreBinaries` 会原地修改解码后的值，所以每个引用都要重新解码。
4. **只留在解密一侧的检查**：AEAD 认证、对象与块的密文编码长度、版本 1 Header 行的 `value_length`、版本 2 的阶段集合检查（在 `headerblock.Expand` 里）、`parsed_json_enc` 的解压。归档读取要自己保证这些输入已经是核对过的明文。
5. **输出还不是归档一侧的最终形式。** `BuildDetail` 接收原始的 Request-URI 字节，Header 的 `ValueLength` 取自值的长度；`BuildSummary` 接收原始的 User-Agent。读取工具手里只有投影后的形式，组装之后要按 D.3 把这三处换回投影项。

对正文其他小节的更正：

- **C.3 说读取工具不需要注册解析器，不对。** 由轮次生成会话要经过 `builtin.Registry().RebuildConversation`，`cmd/audit-archive` 要引入 `parser/builtin`。
- **C.4 的增量操作要有人应用。** `PlainTurnGraph.RequestRefs` 必须是物化后的引用，而把增量操作应用到父轮次引用上的代码（`loadRequestRefs`）只在两个存储的 `graph_writer.go` 里。读取工具需要同一段逻辑：把它移到存储和读取工具都能引入的包里（按 P 节的小选择处理，W-format 负责）。
- **来源阶段的解析在存储里。** `StreamBodyChunks` 读的是 `body_streams.source_stage` 的块；`QueryStreamTimeline` 的时间线和 `Stage` 取自来源阶段，`ObservedLength` 取自所选阶段自己的行。读取工具要照做。
- **版本 1 的 User-Agent 顺序**来自 `QueryRequestHeaderEvidence` 返回行的顺序，`BuildSummary` 要求传入的值已经是这个顺序。

### R.2 `HasAudits`（O.1 第 1 个提交）

两个存储的 `HasAudits` 现在是“`audit_records` 或 `integrity_events` 有行”。目录表加进这个判断留给迁移 008 的提交。新增的启动测试 `TestStartupDoesNotReplaceMissingKeyWhileIntegrityEventsRemain` 是仓库里第一个“密钥文件缺失”的启动测试；把查询改回旧的写法时，它会看到启动新建了密钥并报 `integrity_unavailable`。

### R.3 密钥与分帧加密（O.1 第 2、3 个提交）

实施时定下、格式文档要写进去的细节：

1. **`SignManifest` 不加域字符串**，对传入的字节直接做 HMAC。清单的域字符串（F.2）由 `internal/archive` 的清单编码加在 MAC 输入的最前面，只加一次。密钥指纹与清单 MAC 共用签名密钥，靠这个前缀区分。
2. **`CredentialFingerprint` 对空值照常给出 32 字节的指纹**（D.4 没有特例）；现有的 `CredentialFingerprinter` 对空输入返回空。
3. **加密文件的布局**（`internal/archive/stream`）：
   - 文件头 40 字节：`4C 4C 41 52`（“LLAR”）、流格式版本 `01`、帧大小的对数 `10`、两个保留字节 `00 00`、32 字节随机盐。流格式版本与归档格式版本各自独立。
   - 文件密钥：`HMAC-SHA-256(K_enc, "llmapi-logger/archive-file-key/v1\x00" ‖ 文件头的 40 字节)`。
   - 第 i 帧的 nonce 12 字节：三个 `00`、8 字节大端的帧序号、末帧为 `01` 否则 `00`。AAD 为空。
   - 明文按 65,536 字节切帧，每帧密文后接 16 字节认证标签；没有长度字段，读到文件末尾的那一帧就是末帧。明文为空时文件是文件头加一个 16 字节的末帧。
4. **规范性**：其他帧之后的空末帧被拒绝（写入方从不产生），所以每段明文只有一种编码。
5. **错误**：文件头不对是格式错误，文件头不全或末帧不足 16 字节是截断，其余（在帧边界处截断、追加字节、换盐、错误密钥）都表现为认证失败。追加在末帧之后的字节没有单独的错误。调用方把任何错误都当作整个文件作废。
6. **向量**在 `internal/archive/stream/testdata/vectors.json`；密钥派生的向量和 0、1 字节的完整密文用仓库之外的实现独立算过，结果相同。

### R.4 格式核心（O.1 第 5 个提交）

1. **记录摘要不能只凭一行增量形式的行算出来。** E.2 覆盖物化后的请求引用，而增量形式的行只有操作（C.4）。实现保持 E.2 的字节不变：读取方先用同一分段里排在前面的父行把轮次物化（`Turn.Materialize`），再算摘要；没有物化时 `Digest` 返回 `ErrNotMaterialized`。E.2 里“只凭这一行就能重算”的说法对增量形式不成立。
2. **增量操作的应用移到了 `internal/auditmodel`**（`ApplyImmutableDelta` 等），两个存储改为调用它，行为不变。
3. **行的形状**：
   - `audit_records` 的 29 列全部在行里；子表省去 `audit_id`，轮次的子表省去 `turn_id`，列清单把它们映射到行首的字段；
   - `ended_at_ns` 不会是 `null`（只归档已终结的记录）；
   - 库里取 0/1 的列写成字符串 `"0"`、`"1"`；JSON 布尔值只用于 `has_query`、`has_equals`、`block_present`、`encrypted`；
   - 投影后的值要么是 `{value}`，要么是 `{value_omitted, length, value_fpr}`；
   - `user_agent` 是 `null` 或非空列表；
   - `op_index`、`ordinal` 严格递增，不要求连续；
   - `request_context` 只有 `{form, ops}` 和 `{form, refs}` 两种。
4. **解码的严格程度**：未知、缺失、重复的键都拒绝；整数、十六进制、base64、浮点数只接受规范写法；合法 UTF-8 的文本不允许写成 `{"b64"}`；行首字段和列表顺序在解码时核对。没有拦住的：孤立的代理项转义（`\ud800`）会被解成 U+FFFD。
5. **`parsed_json` 的拆分**：严格大于 1 MiB 才拆，分段从 0 编号；切点落在 UTF-8 序列中间时最多前移 3 字节。
6. **NULL**：内存模型里 nil 表示 NULL，所以导出时“存在但为空”的值要给非 nil 的空切片；空的 `parsed_json_enc` 按 NULL 导出（查询层把非 nil 的空值当完整性错误）。
7. **凭据投影**：名称和值各自用 `url.QueryUnescape` 解码，失败就用原始字节；`;` 和 `#` 不特殊处理；`value_fpr` 和 `length` 按解码后的值算；空的凭据值长度为 0，照常有指纹。已知 Key 的核对给出两个候选（Key 本身，和 `Bearer ` 加 Key）；第三种（归一化后与 `api_key_fpr` 比）要用 `security` 里另一把指纹密钥。
8. **版本 1 的列表 User-Agent 顺序**：按名称小写、`value_index`、名称排序（名称只有大小写不同时，SQL 的顺序没有定义）。
9. **清单**：`archive` 在 MAC 输入最前面加一次 `…/archive-manifest/v0\x00`；`source_schema_version` 是十进制文本，分段和运行的 id 是 32 位小写十六进制；会话包恰好一个会话，桶包有协议、没有 gap 范围，gap 包协议为 `null`、成员为空；文件角色只有 `lines` 和 `objects`。
10. **列清单的类别**：摘要里有其明文哈希的密文列（`body_chunks.data_enc`、`timeline_enc`、`parsed_json_enc`、`value_enc`、`identity_enc`）算“进摘要”；内容对象与二进制对象的 `data_enc`、`created_at_ns`，`turn_context_ops` 的全部列，`audit_gaps` 的全部列算“归档、不进摘要”。主机测试直接解析迁移 SQL 来核对列清单，迁移 008 落地后同一个测试会覆盖它。
11. **没有独立核对的部分**：整条记录的摘要向量只与编码器自己的输出比过；手写的 E.2 字节序列独立核对了 `audit_records`（含 Request-URI 投影）、阶段和 Header 三段，其余九段在其中只以空或 NULL 出现。

### R.5 包的写入、核对与索引（O.1 第 8 个提交，`internal/archive/bundle`）

1. **文件名带运行标识。** 会话包：`sessions/<YYYY>/<MM>/<最早开始_utc>_<最晚结束_utc>_<conversation_id>-<run_id 前 8 位>_s<NNNN>`；桶包把会话 ID 换成 `bucket-<protocol>`；gap 包：`gaps/gaps-<first_id>-<last_id>-<run_id 前 8 位>`。方案 4.4 和 issue 里的会话包文件名没有运行标识，但同一批记录变化后重新导出（修订号加一）会得到完全相同的名字。文件名只给人看，查找走清单，所以加上它。时间形如 `20251128T032000Z`，目录取最早 `started_at_ns` 的 UTC 年月。
2. **滚动由调用方决定。** 每加一条记录后看 `Full()`（未压缩字节超过上限），封好当前分段、开下一个。B.4 说下一个分段“同名”，实际上每个分段的时间取自它自己的成员，名字的前缀不同。
3. **上下文形式由写入方决定。** 调用方总是给出增量操作和物化后的引用；根轮次，以及父轮次已经写在同一分段里的轮次，保留增量形式（先核对操作确实能重建出物化引用），其余改写成物化形式。记录摘要与形式无关。
4. **行的顺序**：同一会话的行连续，按 `(created_at_ns, audit_id)` 严格递增；没有轮次的记录排在最后，按 `(started_at_ns, audit_id)`。会话之间的先后没有规定。
5. **临时文件**叫 `.<segment_id>.<lines|objects|manifest>.tmp-<16 位十六进制>`，写在 `sessions/` 或 `gaps/` 下，不在最终的年月目录里：最终的名字和目录要到封包时才从成员的时间得出。H.6 写的 `.<名称>.tmp-<随机>` 做不到。
6. **发布用硬链接，不用改名**，所以已有的同名文件会让发布失败（`name_exists`），不会被覆盖。清单的临时文件在封包时就写好并 fsync（在登记意向之前），发布时先链接数据文件、fsync 目录，再链接清单、再 fsync。发布中途失败时，已经链接的文件改名加 `.rejected`（清单优先），调用方不能假定这个包不存在。
7. **清单里的计数**：`object_count` 是内容对象、二进制对象和 `parsed_json` 分段之和，`raw_chunk_count` 是 raw 块数；两者之和大于零才有对象文件。`conversations` 按首次出现的顺序列出不同的会话。
8. **比 J.2 写得更严的核对**，每一条不过都会让整个包作废，要在真实夹具上确认（N.1）：轮次引用的对象恰好等于两个信封加请求引用加响应引用；二进制恰好等于二进制引用的哈希；每个 `full` 的 Body 的 `chunk_count` 相符（合并了的成对阶段也算）；对象文件里不允许多余或重复的条目；完整的 Body 必须有 32 字节的 SHA-256。
9. **事件的 MAC**（J.2 第 7 步）只在调用方给了校验器时核对。
10. **对象的查找**：gzip 和分帧加密都不能随机访问。取某几条记录的对象是顺序扫一遍、只留下需要的；raw 一次只持有一块；整包核对为每个分段保留一份只有元数据的索引。在一次完整的核对通过之前不允许迭代记录。
11. **索引里修订号相同的两份**：清单的 `created_at_ns` 较晚的优先，再按路径。
12. **行解码补了一项校验**：轮次的两个信封哈希必须是 32 字节（两个存储的列定义都是 `NOT NULL` 且长度为 32）。

### R.6 目录表与快照读取（O.1 第 6、7 个提交）

迁移 008 按 I.1 原样建表；`HasAudits` 加上 `archive_segments`（L.3），只有运行记录时仍为假。目录表的写、导出快照、变更戳和事件复核在 `internal/storage/postgres` 的 `archive_catalog.go`、`archive_snapshot.go`、`archive_stamp.go`、`archive_events.go`，跨包的类型与输入校验在 `internal/storage/archive_types.go`。下面是与 B、H、I、M.1 不同或正文没有写到的地方。

**目录表的写（I、H.2 第 4 与第 7 步、H.6）**

1. 目录表的每个写操作都独占一个 writer 事务，不只 I 节点名的那几个：登记意向、定稿之类的结果不能被同批无关操作的失败一起回滚。
2. `BeginArchiveRun` 在同一操作里把仍为 `running` 的旧运行改为 `interrupted`，结束时间取新运行的开始时间（M.3 的“下次启动改为 interrupted”）。
3. **水位的缺口。** 一趟里被选中、写进了后来作废的分段（H.2 第 6 步）的 audit 在水位之后，既不是当前成员，也不在 `archive_deferred` 里，而 `reason` 的取值里没有给它们的一种。所以水位、计数、推迟和不再推迟的 audit 由一个操作 `RecordArchivePass` 一起写，runner 只在这一趟的分段全部定稿（或一个都没写）之后调用它；有分段作废时这一趟不推进水位，下次运行从旧水位重来。
4. **水位按格式版本取**：最近一次开始的、格式版本相同且记了水位的运行的水位，不论那次运行的最终状态。
5. **登记意向时成员的状态由存储定。** 调用方只给摘要、变更戳、修订号和时间：
   - 事务内重算的戳与快照的不同，或 audit 已不在热库，登记为 `stale`；
   - 同一 audit 已有 `sealed` 的行时，先把它改为 `stale`（H.2 第 4 步）；已有 `hot_removed` 的行时，新行登记为 `stale`；
   - 修订号必须大于该 audit 已有的全部修订号，否则整个意向被拒绝。
   结果列出登记为 `stale` 的成员和被改为 `stale` 的旧行。
6. gap 成员在登记意向时就是 `sealed`（I.1 的取值里没有过渡状态），是否可移除由分段的状态把关。
7. `member_count` 是分段的成员行数：会话包与桶包数 `archive_members`，gap 包数 `archive_gap_members`。
8. 清单的 SHA-256 可以在登记意向时给出，定稿时必须给出。同一摘要的重复定稿什么都不做，便于确认丢失后重试。
9. 删除意向只删 `publishing` 的分段；登记意向时被改为 `stale` 的旧行不恢复。`stale` 从不作为删除依据，这些 audit 下次重新收录。
10. **对账登记**（H.6 第 2 步）：分段总是插入（清单名或分段号重复则报错）；成员一律 `stale`、没有变更戳，`(audit_id, revision)` 已存在的跳过；gap 成员 `sealed`，已在别的分段里的跳过。两种跳过都在结果里列出（Q12 第 2 点没有说主键冲突怎么办）。

**选取（B.1、B.2）**

11. 选取的四个查询都在导出快照里，与导出共用一个快照（H.2 第 1 步）：
    - `Due`：沿 `audit_records_started_idx` 取水位之后、截止时间之前的一页。页里是看过的每一条，已到期和推迟的都在，最后一条就是新水位；
    - `Candidates`：对给定的 id 再看一遍（推迟的、要重新收录的），不在热库的不出现在结果里，不按截止时间过滤；
    - `ConversationCandidates`：给定会话里截止时间之前的全部 audit，不受水位限制（B.2 的补齐）；
    - `StaleCandidates`：有 `stale` 成员、仍在热库、没有当前成员的 audit。I.1 没有为 `state = 'stale'` 建索引，这个查询扫 `archive_members`。

    PostgreSQL 测试逐项核对了四个查询：推迟原因与优先级、当前成员的规则、下一个修订号、分页（含开始时间相同的两条）、会话补齐越过水位、重新收录与再看一遍时略去已不在热库的。另一个测试在两万条 audit 的库上看 `Due` 的执行计划：沿 `audit_records_started_idx` 只读本页的行。
12. 推迟原因的优先级：未终结（`open`）、解析未到终态（`parse_pending`）、调用者查找未到终态（`caller_pending`）。
13. “当前成员”（B.1 第 4 条）取“不是 `stale`，且所在分段的格式版本等于当前版本”，分段在 `publishing` 时也算：部分唯一索引反正不允许同一 audit 有第二个非 `stale` 的行。

**导出（H.2 第 2 步、H.3、H.4、H.7）**

14. 导出快照要求已经 `EnableIntegrity`，否则打不开。
15. 一条 audit 导出前要全部证明完：
    - 事件复核（H.3）；
    - 每一段密文的认证解密：Header（经 `headerblock.Expand`，用与查询层相同的 `HeaderSource`，含失败与中断的宽松规则）、Request-URI、User-Agent、`parsed_json_enc`、时间线、项目标识、外部引用值、每一个 raw 块、每一个内容对象与二进制对象；
    - 完整 Body 的 SHA-256；
    - 对象的内容地址与语义哈希；
    - 引用的语义哈希与对象一致。
    原因：包写入器在取对象或 raw 块失败时作废整个分段（`SegmentWriter.Add`），所以不能把问题留到写的时候才暴露。
16. 版本 2 的块经 `headerblock.Expand` 展开之后，再打开一次取有段的阶段集合（`block_stages`）。块很小，打开两次换来不复制 `Expand` 的宽松规则。
17. **两项比 H.2 写得更严的检查**，在交给写入器之前做，都只排除这一条：
    - raw 块的布局按 `bundle` 重读时的规则：每块属于某个 `full`、非 `streaming` 的 Body 的来源阶段，块号与偏移相接（只有带 `capture_chunk_missing` 的残缺 Body 允许向前跳，且不越出观察长度），块数与字节数等于 `chunk_count`、`stored_length`。否则原因是 `raw_unservable`。不这样，一条这样的记录要到 H.2 第 6 步的重读才被发现，而那时作废的是整个分段；
    - 时间线按 `query.TimelineFromPlain` 的边界核对，不过的原因是 `timeline`。
18. **排除的原因**（`ArchiveMemberError.Reason`）：
    - 完整性类：`event_missing`、`event_payload`、`event_mac`、`decrypt`、`content_hash`、`turn_graph`。这一类把存储的载荷校验状态置为失败（P 第 4 条）；
    - 其余：`not_found`、`open`、`timeline`、`raw_unservable`、`record_format`。不改载荷校验状态；`record_format` 表示代码有缺陷，不是数据损坏。

    **runner 必须把 `not_found` 以外的每一种排除都登记进 `archive_deferred`**，否则水位越过它们之后再也不会选到（第 3 条的同一个缺口）。完整性类记 `integrity_failed`；`timeline`、`raw_unservable`、`record_format` 不是损坏，记成另加的取值 `export_failed`（迁移 008 未发布，原地修改了 CHECK），不与完整性失败混在一起。
19. **快照本身的故障不当作损坏。** 上下文取消、存储已关闭、事务不再应答（失败之后用 `SELECT 1` 探一次）都原样返回，结束这一趟，不排除成员、不置失败。事件摘要函数在快照仍然可用时报的错，按 `event_payload` 处理。
20. 内存：
    - 对象与二进制每个快照只核对一次，只记哈希，至多 2^20 个，满了清空重来；
    - 写入器要对象时再解密一次；
    - raw 块一次一块；
    - `parsed_json` 整段在记录里，上界 128 MiB（H.7）。
21. NULL 的约定（R.4 第 6 条）：空的 `parsed_json_enc` 导出为 NULL；解密出来为空的值写成非 nil 的空切片。
22. 外部引用的值和内容对象的规范 JSON 原文以前没有读取方。`auditmodel` 为此加了两个薄的导出函数 `OpenContent`、`OpenExternalReference`，AAD 与解压的代码不复制。

**变更戳（M.1）**

23. 字节按 M.1，没有改动：
    - 主键按列的排序规则（`C`）排序，所以阶段按名称的字节序，不按采集顺序；
    - `integrity_events` 的主键是 `sequence`；
    - 两张轮次子表经 `turns.audit_id` 找。
    audit 不存在时，戳是一组空行集合的戳，另返回“不存在”。测试用手写的字节序列核对了一条 audit 的前像。
24. 在 PostgreSQL 18 上测过：重读、`VACUUM (FREEZE)`（测试要求成员行的 `xmin` 早于表的 `relfrozenxid`，也就是确实冻结了；共享库上别的会话的旧快照挡住冻结时这一项跳过）、`VACUUM FULL` 不改戳；`SELECT … FOR UPDATE` 也不改；值不变的 `UPDATE`、M.1 第 1 到 3 行、每张表插入或删除一行都改戳；只动别的 audit、共享内容对象、`conversations.updated_at_ns` 的写不改戳。

25. 登记意向在 writer 上执行，变更戳对每个成员要查 14 张表。实现按每 400 个成员一批查（每张表一条语句），修订号与当前行也成批读，结果与逐条计算的戳逐字节相同（有测试）。本机 2000 个成员的意向约 0.3 秒；逐条计算时约 3.3 秒。

**列覆盖与摘要敏感性（J.1 的 PostgreSQL 部分）**

26. 列覆盖测试从 `information_schema.columns` 和 `pg_constraint` 读当前 schema，调 `archive.CheckSchema`。它也证明会失败：给 `http_stages` 加一列、新建一张引用 `audit_records` 的表、新建一张经 `audit_analysis` 间接引用的表，各自都被点名。
27. 摘要敏感性测试对 `archive.Columns` 里每一个“进摘要”的列改库里的一行，重签它的事件，再导出。测试先删掉测试 schema 里的全部 CHECK 与外键，使任何值都写得进去。结果：
    - 116 列：记录摘要变了；
    - 49 列：这一条被排除，各自写明预期的原因。它们被别的东西绑着：AAD、内容地址、序列哈希、长度、时间线的点、事件本身。其中有 Q6 的两个血缘列 `parent_turn_id`、`parent_base`：随便改成一个不存在的父轮次，轮次图就走不通，语义事件复核不过。这比任务要求的
    - 13 列跳过：11 个作为子表键的 `audit_id`，以及两种引用行的 `object_hash`（移到轮次够不着的对象，引用行就从记录里消失）。这些列的敏感性由主机上的摘要测试覆盖。
28. 测试发现，0/1 的标志列在库里写成 2 时，摘要与 1 相同：归档把非零都读成真。CHECK 约束挡住了这种值，所以不是缺陷。测试对这几列改为翻转 0 与 1。

**三层能接上**

29. 端到端测试的路径：采集版本 2 的 audit 经真实的 unified 会话写入，版本 1 的经存储的逐操作写入；导出；用 `bundle.SegmentWriter` 写会话包和桶包；`bundle.Open(...).Verify` 重读。
    - 报告的摘要与快照算出的逐条相等；
    - 父轮次在同一分段的子轮次保留增量形式；
    - 后一次导出里父轮次不在本分段的孙轮次是物化形式，单独核对通过。
    覆盖的形态：有轮次、无轮次的兜底会话、只有请求并带半截回答的轮次、失败的采集和被中断的采集（都有残缺 Body）、合并的请求对、压缩与明文两种 `parsed_json_enc`、二进制对象、分支、跨两次导出的会话，以及另一个测试里的两种 Header 形态：版本 1 的逐值行（`Authorization` 和 `?key=` 投影成长度加指纹，与已知值的指纹相同），版本 2 失败采集的块里有一段对应的阶段没有行（`Expand` 的宽松规则）。损坏的块和篡改的事件都只排除自己那一条。
30. 三层之间没有发现摘要或格式上的不一致。发现的一处是文件名：包名只取运行 id 的前 8 位，同一会话的两个分段在同一秒内由前 8 位相同的运行写出时同名，发布报 `name_exists`。随机的运行 id 下几乎不会发生，测试里给每个包不同的前缀。

**给 runner 的接口**

| 名称 | 用途 |
| --- | --- |
| `(*Store).OpenArchiveSnapshot(ctx, ArchiveSnapshotOptions{Cipher, Fingerprinter})` | 开导出快照，`Fingerprinter` 用 `*security.ArchiveKeys` |
| `(*ArchiveSnapshot).Due(after, cutoffNS, formatVersion, limit) (ArchiveDuePage, error)` | 水位之后的一页候选 |
| `(*ArchiveSnapshot).Candidates(ids, formatVersion)` | 推迟的与要重新收录的 audit 再看一遍 |
| `(*ArchiveSnapshot).ConversationCandidates(conversationIDs, cutoffNS, formatVersion)` | 补齐一趟涉及的会话 |
| `(*ArchiveSnapshot).StaleCandidates(cutoffNS, formatVersion, after, limit)` | 有 `stale` 成员、要重新收录的 audit |
| `(*ArchiveSnapshot).Export(auditID, revision) (*ArchiveExport, error)` | 一条记录、摘要、变更戳、`turn_created_at_ns`；单条失败为 `*ArchiveMemberError` |
| `(*ArchiveSnapshot).ContentObject`、`BinaryObject`、`RawChunk` | 实现 `bundle.Payloads`，快照本身就是写入器的 `payloads` 参数 |
| `(*ArchiveSnapshot).Close()` | 结束快照，在包写完之后 |
| `ArchiveMemberError{AuditID, Reason}`、`Integrity()`、`ArchiveReason*` | 排除的原因 |
| `(*Store).BeginArchiveRun(ctx, ArchiveRun) (int64, error)` | 开始运行，返回改为 `interrupted` 的旧运行数 |
| `(*Store).RecordArchivePass(ctx, ArchivePass)` | 一趟结束：水位、计数、推迟、不再推迟 |
| `(*Store).UpsertArchiveDeferred`、`DeleteArchiveDeferred` | 单独维护推迟的 audit |
| `(*Store).RegisterArchiveIntent(ctx, ArchiveIntent) (ArchiveIntentResult, error)` | 登记意向 |
| `(*Store).SealArchiveSegment(ctx, ArchiveSeal)` | 定稿 |
| `(*Store).DropArchiveIntent(ctx, segmentID) (bool, error)` | 删掉意向 |
| `(*Store).RegisterReconciledArchive(ctx, ArchiveReconciled) (ArchiveReconciledResult, error)` | 对账登记不认识的包 |
| `(*Store).FinishArchiveRun(ctx, ArchiveRunFinish)` | 结束运行 |
| `(*Store).LastArchiveRun(ctx, status)`、`ArchiveWatermark(ctx, formatVersion)` | 补跑判断与水位 |
| `(*Store).ArchiveSegment`、`ListArchiveSegments(ctx, state, after, limit)` | 分段，对账找 `publishing` 的 |
| `(*Store).ListArchiveMembers(ctx, ArchiveMemberQuery)`、`ListArchiveGapMembers`、`ArchiveCurrentRevision` | 按状态或分段列成员，取一条 audit 的最高修订号 |
| `(*Store).ListArchiveDeferred(ctx, after, limit)` | 推迟的 audit |
| `storage.Archive*` 类型与常量 | 运行、分段、成员、推迟、意向等的形状与取值，以及它们的校验函数 |

快照的类型在 `postgres` 包里：记录类型 `archive.Record` 依赖 `internal/storage`，所以返回记录的接口不能放进 `internal/storage`。runner 如果要用接口隔离存储，需要在自己一侧定义接口，并为 `*postgres.ArchiveSnapshot` 写一层薄的适配。

### R.7 读取工具 `cmd/audit-archive`（O.1 第 10 个提交，逻辑在 `internal/archivecli`）

1. **五个子命令**：`list`、`verify`、`cat`、`export`、`fpr`。退出码：0 完成；1 有核对不过、有包被跳过、有清单被索引剔除（`incomplete`）、密钥不符或输出写不出去；2 用法错误；3 找不到、该记录没有这种导出，或 `fpr` 没有匹配。错误写到标准错误，形如 `audit-archive: <码>: <说明>`。
2. **`list`** 不带密钥也能列出全部包；带 `--key` 时多一列，标明每个包的清单签名是 `ok`、`key_mismatch` 还是 `mac_mismatch`；签名不符不改变退出码（`list` 只是盘点）。
3. **`verify`** 有两个级别：不带密钥只核对文件大小和哈希（`files`，输出里标明较弱）；带密钥做 J.2 的全部检查（`full`）。带密钥时默认核对原完整性事件的 MAC，`--skip-event-mac` 可以关掉并给出告警。
4. **`cat`** 输出的是核对通过后重新编码的行，测试表明与包里存的行逐字节相同；核对不过的包被跳过并以 1 退出。索引因签名或密钥指纹不符、解析不了而剔除了任何清单时，`cat`、`export`（单条与按会话）和 `fpr --dir` 照常输出核对通过的部分，再以 1 退出（码 `incomplete`），不论有没有过滤：被剔除的清单不可信，说不清装着哪些记录，不全的输出不能看起来是全的。验收测试发现过最初的实现只数读取时跳过的包、漏了索引剔除的清单，伪造清单的唯一一个包会让 `cat` 以 0 退出、输出为空。不带过滤时包含 gap 行。`--with-objects` 逐条流出对象文件（为此在 `bundle` 里加了一个 `Objects` 迭代）。
5. **`export`** 的种类：`conversation`（默认）、`headers`、`request`、`response`、`raw-request`、`raw-response`、`timeline-request`、`timeline-response`、`detail`。`detail` 是正文没有列的一种：投影后的详情。`--conversation` 按会话导出时每行一个对象 `{"audit_id","turn_id","created_at_ns","conversation"}`，每条 audit 取最高修订号，跨包按 `(created_at_ns, audit_id)` 排序。
6. **JSON 的形状是照 Agent 门面重新声明的**，因为引入 `internal/web` 会破坏“不链接存储”的依赖守卫。集成测试要拿它与门面真实的 HTTP 输出比一次，防止两边走样。
7. **`fpr`**：已知的 Key 从文件、管道或不回显的终端读入，从不作为命令行参数。输出三个候选（Key 本身、`Bearer ` 加 Key、`api_key_fpr`），带 `--dir` 时在全部修订号里查找并列出匹配。
8. **密钥**：主密钥文件用应用同一个读取函数读，只读不建；带密钥时索引带着签名校验建立，伪造的清单不能顶替真的修订号；因密钥不符而查不到时报“密钥不符”，不报“找不到”。
9. **不回显读取移到了 `internal/termio`**（P 第 14 条），`llmaudit` 改为引用它；`agentcli` 里检查“只用标准库”的测试相应放行这个包。模块 25 里说 `llmaudit` 只依赖标准库加 `agentapi` 的两处要更正。
10. 发布脚本和镜像按 `audit-import` 的方式带上了 `audit-archive`。

### R.8 归档运行、配置与接线（O.1 第 9 个提交）

runner 在 `internal/archive/runner`，配置在 `internal/config/archive.go`，组装与启动护栏在 `internal/app/archive.go`。模块文档是 `doc/features/26-cold-archive.md`（第二部分）。下面是与 B、H、L 节不同或正文没有写到的地方。

**这一步只导出。** `archive_then_delete` 与 `export_only` 做的事完全相同；runner 在全部趟和 gap 之后留了一个移除阶段的接缝（`removalPhase`），现在什么都不做。启动日志在 `archive_then_delete` 下另加一条 `archive_removal_inactive`。唯一的模式差别是 `stale` 成员的重新收录只在 `archive_then_delete` 下进行（P 第 8 条）。

**配置（L.1）**

1. `mode` 省略、为空串或为 `off` 都是关闭，这时整段不做任何检查（不看 `dir`、阈值和时区）。
2. 比 L.1 多的上界：`conversation_min_turns` 至多 1,000,000，`conversation_min_bytes` 至多 4 GiB，`pass_audits` 至多 10,000（导出快照一页的上限），`run_deadline_minutes` 至多 1440。
3. `timezone` 为空时取 `org_reports.timezone`，不论组织周报是否开启（P 第 1 条），并在配置校验里加载一次。`archive.dir` 不得与 `audit.staging.dir` 重叠（P 第 13 条）。
4. 归档目录的启动检查复用暂存目录的 `staging.PrepareDirectory`（不存在就以 0700 创建，Unix 上属主是进程用户、没有组和其他用户的权限，能写入探针文件）。不过时 runner 不组装，日志 `archive runner unavailable`，`reason` 是 `dir_` 加暂存目录的码；审计和代理照常工作，retention 的直接删除仍然不组装。其他不能组装的原因：`audit_unavailable`（存储、查询服务或归档子密钥不在）、`invalid_timezone`、`invalid_options`。

**护栏（L.2）**

5. 第 2 条：`archive.mode` 不为 `off` 时 `retention.Runner` 不组装，audit 和 gap 都不再直接删除；启动日志 `archive export only: hot store keeps growing`（`archive_export_only`）。
6. **第 3 条比 L.2 宽。** L.2 的条件是“目录表里有 `hot_removed` 的成员或 `mode = 'archive_then_delete'` 的运行记录”；实现是目录表里有**任何一条**运行记录（`LastArchiveRun` 不限状态），在 10 秒的超时里查。这一版没有任何成员会是 `hot_removed`，按 L.2 的条件这条提示永远不会出现，而 `export_only` 之后关掉归档同样会恢复直接删除。
7. 第 5 条：`HasAudits`（R.6）之外，归档开启时启动递归查 `archive.dir` 里有没有 `*.manifest.json`（P 第 12 条）；目录读不了按“有”处理，目录不存在按“没有”。因此拒绝新建密钥时，`audit key unavailable` 另带 `reason=archive_manifests_present`。归档关闭时不查目录。
8. 归档子密钥和核对抄录事件用的完整性签名密钥只在归档开启时派生，与其他子密钥一起、主密钥清零之前；派生失败时审计不可用（`audit archive keys unavailable`）。

**调度（H.1、H.4）**

9. 补跑：最近一次 `completed` 的运行开始于 24 小时之前，或者没有，启动后立即运行一次；目录表读不出来时也运行，由运行自己报告失败。
10. 重试：失败后每 10 分钟一次，直到某次 `completed`，或者下一次尝试的开始时间距当天第一次尝试超过 `run_deadline_minutes`。重试沿用当天第一次尝试的期限，不各自另起一个（提交 `f67d4bc`）。
11. 进程关闭时取消正在进行的运行：运行在目录表里留在 `running`（日志 `archive run interrupted`），下一次 `BeginArchiveRun` 把它改为 `interrupted`，它留下的分段由对账处理。

**一趟（B.1、B.2）**

12. 一趟的预算 `pass_audits` 依次分给：推迟过的 audit（每次运行开始时读出全部推迟行，每条每次运行再看一次）、`stale` 的成员（只在 `archive_then_delete` 下，且推迟的看完之后）、水位之后的新范围。B.2 只说新范围。
13. 期限只在趟与趟之间检查，至少做一趟；到了期限这次运行仍以 `completed` 结束，完成日志带 `deadline_reached`。**到了期限时 gap 不导出**，留给下一次。
14. 推迟：快照给出的 `open`、`parse_pending`、`caller_pending`，导出时完整性类的排除记 `integrity_failed`，其余排除记 `export_failed`（R.6 第 18 条）；包写入方拒绝的记录和抽样读出不同的成员（第 25 条）也记 `export_failed`。`not_found` 的和已有当前成员的从推迟表里去掉。不能导出的成员留在热库、登记推迟、按原因计数报告，之后每次运行再看。
15. 水位只在这一趟的分段全部定稿之后，随计数、推迟和不再推迟的 audit 一起由 `RecordArchivePass` 写入（R.6 第 3 条）；新范围这一页没有任何行时水位不动。

**分组与装包（B.3、B.4）**

16. 会话的轮次阈值数的是这一趟选中的该会话到期 audit 的条数（包括随后导出时被排除的）。
17. 字节阈值按估算累计：每条记录编码后的行长、拆出的 `parsed_json` 段，加上本会话还没算过的对象与二进制的明文长度和 raw 块的长度。达到之前的记录先留在内存里，达到时一起写进会话包，会话结束仍不够就进桶包。所以低于阈值的会话至多在内存里留 `conversation_min_bytes` 的估算量。
18. 会话 id 不匹配文件名规则（`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`），或会话里的 audit 不全是同一个协议时，这个会话不独立成包，各条 audit 进各自协议的桶包。
19. 桶包每趟每个协议一个，协议是 `audit_records.protocol`（解析器名的前缀），所以 OpenAI Chat、Completions 与 Responses 共用 `openai` 桶。会话按 id 的字节序处理，桶按协议名的字节序封包。
20. 分段号以（种类、协议、会话）为键，在一次运行的各趟之间连续编号：两趟的桶包可能覆盖同样的秒数，名字里又有运行 id，靠分段号区分。R.6 第 30 条说的“两个运行 id 前 8 位相同的运行在同一秒写出同名分段”仍可能发生，只是概率极小。

**一个分段（H.2 第 3 到 7 步）**

21. 每个分段写满或这一趟写完就立即封包、登记、发布、核对、定稿，再写下一个包；H.2 把关文件、登记、发布写成一趟的第 3 到 7 步，没有说是逐个分段做。分段的清单临时文件在登记之前就已写好并 fsync（R.5 第 6 条）。
22. 重读核对之后，每个成员重算的摘要要等于导出快照里的；gap 包比较 gap 数。
23. **抽样（J.3）。** 抽 `ceil(verify_sample × n)` 条，至少一条：`verify_sample` 为 0 时每个包也比对一条。登记意向时已是 `stale` 的成员不参加；gap 包不抽样。比较的是读取工具的渲染：详情（经 `archive.ProjectDetail` 投影的热库详情）、Header、重建的 Turn 与 provider 请求和响应、会话、两侧时间线、两侧 raw 的元数据和字节的 SHA-256；一侧出错时比较错误类别。**`List` 那一行的摘要不比**（J.3 的表里有）。
24. 比较不等时，在只读连接池上开一个 REPEATABLE READ 快照重算这条成员此刻的变更戳（`ArchiveChangeStamp`）：与导出时不同或 audit 已不在，计入这次运行的 `stale_audits`，不作废这个包；相同则按第 25 条只排除这一条。变更戳变了的那种成员**在目录表里仍是 `sealed`**，只有计数记下它；`exported_audits` 也照样算上它（`exported_audits` 只减去登记意向时就是 `stale` 的）。移除上线时，移除前的变更戳比对会把它挡下。
25. **一条成员的问题只排除这一条**（提交 `a913f30`；H.4 和 J.3 写的是整个包作废、运行失败）：
    - 包写入方以记录本身的原因（`invalid_record`、`order`、`context_mismatch`、`payload_mismatch`、`entry_too_large`）拒绝一条记录时，`SegmentWriter.Add` 已作废整个未封的分段；runner 把这条推迟为 `export_failed`、Warn `archive record refused`（`archive_record_refused`，`reason` 是写入方的码），再从仍然打开的快照里把这个分段的其余成员重新读出写进新分段。被拒记录的子轮次因为父轮次不在分段里了，由写入方改写成物化形式。
    - 抽样发现一条成员读出不同而变更戳没变时，这个包照样作废（`.rejected`、删意向行），但这条推迟为 `export_failed`、Warn `archive sample mismatch`（`archive_sample_mismatch`），包里其余的成员在同一趟里写进一个新包并重新走登记到定稿。
    运行继续，这一趟的水位照常推进；完成日志分别计 `refused_audits`、`sample_mismatch_audits`，两者也计入 `excluded_audits`。真实行上产生不了写入方拒绝（`Export` 先做同样的检查），这条路径由 runner 的主机测试覆盖；抽样的这条有 PostgreSQL 上的测试（提交 `daf91b5`：成员自己的回答对象在快照之后被损坏，共享的内容对象不在变更戳里，所以差异归到这条成员）。
    I/O 与快照的故障、重读 `Verify` 不过，仍然作废这个包并让运行以 `archive_failed` 失败。
    对账里抽样读出不同而变更戳没变时也一样只排除这一条：包作废（`.rejected`、删意向行），这条记入这次运行的扣留集合，同样计 `excluded_audits`、`sample_mismatch_audits` 并 Warn `archive sample mismatch`；这次运行的各趟在分类时跳过它（推迟复查、`stale` 重新收录、新范围和 B.2 的会话补全都不选它），第一趟把它连同那一趟的推迟一起写成 `export_failed`。留在 `publishing` 的分段所在的那一趟从没有记录过（记录在这一趟的分段全部定稿之后），所以包里其余的成员仍按原来的途径到期，由这次运行随后的一趟重新导出（`TestReconciliationDefersAMismatchedMember`）。原先对账作废包后不推迟这条成员，这一趟又把它导出一次、再比较一次，由正常路径推迟。第一趟失败时扣留的推迟随之丢失，下一次运行照正常路径再比较它。
    **抽样时热库读不出来（`sample_failed`）**，新发布的分段与对账的处理相同：`Compare` 出错（`QuerySampler` 里只有热库一侧会让它出错，归档一侧读不出来算作不同）不说明包有问题，包不作废、意向行不删，分段留在 `publishing`；运行以 `archive_failed`（`reason=sample_failed`）结束，这一趟没有记录，水位不动；下一次运行的对账按第 26 条重新抽样，通过就定稿。原先新发布的分段在这时也被改名 `.rejected`，与对账不一致。`sample_failed` 的另一种来源仍然作废包：一条成员比较不等、再查变更戳时热库读不出来，差异没法归到快照之后的改动，包可能有问题。对账里这种情形照旧不作废、留在 `publishing`。

**对账（H.6）**

26. `publishing` 的分段：清单不在就删意向行；在就重读核对，与意向行的成员、修订号、摘要比对，再按第 23、24 条抽样，都通过才定稿（提交 `a2c2420`：对账也要先抽样）。抽样读出不同而变更戳没变时只推迟那一条，见第 25 条。抽样时热库读不出来，这次运行以 `sample_failed` 失败，分段留在 `publishing` 下次再试；新发布的分段同样处理，见第 25 条。
27. 目录表不认识的包：`bundle.Open` 失败（例如密钥不符）的静默跳过；`Verify` 不过的只记一条 Warn，不改名；通过的按 R.6 第 10 条登记，成员一律 `stale`，已有当前成员的 audit 不登记。
28. 写入方命名的临时文件删除；没有清单列出的数据文件改名 `.orphan`；有清单解析不了或签名不对时 Warn 一条 `archive_manifest_unusable`。H.6 第 4 步（继续移除）属于移除阶段，现在不做。

**gap（C.6）**

29. 结束于截止时间之前、不在任何 gap 成员行里的 gap，每包至多 10,000 条，按 id 升序，与分段一样登记、发布、核对、定稿，不抽样。gap 只插入不更新，所以每条只导出一次，没有修订号。

**日志与运行记录（H.5）**

30. 完成日志 `archive run completed` 与失败日志 `archive run failed` 的字段：`status`、`exported_audits`、`deferred_audits`、`integrity_failed_audits`、`excluded_audits`、`stale_audits`、`exported_gaps`、`refused_audits`、`sample_mismatch_audits`、`segments`、`disk_bytes`、`duration_ms`，推迟数大于 0 的原因各一个 `deferred_<原因>`，可选 `reconciled_segments`、`deadline_reached`；失败时加 `error_category=archive_failed`、`reason` 和（不是包层的错误时）`storage_error`。失败的 `reason`：`catalog_failed`、`snapshot_failed`、`intent_failed`、`seal_failed`、`sample_failed`、`count_mismatch`、`digest_mismatch`、`manifest_name`，以及 `internal/archive/bundle` 的码。
31. 一条 audit 的完整性类排除另记一条 Error `archive integrity check failed`（`archive_integrity_failed`，`reason` 是 R.6 第 18 条的原因）。
32. `archive_runs.disk_bytes` 和完成日志的 `disk_bytes` 含清单本身的字节；分段行的 `disk_bytes` 同样含清单。

**给后续提交的说明**

33. `internal/archive/columns.go` 的注释说列规格是“schema version 7 定义的”，现在是 8（迁移 008 只建目录表，没有改归档表，内容不受影响）。R.6 第 27 条第 2 项末尾的“这比任务要求的”是一句没写完的话，原文没有动。

### R.9 校验后移除（O.1 第 13–15 个提交）

**批量（第 13 个提交）**

1. `retention.Batcher` 只管尺寸策略：当前批量、上限、上一轮是否完成。计时和暂停由调用方做，所以 retention 测试换掉的时钟和暂停函数照旧起作用。导出的还有 `TargetBatchTime`（1 秒）、`MaxBatchPause`（5 秒）、`PauseAfter(elapsed)`、`Wait(ctx, d)`。retention 的行为与测试不变。

**存储操作（第 14 个提交，`postgres/archive_remove.go`）**

2. `RemoveArchived(ctx, []ArchiveRemoval, removedAtNS)` 是 writer 操作 `writeRemoveArchived`，与 `writeDeleteExpired` 一样独占事务。与 M.2 的差别：
   - 第 1 步的加锁语句同时锁成员行与分段行（`FOR UPDATE OF m, s`），条件里直接写 `s.format_version >= 1`、两者都是 `sealed`、分段不是 gap 包、成员有变更戳。格式版本门槛在 SQL 里，调用方绕不过去；
   - 调用方给的 `(segment_id, revision, change_stamp)` 只作为额外的匹配条件：与目录表里的行不一致就跳过（`skipped`），删除的依据始终是事务内重算的戳与目录表里存的戳相等；
   - 全部成员的戳在调用 `deleteAuditBatch` 之前算完，同一批里父轮次的检查点不会算到子轮次头上；
   - 每条成员的结果是 `removed`、`stale`、`already_gone`、`skipped` 之一，按请求顺序返回；没有 `sealed` 成员的分段改为 `hot_removed`，`removed_at_ns` 取本批时间。全部成员变 `stale`、一条也没删的分段同样改为 `hot_removed`（M.2 第 4 步的字面意思）。
3. `RemoveArchivedGaps(ctx, limit, removedAtNS)`：按 gap id 升序锁至多 `limit`（≤ 200）条可移除的 gap 成员，删 `audit_gaps`，改 `hot_removed`，空了的 gap 分段改 `hot_removed`。行已不在的 gap 照样标记，结果分别给出标记数和实际删除的行数。
4. `ListRemovableArchiveMembers(ctx, after, limit)` 在只读池上按 `(audit_id, revision)` 分页列出可移除成员，排序由 runner 做（第 6 条）。新增的共享类型在 `storage/archive_types.go`：`ArchiveRemoval`、`ArchiveRemovable`、`ArchiveRemovalOutcome`、`ArchiveRemovalResult`、`ArchiveGapRemovalResult`、`ArchiveRemovalMinFormatVersion`（= 1）、四个结果常量和 `ValidateArchiveRemovals`。没有迁移。

**runner（第 15 个提交，`archive/runner/remove.go`）**

5. 移除阶段只在 `archive_then_delete` 下进入，位置不变：全部趟和 gap 导出之后。一次性列出全部可移除成员（每条约一两百字节，规模是“已导出未移除”的成员数），在 Go 里排序后切批，所以排序只有一份实现。到了运行期限就不再开始新批，不论期限是在趟里还是在移除中途到的；没做完的成员下次运行继续（H.6 第 4 条）。一批失败时整次运行以 `removal_failed` 结束，已提交的批保留。
6. 导出的 `RemovalOrder`：`turn_created_at_ns` 降序，没有轮次的在最前，相同时 `audit_id` 降序（字节序，与目录表的 `C` 排序规则一致）。
7. 批量：`Batcher` 从 1 起，整批且不超过 0.5 秒翻倍，超过 1 秒按比例缩小，慢失败降到 1；每批之后暂停同样长，至多 5 秒。gap 每批 200 条。`Batcher` 保存在 `Runner` 上，跨运行保留。
8. 计数：`Result.Removal`（`Removed`、`Stale`、`AlreadyGone`、`Skipped`、`RemovedGaps`、`RemovedSegments`、`Batches`、`GapBatches`、`Duration`）。移除的 audit 与 gap 写进运行记录的 `removed_audits`、`removed_gaps`；移除时发现变化的成员计入 `stale_audits`，与登记意向时发现的合在一起。完成日志 `archive removal completed`，`event=archive_removal_completed`，只有计数和耗时。
9. 测试点：`StepBetweenRemovalBatches`（每个已提交、不是最后一批之后）、`StepAfterRemoval`（全部批之后、运行记录写完之前）。
10. 被移除时标成 `stale` 的成员由现有的 `StaleCandidates` 在下一次运行里重新收录（修订号加一），主机测试和 PostgreSQL 测试都证实了。
11. 启动日志：`archive_then_delete` 下 `archive_removal_active`（校验后移除对格式版本不低于 1 的包生效，带 `format_version`）；格式版本低于 1 时再加 `archive_removal_trial_format`：试行格式的包只导出、从不作为移除依据，热库不会删任何东西、持续增长。原来的 `archive_removal_inactive` 和 `archive_then_delete` 下的 `archive_export_only` 不再输出。
12. 测试怎样走到格式版本 1：`runner.Options.FormatVersionOverride` 只供测试，`app` 只经过测试用的 `archiveSeams` 传入，配置里没有它。runner 因此在选取、水位和登记分段时都用版本 1，包本身仍写 `archive.FormatVersion`（0）。只改目录表的 `format_version` 行不通：R.6 第 13 条的“当前成员”要求分段版本等于 runner 的版本，下一次运行会把这些成员重新导出并把旧行改成 `stale`。

**测试的发现**

13. 真实流量里造不出分支：代理按会话 key 把新轮次挂到该会话最新的轮次上，`Fork` 出来的两条续写在库里仍是一条链。分支的顺序由 runner 的主机测试覆盖，PostgreSQL 测试用的是链和成对的会话。
14. M.1 第 1 行（计费回填）的完整循环（变 `stale`、下次以修订号 2 导出并移除）只在存储测试里做了：测试流量没有 `X-Oneapi-Request-Id`，补上调用者字段会让 `capture_finalized` 复核不过。应用层的循环用项目标识的首次写入与升级、以及检查点三种写。
15. 按 `started_at_ns` 降序（A/B 情形，测试里只改目录表里的 `started_at_ns` 副本）逐条移除一个四轮会话：2 条成员误成 `stale`、2 个轮次被检查点改写；按 `RemovalOrder` 都是 0。

**待维护者决定：删除之前是否再核对一次包**

M、H.6 和 4.5 只在导出时（H.2 第 6 步）重开已发布的文件做完整核对，删除时只核对变更戳，不看盘上的包。实现照此办理，没有加额外的核对。所以分段定稿之后、移除之前包被删掉或损坏，成员仍会被移除，热库里的数据就只剩坏掉的包。可选的做法：

- 甲，照现在：不再核对。代价：上面的情形无人发现，直到有人去读那个包。
- 乙，每个分段在它的第一批移除之前做一次便宜的核对：文件存在、清单 MAC、清单与数据文件的 SHA-256 与目录表的 `manifest_sha256` 相符。代价：每个分段读一遍文件求哈希（每个分段至多 `segment_max_bytes` 的压缩后字节），不解密、不解析；失败时这个分段的成员不移除并报一个稳定码。
- 丙，乙再加 J.2 的完整重读。代价：与导出时的重读相同，移除阶段的耗时大约翻倍，而它与导出时的重读重复。

推荐乙。
