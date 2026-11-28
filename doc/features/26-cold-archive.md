# 模块 26：冷归档（只导出）与归档格式

> 状态：issue #59 第 4 阶段的 P3（只导出）已实现，格式版本 0（试行）。校验后移除（P4）还没有生效。
> 设计：[第 4 阶段详细设计](../design/issue-59-stage4-cold-archive.md)；实际做成的样子以它末尾的实施记录 R.1 到 R.8 为准。

本文分两部分。第一部分（§2 到 §16）是归档格式规范：写到不读本仓库代码也能解析一个包、核对它的签名和每条记录的摘要。第二部分（§17 到 §24）是模块本身：模式、配置、一次运行做什么、日志、对账、读取工具和风险。

## 1. 目标与边界

冷归档把 retention 本来要删除的 audit 导出到一个目录里，每天一次。导出的是解密之后的明文行，按会话或协议装成包，整包压缩并加密（可以关闭），每个包有一份签名的明文清单。归档目录离开数据库、离开运行中的代理，只凭主密钥文件和读取工具 `audit-archive` 就能核对和读出。

- **本版本只导出。** `export_only` 与 `archive_then_delete` 两种模式都不从热库删除任何 audit 或 gap：打开归档以后 retention 的直接删除不再组装，热库会一直增长（§17.3）。`archive_then_delete` 现在的行为与 `export_only` 相同，校验后移除（设计 M 节）是以后单独的改动。
- **不做恢复。** 归档读不回 PostgreSQL，也不进管理界面；已归档的记录只能用读取工具查看。
- **只在 PostgreSQL 上。** SQLite 存储没有目录表，也不归档。
- 归档的完整性要靠检查来证明（设计 J 节）：列覆盖测试保证每一列要么进了归档、要么写明了为什么不进；每个包发布后重读核对；再抽样与热库的读出比对。

---

# 第一部分　归档格式（版本 0）

## 2. 格式版本与兼容承诺

格式版本 0 是试行版本：

- **版本 0 的包永远不作为从热库删除数据的依据。** 将来的移除只作用于格式版本不低于 1 的分段。
- 格式在版本 0 期间可以改动，改动之后旧包要重新导出。现在的读取工具只接受 `format_version` 为 `"0"` 的清单。
- 本地验收通过后，格式定为版本 1，这是单独的一个改动（维护者的决定，见设计 0.0）。从那以后的承诺是：任何正式发布过的格式版本，当前和以后的读取工具都能读。清单带着各表的列清单（§14），每个发布过的版本还要冻结一个夹具包，用当前的读取工具逐个读一遍；版本 1 的冻结夹具随那次改动提交。

### 2.1 随格式版本变化的字符串

定为版本 1 时只改这一节列出的值，本文其他地方用左列的名字指代它们。

| 名字 | 版本 0 的值 | 用在 |
| --- | --- | --- |
| `<格式版本>` | `0`（清单里写成字符串 `"0"`） | 清单的 `format_version`（§14） |
| `<记录摘要域>` | `llmapi-logger/archive-record/v0` 加一个 `0x00` 字节 | 记录摘要的开头（§13） |
| `<清单域>` | `llmapi-logger/archive-manifest/v0` 加一个 `0x00` 字节 | 清单 MAC 的输入开头（§14.2） |
| 测试向量文件 | `internal/archive/testdata/record_full_v0.jsonl`、`record_full_v0.digest`、`record_hand_v0.jsonl`、`record_hand_v0.digest`、`manifest_v0.json`、`manifest_v0.encoding.hex` | §13.3、§14.4 |
| `record_full_v0` 的摘要 | `2a101c5f55d7d10792ded30f13b2e6778103db600f5675ca4e75dcc998e77cbf` | §13.3 |
| `record_hand_v0` 的摘要 | `2f0edc602dc5407b3f1f936af139584b43928fc49a26ded79c2d40b8bf915730` | §13.3 |

不随格式版本变化的：密钥派生的五个域字符串（都是 `…/v1`，§6）、文件密钥的域字符串和加密流的文件头版本字节 `0x01`（§5，流格式版本与归档格式版本各自独立）、内容地址和序列哈希的域字符串（§10.2、§9.3）、`streamtimeline` 的版本字节（§8.7）。

## 3. 目录与文件

### 3.1 布局

~~~text
<archive.dir>/
  sessions/<YYYY>/<MM>/
    <最早开始>_<最晚结束>_<conversation_id>-<run8>_s<NNNN>.jsonl.gz.enc          会话包的行文件
    <最早开始>_<最晚结束>_<conversation_id>-<run8>_s<NNNN>.objects.jsonl.gz.enc  对象文件（可能没有）
    <最早开始>_<最晚结束>_<conversation_id>-<run8>_s<NNNN>.manifest.json         清单
    <最早开始>_<最晚结束>_bucket-<protocol>-<run8>_s<NNNN>.jsonl.gz.enc          桶包，三个文件同上
  gaps/
    gaps-<first_id>-<last_id>-<run8>.jsonl.gz.enc                                 gap 包的行文件
    gaps-<first_id>-<last_id>-<run8>.manifest.json
~~~

- `archive.encrypt: false` 时数据文件的后缀是 `.jsonl.gz`，没有 `.enc`。清单始终是明文。
- `<最早开始>`、`<最晚结束>` 是包里成员 `started_at_ns` 的最小值和 `ended_at_ns` 的最大值，按 UTC 写成 `YYYYMMDDTHHMMSSZ`（例如 `20261128T030000Z`）。年月目录取最早开始时间的 UTC 年月。
- `<run8>` 是写出它的运行 id 的前 8 个十六进制字符：同一批记录变化后在另一次运行里重新导出（修订号加一）时，时间范围相同，靠它区分名字。
- `<NNNN>` 是分段号，从 `0001` 起，四位。同一次运行里同一个包（同一种类、协议和会话）的分段号跨“趟”（§18.2）连续编号。
- 会话 id 或协议只有匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` 才放进文件名。会话 id 不匹配的会话进桶包（§18.4）。
- gap 包直接放在 `gaps/` 下，没有年月目录，也没有对象文件。
- 新建的目录是 0700，文件是 0600。

**文件名只给人看。** 按会话或 audit 查找一律经过清单（§14 的 `members`、`conversations`），从不按文件名匹配：同一个会话可能分布在多个会话包和桶包里。清单的 `files[].name` 是与清单同目录的裸文件名。

### 3.2 一个包什么时候算存在

一个包由它的清单代表：清单存在，包才存在。写入方先把数据文件链接到正式名，最后才链接清单；正式名已经存在时发布失败，从不覆盖已有文件。

目录里还可能有三种别的文件：

| 文件 | 来历 | 处理 |
| --- | --- | --- |
| `.<segment_id>.<lines\|objects\|manifest>.tmp-<16 位十六进制>` | 写入方的临时文件，位于 `sessions/` 或 `gaps/` 下 | 只有这种文件会被归档器删除（写入失败时，以及每次运行开始的对账） |
| `<原名>.rejected`（或 `<原名>.<n>.rejected`） | 发布后重读核对不过、或对账发现不对的包，三个文件都改名 | 永不删除，留作诊断 |
| `<原名>.orphan`（或 `<原名>.<n>.orphan`） | 没有任何清单列出的数据文件 | 永不删除 |

改过名的清单不再以 `.manifest.json` 结尾，任何读取方都不会再索引到它。

## 4. 数据文件的编码层

行文件、对象文件和 gap 文件都是同一套层次，写入顺序是：

~~~text
JSON Lines → gzip → （加密开启时）分帧加密（§5） → 文件
~~~

- 每个条目是一个 JSON 对象，占一行，以一个 `\n` 结束，最后一行也有 `\n`。条目里没有未转义的换行。
- 每个条目的字节必须是合法的 UTF-8。单个条目最长 1 GiB（2^30 字节），读取方超过它就停。
- gzip 是单个成员（RFC 1952），不接受多成员；gzip 流结束后不能再有任何字节。
- 读取时任何一层出错（帧认证失败、gzip 校验失败、最后一行没有换行），整个文件作废。分帧加密在出错之前已经交出的帧是真的，但上层不能使用半个文件：读取工具和运行时的重读都要读完整个文件、核对通过之后才输出任何内容（§16）。

## 5. 分帧加密

构造是 STREAM（Hoang、Reyhanitabar、Rogaway、Vizár 2015）加 AES-256-GCM，代码在 `internal/archive/stream`。

**文件头，40 字节：**

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | 魔数 `4C 4C 41 52`（`LLAR`） |
| 4 | 1 | 流格式版本 `01` |
| 5 | 1 | 帧大小的以 2 为底的对数，固定 `10`（65,536） |
| 6 | 2 | 保留，`00 00` |
| 8 | 32 | 随机盐，每个文件新取 |

**文件密钥：**

~~~text
K_file = HMAC-SHA-256(K_enc, "llmapi-logger/archive-file-key/v1" 0x00 || 文件头的 40 个字节)
~~~

`K_enc` 见 §6。文件头的每一个字节都进了密钥派生，改动文件头的任何一位，第一帧就解不开。

**帧：**

- 明文按 65,536 字节切成帧 `P_0 … P_n`：除最后一帧外每帧恰好 65,536 字节，最后一帧 0 到 65,536 字节。只有整个明文为空时最后一帧才是空的；在别的帧之后出现空的末帧是格式错误，所以一段明文只有一种编码。
- 第 i 帧的 nonce 是 12 字节：三个 `00`，i 的 8 字节大端，末帧为 `01`、其余帧为 `00`。
- `C_i = AES-256-GCM-Seal(K_file, nonce_i, P_i, AAD 为空)`，长度是 `len(P_i) + 16`。
- 文件 = 文件头 `||` `C_0` `||` … `||` `C_n`。没有长度字段：每个非末帧的密文恰好 65,552 字节，读到文件末尾的那一帧就是末帧。明文为空时，文件是文件头加一个 16 字节的末帧，共 56 字节。

**读取：**

1. 读 40 字节文件头，核对魔数、版本、帧大小和保留字节。文件头不全是截断错误，内容不对是格式错误。
2. 每次读至多 65,552 字节：读满而后面还有字节，按非末帧解；读满而恰好到文件末尾，或不满 65,552 字节，按末帧解；不足 16 字节是截断错误。
3. 任何一帧认证失败都中止，不交出这一帧的明文。在帧边界截断、帧重排、删去一帧、从另一个文件拼帧、在末尾追加字节、改文件头、用错密钥，都表现为认证失败。

**测试向量**：`internal/archive/stream/testdata/vectors.json`。密钥是字节 `00` 到 `1f`，盐是 `a0` 到 `bf`；长度为 n 的明文是 `SHA-256("llmapi-logger/archive-stream-test-plaintext" 0x00 || uint64_be(j))`（j = 0, 1, …）依次拼接后截到 n 字节。文件给出 `K_file`，以及长度 0、1、65,535、65,536、65,537、200,000 的密文的 SHA-256、前 64 字节和文件长度；0 和 1 字节的完整密文也在里面。

## 6. 密钥派生

主密钥是代理的 `key_path` 文件：恰好 32 个原始字节。归档用到的子密钥都是 `HMAC-SHA-256(主密钥, 域字符串)`，取全部 32 字节；每个域字符串都以一个 `0x00` 字节结束：

| 密钥 | 域字符串（不含末尾的 `0x00`） | 用途 |
| --- | --- | --- |
| `K_enc` | `llmapi-logger/archive-encryption-key/v1` | §5 的分帧加密 |
| `K_sign` | `llmapi-logger/archive-signing-key/v1` | 清单 MAC 与密钥指纹（§14） |
| `K_fpr` | `llmapi-logger/archive-credential-fingerprint-key/v1` | 凭据值的指纹 `value_fpr`（§12） |
| 完整性密钥 | `llmapi-logger/integrity-key/v1` | 核对行里抄录的原完整性事件的 MAC（§8.11） |
| 凭据指纹密钥 | `llmapi-logger/credential-fingerprint-key/v1` | 热库的 `api_key_fpr`，只在核对已知 Key 时用（§12.4） |

清单里的密钥指纹是 `HMAC-SHA-256(K_sign, "llmapi-logger/archive-key-fingerprint/v1" 0x00)`。读取方先比对它，不同就报 `key_mismatch`，不解密、不核对任何东西。

前三把是归档自己的子密钥，域字符串互不相同，也不同于完整性密钥、凭据指纹密钥和分析指纹密钥，彼此独立。主密钥为字节 `00` 到 `1f` 时的 `K_enc`、`K_sign`、`K_fpr`、密钥指纹和两个 `value_fpr` 的向量在 `internal/security/archive_keys_test.go`（用仓库之外的 HMAC 实现算出）。那个文件里还有一个“manifest MAC”向量，它只是对一段任意字节做 HMAC，前缀不是 `<清单域>`，不能拿来核对清单；清单的向量见 §14.4。

## 7. JSON 编码规则

行文件、对象文件、gap 文件和清单共用下面的规则。写入方按本文表格里的顺序写键；读取方不得依赖键的顺序，但必须要求恰好是文档列出的键，每个出现一次：未知的键、缺少的键、重复的键都拒绝。

| 值 | 写法 |
| --- | --- |
| 64 位整数、纳秒时间戳、计数 | JSON 字符串，内容是规范的十进制：没有前导零、没有加号，负数带 `-`，例如 `"1764300000123456789"` |
| 库里取 0 或 1 的列 | 字符串 `"0"` 或 `"1"`。这些列是 `hash_complete`、`eof_seen`、`stream_timeline_complete`、`timeline_complete`、`requested_stream`、`observed_stream`、`has_tool_call`、`body_scanned` |
| 格式自己的标志 | JSON 的 `true`、`false`，只用于 `has_query`、`has_equals`、`block_present`、`encrypted` |
| 浮点（只有 `token_links.quota_per_unit`） | JSON 字符串，与 Go 的 `strconv.FormatFloat(v, 'g', -1, 64)` 逐字相同：能精确还原的最短写法，例如 `"500000"`、`"1e+06"`、`"2.5"`、`"1e-05"` |
| 哈希、MAC、keyed 指纹 | JSON 字符串，小写十六进制。标为 32 字节的字段必须恰好 64 个十六进制字符 |
| 二进制内容（图片、raw 块、时间线明文） | JSON 字符串，带填充的标准 base64（RFC 4648 第 4 节），只接受规范写法 |
| 文本列 | 字节是合法 UTF-8 时写 JSON 字符串；否则写 `{"b64": "<那些字节的 base64>"}`。合法 UTF-8 的值写成 `{"b64"}` 形式要拒绝 |
| SQL 的 NULL | `null`。任何键都不能因为值是 NULL 而省略 |
| 列表 | JSON 数组。没有行时写 `[]`，表的可选部分没有行时写 `null`（各节分别说明） |

内容对象的明文、`parsed_json` 和项目标识的明文都是 JSON 文本，但在行里写成 **JSON 字符串**（内容是原来的字节），不作为嵌套的 JSON 嵌入：重新序列化会改变字节，内容地址和哈希就对不上了。

Header 值、Request-URI 分段、User-Agent 都可能不是合法 UTF-8，所以都按“文本列”的规则写。已知的一个缺口：读取方解码 JSON 字符串时，孤立的代理项转义（如 `\ud800`）会被解成 U+FFFD，本仓库的读取方没有拒绝它。

## 8. 行文件

行文件每行一条 audit。gap 包的行文件见 §11。

### 8.1 一行的顶层

| 键 | 编码 | 说明 |
| --- | --- | --- |
| `type` | 字符串 | 固定 `"audit"` |
| `audit_id` | 文本 | 必须等于 `audit_records.audit_id` |
| `conversation_id` | 文本或 `null` | 有轮次时等于 `turn.turns.conversation_id`，没有轮次时为 `null` |
| `protocol` | 文本 | 必须等于 `audit_records.protocol` |
| `started_at_ns` | 整数 | 必须等于 `audit_records.started_at_ns` |
| `ended_at_ns` | 整数 | 必须等于 `audit_records.ended_at_ns` |
| `revision` | 整数 | 修订号，第一次导出为 1，同一 audit 重新导出时加一；不进记录摘要 |
| `audit_records` | 对象 | §8.2 |
| `http_stages` | 数组 | §8.3 |
| `headers` | 对象 | §8.4 |
| `body_streams` | 数组 | §8.5 |
| `raw_chunks` | 数组 | §8.6 |
| `stream_timelines` | 数组 | §8.7 |
| `parsed_results` | 对象或 `null` | §8.8 |
| `token_links` | 对象或 `null` | §8.9 |
| `turn` | 对象或 `null` | §8.10、§9 |
| `conversation` | 对象或 `null` | §8.11 |
| `audit_project_identity` | 对象或 `null` | §8.11 |
| `integrity_events` | 数组 | §8.11 |
| `record_digest` | 32 字节十六进制 | §13 |

行首的检索字段（`audit_id` 到 `ended_at_ns`）与行内各表的值不一致时，整行无效。子表的行不带 `audit_id`，轮次的子表不带 `turn_id`：它们由所在的行给出（§15 的“key column given by the enclosing record”）。

### 8.2 `audit_records`

| 键 | 编码 |
| --- | --- |
| `audit_id`、`route_id`、`protocol`、`parser_name`、`method`、`path`、`mode`、`forward_status`、`capture_status`、`parse_status`、`caller_status` | 文本 |
| `schema_generation`、`started_at_ns`、`ended_at_ns`、`caller_attempts`、`parse_save_failures`、`capture_version` | 整数 |
| `status_code`、`ttft_ns`、`caller_next_at_ns`、`caller_updated_at_ns`、`parse_next_at_ns` | 整数或 `null` |
| `blocked_by`、`block_code`、`error_code`、`newapi_request_id` | 文本或 `null` |
| `api_key_fpr` | 十六进制或 `null`。热库的 keyed 指纹（§12.4），不是凭据值 |
| `request_uri` | 投影后的 Request-URI 对象（§12.2） |
| `user_agent` | `null`，或至少一项的投影值数组（§12.1）。`null` 对应热库 `user_agent_enc` 为 NULL；采集版本 1 恒为 `null` |

一共 29 个键，写入顺序：`audit_id`、`schema_generation`、`started_at_ns`、`ended_at_ns`、`route_id`、`protocol`、`parser_name`、`method`、`path`、`request_uri`、`mode`、`status_code`、`ttft_ns`、`forward_status`、`capture_status`、`parse_status`、`blocked_by`、`block_code`、`error_code`、`newapi_request_id`、`caller_status`、`caller_attempts`、`caller_next_at_ns`、`caller_updated_at_ns`、`api_key_fpr`、`parse_save_failures`、`parse_next_at_ns`、`capture_version`、`user_agent`。`ended_at_ns` 不会是 `null`：只归档已终结的记录。`protocol` 是解析器名第一个点之前的部分（`openai`、`anthropic`、`gemini`），所以 OpenAI 的 Chat 与 Responses 属于同一个协议。`path` 是 `URL.EscapedPath()`，不含查询串；完整的 Request-URI 只在 `request_uri` 里。

### 8.3 `http_stages[]`

每个阶段一项：`stage`（文本）、`state`（文本）、`proto`、`method`、`host`（文本）、`status_code`、`content_length`（整数或 `null`）、`started_at_ns`（整数）、`ended_at_ns`（整数或 `null`）、`error_code`、`content_type`、`content_encoding`（文本或 `null`）。最后两列是采集版本 2 的阶段内容头，版本 1 恒为 `null`。

**阶段顺序**（所有按阶段排序的列表都用它）：

| 序号 | 阶段 |
| --- | --- |
| 0 | `request_for_newapi_received_from_nginx` |
| 1 | `request_sent_to_newapi` |
| 2 | `response_received_from_newapi` |
| 3 | `response_from_newapi_sent_to_nginx` |

不在这四个里的阶段名使整行无效。

### 8.4 `headers`

~~~json
{
  "capture_version": "2",
  "block_present": true,
  "block_stages": ["request_for_newapi_received_from_nginx"],
  "values": [
    { "stage": "request_for_newapi_received_from_nginx", "kind": "header", "name": "Content-Type", "value_index": "0", "value": "application/json" },
    { "stage": "request_for_newapi_received_from_nginx", "kind": "header", "name": "X-Goog-Api-Key", "value_index": "0",
      "value_omitted": "credential", "length": "12", "value_fpr": "<64 位十六进制>" }
  ]
}
~~~

- `capture_version` 必须等于 `audit_records.capture_version`。
- 两个采集版本归档成同一种扁平形式：`values` 是全部阶段的 Header 和 Trailer，每个值一项。版本 1 的热库每个值一行（`http_headers`）；版本 2 每条 audit 一个密封的块（`http_header_blocks`），块的明文从不写进归档，展开成同样的列表。
- 版本 1：`block_present` 为 `false`，`block_stages` 为 `null`。版本 2：`block_present` 说明有没有块，`block_stages` 是块里有段的阶段，按阶段顺序；没有块时为 `null`，没有块而 `block_stages` 不是 `null` 时整行无效。失败或被中断的采集里，块里的阶段集合可以与阶段行集合不同（模块 09 §8 的宽松规则），`block_stages` 记下的是块里实际有的。
- `values[]` 每项有 `stage`、`kind`（`header` 或 `trailer`）、`name`（原样大小写）、`value_index`（同名的第几个值，从 0 起），加投影后的值（§12.1）。
- `values` 的顺序：阶段顺序，`kind` 的字节序（`header` 在 `trailer` 之前），`name` 的字节序，`value_index`；严格递增，不允许两项键相同。

### 8.5 `body_streams[]`

每个有 Body 行的阶段一项，按阶段顺序：`stage`、`source_stage`（文本）、`observed_length`、`stored_length`（整数）、`sha256`（十六进制或 `null`）、`hash_complete`、`eof_seen`（`"0"`/`"1"`）、`state`、`retention_state`（文本；`pending`、`metadata`、`full`）、`first_observed_at_ns`、`last_observed_at_ns`（整数或 `null`）、`chunk_count`、`stream_event_count`（整数）、`stream_timeline_complete`（`"0"`/`"1"`）、`error_code`（文本或 `null`）。

`source_stage` 指向持有块的阶段：成对的两个阶段字节相同、在终结时合并时，后一个阶段的 `source_stage` 是前一个，它自己没有块。读取一个阶段的 raw 时，按它的 `source_stage` 去取块。

“完整的 Body”指：`state` 为 `complete`、`hash_complete` 与 `eof_seen` 为 `"1"`、`stored_length` 等于 `observed_length`。这时 `sha256` 是全部字节的 SHA-256，必须是 32 字节。

### 8.6 `raw_chunks[]`

`retention_state` 为 `full` 的阶段的每一个块一项：`stage`（持有块的阶段）、`seq`、`offset`、`plaintext_length`、`observed_at_ns`（整数）、`sha256`（这一块明文的 SHA-256，32 字节）。按（阶段顺序，`seq`）严格递增。块的字节在对象文件的 `raw_chunk` 条目里（§10）。

### 8.7 `stream_timelines[]`

每个有时间线行的阶段一项，按阶段顺序：`stage`、`event_count`（整数）、`first_event_at_ns`、`last_event_at_ns`（整数或 `null`）、`timeline_complete`（`"0"`/`"1"`）、`plaintext_length`（整数）、`timeline_b64`（解密、解压后的时间线明文的 base64，或 `null`）。

**时间线明文的编码**（`internal/streamtimeline`）：记录 SSE 逻辑事件的观察点，每个点是（`Offset`，`AtNS`）。`Offset` 是这个事件结束的那个空行的行结束符（`\r` 或 `\n`）在 Body 里的字节位置加一，也就是到它为止的字节数；`AtNS` 是收到包含这个字节的那次读取时的墙上时钟纳秒。

~~~text
明文 = 0x01                         版本字节
       uvarint(n)                   点数
       对每个点 i（从 0 起）：
         uvarint(Offset_i − Offset_{i−1})   其中 Offset_{−1} = 0
         uvarint(AtNS_0)                    i = 0 时
         uvarint(AtNS_i − AtNS_{i−1})       i > 0 时
~~~

`uvarint` 是无符号 LEB128（Go 的 `encoding/binary` `Uvarint`：每字节低 7 位，高位为 1 表示后面还有）。规则：`Offset` 严格递增（每个偏移差至少为 1），`AtNS` 为正且不减；点数至多 100,000；解码后不能有剩余字节。

查询层对时间线的核对（读取工具同样执行）：`event_count` 与 `plaintext_length` 为正，明文长度等于 `plaintext_length`，点数在 1 和 `event_count` 之间；`timeline_complete` 为 `"1"` 时点数等于 `event_count`，最后一点的时间等于 `last_event_at_ns`；不完整时点数少于 `event_count` 只允许是达到了 100,000 的上限；第一点的时间等于 `first_event_at_ns`，最后一点不晚于 `last_event_at_ns`，最后一点的偏移不超过所选阶段 Body 的 `observed_length`。时间线取自 Body 的 `source_stage` 那一行，`observed_length` 取自所选阶段自己的 Body 行。

### 8.8 `parsed_results`

没有解析结果行时为 `null`。否则：`parser_name`、`parser_version`、`status`（文本）、`request_model`、`response_model`（文本或 `null`）、`requested_stream`、`observed_stream`（`"0"`/`"1"` 或 `null`）、`response_id`（文本或 `null`）、`usage_input`、`usage_output`、`usage_total`（整数或 `null`）、`error_type`、`error_code`、`upstream_error_class`（文本或 `null`）、`message_count`、`tool_call_count`（整数或 `null`）、`has_tool_call`（`"0"`/`"1"` 或 `null`）、`parsed_json`、`parsed_json_ref`、`parsed_at_ns`（整数）。

`parsed_json` 是热库 `parsed_json_enc` 解密后的 JSON 文本；密文里是 gzip 流（以 `1f 8b` 开头）时写的是解压后的文本。两种存储形态在归档里没有区别。

- 不超过 1 MiB（1,048,576 字节）时：`parsed_json` 是这段文本（§7 的文本规则），`parsed_json_ref` 为 `null`。
- 严格大于 1 MiB 时：`parsed_json` 为 `null`，正文拆进对象文件的 `parsed_json_part` 条目（§10），`parsed_json_ref` 是 `{"sha256", "length", "parts"}`：整段的 SHA-256、字节数和段数。这时 `length` 必须大于 1 MiB，`parts` 至少为 2。
- `parsed_json_enc` 为 NULL 时两者都是 `null`。热库里存在但为空的值按 NULL 导出。

拆分：从头起每段至多 1 MiB，段号从 0 起。切点落在一个 UTF-8 多字节序列中间时，向前移到该序列的开头（至多 3 字节）；切点附近不是合法 UTF-8 时不移动。拼回时依次连接全部段，长度和 SHA-256 必须与 `parsed_json_ref` 相同。

`parsed_json` 里可能有兜底会话 `conversation`（没有轮次的旧记录）或 `partial_response_messages`（只有请求的轮次的半截回答）；读取工具与查询层一样经 `query.MergePartialResponse` 把半截回答接在重建出的请求消息之后（模块 18 §6）。

### 8.9 `token_links`

没有调用者关联时为 `null`。否则：`newapi_user_id`（整数）、`username`（文本）、`newapi_token_id`（整数）、`token_name`（文本）、`linked_at_ns`（整数）、`billing_state`（文本）、`quota`（整数或 `null`）、`quota_per_unit`（浮点或 `null`）、`billed_prompt_tokens`、`billed_completion_tokens`（整数或 `null`）、`billing_attempts`（整数）。

### 8.10 `turn`

没有轮次时为 `null`。否则是七个键：

- `turns`：轮次行，`turn_id`、`conversation_id`（文本）、`parent_turn_id`（文本或 `null`）、`parent_base`、`link_reason`（文本）、`link_confidence`（整数）、`request_layout`、`response_layout`（文本）、`request_envelope_hash`、`response_envelope_hash`（32 字节十六进制）、`request_item_count`、`response_item_count`（整数）、`request_sequence_hash`、`response_sequence_hash`、`request_reconstruction_hash`、`response_reconstruction_hash`（十六进制）、`reconstruction_status`（文本）、`previous_response_id`、`response_id`（文本或 `null`）、`created_at_ns`（整数）。血缘字段（`parent_turn_id`、`parent_base`、`link_reason`、`link_confidence`）是导出那一刻热库里的值，与 `request_context` 的形式无关。
- `request_context`：请求上下文，`{"form": "delta", "ops": [...]}` 或 `{"form": "materialized", "refs": [...]}`，见 §9。
- `response_items[]`：`ordinal`（整数）、`slot`（文本）、`object_hash`、`semantic_hash`（十六进制），按 `ordinal` 严格递增（不要求连续）。
- `objects[]`：这一轮引用的全部内容对象的元数据，`object_hash`、`semantic_hash`（十六进制）、`object_kind`（文本）、`plaintext_length`（整数），按 `object_hash` 的字节序严格递增。它必须恰好是两个 envelope、物化后的请求引用和响应条目引用到的对象（§16.3）。
- `binary_refs[]`：这些对象的 `content_binary_refs` 行，`object_hash`、`json_pointer`、`binary_hash`、`media_type`、`encoding`，按（`object_hash`，`json_pointer`，`binary_hash`）严格递增。
- `external_refs[]`：这些对象的 `content_external_refs` 行，`object_hash`、`json_pointer`、`ref_kind`、`value_hash`、`value`（`file_id` 一类的值本身），按（`object_hash`，`json_pointer`，`ref_kind`）严格递增。
- `binaries[]`：二进制引用指向的二进制对象的元数据，`binary_hash`、`media_type`、`plaintext_length`，按 `binary_hash` 的字节序严格递增。

对象的明文和二进制的字节不在行里，在对象文件里（§10），每个分段只存一次。

### 8.11 `conversation`、`audit_project_identity`、`integrity_events`

- `conversation`：轮次所在的会话行，`conversation_id`、`protocol`（文本）、`key_hash`（十六进制或 `null`）、`created_at_ns`（整数）。不归档 `updated_at_ns`：它随会话后来的每一轮变化，不是某条 audit 的属性。有轮次时 `conversation_id` 必须等于轮次的。
- `audit_project_identity`：项目标识行（组织周报开启时才有，模块 23），`identity_version`、`extracted_at_ns`（整数）、`source`（文本）、`body_scanned`（`"0"`/`"1"`）、`identity_fpr`、`remote_fpr`、`repo_root_fpr`、`cwd_fpr`（十六进制或 `null`）、`identity`（身份明文 JSON 文本，或 `null`）。
- `integrity_events[]`：这条 audit 在热库完整性链上的全部事件，原样抄录，`sequence`（整数）、`event_type`（文本）、`previous_mac`（十六进制或 `null`）、`payload_digest`、`event_mac`（十六进制）、`created_at_ns`（整数），按 `sequence` 严格递增。

事件的 MAC（模块 09 §7）可以用完整性密钥（§6）核对：

~~~text
event_mac = HMAC-SHA-256(完整性密钥,
              "llmapi-logger/integrity-event/v1" 0x00
              || u64be(len(previous_mac)) || previous_mac
              || u64be(len(audit_id)) || audit_id
              || u64be(len(event_type)) || event_type
              || u64be(len(payload_digest)) || payload_digest
              || u64be(created_at_ns))
~~~

`previous_mac` 为 `null` 时按空字节串计（只有整个数据库的第一个事件如此）。载荷摘要绑定的是热库里的密文，从归档的明文算不出来；所以核对 MAC 证明的是事件本身是真的，“归档时这些明文对应的行通过了事件复核”由清单签名表达（§14.3）。

### 8.12 两种采集版本与旧形态

| 热库里 | 归档里 |
| --- | --- |
| 采集版本 1：每个 Header 值一行，`user_agent_enc` 为 NULL，阶段的两个内容头列为 NULL | `headers.capture_version = "1"`、`block_present: false`、`block_stages: null`；`audit_records.user_agent: null`；`http_stages[].content_type`、`content_encoding` 为 `null` |
| 采集版本 2：一个 Header 块、`user_agent_enc`、两个内容头列 | `headers.capture_version = "2"`，块的段集合；`user_agent` 是投影值数组或 `null`；两列原样 |
| `parsed_json_enc` 是明文 JSON 或 gzip 流 | 都写解压后的 JSON |
| 没有轮次的旧记录（会话在 `parsed_json_enc` 里，raw 为 `full`） | `turn: null`，`parsed_json` 带会话，raw 块进对象文件 |
| 旧的 OpenAI 流式 layout、紧凑 SSE layout | layout 名与对象原样照抄；装配和重建由 `internal/auditmodel` 与 `internal/parser/builtin` 完成（读取工具也要用它们） |

## 9. 请求上下文与物化

### 9.1 两种形式

- **`delta`**：`ops` 是热库 `turn_context_ops` 的原样行，每项 `op_index`（整数）、`operation`（`retain`、`delete`、`insert`）、`item_count`（整数）、`slot`（文本或 `null`）、`object_hash`、`semantic_hash`（十六进制或 `null`），按 `op_index` 严格递增。`retain` 与 `delete` 的 `slot`、两个哈希必须都是 `null`；`insert` 必须有 `slot`。
- **`materialized`**：`refs` 是物化后的完整请求引用，每项 `slot`、`object_hash`、`semantic_hash`，顺序就是请求条目的顺序。

写入方选择形式的规则：根轮次（`parent_turn_id` 为 `null`，包括被 retention 检查点改写成根的），以及父轮次已经写在**同一分段、同一会话的连续行里、排在它前面**的轮次，写 `delta`；其余一律写 `materialized`。所以一个分段不依赖别的包，也不依赖热库，就能物化每一轮。

### 9.2 物化一个 `delta` 轮次

1. 取基底：
   - `parent_turn_id` 为 `null`：基底为空，`parent_base` 必须是 `root`；
   - `parent_base` 为 `request`：父轮次物化后的请求引用；
   - `parent_base` 为 `post_turn`：父轮次物化后的请求引用，后接父轮次的 `response_items`（按 `ordinal`，每项取 `slot`、`object_hash`、`semantic_hash`）；
   - 其他值是错误。父轮次必须是本分段里同一会话的连续行中排在前面的一行；找不到是错误（`reference_open`）。
2. 依次应用 `ops`，从基底的第 0 项开始，维持一个读位置：
   - `retain N`：N 必须大于 0、不超过剩余项数，把基底接下来的 N 项原样加进结果；
   - `delete N`：同样的约束，跳过接下来的 N 项；
   - `insert`：`item_count` 必须为 1，`slot` 非空、`object_hash` 非空，把 `{slot, object_hash, semantic_hash}` 加进结果。
3. 应用完后读位置必须正好到基底末尾。
4. 结果的项数必须等于 `request_item_count`，序列哈希（§9.3）必须等于 `request_sequence_hash`。

`materialized` 形式直接取 `refs`，同样核对第 4 步的两项。物化后的引用是记录摘要覆盖的对象（§13），所以 **`delta` 形式的行必须先物化才能算摘要**：只凭这一行算不出来，要用排在它前面的父行。

### 9.3 序列哈希

~~~text
SequenceHash(refs) = SHA-256("llmapi-logger/sequence/v1" 0x00
                      || 对每个 ref：u64be(len(slot)) || slot || u64be(len(object_hash)) || object_hash)
~~~

`semantic_hash` 不进序列哈希。

## 10. 对象文件

对象文件每行一个条目，`type` 区分四种：

| `type` | 键（写入顺序） |
| --- | --- |
| `content_object` | `type`、`object_hash`、`semantic_hash`（十六进制）、`object_kind`（文本）、`plaintext_length`、`created_at_ns`（整数）、`data`（规范 JSON 文本，§7 的文本规则） |
| `binary_object` | `type`、`binary_hash`（十六进制）、`media_type`（文本）、`plaintext_length`、`created_at_ns`（整数）、`data_b64`（字节的 base64） |
| `raw_chunk` | `type`、`audit_id`、`stage`（文本）、`seq`（整数）、`data_b64`（块明文的 base64） |
| `parsed_json_part` | `type`、`audit_id`（文本）、`part`（整数，从 0 起）、`data`（一段 JSON 文本，§8.8 的拆分） |

- 一个分段里每个内容对象和二进制对象只出现一次，在第一次被某一行引用时写出。`created_at_ns` 是对象首次写进热库的时间，被多条 audit 共享，不进记录摘要。
- raw 块以（`audit_id`，`stage`，`seq`）为键，每块一个条目。
- 写入顺序：每一行之后，依次是这一行带来的、本分段还没写过的内容对象（按 `turn.objects` 的顺序）、二进制对象（按 `turn.binaries` 的顺序）、这一行的 raw 块（按阶段顺序和 `seq`）、拆开的 `parsed_json` 段（按段号）。读取方依赖“同一阶段的块按 `seq` 出现、同一 audit 的段按段号出现”。
- 分段里没有任何对象、raw 块和 `parsed_json` 段时，不产生对象文件，清单里也不列它。

### 10.1 内容对象的明文

`data` 是 Go 的 `encoding/json` 对下面这个值的输出（`auditmodel.CanonicalJSON`）：

~~~json
{"kind":"<object_kind>","schema_version":1,"value":<内容>}
~~~

规范化的规则：值先按 `json.Decoder.UseNumber` 解码（数字保留原来的写法），再由标准编码器写出：对象的键按字节序排序、没有空白、字符串按 Go 的规则转义（`<`、`>`、`&`、U+2028、U+2029 写成 `\u` 转义）。`schema_version` 现在恒为 1，读取方要求它是 1，并且 `kind` 等于 `object_kind`。

### 10.2 内容地址与语义哈希

~~~text
object_hash   = SHA-256("llmapi-logger/content/v1" 0x00 || data 的字节)
binary_hash   = SHA-256("llmapi-logger/binary/v1" 0x00 || 解码后的字节)
value_hash    = SHA-256("llmapi-logger/external-ref/v1" 0x00 || ref_kind || 0x00 || value)
~~~

`semantic_hash`：`object_kind` 为 `request_envelope` 或 `response_envelope` 时等于 `object_hash`；其余条目是

~~~text
semantic_hash = SHA-256("llmapi-logger/content/v1" 0x00 || CanonicalJSON({"kind": object_kind, "value": P(value)}))
~~~

其中 `P` 在每一层对象里去掉键 `id`、`status`、`created_at`、`completed_at`、`sequence_number`（这些是只用于推断父轮次的出现属性），数组逐项处理，其余原样。

二进制对象在内容对象里以 marker 引用，重建 provider JSON 时由 `binary_refs` 的 `media_type`、`encoding` 还原成 data URL（模块 18 §4）。marker 的形状和各 layout 的装配规则见模块 18 与 `internal/auditmodel`，本文不重复。

## 11. gap 文件

gap 包的行文件每行一条 `audit_gaps`（进程级的采集缺口，模块 13 §5）：

| 键 | 编码 |
| --- | --- |
| `type` | 固定 `"gap"` |
| `id`、`started_at_ns`、`ended_at_ns`、`request_count`、`created_at_ns` | 整数 |
| `reason`、`detail` | 文本 |

`id` 严格递增。第一行的 `id` 等于清单 `gaps.first_id`，最后一行等于 `last_id`，行数等于 `count` 和 `line_count`；`started_at_ns` 的最小值、`ended_at_ns` 的最大值等于清单的 `first_started_at_ns`、`last_ended_at_ns`。gap 不在完整性链里，只受清单签名保护。

## 12. 凭据投影

**归档里没有任何凭据值。** 加密开启或关闭都一样：凭据只留名称、字节长度、省略标记和 keyed 指纹。这是归档里唯一允许缺内容的地方。

一个值是否是凭据，逐值按下面的规则判定（与 Agent 门面同一个函数 `agentapi.IsCredential(name, value)`），三条任一成立即是：

1. 名称转小写后恰好是 `authorization`、`proxy-authorization`、`cookie`、`set-cookie`、`x-api-key`、`x-goog-api-key`、`api-key`、`key`、`token` 之一，或以 `-token`、`_token` 结尾；
2. 小写名称包含 `secret`、`password`、`passwd`、`credential`、`signature`、`api-key`、`apikey`、`api_key` 之一；
3. 值去掉前导的空格、`\t`、`\r`、`\n`、`\v`、`\f` 之后，开头与 `bearer `、`basic `、`sk-`、`lla_` 之一不区分大小写地相同（比较值开头的同样字节数）。

### 12.1 Header、Trailer 与 User-Agent 的值

每个 Header 或 Trailer 值以它的名称判定；User-Agent 的每个值以名称 `User-Agent` 判定。投影后的值是两种形式之一，互斥：

~~~json
{ "value": "<原值，§7 的文本规则>" }
{ "value_omitted": "credential", "length": "<原值的字节数>", "value_fpr": "<64 位十六进制>" }
~~~

在 `headers.values[]` 里这两组键与 `stage`、`kind`、`name`、`value_index` 并列；在 `user_agent` 里是单独的对象。`length` 不能为负。

### 12.2 Request-URI

~~~json
"request_uri": {
  "path": "/v1beta/models/x:generateContent",
  "has_query": true,
  "segments": [
    { "raw": "alt=sse" },
    { "raw_name": "key", "has_equals": true, "value_omitted": "credential", "length": "12", "value_fpr": "<64 位十六进制>" }
  ]
}
~~~

- `path` 是第一个 `?` 之前的原始字节；没有 `?` 时 `has_query` 为 `false`、`segments` 为 `[]`，有 `?` 时 `segments` 至少一项。
- 查询串按每个 `&` 切开，空段也保留（`{"raw": ""}`）。每段在第一个 `=` 处分成名称和值（没有 `=` 时值为空）。名称和值各自用 `url.QueryUnescape` 解码（`+` 变空格，`%XX` 解码），解码失败就用原始字节；用解码后的名称和值判定。`;` 和 `#` 没有特殊含义。
- 不是凭据的段写 `{"raw": <整段原始字节>}`，凭据以外的部分能逐字节拼回原串：`path`，若 `has_query` 再接 `?`，再用 `&` 连接各段。
- 凭据段写 `raw_name`（`=` 之前的原始字节）、`has_equals`（有没有 `=`）、`length` 和 `value_fpr`。**`length` 和 `value_fpr` 按解码后的值计算**（解码失败时按原始字节），所以 `?key=` 里的 Key 与 Header 里的同一个 Key 可以直接比对。空的凭据值长度为 0，照常有指纹。

### 12.3 指纹

~~~text
value_fpr = HMAC-SHA-256(K_fpr, "llmapi-logger/archive-credential-value/v1" 0x00 || value)
~~~

`value` 是原值的全部字节（Request-URI 是解码后的值），不含名称、不归一化。同一个凭据在入站和出站阶段得到相同的指纹，可以证明两侧一致。指纹只能用来核对一个已知的值，不能反推。

### 12.4 拿一个已知的 Key 核对

`audit-archive fpr` 给出三个候选（§24.6）：

| 候选 | 计算 | 对应 |
| --- | --- | --- |
| `raw` | `value_fpr` 作用在 Key 本身 | `X-Api-Key`、`X-Goog-Api-Key`、`?key=` |
| `bearer` | `value_fpr` 作用在 `"Bearer "` 加 Key | `Authorization: Bearer …` |
| `api_key_fpr` | `HMAC-SHA-256(凭据指纹密钥, "llmapi-logger/credential-fingerprint/v1" 0x00 || N(Key))` | `audit_records.api_key_fpr` |

`N` 是 NewAPI 的 Key 归一化：去掉前导空格和制表符，去掉不区分大小写的 `Bearer ` 前缀，去掉首尾空白，去掉 `sk-` 前缀，再取第一个 `-` 之前的部分。`api_key_fpr` 是热库里本来就有的 keyed 指纹（模块 09 §7.1），归档原样保留；它跨传输方式可比，`value_fpr` 则按逐字节的原值比。

### 12.5 不投影的地方

凭据投影只作用于 Header、Trailer、User-Agent 和 Request-URI 的查询参数。下面这些位置原样归档，即使内容里出现了 Key（例如用户把 Key 粘进对话、上游错误回显了半个 Key）：`full` 记录的 raw Body、内容对象与二进制对象、`parsed_json`（兜底会话和半截回答）、`content_external_refs` 的值。改写它们会让 raw 的 SHA-256、内容地址和重建哈希全部对不上，等于改写证据（设计 Q4）。加密开启时它们和对话内容一样在密文里，关闭时是明文。

## 13. 记录摘要

记录摘要是对一条记录的明文算的 SHA-256，与密钥、nonce、压缩和加密都无关；加密包与非加密包的摘要相同。它在导出时从热库解密出的值算一次，重读时从行重新算一次，两者必须相同。

### 13.1 记号

| 记号 | 字节 |
| --- | --- |
| `B(x)` | `u64be(len(x)) || x` |
| `T(s)` | `B(s 的字节)`；文本不是合法 UTF-8 时就是那些原始字节，与它在 JSON 里写成 `{"b64"}` 无关 |
| `I(v)` | `B(v 的 8 字节大端补码)`，也就是 `00 00 00 00 00 00 00 08` 后接 8 个字节 |
| `F(b)` | `I(1)` 或 `I(0)`：库里 0/1 的列和格式标志都这样编码 |
| `N(e)` | 值为 NULL 时一个字节 `00`；否则一个字节 `01` 后接 `e` |
| `H(p)` | `B(SHA-256(p))` |
| `L(n)` | `I(n)`，后面跟 n 个元素 |
| `M(s)` | `T(s)`，段名标记 |
| `V(value)` | 非凭据：`00 || H(值的字节)`；凭据：`01 || I(length) || B(value_fpr)` |

Request-URI：

~~~text
U = M("request_uri") T(path) F(has_query) L(n) 段*
段 = 00 T(raw)                                               ; 非凭据段
   | 01 T(raw_name) F(has_equals) I(length) B(value_fpr)      ; 凭据段
~~~

### 13.2 字节序列

记录摘要 = SHA-256 作用在下面的序列上。列表都按 §8 规定的顺序（规范顺序）逐项编码；行里的列表不是规范顺序时整行无效。

~~~text
<记录摘要域>                                            ; 原样写入，没有长度前缀
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
  N( L(k) V(ua_1) … V(ua_k) )                            ; user_agent
M("http_stages") L(n)，每项：
  T(stage) T(state) T(proto) T(method) T(host)
  N(I(status_code)) N(I(content_length)) I(started_at_ns) N(I(ended_at_ns))
  N(T(error_code)) N(T(content_type)) N(T(content_encoding))
M("headers") I(capture_version) F(block_present) N( L(k) T(stage)* )     ; block_stages
  L(n)，每项：T(stage) T(kind) T(name) I(value_index) V(value)
M("body_streams") L(n)，每项：
  T(stage) T(source_stage) I(observed_length) I(stored_length) N(B(sha256))
  F(hash_complete) F(eof_seen) T(state) T(retention_state)
  N(I(first_observed_at_ns)) N(I(last_observed_at_ns))
  I(chunk_count) I(stream_event_count) F(stream_timeline_complete) N(T(error_code))
M("body_chunks") L(n)，raw_chunks 的每项：
  T(stage) I(seq) I(offset) I(plaintext_length) I(observed_at_ns) B(sha256)
M("stream_timelines") L(n)，每项：
  T(stage) I(event_count) N(I(first_event_at_ns)) N(I(last_event_at_ns))
  F(timeline_complete) I(plaintext_length) N(H(时间线明文))
M("parsed_results") N(
  T(parser_name) T(parser_version) T(status)
  N(T(request_model)) N(T(response_model)) N(F(requested_stream)) N(F(observed_stream))
  N(T(response_id)) N(I(usage_input)) N(I(usage_output)) N(I(usage_total))
  N(T(error_type)) N(T(error_code)) N(T(upstream_error_class))
  N(I(message_count)) N(I(tool_call_count)) N(F(has_tool_call))
  N(B(parsed_json 的 SHA-256)) I(parsed_at_ns) )
M("token_links") N(
  I(newapi_user_id) T(username) I(newapi_token_id) T(token_name) I(linked_at_ns)
  T(billing_state) N(I(quota)) N(B(quota_per_unit 的 IEEE-754 双精度位，8 字节大端))
  N(I(billed_prompt_tokens)) N(I(billed_completion_tokens)) I(billing_attempts) )
M("turn") N(
  T(turn_id) T(conversation_id) N(T(parent_turn_id)) T(parent_base) T(link_reason) I(link_confidence)
  T(request_layout) T(response_layout) B(request_envelope_hash) B(response_envelope_hash)
  I(request_item_count) I(response_item_count) B(request_sequence_hash) B(response_sequence_hash)
  B(request_reconstruction_hash) B(response_reconstruction_hash) T(reconstruction_status)
  N(T(previous_response_id)) N(T(response_id)) I(created_at_ns)
  M("request_refs") L(n)，物化后的请求引用按序：T(slot) B(object_hash) B(semantic_hash)
  M("response_items") L(n)：I(ordinal) T(slot) B(object_hash) B(semantic_hash)
  M("content_objects") L(n)，turn.objects：B(object_hash) B(semantic_hash) T(object_kind) I(plaintext_length)
  M("binary_refs") L(n)：B(object_hash) T(json_pointer) B(binary_hash) T(media_type) T(encoding)
  M("external_refs") L(n)：B(object_hash) T(json_pointer) T(ref_kind) B(value_hash) H(value)
  M("binary_objects") L(n)，turn.binaries：B(binary_hash) T(media_type) I(plaintext_length) )
M("conversation") N( T(conversation_id) T(protocol) N(B(key_hash)) I(created_at_ns) )
M("audit_project_identity") N(
  I(identity_version) I(extracted_at_ns) T(source) F(body_scanned)
  N(B(identity_fpr)) N(B(remote_fpr)) N(B(repo_root_fpr)) N(B(cwd_fpr)) N(H(identity 的字节)) )
M("integrity_events") L(n)，每项：
  I(sequence) T(event_type) N(B(previous_mac)) B(payload_digest) B(event_mac) I(created_at_ns)
~~~

说明：

- `B(sha256)` 与 `B(parsed_json 的 SHA-256)` 是 32 字节的哈希本身加长度前缀，等价于 `H(块明文)` 与 `H(parsed_json)`。`parsed_json` 拆进对象文件时，用 `parsed_json_ref.sha256`；没有 `parsed_json` 时是 `N` 的 NULL。
- `parsed_results.upstream_error_class` 在摘要里紧跟 `error_code`，与它在行里的位置（`error_code` 之后）一致。
- 不在摘要里的：`revision`（内容相同的不同修订号摘要相同）；行首的检索字段（它们与表里的值逐项比对）；`turn_context_ops`（摘要覆盖物化后的引用，§9）；`created_at_ns` 与对象明文（对象以内容地址进入，内容地址就是对明文的哈希，重读时重算）；§15 里“不归档”的存储编码列。
- **增量形式的行要先物化。** 有轮次、`request_item_count` 大于 0 而还没有物化引用时算不出摘要（`ErrNotMaterialized`）。根轮次的增量操作本身就是全量插入，只凭这一行也能物化。
- 凭据以投影形式进入（`V`、`U`），所以热库一侧先做同样的投影再算摘要，两边才可比。

### 13.3 测试向量

`internal/archive/testdata/record_full_v0.jsonl` 是一条每列都非空、`materialized` 形式、每个投影位置都有一个凭据的采集版本 2 记录，`record_full_v0.digest` 是它的摘要；`record_hand_v0.jsonl` 是一条按手写字节序列核对过的最小记录（Gemini，`?key=`、`X-Goog-Api-Key` 和一个 User-Agent 值是凭据）。两个摘要的值见 §2.1。生成它们用的不是派生出的子密钥，而是两把固定的测试密钥：`K_fpr` 为字节 `01` 到 `20`，`K_sign` 为字节 `80` 到 `9f`。手写的字节序列独立核对了 `audit_records`（含 Request-URI 投影）、`http_stages` 和 `headers` 三段；其余各段在向量里只以空或 NULL 出现，整条记录的摘要只与编码器自己的输出比过（设计实施记录 R.4 第 11 条）。

## 14. 清单

`<名称>.manifest.json`，明文 JSON，不含任何对话内容或凭据。写入方写成两个空格缩进、末尾一个换行；读取方接受任意空白和键顺序。

### 14.1 字段

| 键 | 编码 | 说明 |
| --- | --- | --- |
| `format` | 文本 | 固定 `llmapi-logger-archive` |
| `format_version` | 文本 | `<格式版本>` |
| `source_schema_version` | 文本 | 写出时热库的迁移版本，规范十进制（现在是 `8`） |
| `segment_id`、`run_id` | 文本 | 各 32 个小写十六进制字符（16 个随机字节） |
| `bundle_kind` | 文本 | `conversation`、`bucket` 或 `gaps` |
| `protocol` | 文本或 `null` | 会话包和桶包是包的协议；gap 包为 `null` |
| `conversations` | 文本数组 | 行里出现的会话，按首次出现的顺序。会话包恰好一个；gap 包为 `[]` |
| `first_started_at_ns`、`last_ended_at_ns` | 整数 | 成员（gap 包是 gap）`started_at_ns` 的最小值、`ended_at_ns` 的最大值 |
| `created_at_ns` | 整数 | 清单写出的时间 |
| `encrypted` | 布尔 | 数据文件是否分帧加密 |
| `key_fingerprint` | 32 字节十六进制 | §6；不加密的包也有 |
| `tables` | 对象 | 每张归档表的归档列（§15 里不是“不归档”的列），键是表名，值是列名数组，按 `internal/archive/columns.go` 的顺序 |
| `files` | 数组 | 每个数据文件 `{role, name, bytes, sha256}`：`role` 为 `lines` 或 `objects`，每种至多一个；`name` 是同目录的裸文件名；`bytes` 与 `sha256` 是落盘字节（加密后）的大小和 SHA-256，不拿密钥也能核对 |
| `line_count` | 整数 | 行文件的行数 |
| `object_count` | 整数 | 对象文件里 `content_object`、`binary_object`、`parsed_json_part` 三种条目的总数 |
| `raw_chunk_count` | 整数 | 对象文件里 `raw_chunk` 条目的数目 |
| `members` | 数组 | 每行一项，按行的顺序：`{audit_id, revision, conversation_id, started_at_ns, ended_at_ns, record_digest}`；`conversation_id` 可为 `null`；gap 包为 `[]` |
| `gaps` | 对象或 `null` | 只有 gap 包有：`{first_id, last_id, count}` |
| `mac` | 32 字节十六进制 | §14.2 |

有效性规则：会话包有协议、恰好一个会话、没有 `gaps`；桶包有协议、没有 `gaps`；gap 包没有协议、会话和成员，有 `gaps`，没有对象文件，两个对象计数为 0。会话包和桶包有对象文件当且仅当 `object_count + raw_chunk_count > 0`。计数不能为负，`tables` 只能出现归档表的名字。清单文件不超过 256 MiB。

### 14.2 签名

~~~text
mac = HMAC-SHA-256(K_sign, <清单域> || 清单编码)
~~~

清单编码与 JSON 的写法无关，读取方从解析出的值重建它（§13.1 的记号）：

~~~text
T(format) T(format_version) T(source_schema_version) T(segment_id) T(run_id)
T(bundle_kind) N(T(protocol)) L(n) T(conversation)*
I(first_started_at_ns) I(last_ended_at_ns) I(created_at_ns) F(encrypted) B(key_fingerprint)
L(表数) ( T(表名) L(列数) T(列名)* )*                  ; 表按表名的字节序；列按数组顺序
L(n) ( T(role) T(name) I(bytes) B(sha256) )*          ; 按 files 的顺序
I(line_count) I(object_count) I(raw_chunk_count)
L(n) ( T(audit_id) I(revision) N(T(conversation_id)) I(started_at_ns) I(ended_at_ns) B(record_digest) )*
N( I(first_id) I(last_id) I(count) )                  ; gaps
~~~

`key_fingerprint` 在签名覆盖的范围里。`K_sign` 同时用于密钥指纹，两者的输入靠各自的域字符串区分。

### 14.3 签名的含义

签名说明：这些文件的字节、这些成员的记录摘要，在归档那一刻对应热库里通过了原完整性事件复核的行。行文件由文件哈希和逐行的记录摘要两层绑定；对象文件由文件哈希绑定，对象内容由内容地址自证。

热库里不是每一列都受完整性事件保护（设计 E.4）：例如 `token_links`、`parse_status`、`caller_*`、`api_key_fpr`、血缘字段和会话行在热库里没有任何密码学保护，归档签名对它们的含义只是“归档那一刻热库里是这个值”。

### 14.4 测试向量

`internal/archive/testdata/manifest_v0.json` 是一份会话包的清单（`K_sign` 为字节 `80` 到 `9f`，§13.3），`manifest_v0.encoding.hex` 是它的清单编码（不含 `<清单域>`）的十六进制。

## 15. 列规格

下表逐行对应 `internal/archive/columns.go` 的 `archive.Columns`（206 项，20 张表），由一个一次性的测试从这份数据表生成，“说明”一列是代码里的原文。列覆盖测试拿它与 PostgreSQL 的 `information_schema.columns` 逐列比对：库里有而这里没有的列、这里有而库里没有的列都让测试失败；以外键直接或间接引用 `audit_records`、`turns`、`content_objects`、`binary_objects` 或 `conversations` 的表，要么是下表的归档表，要么是派生表（`audit_analysis`、`agent_spawn_hints`、`analysis_detail_objects`，可重算，不归档）。改了 `columns.go` 就要重新生成这一节。

- **归档，进摘要**：在行里，进记录摘要；密文列以它明文的哈希进摘要（例如 `body_chunks.data_enc` 以 `raw_chunks[].sha256`）。
- **归档，不进摘要**：在归档里但不进记录摘要：对象的明文和首次写入时间（由内容地址绑定）、增量操作（摘要覆盖物化引用）、gap 的全部列（受清单签名保护）。
- **不归档**：只描述密文容器的存储编码，或随会话后续轮次变化的列。
- 归档位置的写法：`audit_records.status_code` 是行里的路径，`[]` 表示数组的每一项，`objects:` 和 `gaps:` 前缀表示对象文件和 gap 文件的条目，`audit_id` 表示由所在的行给出。

| 表 | 列 | 类别 | 归档位置 | 说明 |
| --- | --- | --- | --- | --- |
| `audit_records` | `audit_id` | 归档，进摘要 | `audit_records.audit_id` |  |
| `audit_records` | `schema_generation` | 归档，进摘要 | `audit_records.schema_generation` |  |
| `audit_records` | `started_at_ns` | 归档，进摘要 | `audit_records.started_at_ns` |  |
| `audit_records` | `ended_at_ns` | 归档，进摘要 | `audit_records.ended_at_ns` |  |
| `audit_records` | `route_id` | 归档，进摘要 | `audit_records.route_id` |  |
| `audit_records` | `protocol` | 归档，进摘要 | `audit_records.protocol` |  |
| `audit_records` | `parser_name` | 归档，进摘要 | `audit_records.parser_name` |  |
| `audit_records` | `method` | 归档，进摘要 | `audit_records.method` |  |
| `audit_records` | `path` | 归档，进摘要 | `audit_records.path` |  |
| `audit_records` | `request_uri_enc` | 归档，进摘要 | `audit_records.request_uri` | projected Request-URI (D.3) |
| `audit_records` | `mode` | 归档，进摘要 | `audit_records.mode` |  |
| `audit_records` | `status_code` | 归档，进摘要 | `audit_records.status_code` |  |
| `audit_records` | `ttft_ns` | 归档，进摘要 | `audit_records.ttft_ns` |  |
| `audit_records` | `forward_status` | 归档，进摘要 | `audit_records.forward_status` |  |
| `audit_records` | `capture_status` | 归档，进摘要 | `audit_records.capture_status` |  |
| `audit_records` | `parse_status` | 归档，进摘要 | `audit_records.parse_status` |  |
| `audit_records` | `blocked_by` | 归档，进摘要 | `audit_records.blocked_by` |  |
| `audit_records` | `block_code` | 归档，进摘要 | `audit_records.block_code` |  |
| `audit_records` | `error_code` | 归档，进摘要 | `audit_records.error_code` |  |
| `audit_records` | `newapi_request_id` | 归档，进摘要 | `audit_records.newapi_request_id` |  |
| `audit_records` | `caller_status` | 归档，进摘要 | `audit_records.caller_status` |  |
| `audit_records` | `caller_attempts` | 归档，进摘要 | `audit_records.caller_attempts` |  |
| `audit_records` | `caller_next_at_ns` | 归档，进摘要 | `audit_records.caller_next_at_ns` |  |
| `audit_records` | `caller_updated_at_ns` | 归档，进摘要 | `audit_records.caller_updated_at_ns` |  |
| `audit_records` | `api_key_fpr` | 归档，进摘要 | `audit_records.api_key_fpr` |  |
| `audit_records` | `parse_save_failures` | 归档，进摘要 | `audit_records.parse_save_failures` |  |
| `audit_records` | `parse_next_at_ns` | 归档，进摘要 | `audit_records.parse_next_at_ns` |  |
| `audit_records` | `capture_version` | 归档，进摘要 | `audit_records.capture_version` |  |
| `audit_records` | `user_agent_enc` | 归档，进摘要 | `audit_records.user_agent` | projected values (D.3) |
| `http_stages` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `http_stages` | `stage` | 归档，进摘要 | `http_stages[].stage` |  |
| `http_stages` | `state` | 归档，进摘要 | `http_stages[].state` |  |
| `http_stages` | `proto` | 归档，进摘要 | `http_stages[].proto` |  |
| `http_stages` | `method` | 归档，进摘要 | `http_stages[].method` |  |
| `http_stages` | `host` | 归档，进摘要 | `http_stages[].host` |  |
| `http_stages` | `status_code` | 归档，进摘要 | `http_stages[].status_code` |  |
| `http_stages` | `content_length` | 归档，进摘要 | `http_stages[].content_length` |  |
| `http_stages` | `started_at_ns` | 归档，进摘要 | `http_stages[].started_at_ns` |  |
| `http_stages` | `ended_at_ns` | 归档，进摘要 | `http_stages[].ended_at_ns` |  |
| `http_stages` | `error_code` | 归档，进摘要 | `http_stages[].error_code` |  |
| `http_stages` | `content_type` | 归档，进摘要 | `http_stages[].content_type` |  |
| `http_stages` | `content_encoding` | 归档，进摘要 | `http_stages[].content_encoding` |  |
| `http_headers` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `http_headers` | `stage` | 归档，进摘要 | `headers.values[].stage` |  |
| `http_headers` | `kind` | 归档，进摘要 | `headers.values[].kind` |  |
| `http_headers` | `name` | 归档，进摘要 | `headers.values[].name` |  |
| `http_headers` | `value_index` | 归档，进摘要 | `headers.values[].value_index` |  |
| `http_headers` | `value_length` | 归档，进摘要 | `headers.values[].value` | the length of value, or length for a credential |
| `http_headers` | `value_enc` | 归档，进摘要 | `headers.values[].value` | projected value (D.3) |
| `http_header_blocks` | `audit_id` | 归档，进摘要 | `headers.block_present` | the row's existence |
| `http_header_blocks` | `block_enc` | 归档，进摘要 | `headers.values` | decoded into the flat list and headers.block_stages; the block plaintext is never archived |
| `http_header_blocks` | `compression` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `http_header_blocks` | `plaintext_length` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `body_streams` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `body_streams` | `stage` | 归档，进摘要 | `body_streams[].stage` |  |
| `body_streams` | `source_stage` | 归档，进摘要 | `body_streams[].source_stage` |  |
| `body_streams` | `observed_length` | 归档，进摘要 | `body_streams[].observed_length` |  |
| `body_streams` | `stored_length` | 归档，进摘要 | `body_streams[].stored_length` |  |
| `body_streams` | `sha256` | 归档，进摘要 | `body_streams[].sha256` |  |
| `body_streams` | `hash_complete` | 归档，进摘要 | `body_streams[].hash_complete` |  |
| `body_streams` | `eof_seen` | 归档，进摘要 | `body_streams[].eof_seen` |  |
| `body_streams` | `state` | 归档，进摘要 | `body_streams[].state` |  |
| `body_streams` | `retention_state` | 归档，进摘要 | `body_streams[].retention_state` |  |
| `body_streams` | `first_observed_at_ns` | 归档，进摘要 | `body_streams[].first_observed_at_ns` |  |
| `body_streams` | `last_observed_at_ns` | 归档，进摘要 | `body_streams[].last_observed_at_ns` |  |
| `body_streams` | `chunk_count` | 归档，进摘要 | `body_streams[].chunk_count` |  |
| `body_streams` | `stream_event_count` | 归档，进摘要 | `body_streams[].stream_event_count` |  |
| `body_streams` | `stream_timeline_complete` | 归档，进摘要 | `body_streams[].stream_timeline_complete` |  |
| `body_streams` | `error_code` | 归档，进摘要 | `body_streams[].error_code` |  |
| `body_chunks` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `body_chunks` | `stage` | 归档，进摘要 | `raw_chunks[].stage` |  |
| `body_chunks` | `seq` | 归档，进摘要 | `raw_chunks[].seq` |  |
| `body_chunks` | `offset` | 归档，进摘要 | `raw_chunks[].offset` |  |
| `body_chunks` | `plaintext_length` | 归档，进摘要 | `raw_chunks[].plaintext_length` |  |
| `body_chunks` | `observed_at_ns` | 归档，进摘要 | `raw_chunks[].observed_at_ns` |  |
| `body_chunks` | `data_enc` | 归档，进摘要 | `raw_chunks[].sha256` | plaintext in objects:raw_chunk.data_b64; the digest covers its SHA-256 |
| `body_chunks` | `encoded_length` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `body_chunks` | `compression` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `stream_timelines` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `stream_timelines` | `stage` | 归档，进摘要 | `stream_timelines[].stage` |  |
| `stream_timelines` | `event_count` | 归档，进摘要 | `stream_timelines[].event_count` |  |
| `stream_timelines` | `first_event_at_ns` | 归档，进摘要 | `stream_timelines[].first_event_at_ns` |  |
| `stream_timelines` | `last_event_at_ns` | 归档，进摘要 | `stream_timelines[].last_event_at_ns` |  |
| `stream_timelines` | `timeline_complete` | 归档，进摘要 | `stream_timelines[].timeline_complete` |  |
| `stream_timelines` | `plaintext_length` | 归档，进摘要 | `stream_timelines[].plaintext_length` |  |
| `stream_timelines` | `compression` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `stream_timelines` | `timeline_enc` | 归档，进摘要 | `stream_timelines[].timeline_b64` | the digest covers the plaintext's SHA-256 |
| `parsed_results` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `parsed_results` | `parser_name` | 归档，进摘要 | `parsed_results.parser_name` |  |
| `parsed_results` | `parser_version` | 归档，进摘要 | `parsed_results.parser_version` |  |
| `parsed_results` | `status` | 归档，进摘要 | `parsed_results.status` |  |
| `parsed_results` | `request_model` | 归档，进摘要 | `parsed_results.request_model` |  |
| `parsed_results` | `response_model` | 归档，进摘要 | `parsed_results.response_model` |  |
| `parsed_results` | `requested_stream` | 归档，进摘要 | `parsed_results.requested_stream` |  |
| `parsed_results` | `observed_stream` | 归档，进摘要 | `parsed_results.observed_stream` |  |
| `parsed_results` | `response_id` | 归档，进摘要 | `parsed_results.response_id` |  |
| `parsed_results` | `usage_input` | 归档，进摘要 | `parsed_results.usage_input` |  |
| `parsed_results` | `usage_output` | 归档，进摘要 | `parsed_results.usage_output` |  |
| `parsed_results` | `usage_total` | 归档，进摘要 | `parsed_results.usage_total` |  |
| `parsed_results` | `error_type` | 归档，进摘要 | `parsed_results.error_type` |  |
| `parsed_results` | `error_code` | 归档，进摘要 | `parsed_results.error_code` |  |
| `parsed_results` | `message_count` | 归档，进摘要 | `parsed_results.message_count` |  |
| `parsed_results` | `tool_call_count` | 归档，进摘要 | `parsed_results.tool_call_count` |  |
| `parsed_results` | `has_tool_call` | 归档，进摘要 | `parsed_results.has_tool_call` |  |
| `parsed_results` | `parsed_json_enc` | 归档，进摘要 | `parsed_results.parsed_json` | decompressed JSON, or parsed_json_ref and objects:parsed_json_part over 1 MiB; the digest covers its SHA-256 |
| `parsed_results` | `parsed_at_ns` | 归档，进摘要 | `parsed_results.parsed_at_ns` |  |
| `parsed_results` | `upstream_error_class` | 归档，进摘要 | `parsed_results.upstream_error_class` |  |
| `token_links` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `token_links` | `newapi_user_id` | 归档，进摘要 | `token_links.newapi_user_id` |  |
| `token_links` | `username` | 归档，进摘要 | `token_links.username` |  |
| `token_links` | `newapi_token_id` | 归档，进摘要 | `token_links.newapi_token_id` |  |
| `token_links` | `token_name` | 归档，进摘要 | `token_links.token_name` |  |
| `token_links` | `linked_at_ns` | 归档，进摘要 | `token_links.linked_at_ns` |  |
| `token_links` | `billing_state` | 归档，进摘要 | `token_links.billing_state` |  |
| `token_links` | `quota` | 归档，进摘要 | `token_links.quota` |  |
| `token_links` | `quota_per_unit` | 归档，进摘要 | `token_links.quota_per_unit` |  |
| `token_links` | `billed_prompt_tokens` | 归档，进摘要 | `token_links.billed_prompt_tokens` |  |
| `token_links` | `billed_completion_tokens` | 归档，进摘要 | `token_links.billed_completion_tokens` |  |
| `token_links` | `billing_attempts` | 归档，进摘要 | `token_links.billing_attempts` |  |
| `turns` | `turn_id` | 归档，进摘要 | `turn.turns.turn_id` |  |
| `turns` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `turns` | `conversation_id` | 归档，进摘要 | `turn.turns.conversation_id` |  |
| `turns` | `parent_turn_id` | 归档，进摘要 | `turn.turns.parent_turn_id` |  |
| `turns` | `parent_base` | 归档，进摘要 | `turn.turns.parent_base` |  |
| `turns` | `link_reason` | 归档，进摘要 | `turn.turns.link_reason` |  |
| `turns` | `link_confidence` | 归档，进摘要 | `turn.turns.link_confidence` |  |
| `turns` | `request_layout` | 归档，进摘要 | `turn.turns.request_layout` |  |
| `turns` | `response_layout` | 归档，进摘要 | `turn.turns.response_layout` |  |
| `turns` | `request_envelope_hash` | 归档，进摘要 | `turn.turns.request_envelope_hash` |  |
| `turns` | `response_envelope_hash` | 归档，进摘要 | `turn.turns.response_envelope_hash` |  |
| `turns` | `request_item_count` | 归档，进摘要 | `turn.turns.request_item_count` |  |
| `turns` | `response_item_count` | 归档，进摘要 | `turn.turns.response_item_count` |  |
| `turns` | `request_sequence_hash` | 归档，进摘要 | `turn.turns.request_sequence_hash` |  |
| `turns` | `response_sequence_hash` | 归档，进摘要 | `turn.turns.response_sequence_hash` |  |
| `turns` | `request_reconstruction_hash` | 归档，进摘要 | `turn.turns.request_reconstruction_hash` |  |
| `turns` | `response_reconstruction_hash` | 归档，进摘要 | `turn.turns.response_reconstruction_hash` |  |
| `turns` | `reconstruction_status` | 归档，进摘要 | `turn.turns.reconstruction_status` |  |
| `turns` | `previous_response_id` | 归档，进摘要 | `turn.turns.previous_response_id` |  |
| `turns` | `response_id` | 归档，进摘要 | `turn.turns.response_id` |  |
| `turns` | `created_at_ns` | 归档，进摘要 | `turn.turns.created_at_ns` |  |
| `turn_context_ops` | `turn_id` | 归档，不进摘要 | `turn.turns.turn_id` | key column given by the enclosing record |
| `turn_context_ops` | `op_index` | 归档，不进摘要 | `turn.request_context.ops[].op_index` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_context_ops` | `operation` | 归档，不进摘要 | `turn.request_context.ops[].operation` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_context_ops` | `item_count` | 归档，不进摘要 | `turn.request_context.ops[].item_count` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_context_ops` | `slot` | 归档，不进摘要 | `turn.request_context.ops[].slot` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_context_ops` | `object_hash` | 归档，不进摘要 | `turn.request_context.ops[].object_hash` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_context_ops` | `semantic_hash` | 归档，不进摘要 | `turn.request_context.ops[].semantic_hash` | archived only in the delta request context; the digest covers the materialised refs instead (Q6) |
| `turn_response_items` | `turn_id` | 归档，进摘要 | `turn.turns.turn_id` | key column given by the enclosing record |
| `turn_response_items` | `ordinal` | 归档，进摘要 | `turn.response_items[].ordinal` |  |
| `turn_response_items` | `slot` | 归档，进摘要 | `turn.response_items[].slot` |  |
| `turn_response_items` | `object_hash` | 归档，进摘要 | `turn.response_items[].object_hash` |  |
| `turn_response_items` | `semantic_hash` | 归档，进摘要 | `turn.response_items[].semantic_hash` |  |
| `conversations` | `conversation_id` | 归档，进摘要 | `conversation.conversation_id` |  |
| `conversations` | `protocol` | 归档，进摘要 | `conversation.protocol` |  |
| `conversations` | `key_hash` | 归档，进摘要 | `conversation.key_hash` |  |
| `conversations` | `created_at_ns` | 归档，进摘要 | `conversation.created_at_ns` |  |
| `conversations` | `updated_at_ns` | 不归档 |  | changes with every later turn of the conversation; not a property of one audit (Q7) |
| `content_objects` | `object_hash` | 归档，进摘要 | `turn.objects[].object_hash` |  |
| `content_objects` | `semantic_hash` | 归档，进摘要 | `turn.objects[].semantic_hash` |  |
| `content_objects` | `kind` | 归档，进摘要 | `turn.objects[].object_kind` |  |
| `content_objects` | `compression` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `content_objects` | `plaintext_length` | 归档，进摘要 | `turn.objects[].plaintext_length` |  |
| `content_objects` | `encoded_length` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `content_objects` | `data_enc` | 归档，不进摘要 | `objects:content_object.data` | bound by object_hash, its content address |
| `content_objects` | `created_at_ns` | 归档，不进摘要 | `objects:content_object.created_at_ns` | first write time, shared by every audit that references the object |
| `binary_objects` | `binary_hash` | 归档，进摘要 | `turn.binaries[].binary_hash` |  |
| `binary_objects` | `media_type` | 归档，进摘要 | `turn.binaries[].media_type` |  |
| `binary_objects` | `compression` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `binary_objects` | `plaintext_length` | 归档，进摘要 | `turn.binaries[].plaintext_length` |  |
| `binary_objects` | `encoded_length` | 不归档 |  | storage encoding of the ciphertext container; the plaintext and its length are archived |
| `binary_objects` | `data_enc` | 归档，不进摘要 | `objects:binary_object.data_b64` | bound by binary_hash, its content address |
| `binary_objects` | `created_at_ns` | 归档，不进摘要 | `objects:binary_object.created_at_ns` | first write time, shared by every audit that references the object |
| `content_binary_refs` | `object_hash` | 归档，进摘要 | `turn.binary_refs[].object_hash` |  |
| `content_binary_refs` | `json_pointer` | 归档，进摘要 | `turn.binary_refs[].json_pointer` |  |
| `content_binary_refs` | `binary_hash` | 归档，进摘要 | `turn.binary_refs[].binary_hash` |  |
| `content_binary_refs` | `media_type` | 归档，进摘要 | `turn.binary_refs[].media_type` |  |
| `content_binary_refs` | `encoding` | 归档，进摘要 | `turn.binary_refs[].encoding` |  |
| `content_external_refs` | `object_hash` | 归档，进摘要 | `turn.external_refs[].object_hash` |  |
| `content_external_refs` | `json_pointer` | 归档，进摘要 | `turn.external_refs[].json_pointer` |  |
| `content_external_refs` | `ref_kind` | 归档，进摘要 | `turn.external_refs[].ref_kind` |  |
| `content_external_refs` | `value_hash` | 归档，进摘要 | `turn.external_refs[].value_hash` |  |
| `content_external_refs` | `value_enc` | 归档，进摘要 | `turn.external_refs[].value` | the digest covers the plaintext's SHA-256 |
| `audit_project_identity` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `audit_project_identity` | `identity_version` | 归档，进摘要 | `audit_project_identity.identity_version` |  |
| `audit_project_identity` | `extracted_at_ns` | 归档，进摘要 | `audit_project_identity.extracted_at_ns` |  |
| `audit_project_identity` | `source` | 归档，进摘要 | `audit_project_identity.source` |  |
| `audit_project_identity` | `body_scanned` | 归档，进摘要 | `audit_project_identity.body_scanned` |  |
| `audit_project_identity` | `identity_fpr` | 归档，进摘要 | `audit_project_identity.identity_fpr` |  |
| `audit_project_identity` | `remote_fpr` | 归档，进摘要 | `audit_project_identity.remote_fpr` |  |
| `audit_project_identity` | `repo_root_fpr` | 归档，进摘要 | `audit_project_identity.repo_root_fpr` |  |
| `audit_project_identity` | `cwd_fpr` | 归档，进摘要 | `audit_project_identity.cwd_fpr` |  |
| `audit_project_identity` | `identity_enc` | 归档，进摘要 | `audit_project_identity.identity` | the digest covers the plaintext's SHA-256 |
| `integrity_events` | `sequence` | 归档，进摘要 | `integrity_events[].sequence` |  |
| `integrity_events` | `audit_id` | 归档，进摘要 | `audit_id` | key column given by the enclosing record |
| `integrity_events` | `event_type` | 归档，进摘要 | `integrity_events[].event_type` |  |
| `integrity_events` | `previous_mac` | 归档，进摘要 | `integrity_events[].previous_mac` |  |
| `integrity_events` | `payload_digest` | 归档，进摘要 | `integrity_events[].payload_digest` |  |
| `integrity_events` | `event_mac` | 归档，进摘要 | `integrity_events[].event_mac` |  |
| `integrity_events` | `created_at_ns` | 归档，进摘要 | `integrity_events[].created_at_ns` |  |
| `audit_gaps` | `id` | 归档，不进摘要 | `gaps:gap.id` |  |
| `audit_gaps` | `started_at_ns` | 归档，不进摘要 | `gaps:gap.started_at_ns` |  |
| `audit_gaps` | `ended_at_ns` | 归档，不进摘要 | `gaps:gap.ended_at_ns` |  |
| `audit_gaps` | `reason` | 归档，不进摘要 | `gaps:gap.reason` |  |
| `audit_gaps` | `request_count` | 归档，不进摘要 | `gaps:gap.request_count` |  |
| `audit_gaps` | `detail` | 归档，不进摘要 | `gaps:gap.detail` |  |
| `audit_gaps` | `created_at_ns` | 归档，不进摘要 | `gaps:gap.created_at_ns` |  |

清单的 `tables` 就是这张表里不是“不归档”的列，按表分组、按表中的顺序（§14.1）。

## 16. 核对流程

`audit-archive verify --key`、运行时的发布后重读和对账走的是同一个函数（`bundle.Open` 加 `Verify`）。按下面的顺序检查，任何一项不过整个包作废，结果码在括号里。

### 16.1 清单

1. 清单是普通文件、不超过 256 MiB、是合法 UTF-8，按 §7 严格解码，满足 §14.1 的有效性规则（`manifest_invalid`）。`files[].name` 必须是裸文件名（不含 `/`、`\`、`:`，不以 `.` 开头）。
2. 有密钥时：`key_fingerprint` 等于手里密钥的指纹（`key_mismatch`，这时什么都不解密），再重算 `mac`（`mac_mismatch`）。
3. 每个数据文件的落盘字节数和 SHA-256 等于清单（`file_missing`、`file_mismatch`）。不带密钥的 `verify` 只做到这一步（§24.3）。

### 16.2 行文件（一遍顺序读）

解密、解压、按行切分（`decrypt_failed`、`decompress_failed`、`line_invalid`）。对每一行：

1. 按 §7、§8 严格解码，列表是规范顺序，行首字段与行内各表一致（`line_invalid`）。
2. 行数不超过成员数；第 i 行与 `members[i]` 的 `audit_id`、`revision`、`started_at_ns`、`ended_at_ns`、`conversation_id` 相同（`count_mismatch`、`member_mismatch`）。
3. 同一 audit 不在包里出现两次；`revision` 至少为 1；`audit_records.protocol` 等于清单的 `protocol`；会话包里每行的会话就是清单的那一个（`member_mismatch`）。
4. 行的顺序（`order`）：同一会话的行连续，按（`turns.created_at_ns`，`audit_id`）严格递增；没有轮次的行都排在有轮次的行之后，按（`started_at_ns`，`audit_id`）严格递增。会话之间的先后没有规定。同一轮次在一个会话组里不能出现两次。
5. 物化请求上下文（§9.2）。`delta` 形式而父轮次不是本会话组里排在前面的一行（`reference_open`）；应用失败或项数、序列哈希不符（`context_mismatch`）。
6. 从行重算记录摘要（§13），必须等于行尾的 `record_digest` 和清单 `members[i].record_digest`（`digest_mismatch`）。运行时的重读还要等于导出时从热库算出的值，对账时等于目录表意向行里的值。
7. 引用闭合（`reference_open`、`object_mismatch`）：`turn.objects` 恰好是两个 envelope、物化请求引用和响应条目引用到的对象，没有多余；引用里的 `semantic_hash` 等于该对象的；`turn.binaries` 恰好是 `binary_refs` 指向的二进制；每个二进制引用和外部引用都属于列出的对象；每个外部引用的 `value_hash` 按 §10.2 重算相符。
8. raw 的元数据（`raw_mismatch`）：对每个 `retention_state` 为 `full`、`state` 不是 `streaming` 的 Body，它的 `source_stage` 的块从 `seq` 0、`offset` 0 起首尾相接；只有 `state` 为 `partial` 且 `error_code` 为 `capture_chunk_missing` 的 Body 允许向前跳（`seq` 与 `offset` 只能增大），而且块不能越出 `observed_length`；块数等于 `chunk_count`，字节数之和等于 `stored_length`；完整的 Body（§8.5）必须有 32 字节的 `sha256`。每个 raw 块都必须属于某个这样的 Body 的来源阶段。
9. 给了完整性密钥时，逐个核对抄录的事件的 MAC（§8.11，`event_mac_mismatch`）。`verify --skip-event-mac` 跳过这一项。

读完全部行之后：行数等于 `line_count` 和成员数；`started_at_ns` 的最小值、`ended_at_ns` 的最大值等于清单的两个时间；按首次出现顺序收集的会话等于 `conversations`（`count_mismatch`、`member_mismatch`）。文件末尾 gzip 之后没有多余字节，读过的字节数和 SHA-256 再次等于清单。

### 16.3 对象文件（一遍顺序读）

对每个条目（`object_mismatch`、`raw_mismatch`、`order`）：

- `content_object`：必须被某一行的 `turn.objects` 列出，且之前没有出现过；`semantic_hash`、`object_kind`、`plaintext_length` 与行里的相同；`data` 的长度等于 `plaintext_length`；`object_hash` 按 §10.2 重算相符；`data` 能按 §10.1 解码、`schema_version` 为 1、`kind` 等于 `object_kind`；`semantic_hash` 重算相符。
- `binary_object`：被某一行列出、之前没有出现过，`media_type` 与长度相符，`binary_hash` 重算相符。
- `raw_chunk`：（`audit_id`，`stage`，`seq`）被某一行列出、之前没有出现过，长度和 SHA-256 等于行里的那一项；同一（audit，阶段）的块按 `seq` 的顺序出现。
- `parsed_json_part`：属于某一行的 `parsed_json_ref`，段号从 0 起依次出现，每段非空、不超过 1 MiB。

读完之后：行里列出的每个对象、二进制、raw 块和 `parsed_json` 段都出现过（`reference_open`）；每个完整的 `full` Body，按序拼起它来源阶段的全部块，SHA-256 等于 `body_streams.sha256`（`raw_mismatch`）；每个拆开的 `parsed_json` 段数、总长和 SHA-256 等于 `parsed_json_ref`；`content_object`、`binary_object`、`parsed_json_part` 的条目数之和等于 `object_count`，`raw_chunk` 数等于 `raw_chunk_count`（`count_mismatch`）。

### 16.4 gap 包

行按 §11 解码；`id` 严格递增；第一行的 `id`、最后一行的 `id`、行数、时间范围与清单相符（`line_invalid`、`order`、`member_mismatch`、`count_mismatch`）。

### 16.5 不在这一步核对的

- **重建哈希。** `turns` 的两个重建哈希在重建 provider 请求和响应时核对（读取工具的 `export`，与查询层相同），`verify` 不重建。
- **事件的载荷摘要。** 它绑定热库的密文，从明文算不出来（§8.11）。
- **残缺 Body 的整体哈希。** 残缺 Body 没有整体 SHA-256，它的每一块由记录摘要逐块覆盖。

有一项核对通过之前，读取工具不输出这个包的任何内容：`cat` 和 `export` 都先完整核对一遍，再从头输出。

---

# 第二部分　模块

## 17. 模式与配置

### 17.1 `archive` 段

~~~yaml
archive:
  mode: "off"                     # off | export_only | archive_then_delete；省略或空串同 off
  dir: ""                         # 归档目录，绝对路径；mode 不为 off 时必填
  encrypt: true                   # false 时数据文件是普通的 .jsonl.gz
  run_at: "03:00"                 # 每天运行的本地时间 HH:MM
  timezone: ""                    # IANA 名称；空则取 org_reports.timezone
  segment_max_bytes: 268435456    # 一个分段的未压缩字节上限
  conversation_min_turns: 16      # 一趟里到期轮次数达到它的会话独立成包
  conversation_min_bytes: 16777216  # 或到期部分的归档明文达到它
  pass_audits: 5000               # 一趟最多看多少条 audit
  run_deadline_minutes: 240       # 一次运行（含重试）的期限
  verify_sample: 0.05             # 发布后与热库比对的抽样比例
~~~

| 键 | 默认 | 校验（`mode` 为 `off` 或空时这一段不做任何检查） |
| --- | --- | --- |
| `mode` | `off` | `off`、`export_only`、`archive_then_delete` 之一 |
| `dir` | 空 | 必填，绝对路径；不能是 `key_path` 所在的目录，也不能包含它或位于其中；也不能与 `audit.staging.dir` 相同、包含它或位于其中 |
| `encrypt` | `true` | — |
| `run_at` | `03:00` | `HH:MM` |
| `timezone` | 空 | 非空时必须是可加载的 IANA 名称；为空时取 `org_reports.timezone`（其默认值 `Asia/Shanghai`），不论组织周报是否开启。二进制内嵌时区数据 |
| `segment_max_bytes` | 256 MiB（268435456） | 16 MiB 到 4 GiB |
| `conversation_min_turns` | 16 | 1 到 1,000,000 |
| `conversation_min_bytes` | 16 MiB（16777216） | 1 到 4 GiB |
| `pass_audits` | 5000 | 1 到 10,000 |
| `run_deadline_minutes` | 240 | 1 到 1440 |
| `verify_sample` | 0.05 | 0 到 1 |

`mode` 不为 `off` 时还要求 `retention_days > 0`。目录本身（存在与否、属主、权限、能否写入）只在启动时检查，`--validate-config` 不检查（§17.4）。配置文件之外没有运行时修改，管理界面的设置页也没有这一段。

配置加载是严格模式：不认识 `archive:` 段的旧版本会拒绝启动，升级与回滚的顺序见[部署说明](../deployment/README.md)。

### 17.2 两种开启的模式

| 模式 | 现在的行为 |
| --- | --- |
| `export_only` | 每天导出到期的 audit 和 gap。热库里什么都不删，会一直增长 |
| `archive_then_delete` | **现在与 `export_only` 完全相同**：只导出，不移除。启动日志另加一条 `archive_removal_inactive`。校验后移除（设计 M 节）以后单独上线，并且只作用于格式版本不低于 1 的分段 |

两者唯一的不同是重新收录：`archive_then_delete` 下，目录表里状态为 `stale`、仍在热库、又没有当前成员的 audit 会以更高的修订号重新导出；`export_only` 下每条到期记录只导出一次，之后的变化不再跟踪（设计 P 第 8 条）。

### 17.3 五条护栏（决策 5.7）

| # | 护栏 | 落在哪里 |
| --- | --- | --- |
| 1 | `archive.mode` 不为 `off` 而 `retention_days` 为 0：拒绝 | 配置校验 |
| 2 | 开启归档时不做任何直接删除 | 组装：`archive.mode` 不为 `off` 时不组装 retention runner（audit 和 gap 都不再直接删除）；归档 runner 本身不删除任何东西。启动日志 Warn `archive export only: hot store keeps growing`，`error_category=archive_export_only` |
| 3 | 归档关掉、`retention_days > 0`，而以前运行过归档：醒目提示直接删除已经恢复 | 启动：目录表里有任何一条运行记录时 Warn `archive is off and retention deletes directly again; to pause archiving set retention_days: 0`，`error_category=archive_direct_delete_resumed`，带 `retention_days`。想暂停归档而不恢复直接删除，应把 `retention_days` 设为 0 |
| 4 | `archive.dir` 与 `key_path` 的目录相同或互相包含：拒绝 | 配置校验（暂存目录同样不许，见上表） |
| 5 | 已有数据或已有归档包时不新建主密钥 | 启动：见 §17.4 |

### 17.4 主密钥与归档目录的启动检查

主密钥只在“它要打开的东西一样都不存在”时才新建：

- 数据库里 `audit_records`、`integrity_events`、`archive_segments` 三张表都没有行（`HasAudits`）；并且
- 归档开启时，`archive.dir` 下（递归）没有任何 `*.manifest.json`。目录读不了时按“有”处理；目录不存在按“没有”处理。

任何一条不满足而密钥文件缺失时，不新建密钥，审计按密钥不可用处理（available 不审计照常转发，strict 准入回 `503`）。因为归档目录里有清单而拒绝时，日志 `audit key unavailable` 另带 `reason=archive_manifests_present`。这一条防的是数据库整个丢失、只剩归档目录时，新密钥让旧包全部打不开。

归档 runner 组装时检查归档目录，规则与暂存目录相同：不存在就以 0700 创建；Unix 上要求属主是进程用户、组和其他用户没有任何权限；要能在里面创建并删除一个探针文件。检查不过时 runner 不组装，日志 `archive runner unavailable`（`error_category=archive_unavailable`，`reason=dir_<码>`，码为 `not_absolute`、`create_failed`、`inspect_failed`、`not_directory`、`wrong_owner`、`open_permissions`、`not_writable`），代理和审计照常工作，retention 的直接删除仍然不组装。

## 18. 一次运行

### 18.1 调度

- 每天在 `timezone` 里的 `run_at` 运行一次；那一刻已经过了就等明天（与会话分析的调度算法相同）。同一时间只有一次运行。
- **补跑：** 启动时，最近一次 `completed` 的运行开始于 24 小时之前，或者从来没有过，就立即运行一次。目录表读不出来时也运行，由运行自己报告失败。
- **重试：** 一次运行失败后每 10 分钟重试一次，直到成功，或者下一次尝试的开始时间超过当天第一次尝试起算的 `run_deadline_minutes`。重试沿用当天的期限，不另起一个。
- 进程关闭时取消正在进行的运行；它在目录表里留在 `running`，下一次运行开始时改为 `interrupted`，留下的东西由对账处理（§20）。

### 18.2 运行的步骤

截止时间与 retention 相同：`now − retention_days × 24h`。一次运行依次：

1. **对账**（§20）。
2. **一趟接一趟。** 每趟一个只读的 REPEATABLE READ 快照（在只读连接池上，不占用 writer）。到了期限就停在趟与趟之间（至少做一趟）。每趟取至多 `pass_audits` 条要看的 audit，依次是：
   - 推迟过的 audit（`archive_deferred` 里的，每次运行每条再看一次）；
   - 只在 `archive_then_delete` 下：要重新收录的 `stale` 成员；
   - 水位之后、截止时间之前的新范围，沿 `(started_at_ns, audit_id)` 升序。
   然后把这些 audit 所在会话里其余到期的 audit 补进来，使一个会话的到期轮次总在同一趟里。
3. **gap。** 期限没到时，把结束于截止时间之前、还不在任何分段里的 gap 导出成 gap 包，每包至多 10,000 条，与分段一样登记、发布、重读、定稿。期限到了就留给下一次。
4. 移除阶段的接缝：本版本什么都不做。

一次运行只导出，不删除热库里的任何行。

### 18.3 选取、推迟与水位

一条 audit 要导出，必须已终结、`started_at_ns` 在截止时间之前、解析与调用者查找都到了终态，并且没有“当前成员”（目录表里不是 `stale`、所在分段的格式版本等于当前版本的成员行）。不满足的按下表推迟：

| 推迟原因 | 含义 |
| --- | --- |
| `open` | 还没有终结 |
| `parse_pending` | `parse_status` 是 `pending` 或 `processing` |
| `caller_pending` | `caller_status` 是 `pending` |
| `integrity_failed` | 原完整性事件复核不过、或某段密文解不开（§18.6） |
| `export_failed` | 这一条不能归档，而原因不是数据损坏：导出时时间线边界、raw 布局或记录格式不过，包写入方以记录本身的原因拒绝了它，或抽样时它读出来与热库不同而变更戳没变（§18.5） |

不能导出的 audit 留在热库，登记进 `archive_deferred` 并写明原因，之后每次运行再看一次；每次运行按原因报告推迟的条数（§19）。推迟没有上限：推迟数一直不降，说明解析、调用者查找或数据本身卡住了，应当去修那里。已不在热库的 audit 从推迟表里去掉。

**水位**：新范围从上一个水位之后开始，一趟看过的最后一条就是新水位，不论其中多少条被推迟。**一趟的全部分段都定稿之后**，水位、计数、推迟和不再推迟的 audit 才由一个 writer 操作一起写进目录表；这一趟有分段失败时水位不推进，下次运行从旧水位重来。水位按格式版本记录：格式定为版本 1 时水位归零，版本 0 的成员全部重新导出。

### 18.4 分组与装包

一趟里选出的 audit：

1. 有轮次的按会话分组，组内按（`turns.created_at_ns`，`audit_id`）排序，父轮次在前。
2. 一个会话在本趟到期的轮次数达到 `conversation_min_turns`，或它们的归档明文（行、还没算过的对象和 raw 块，未压缩）累计达到 `conversation_min_bytes`，写成独立的会话包（`bundle_kind: conversation`）。会话 id 不能放进文件名（§3.1），或会话里的 audit 不全是同一个协议时，不独立成包。
3. 其余会话和没有轮次的 audit 装进本趟的桶包（`bundle_kind: bucket`），**每个协议一个**。协议是 `audit_records.protocol`，也就是协议族：OpenAI Chat、Completions 与 Responses 同在 `openai` 桶里。一个会话的 audit 混有多个协议时，各条进各自协议的桶。没有轮次的 audit 排在桶包末尾，按（`started_at_ns`，`audit_id`）。
4. 一个包累计的未压缩字节超过 `segment_max_bytes` 时，在下一条 audit 之前封好当前分段、开下一个分段。一条 audit 从不跨分段，所以一个分段可能超出上限一条 audit 的量。

阈值是推测的默认值（设计 B.3）：真实分布没有量过，格式版本 0 期间可以调整，调整不影响已写的包。

### 18.5 一个分段的发布

每个分段写完就立即走完下面的步骤，再写下一个：

1. **写。** 每条 audit 导出前已在快照里复核完原完整性事件、认证解密了它的每一段密文、核对了完整 Body 的 SHA-256 和对象的内容地址（设计实施记录 R.6 第 15 条）。行和对象流式写进临时文件：JSONL → gzip → 分帧加密，边写边算落盘字节的 SHA-256。封包时关 gzip、发末帧、fsync，再写好签名的清单临时文件并 fsync。
2. **登记意向。** 一个 writer 操作在目录表插入 `publishing` 的分段行和全部成员行（记录摘要、变更戳、修订号）。同一事务里重算每个成员的变更戳：与快照时不同、或 audit 已不在，登记为 `stale`（快照之后它已经变了）。
3. **发布。** 用硬链接把数据文件链到正式名，fsync 目录，再链接清单，再 fsync 目录。正式名已存在时失败，从不覆盖。中途失败时已经链上的文件改名加 `.rejected`，意向行删掉。
4. **重读核对**（§16）：重新打开已发布的包，做全部检查，并且每个成员重算的摘要必须等于快照里算出的。
5. **抽样比对**（设计 J.3）：按 `verify_sample` 抽取 `ceil(比例 × 成员数)` 条，每个包至少一条（比例为 0 时也是一条），登记意向时已是 `stale` 的成员不参加。用读取工具的同一套渲染，把归档读出的详情、Header、重建的 Turn 与 provider 请求和响应、会话、两侧时间线、两侧 raw 的元数据和字节的 SHA-256，与查询层从热库对同一条记录给出的结果（经同样的凭据投影）逐字节比较；一侧报错时比较错误类别。比较不等时，再查这条成员此刻在热库里的变更戳：与导出时不同（快照之后被改过）就把它算作 `stale`，不作废这个包；相同则这条成员读出来与热库不同，处理见下。gap 包不抽样。
6. **定稿。** 一个 writer 操作把分段改为 `sealed`，写清单的 SHA-256。

**一条成员的问题只排除这一条。** 两种情形：

- 写入方以记录本身的原因拒绝一条记录（`invalid_record`、`order`、`context_mismatch`、`payload_mismatch`、`entry_too_large`）。写入方这时已作废整个未封的分段（删掉它的临时文件，不会发布半条记录），runner 从仍然打开的快照里把这个分段的其余成员重新读出、写进新的分段；这条记录的子轮次因为父轮次不在分段里了，改写成物化形式。日志 Warn `archive record refused`（`error_category=archive_record_refused`，`reason` 是写入方的码）。
- 第 5 步发现一条成员读出不同而变更戳没变。这个包照样作废（改名 `.rejected`、意向行删掉），这条成员排除，包里其余的成员在同一趟里写进一个新的包，再走一遍第 2 到 6 步。日志 Warn `archive sample mismatch`（`error_category=archive_sample_mismatch`）。

两种情形下被排除的成员都留在热库，推迟原因 `export_failed`，之后每次运行再看一次；运行照常继续，水位照常推进。完成日志分别计入 `refused_audits` 和 `sample_mismatch_audits`（也计入 `excluded_audits`）。

除此之外，第 4 步核对不过，这个包作废（改名 `.rejected`，不删除；意向行删掉），这次运行以 `archive_failed` 失败结束；成员仍是热库里的普通 audit，这一趟的水位没有推进，下一次运行重新导出它们。

第 5 步无法比较时分两种。比较时热库读不出来，这并不说明包有问题：包不作废，分段留在 `publishing`，这次运行以 `archive_failed` 失败结束（`reason=sample_failed`），这一趟的水位没有推进；下一次运行的对账重新抽样，通过就定稿（§20 第 1 条），与对账里遇到同样情形时一样。一条成员读出不同、而查它此刻的变更戳时热库读不出来，差异没法归到快照之后的改动，包可能有问题：这个包照样作废（`.rejected`、意向行删掉），运行同样以 `sample_failed` 失败。

### 18.6 失败

| 情形 | 处理 |
| --- | --- |
| 一条 audit 的完整性事件复核不过、或某段密文解不开 | 只排除这一条：不归档、留在热库，推迟原因 `integrity_failed`，计入 `integrity_failed_audits`，日志 Error `archive integrity check failed`（`error_category=archive_integrity_failed`，`reason` 是具体原因）。存储的载荷校验状态置为失败，与后台载荷校验发现损坏时相同，存储因此报告不健康 |
| 一条 audit 不能导出、被写入方拒绝，或抽样时读出不同而变更戳没变 | 只排除这一条，推迟原因 `export_failed`，其余成员照常写进包（§18.5）；运行继续 |
| 重读核对不过 | 这个包作废（`.rejected`），运行以 `archive_failed` 结束，10 分钟后重试 |
| 抽样时热库读不出来（`sample_failed`） | 包不作废，分段留在 `publishing`，运行以 `archive_failed` 结束、水位不动；下一次运行的对账重新抽样后定稿。读出不同而变更戳读不出来时包作废（§18.5） |
| 磁盘满、写入或 fsync 失败 | 删掉这个分段自己的临时文件，不登记；运行以 `archive_failed` 结束（`reason` 是写入方的码，如 `disk_full`、`write_failed`、`sync_failed`）；10 分钟后重试 |
| 登记意向、定稿或目录表的其他写失败 | 运行以 `archive_failed` 结束；已发布而没定稿的分段留给对账 |
| 快照本身出错（取消、存储关闭、事务不再应答） | 结束这一趟和这次运行（`snapshot_failed`），不排除任何成员，不置失败状态 |
| 发布后、定稿前崩溃 | 下一次运行的对账处理（§20） |

启用归档以后，任何情况下都不会跳过归档直接删除。

## 19. 状态、计数与日志

每次运行在 `archive_runs` 留一行（表结构见[模块 04](04-sqlite-storage-and-migrations.md#310-冷归档目录表postgresql-migration-008) §3.10）：

| 状态 | 含义 |
| --- | --- |
| `running` | 正在运行，或进程在运行中退出 |
| `completed` | 正常结束（包括到了期限、停在趟与趟之间） |
| `archive_failed` | 失败结束，之后按 §18.1 重试 |
| `interrupted` | 下一次运行开始时发现它仍是 `running` |

管理界面和 Agent 门面不展示运行记录；它们只供补跑判断和排障时查库。

日志只写稳定的码、计数、字节数和耗时，不写路径、文件名、会话内容或底层错误原文；存储错误只给 `storage_error` 类别。

| 日志 | 级别 | 字段 | 何时 |
| --- | --- | --- | --- |
| `archive export only: hot store keeps growing` | Warn | `error_category=archive_export_only` | 启动，模式为 `export_only` 或 `archive_then_delete` |
| `archive removal is not active in this build: archive_then_delete exports only` | Warn | `error_category=archive_removal_inactive` | 启动，模式为 `archive_then_delete` |
| `archive is off and retention deletes directly again; to pause archiving set retention_days: 0` | Warn | `error_category=archive_direct_delete_resumed`、`retention_days` | 启动，护栏 3 |
| `archive runner unavailable` | Warn | `error_category=archive_unavailable`、`reason`（`audit_unavailable`、`dir_<码>`、`invalid_timezone`、`invalid_options`） | 开启了归档而 runner 不能组装；代理与审计照常 |
| `audit key unavailable` | Warn | `mode`、`error_category=key_unavailable`，因归档目录里有清单而拒绝新建密钥时另有 `reason=archive_manifests_present` | 启动 |
| `audit archive keys unavailable` | Warn | `mode`、`error_category=key_unavailable` | 派生归档子密钥失败 |
| `archive run completed` | Info | 见下 | 一次运行正常结束 |
| `archive run failed` | Warn | 同下，另加 `error_category=archive_failed`、`reason`，存储错误时 `storage_error` | 一次运行失败结束；运行开始前就失败时只有 `error_category`、`reason=catalog_failed`、`storage_error` |
| `archive run interrupted` | Warn | `error_category=archive_interrupted`、`exported_audits`、`duration_ms` | 运行被取消（进程关闭） |
| `archive integrity check failed` | Error | `error_category=archive_integrity_failed`、`reason` | 一条 audit 复核不过（§18.6） |
| `archive record refused` | Warn | `error_category=archive_record_refused`、`reason`（写入方的码） | 包写入方以记录本身的原因拒绝一条记录，只排除它（§18.5） |
| `archive sample mismatch` | Warn | `error_category=archive_sample_mismatch`、`reason=sample_mismatch` | 抽样时（新发布的分段或对账里 `publishing` 的分段）一条成员读出不同而变更戳没变：包作废，只排除它，其余成员重写（§18.5、§20） |
| `archive directory has manifests that do not verify` | Warn | `error_category=archive_manifest_unusable`、`manifests` | 对账时有清单解析不了或签名不对 |
| `archive bundle unknown to the catalog does not verify` | Warn | `error_category=archive_manifest_unusable`、`reason` | 对账时一个目录表不认识的包核对不过 |
| `archive bundle registered from the directory` | Info | `bundle_kind`、`members` | 对账登记了一个目录表不认识的包 |

**完成日志的字段**：`status`、`exported_audits`（登记为当前成员的条数，不含登记时已是 `stale` 的）、`deferred_audits`、`integrity_failed_audits`、`excluded_audits`（被排除的条数，含下两项）、`stale_audits`、`exported_gaps`、`refused_audits`（写入方拒绝的）、`sample_mismatch_audits`（抽样读出不同的）、`segments`、`disk_bytes`、`duration_ms`；推迟数大于 0 的原因各有一个 `deferred_<原因>`；对账定稿了分段时有 `reconciled_segments`；到了期限时有 `deadline_reached=true`。

**失败的 `reason`**：`catalog_failed`（目录表读写失败）、`snapshot_failed`、`intent_failed`、`seal_failed`、`sample_failed`（抽样时热库读不出来；包是否作废见 §18.5）、`count_mismatch`、`digest_mismatch`、`manifest_name`，以及写入、发布和核对时 `internal/archive/bundle` 的码（如 `disk_full`、`write_failed`、`sync_failed`、`name_exists`、`link_failed`，§24.3 的结果码）。

## 20. 对账

每次运行开始时先把目录表和归档目录对齐。对账只读、改名和登记；唯一删除的是写入方自己命名的临时文件。

1. **`publishing` 的分段**（上次发布后、定稿前中断）：清单不在，删掉意向行，已链上的数据文件留给第 3 步当孤儿；清单在，就按 §16 重读核对，成员与修订号、摘要都与意向行一致，再做 §18.5 第 5 步的抽样，都通过就定稿。核对或抽样不一致时，包改名 `.rejected`、意向行删掉。抽样发现一条成员读出不同而变更戳没变时，与 §18.5 一样只排除这一条：它推迟为 `export_failed`（日志 Warn `archive sample mismatch`，计入 `sample_mismatch_audits`），这次运行的各趟都不再选它，包里其余的成员照常到期，由随后的一趟重新导出。抽样时热库读不出来，这次运行以失败结束（`sample_failed`），分段留在 `publishing`，下一次再试；新发布的分段遇到同样情形时也这样处理（§18.5）。
2. **目录表不认识的包**（例如数据库从备份恢复，或回滚后重新升级）：用密钥核对通过的，登记为 `sealed` 的分段；成员一律登记为 `stale`、没有变更戳，可以列出和读取，但永远不作为删除依据；某个 audit 已经有当前成员时只登记分段、不登记它。分段行的 `run_id` 记为执行对账的这次运行。核对不过的只记日志，不改名。
3. **残留文件**：写入方命名的临时文件（§3.2）删掉；没有任何清单列出的数据文件改名加 `.orphan`，不删除。

暂存目录不在对账范围里，归档也从不读它（§23）。

## 21. 归档什么、不归档什么

| 进归档 | 不进归档 |
| --- | --- |
| §15 里 20 张表每一列的值（存储编码列除外），密文列写解密后的明文 | 三张派生表 `audit_analysis`、`agent_spawn_hints`、`analysis_detail_objects`：可以重算 |
| 每条 audit 在完整性链上的全部事件的副本 | 会话分析、组织周报的派生表；运行时设置、规则表 |
| 到期的 `audit_gaps` | `conversations.updated_at_ns`；各密文列的压缩方式和编码长度 |
| `full` 阶段的 raw 块、全部内容对象和二进制对象 | 凭据值：只有名称、长度、省略标记和指纹（§12） |
| | 目录表本身（它在热库里） |
| | 本地暂存目录里的任何文件 |

## 22. 从热库到归档的数据流

~~~text
PostgreSQL（只读快照）
  └─ 复核原完整性事件、认证解密、核对哈希
       └─ 凭据投影 → 记录结构 → 记录摘要、变更戳
            └─ 行与对象 → gzip → 分帧加密 → 归档盘上的临时文件
                 └─ 登记意向（writer）→ 硬链接发布 → 重读核对 → 抽样比对 → 定稿（writer）
~~~

明文和未加密的压缩流只存在于进程内存里，不落盘（加密开启时）。Header 块、User-Agent 和 Request-URI 解密后立即投影，记录结构、摘要和行里只有投影后的形式。

## 23. 限制与风险

- **没有恢复路径。** 归档读不回 PostgreSQL，不进管理界面，不参与洞察、周报这类统计。格式保留了以后做恢复所需的信息，但没有任何代码验证过这条路。
- **主密钥是单点。** 归档的加密密钥、签名密钥和凭据指纹密钥都由它派生。主密钥丢了，加密的包全部打不开，不加密的包也无法核对签名。**主密钥的备份必须与归档盘分开保存**；配置校验已经禁止归档目录与密钥目录重叠（护栏 4），但备份的去向要由部署者保证（[部署说明](../deployment/README.md)）。
- **归档里没有凭据值。** `Authorization`、`x-api-key`、`?key=` 这类值只剩名称、长度和 keyed 指纹，原值无法从归档找回；指纹只能核对已知的 Key。
- **内容里的凭据原样归档。** 用户贴进对话的 Key、上游错误里回显的 Key 随 raw、内容对象和 `parsed_json` 进入归档（§12.5）。加密开启时它们在密文里，关闭时是明文。
- **明文会经读取工具流出。** `cat` 和 `export` 的输出是解密后的对话内容，没有凭据值，但内容不遮蔽；输出去向由使用者负责。
- **热库持续增长。** 本版本开启归档后什么都不删（§17.2）。要控制热库大小，只能在移除上线之前关掉归档（这会恢复直接删除，护栏 3），或者接受增长。
- **暂存目录里的残留不在归档里。** 启动导入改名留下的 `.orphan`、`.corrupt` 暂存文件可能是某条已终结 audit 的一部分 raw 的唯一副本；归档只读数据库，按库里的样子归档这条 audit，暂存目录里的文件既不读也不删，需要人工处理（模块 03 §13）。
- **调用者查找关掉之后**，遗留的 `caller_status = 'pending'` 记录会一直被推迟。
- **长快照。** 每趟一个 REPEATABLE READ 快照；一个极长的会话会让单趟变长，挡住 VACUUM 的清理水位。没有在大库上量过。
- **阈值是推测的**（§18.4），格式版本 0 期间可以改。
- **新增的密码学代码**（§5）只用标准库，有固定向量和篡改测试，需要单独评审。
- **Windows 上目录 fsync 是空操作**；部署目标是 Linux。

## 24. 读取工具 `audit-archive`

`cmd/audit-archive`，逻辑在 `internal/archivecli`。它只读归档目录，不连数据库，不需要 PostgreSQL 也不需要运行中的代理；它不链接任何存储实现和数据库驱动（`TestDependencyGuard` 用 `go list -deps` 守着）。镜像里在 `/audit-archive`，发布构建与 `audit-import` 一起产出。

### 24.1 共同规则

- `--key` 是代理的主密钥文件（`key_path` 的那个 32 字节文件）。归档子密钥由它派生，文件只读、从不创建。密钥不对时报 `key_mismatch`，不报“找不到”；带密钥时索引只收签名核对通过的清单，伪造的清单顶替不了真的修订号。
- 密钥和凭据从不作为命令行的值。
- 查找一律经清单建的索引（`audit_id` → 各修订号，`conversation_id` → 分段），从不按文件名。同一 audit 默认取最高修订号；修订号相同的两份，清单 `created_at_ns` 较晚的优先，再按路径。
- 改名为 `.rejected`、`.orphan` 的文件不被索引。
- 输出到标准输出，诊断写到标准错误，形如 `audit-archive: <码>: <说明>`。

**退出码**：

| 码 | 含义 |
| --- | --- |
| 0 | 完成 |
| 1 | 有核对不过、有包读不了被跳过、有清单被索引剔除（签名或密钥指纹不符、解析不了；`cat`、`export`、`fpr --dir` 照常输出核对通过的部分，再以码 `incomplete` 退出，因为被剔除的包可能装着结果的一部分）、密钥不符，或输出写不出去 |
| 2 | 命令行用法错误 |
| 3 | 找不到；该记录没有这种导出（`not_available`、`not_retained`、`not_ready`、`no_turn_graph`）；`fpr` 没有匹配 |

### 24.2 `list`

~~~text
audit-archive list --dir <archive> [--key <file>] [--conversation <id> | --audit <id>] [--json]
~~~

按清单列出包：种类、协议、时间范围（UTC）、成员数、会话、是否加密、格式版本、清单相对 `--dir` 的路径。不需要密钥；给了 `--key` 时多一列 `AUTH`，标明清单签名是 `ok`、`key_mismatch` 还是 `mac_mismatch`（没给密钥为 `not_checked`）。解析不了的清单报到标准错误。不读数据文件。`--json` 每个包一行 JSON。过滤没有命中时退出码 3。签名不符的包照样列出并在 `AUTH` 里标明，不影响退出码：`list` 是清单盘点，核对由 `verify` 负责。

### 24.3 `verify`

~~~text
audit-archive verify (--dir <archive> | --bundle <manifest>) [--key <file>] [--skip-event-mac] [--json]
~~~

对一个包（`--bundle` 给清单路径）或整个目录核对，每个包一行 `<结果> <级别> <成员数> <清单>`，最后一行汇总。

| 级别 | 条件 | 做什么 |
| --- | --- | --- |
| `files` | 不带 `--key` | 较弱：清单能解析，每个数据文件的大小和 SHA-256 等于清单（§16.1 第 1、3 步）。能发现损坏，发现不了伪造；加密的包不解密 |
| `full` | 带 `--key` | §16 的全部检查，含抄录事件的 MAC（`--skip-event-mac` 只跳过这一项） |

结果码：`ok`；`file_missing`、`file_mismatch`、`manifest_invalid`、`mac_mismatch`、`key_mismatch`、`decrypt_failed`、`decompress_failed`、`line_invalid`、`count_mismatch`、`member_mismatch`、`order`、`context_mismatch`、`digest_mismatch`、`object_mismatch`、`raw_mismatch`、`reference_open`、`event_mac_mismatch`、`read_failed`。用 `--dir` 时，解析不了的清单算一个失败的包；没有清单的数据文件和中断留下的临时文件作为提示写到标准错误，不算失败。全部通过时退出码 0，有失败时 1。

### 24.4 `cat`

~~~text
audit-archive cat --dir <archive> (--key <file> | --unauthenticated) [--conversation <id> | --audit <id>] [--all-revisions] [--with-objects] [--skip-event-mac]
~~~

把解密后的行按归档自己的行格式输出为 JSON Lines（`"type": "audit"` 的行，以及 gap 包的 `"type": "gap"` 行）：明文对话内容，凭据只有投影形式。涉及的每个包都先完整核对（同 `verify --key`）；核对不过的包跳过，原因写到标准错误，它的任何内容都不输出，退出码 1。索引因签名或密钥指纹不符、解析不了而剔除了任何清单时，同样以 1 退出（码 `incomplete`），不论有没有过滤：被剔除的清单不可信，说不清它装着哪些 audit，所以输出可能不全；过滤后什么都没找到时也报 `incomplete` 而不是“找不到”。输出的是核对通过后重新编码的行，与包里存的逐字节相同。

- 不带过滤时输出全部包，含 gap 行；带过滤时只输出匹配的 audit，不含 gap 包。
- 默认每条 audit 只输出最高修订号，`--all-revisions` 全部输出。
- `--with-objects` 在每个包选中的行之后，输出这些行引用的对象文件条目（内容对象、二进制对象、raw 块、拆开的 `parsed_json` 段）。
- `--unauthenticated` 用来不带密钥读**不加密**的包：这时不核对签名。加密的包不带密钥读不了。

### 24.5 `export`

~~~text
audit-archive export --dir <archive> (--key <file> | --unauthenticated) (--audit <id> --what <kind> | --conversation <id>) [--skip-event-mac]
~~~

把一条 audit（最高修订号）导出成单条导出的某一种形态，只用持有它的那个包，先完整核对；JSON 的形状与 Agent 门面的导出相同（[接口合同](25-agent-access-contract.md)）：

| `--what` | 输出 |
| --- | --- |
| `conversation`（默认） | 这条记录的会话 |
| `headers` | `{"audit_id", "headers": [...]}`：四个阶段的全部 Header 和 Trailer，凭据项是 `value_omitted`、`length`、`value_fpr` |
| `request`、`response` | 由轮次重建的 provider 请求或响应（核对重建哈希） |
| `raw-request`、`raw-response` | raw Body 的原始字节（只有归档里是 `full` 的才有），元数据写到标准错误 |
| `timeline-request`、`timeline-response` | 流式时间线 |
| `detail` | 整条记录的详情，Request-URI、Header 和 User-Agent 是投影形式（门面没有这一种） |

`--conversation` 按会话导出：这个会话在全部包里的每条 audit（各取最高修订号），按（`created_at_ns`，`audit_id`）排序，每行一个 `{"audit_id", "turn_id", "created_at_ns", "conversation"}`。不在归档里或没有这种导出时退出码 3。索引剔除了任何清单时，导出照常写出，然后以 1 退出（码 `incomplete`）：被剔除的包可能装着这条 audit 更高的修订号，或这个会话的更多轮次。

门面的 JSON 形状是在 `internal/archivecli` 里照着重新声明的（引入 `internal/web` 会让工具链接存储），两边可能走样；运行时的抽样比对用的正是这套渲染。

### 24.6 `fpr`

~~~text
audit-archive fpr --key <file> [--known-key-file <file>] [--dir <archive> [--conversation <id> | --audit <id>]] [--skip-event-mac]
~~~

读入一个已知的 API Key，每行输出一个候选指纹 `<形式> <十六进制>`：`raw`、`bearer`、`api_key_fpr`（§12.4）。Key 从 `--known-key-file`（第一行）或标准输入读：标准输入是终端时不回显地读（`internal/termio`，与 `llmaudit` 共用），否则读第一行。Key 从不作为命令行的值，也从不输出。指纹以主密钥为键，没有它什么也看不出来。

带 `--dir` 时在全部核对通过的包里（全部修订号，或只在给定的会话、audit 里）查找，每个匹配一行 `match <audit_id> revision <n> <位置> <形式>`，位置是 `header <stage> <kind> <name>`、`user_agent`、`request_uri <name>` 或 `api_key_fpr`。给了 `--dir` 而没有匹配时退出码 3；有包被跳过或有清单被索引剔除时退出码 1（被剔除的包里可能有匹配）。

### 24.7 测试

归档的测试分布见[模块 14](14-test-benchmark-and-fault-injection.md) §10。
