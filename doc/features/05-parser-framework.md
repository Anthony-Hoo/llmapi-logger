# 模块 05：协议解析框架

## 1. 目标与边界

解析器把已经落盘的请求和响应证据转换为便于查询的派生结果。

硬性边界：

- parser 完全异步，不进入 HTTP 转发链。
- parser 只处理明确 LLM API 白名单产生且未被 interceptor 拒绝的 audit；Nginx 直连 NewAPI 的其他路径没有 audit 输入。
- 原始 Header、Body、chunk、长度和哈希始终是权威证据。
- JSON/SSE 解析失败只更新 `parse_status`，不影响转发结果和原始证据。
- 首版只支持 OpenAI、Anthropic Messages 和 Gemini GenerateContent。
- 不推断 NewAPI 后方渠道、厂商请求、厂商响应或重试。

## 2. 精简结构

阶段 3 的最小范围都放在 `internal/parser`：公共接口、JSON/SSE 解码、一个内存队列、一个 worker，以及三个协议的少量实现文件。只有单个文件明显过大时才拆子包，不预先建立插件系统或持久化任务系统。

`proxy`、`audit` 和证据采集不依赖 parser。parser 只读取已经落盘的证据，通过存储接口更新 `parsed_results` 和 `parse_status`。

## 3. 接口与公共输出

```go
type Parser interface {
    Name() string
    Version() string
    Parse(ctx context.Context, in Input) Result
}

type Input struct { AuditID, Protocol, Endpoint string; Request, Response BodySource }

type Result struct {
    Status          string // ok、partial、error、skipped
    RequestModel    string
    ResponseModel   string
    RequestedStream *bool
    ObservedStream  *bool
    ResponseID      string
    Usage           Usage
    ErrorType       string
    ErrorCode       string
    MessageCount    *int
    ToolCallCount   *int
    HasToolCall     *bool
    ParsedJSON      []byte // 只保存紧凑摘要，加密后落盘
}
```

公共查询字段只包含模型、流式标志、response ID、usage、错误类型/代码、消息数量和工具调用数量。阶段 3 的 `parsed_json` 也只保存这些字段的紧凑摘要，不保存或重建完整消息正文、输出全文、思维内容、工具参数和事件时间线。

## 4. 三协议最小解析范围

- OpenAI 兼容接口：常见 JSON 与 SSE，提取 model、stream、response ID、usage、错误摘要和消息/工具调用计数。
- Anthropic Messages：常见 JSON 与 SSE，提取 model、stream、message ID、usage、错误摘要和内容块/工具调用计数。
- Gemini GenerateContent：常见 JSON 与 SSE，提取请求模型、usage、错误摘要和候选/函数调用计数。

未知字段和未知 SSE event 可以忽略。事件缺失、字段形态变化或流中途截断时，只保存仍可信的字段并标记 `partial`；没有可信摘要时标记 `error`。协议细节见模块 06–08，但阶段 3 不追求完整供应商对象映射。

## 5. 队列与 worker

- 使用一个容量约 100 的 Go channel。
- 固定启动 1 个 worker；个人单机首版不提供并发调优项。
- 非 rejected audit 完成落盘后，把 `audit_id` 尝试放入队列；rejected 已是 `parse_status=skipped`，不得入队。
- 队列满时不阻塞转发，只保留 `audit_records.parse_status=pending`，由后台扫描稍后重试。
- 进程启动时扫描 `parse_status=pending` 的记录并重新入队。
- 启动时可把上次异常退出留下的 `processing` 重置为 `pending`。
- 调度状态只保存在 `audit_records.parse_status`，不另建持久化任务或历史表。
- 阶段 3 不提供 reparse 管理端点。自动恢复只处理正常产生的 pending/processing 记录；人工重跑可以留给以后需要时再设计。

## 6. 证据读取

转发链最多产生四个 canonical HTTP 阶段：

1. `request_for_newapi_received_from_nginx`
2. `request_sent_to_newapi`
3. `response_received_from_newapi`
4. `response_from_newapi_sent_to_nginx`

parser 的最小范围读取第一阶段请求 Body 和第三阶段响应 Body。阶段行按实际触发存在，不能把缺失行当成空 Body；rejected audit 不进入 parser。

Body 由 `body_streams` 和按序排列的 `body_chunks` 重建。缺块、顺序错误或解密失败返回 `capture_integrity_error`，结果记为 `error` 或 `partial`，不得跳过坏块拼接。

## 7. parsed_results

每个 audit 最多一行：

```text
audit_id PK; parser_name; parser_version; status
request_model; response_model; requested_stream; observed_stream; response_id
usage_input; usage_output; usage_total; error_type; error_code
message_count; tool_call_count; has_tool_call; parsed_json_enc; parsed_at_ns
```

`parsed_json_enc` 使用安全模块固定的 `nonce || ciphertext || tag` BLOB。更新 `parsed_results` 与 `audit_records.parse_status` 应在同一 SQLite writer 事务中完成。

模型筛选同时匹配 `request_model` 和 `response_model`；列表展示优先 `response_model`，为空时回退 `request_model`。

## 8. JSON、SSE 与限额

- 请求侧解码后最多读取 16 MiB。
- 响应侧解码后最多读取 16 MiB。
- gzip 最大解压比为 50:1。
- 超限时停止继续解析，已有可信字段可保存为 `partial`；没有可信结果则为 `error`。
- JSON 使用 decoder 和 `UseNumber`，未知字段直接忽略。
- SSE reader 支持 LF/CRLF、跨 chunk 行、多条 `data:` 和正常 EOF。
- parser 可以在固定 16 MiB 上限内重建一次待解析 Body；超过上限立即停止，不实现面向任意大 Body 的全文重建。
- parser 不修改、重新编码或覆盖原始证据。

## 9. 状态与错误

`audit_records.parse_status` 使用：

- `pending`：等待入队。
- `processing`：worker 正在解析。
- `ok`：核心字段解析完成。
- `partial`：证据截断、个别事件错误或达到限额。
- `error`：无法得到可信协议结果。
- `skipped`：interceptor 已拒绝、无 Body、未注册协议或不支持的编码；rejected 的 skipped 由审计终态直接写入，不调用 parser。

worker 必须 recover parser panic，并把 `parser_panic` 等稳定值写入 `error_code`。错误文本不得包含 Body、Header value、工具参数或密钥。

## 10. 最少测试

- audit 完成后异步解析，证明 HTTP 响应不等待 parser。
- 队列满时转发不阻塞，pending 记录能被扫描补入队。
- 进程重启后 pending/processing 记录能继续解析。
- JSON 未知字段、畸形 JSON、畸形 SSE、gzip 损坏和 16 MiB/50:1 限额。
- OpenAI、Anthropic 和 Gemini 的常见 JSON/SSE 样例可生成最小摘要，畸形或截断输入得到 partial/error。
- rejected audit 保持 skipped，不进入启动扫描或周期扫描，且不创建 `parsed_results`。
- 敏感 canary 不出现在 SQLite/WAL、日志和普通查询字段中。

## 11. 实施任务

1. 定义 Parser、Input、Result 和 `parsed_results` migration。
2. 实现容量 100 的队列、单 worker、启动扫描和每 30 秒 pending 补扫。
3. 实现证据 reader、gzip 限额、JSON decoder 和通用 SSE reader。
4. 接入三个协议的最小 JSON/SSE parser，并加密保存紧凑 `parsed_json`。
5. 完成队列、重启、错误隔离和敏感数据测试。
