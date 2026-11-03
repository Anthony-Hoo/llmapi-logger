import { useEffect, useState, type FormEvent } from "react";

import { ApiError, type ApiClient } from "../api";
import { errorMessage, isAbortError } from "../lib/errors";
import { cn } from "../lib/utils";
import type { ContentPolicyRule, ContentPolicyRuleInput } from "../types";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { controlClassName, Input } from "./ui/input";
import { PageHeader } from "./ui/page-header";
import { Select } from "./ui/select";
import { Skeleton } from "./ui/skeleton";
import { emptyStateClassName } from "./ui/styles";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

/** Mirrors contentpolicy.AllScanScopes / MaxNameBytes and friends in Go. */
export const ALL_SCAN_SCOPES = [
  { value: "system", label: "系统提示（system / instructions）", short: "系统" },
  { value: "latest_user", label: "最后一条用户消息", short: "最新用户" },
  { value: "user_history", label: "更早的用户消息", short: "历史用户" },
  { value: "assistant", label: "助手历史文本与推理", short: "助手" },
  { value: "tool_calls", label: "历史工具调用", short: "工具调用" },
  { value: "tool_results", label: "工具返回内容", short: "工具结果" },
  { value: "tool_definitions", label: "工具定义 / 函数 schema", short: "工具定义" },
] as const;

export const CONTENT_POLICY_ACTIONS = [
  { value: "block", label: "拦截（本地返回 HTTP 400）" },
  { value: "dry_run", label: "仅记录（继续转发）" },
] as const;

export const MAX_CONTENT_POLICY_NAME_CHARS = 128;
export const MAX_CONTENT_POLICY_MODEL_PATTERN_CHARS = 2048;
export const MAX_CONTENT_POLICY_KEYWORDS = 500;
/** The Go service bounds one keyword by 200 UTF-8 bytes, not characters. */
export const MAX_CONTENT_POLICY_KEYWORD_BYTES = 200;

interface ContentPolicyDraft {
  name: string;
  enabled: boolean;
  action: string;
  model_pattern: string;
  scan_scopes: string[];
  keywordsText: string;
}

function defaultScanScopes(): string[] {
  return ALL_SCAN_SCOPES.map((scope) => scope.value);
}

const emptyDraft: ContentPolicyDraft = {
  name: "",
  enabled: true,
  action: "block",
  model_pattern: "",
  scan_scopes: defaultScanScopes(),
  keywordsText: "",
};

function scopeShortLabel(scope: string): string {
  return ALL_SCAN_SCOPES.find((option) => option.value === scope)?.short ?? scope;
}

function scanScopeSummary(rule: ContentPolicyRule): string {
  if (rule.scan_scopes.length === ALL_SCAN_SCOPES.length) {
    return "全部 7 类";
  }
  return rule.scan_scopes.map(scopeShortLabel).join("、") || "未设置";
}

/** parseKeywordLines splits the textarea into trimmed, non-empty keywords. */
export function parseKeywordLines(text: string): { keywords: string[]; error: string | null } {
  const keywords = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  if (keywords.length === 0) {
    return { keywords: [], error: "至少填写一个关键词" };
  }
  if (keywords.length > MAX_CONTENT_POLICY_KEYWORDS) {
    return { keywords, error: `关键词最多 ${MAX_CONTENT_POLICY_KEYWORDS} 条` };
  }
  const encoder = new TextEncoder();
  const tooLong = keywords.find((keyword) => encoder.encode(keyword).length > MAX_CONTENT_POLICY_KEYWORD_BYTES);
  if (tooLong !== undefined) {
    return {
      keywords,
      error: `关键词“${tooLong.slice(0, 12)}${tooLong.length > 12 ? "…" : ""}”超过 ${MAX_CONTENT_POLICY_KEYWORD_BYTES} 字节（中文约 ${Math.floor(MAX_CONTENT_POLICY_KEYWORD_BYTES / 3)} 个字符）`,
    };
  }
  return { keywords, error: null };
}

export function ContentPolicyPanel({ client }: { client: ApiClient }) {
  const [rules, setRules] = useState<ContentPolicyRule[]>([]);
  const [draft, setDraft] = useState<ContentPolicyDraft>(emptyDraft);
  const [editingID, setEditingID] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [keywordError, setKeywordError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    client
      .listContentPolicyRules(controller.signal)
      .then((result) => setRules(result.items))
      .catch((cause: unknown) => {
        if (!isAbortError(cause) && !(cause instanceof ApiError && cause.status === 401)) {
          setError(errorMessage(cause));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      });
    return () => controller.abort();
  }, [client, reloadKey]);

  function edit(rule: ContentPolicyRule) {
    setEditingID(rule.id);
    setDraft({
      name: rule.name,
      enabled: rule.enabled,
      action: rule.action,
      model_pattern: rule.model_pattern,
      scan_scopes: rule.scan_scopes.length > 0 ? [...rule.scan_scopes] : defaultScanScopes(),
      keywordsText: rule.keywords.join("\n"),
    });
    setError(null);
    setNotice(null);
    setKeywordError(null);
  }

  function resetForm() {
    setEditingID(null);
    setDraft(emptyDraft);
    setKeywordError(null);
  }

  function toggleScope(scope: string, checked: boolean) {
    setDraft((current) => ({
      ...current,
      scan_scopes: checked
        ? [...current.scan_scopes, scope]
        : current.scan_scopes.filter((value) => value !== scope),
    }));
  }

  function buildInput(current: ContentPolicyDraft): ContentPolicyRuleInput | null {
    const parsed = parseKeywordLines(current.keywordsText);
    setKeywordError(parsed.error);
    if (parsed.error) {
      return null;
    }
    if (current.scan_scopes.length === 0) {
      setKeywordError("至少选择一个扫描范围");
      return null;
    }
    return {
      name: current.name.trim(),
      enabled: current.enabled,
      action: current.action,
      model_pattern: current.model_pattern.trim(),
      scan_scopes: current.scan_scopes,
      keywords: parsed.keywords,
    };
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving) {
      return;
    }
    const input = buildInput(draft);
    if (!input) {
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      if (editingID === null) {
        await client.createContentPolicyRule(input);
        setNotice("规则已创建并立即生效。");
      } else {
        await client.updateContentPolicyRule(editingID, input);
        setNotice("规则已保存并立即生效。");
      }
      resetForm();
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setSaving(false);
    }
  }

  async function toggle(rule: ContentPolicyRule) {
    setError(null);
    setNotice(null);
    try {
      await client.updateContentPolicyRule(rule.id, {
        name: rule.name,
        enabled: !rule.enabled,
        action: rule.action,
        model_pattern: rule.model_pattern,
        scan_scopes: rule.scan_scopes,
        keywords: rule.keywords,
      });
      setNotice(rule.enabled ? "规则已停用。" : "规则已启用并立即生效。");
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  async function remove(rule: ContentPolicyRule) {
    if (!window.confirm(`确认删除关键词规则“${rule.name}”？删除后立即停止拦截。`)) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await client.deleteContentPolicyRule(rule.id);
      if (editingID === rule.id) {
        resetForm();
      }
      setNotice("规则已删除。");
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  const canSave =
    !saving &&
    draft.name.trim() !== "" &&
    draft.keywordsText.trim() !== "" &&
    draft.scan_scopes.length > 0 &&
    keywordError === null;

  return (
    <div className="space-y-section">
      <PageHeader
        title="关键词拦截"
        description="按模型范围和关键词扫描请求正文，命中后在访问 NewAPI 之前本地拒绝；扫描范围可逐条规则收窄。"
      />
      <Card>
        <CardHeader>
          <CardTitle>{editingID === null ? "新增规则" : "编辑规则"}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-stack">
          <Alert variant="info">
            <AlertTitle>先了解误报风险</AlertTitle>
            <AlertDescription>
              <ul className="list-disc space-y-1 pl-4">
                <li>默认扫描全部 7 类内容（system、用户消息、助手文本、工具调用与结果、工具定义）。范围越大越可能误报，例如工具 schema 或历史文本里出现同名关键词。</li>
                <li>不确定时建议先把动作设为“仅记录”（dry_run）：命中只写进程日志、请求继续转发；确认关键词可靠后再改为“拦截”。</li>
                <li>关键词是大小写不敏感的字面量子串，不是正则；模型正则为 Go RE2 语法，留空表示全部模型。保存后立即生效，无效规则会被拒绝且当前规则保持不变。</li>
              </ul>
            </AlertDescription>
          </Alert>
          {error ? (
            <Alert variant="danger">
              <AlertTitle>操作失败</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {notice ? (
            <Alert variant="success">
              <AlertDescription>{notice}</AlertDescription>
            </Alert>
          ) : null}
          <form className="space-y-stack" onSubmit={save}>
            <div className="grid gap-3 lg:grid-cols-2">
              <label htmlFor="content-policy-name" className="min-w-0 space-y-1">
                <span className="block text-label font-medium text-muted">规则名称</span>
                <Input
                  id="content-policy-name"
                  value={draft.name}
                  onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))}
                  maxLength={MAX_CONTENT_POLICY_NAME_CHARS}
                  required
                  placeholder="例如：拦截 cyber 高风险提问"
                />
              </label>
              <label htmlFor="content-policy-action" className="min-w-0 space-y-1">
                <span className="block text-label font-medium text-muted">命中动作</span>
                <Select
                  id="content-policy-action"
                  value={draft.action}
                  onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))}
                >
                  {CONTENT_POLICY_ACTIONS.map((action) => (
                    <option key={action.value} value={action.value}>
                      {action.label}
                    </option>
                  ))}
                </Select>
              </label>
            </div>
            <label htmlFor="content-policy-model-pattern" className="min-w-0 space-y-1">
              <span className="block text-label font-medium text-muted">模型正则（可选）</span>
              <Input
                id="content-policy-model-pattern"
                className="font-mono"
                value={draft.model_pattern}
                onChange={(event) => setDraft((current) => ({ ...current, model_pattern: event.target.value }))}
                maxLength={MAX_CONTENT_POLICY_MODEL_PATTERN_CHARS}
                placeholder="留空表示全部模型，例如 ^gpt"
              />
            </label>
            <fieldset className="space-y-2">
              <legend className="text-label font-medium text-muted">扫描范围（默认全选）</legend>
              <div className="grid gap-2 rounded-md border bg-surface-muted p-3 sm:grid-cols-2 lg:grid-cols-4">
                {ALL_SCAN_SCOPES.map((scope) => (
                  <label key={scope.value} className="flex items-center gap-2 text-body">
                    <input
                      className="accent-primary"
                      type="checkbox"
                      checked={draft.scan_scopes.includes(scope.value)}
                      onChange={(event) => toggleScope(scope.value, event.target.checked)}
                    />
                    {scope.label}
                  </label>
                ))}
              </div>
              {draft.scan_scopes.length === 0 ? (
                <p role="alert" className="text-label text-danger-fg">至少选择一个扫描范围。</p>
              ) : null}
            </fieldset>
            <label htmlFor="content-policy-keywords" className="min-w-0 space-y-1">
              <span className="block text-label font-medium text-muted">
                关键词（每行一个，最多 {MAX_CONTENT_POLICY_KEYWORDS} 条，每条 ≤ {MAX_CONTENT_POLICY_KEYWORD_BYTES} 字节）
              </span>
              <textarea
                id="content-policy-keywords"
                className={cn(controlClassName, "h-auto min-h-32 py-2 font-mono text-label")}
                value={draft.keywordsText}
                onChange={(event) => {
                  setKeywordError(null);
                  setDraft((current) => ({ ...current, keywordsText: event.target.value }));
                }}
                rows={8}
                required
                placeholder={"cybersecurity risk\nhigh-risk cyber activity\n制作勒索软件"}
              />
              <span className="block text-caption text-subtle">
                大小写不敏感、连续子串匹配；中文按 UTF-8 字节计数，约每 66 个汉字达到 200 字节上限。
              </span>
              {keywordError ? <p role="alert" className="text-label text-danger-fg">{keywordError}</p> : null}
            </label>
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex h-9 items-center gap-2 rounded-md border border-border-strong bg-surface px-3 text-body shadow-xs">
                <input
                  className="accent-primary"
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))}
                />
                启用
              </label>
              <Button type="submit" disabled={!canSave}>
                {saving ? "保存中…" : editingID === null ? "新增规则" : "保存修改"}
              </Button>
              {editingID !== null ? (
                <Button variant="outline" onClick={resetForm}>取消</Button>
              ) : null}
              {!canSave && !saving ? (
                <span className="text-caption text-subtle">填写名称与至少一个关键词后即可保存。</span>
              ) : null}
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <PageHeader
            level="panel"
            as="h2"
            title="当前关键词规则"
            description={`${rules.length} 条 · 启用的规则即时参与请求判断`}
            actions={<Button variant="outline" size="sm" onClick={() => setReloadKey((value) => value + 1)} disabled={loading}>刷新</Button>}
          />
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-32 w-full" />
          ) : rules.length === 0 ? (
            <div className={emptyStateClassName}>当前没有关键词规则；空规则表等于不拦截。</div>
          ) : (
            <div className="overflow-x-auto rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>状态</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead>模型正则</TableHead>
                    <TableHead>扫描范围</TableHead>
                    <TableHead>关键词</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell><Badge variant={rule.enabled ? "success" : "outline"}>{rule.enabled ? "启用" : "停用"}</Badge></TableCell>
                      <TableCell className="font-medium">{rule.name}</TableCell>
                      <TableCell>
                        <Badge variant={rule.action === "block" ? "danger" : "warning"}>
                          {rule.action === "block" ? "拦截" : rule.action === "dry_run" ? "仅记录" : rule.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-label">{rule.model_pattern || "全部模型"}</TableCell>
                      <TableCell className="text-label" title={rule.scan_scopes.join(", ")}>{scanScopeSummary(rule)}</TableCell>
                      <TableCell className="text-label">{rule.keywords.length} 条</TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" size="sm" onClick={() => edit(rule)}>编辑</Button>
                          <Button variant="outline" size="sm" onClick={() => void toggle(rule)}>{rule.enabled ? "停用" : "启用"}</Button>
                          <Button variant="danger" size="sm" onClick={() => void remove(rule)}>删除</Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
