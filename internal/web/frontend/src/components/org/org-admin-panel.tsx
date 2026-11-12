import { useEffect, useState, type FormEvent } from "react";

import { ApiError, type ApiClient } from "../../api";
import { errorMessage, isAbortError } from "../../lib/errors";
import {
  draftFromUnattributed,
  MAX_RULES_PER_PROJECT,
  RULE_KINDS,
  ruleKindLabel,
  ruleSummary,
  scopeLabel,
  validateRules,
} from "../../lib/org/format";
import type {
  OrgCatalog,
  OrgPreviewResult,
  OrgProject,
  OrgRule,
  OrgUnattributedEntry,
  PrincipalClass,
  PrincipalKind,
  RuleKind,
} from "../../lib/org/types";
import type { NewAPIUser } from "../../types";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Input } from "../ui/input";
import { PageHeader } from "../ui/page-header";
import { Select } from "../ui/select";
import { Skeleton } from "../ui/skeleton";
import { emptyStateClassName } from "../ui/styles";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";

interface ProjectDraft {
  name: string;
  groupID: string; // "" = global
  enabled: boolean;
  rules: OrgRule[];
}

const emptyProject: ProjectDraft = { name: "", groupID: "", enabled: true, rules: [{ kind: "repo_url", pattern: "" }] };

function userLabel(users: NewAPIUser[], id: number): string {
  const user = users.find((candidate) => candidate.id === id);
  return user ? `${user.display_name || user.username} (#${id})` : `#${id}`;
}

/** Settings section "项目组与项目" of the administrator's "系统配置" menu (doc/features/23 section 8). */
export function OrgAdminPanel({ client }: { client: ApiClient }) {
  const [catalog, setCatalog] = useState<OrgCatalog | null>(null);
  const [users, setUsers] = useState<NewAPIUser[]>([]);
  const [unattributed, setUnattributed] = useState<OrgUnattributedEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [busy, setBusy] = useState(false);

  const [groupName, setGroupName] = useState("");
  const [editingGroup, setEditingGroup] = useState<number | null>(null);
  const [groupEnabled, setGroupEnabled] = useState(true);

  const [project, setProject] = useState<ProjectDraft>(emptyProject);
  const [editingProject, setEditingProject] = useState<number | null>(null);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [preview, setPreview] = useState<OrgPreviewResult | null>(null);

  const [memberUser, setMemberUser] = useState("");
  const [memberGroup, setMemberGroup] = useState("");
  const [principalKind, setPrincipalKind] = useState<PrincipalKind>("user");
  const [principalID, setPrincipalID] = useState("");
  const [principalClass, setPrincipalClass] = useState<PrincipalClass>("service");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    Promise.all([
      client.org.catalog(controller.signal),
      client.listNewAPICallers(controller.signal).catch(() => ({ items: [] as NewAPIUser[], refreshed_at: null })),
      client.org.unattributed(undefined, 20, controller.signal).catch(() => ({ items: [] as OrgUnattributedEntry[] })),
    ])
      .then(([loaded, callers, top]) => {
        setCatalog(loaded);
        setUsers(callers.items);
        setUnattributed(top.items);
      })
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

  async function run(action: () => Promise<unknown>, success: string) {
    if (busy) {
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(success);
      setReloadKey((value) => value + 1);
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    } finally {
      setBusy(false);
    }
  }

  function saveGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = { name: groupName.trim(), enabled: groupEnabled };
    void run(
      () => (editingGroup === null ? client.org.createGroup(input) : client.org.updateGroup(editingGroup, input)),
      editingGroup === null ? "项目组已创建。" : "项目组已保存。",
    ).then(() => {
      setEditingGroup(null);
      setGroupName("");
      setGroupEnabled(true);
    });
  }

  function editProject(item: OrgProject) {
    setEditingProject(item.id);
    setProject({ name: item.name, groupID: item.group_id === null ? "" : String(item.group_id), enabled: item.enabled, rules: item.rules.map((rule) => ({ ...rule })) });
    setPreview(null);
    setRuleError(null);
  }

  function resetProject() {
    setEditingProject(null);
    setProject(emptyProject);
    setPreview(null);
    setRuleError(null);
  }

  function projectInput() {
    const rules = project.rules.map((rule) => ({ kind: rule.kind, pattern: rule.pattern.trim() }));
    const problem = validateRules(rules);
    setRuleError(problem);
    if (problem) {
      return null;
    }
    return { name: project.name.trim(), group_id: project.groupID === "" ? null : Number(project.groupID), enabled: project.enabled, rules };
  }

  function saveProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = projectInput();
    if (!input) {
      return;
    }
    void run(
      () => (editingProject === null ? client.org.createProject(input) : client.org.updateProject(editingProject, input)),
      "项目已保存；未冻结的周立即按新规则重新归属。",
    ).then(resetProject);
  }

  async function runPreview() {
    const input = projectInput();
    if (!input || input.rules.length === 0) {
      return;
    }
    setError(null);
    try {
      setPreview(await client.org.preview({ group_id: input.group_id, rules: input.rules, project_id: editingProject ?? undefined }));
    } catch (cause: unknown) {
      if (!(cause instanceof ApiError && cause.status === 401)) {
        setError(errorMessage(cause));
      }
    }
  }

  function updateRule(index: number, change: Partial<OrgRule>) {
    setProject((current) => ({ ...current, rules: current.rules.map((rule, position) => (position === index ? { ...rule, ...change } : rule)) }));
    setPreview(null);
  }

  function applyDraft(entry: OrgUnattributedEntry) {
    const draft = draftFromUnattributed(entry);
    setEditingProject(null);
    setProject({ ...emptyProject, name: draft.name, rules: draft.rules });
    setPreview(null);
    setNotice("已根据未归属条目生成项目草稿，确认名称与范围后保存。");
  }

  if (loading && !catalog) {
    return <Skeleton className="h-64 w-full" />;
  }
  const groups = catalog?.groups ?? [];

  return (
    <div className="space-y-section">
      <PageHeader title="项目组与项目" description="按 NewAPI 用户分组，配置统一项目与组内项目，规则按指纹解密后匹配，不保存明文路径。" />
      {error ? (
        <Alert variant="danger">
          <AlertTitle>操作失败</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert variant="info">
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {catalog && catalog.service_candidates.length > 0 ? (
        <Alert variant="warning">
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span>NewAPI 管理员账号 {catalog.service_candidates.map((id) => userLabel(users, id)).join("、")} 尚未分类，建议标为服务/系统主体。</span>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(() => Promise.all(catalog.service_candidates.map((id) => client.org.setPrincipal("user", id, "service"))), "已标为服务主体。")}>
              标为服务
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-section xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>项目组</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <form className="flex flex-wrap items-end gap-2" onSubmit={saveGroup}>
              <Input aria-label="项目组名称" placeholder="项目组名称" value={groupName} maxLength={128} required onChange={(event) => setGroupName(event.target.value)} className="min-w-0 flex-1" />
              <label className="flex items-center gap-1 text-body-sm">
                <input type="checkbox" checked={groupEnabled} onChange={(event) => setGroupEnabled(event.target.checked)} /> 启用
              </label>
              <Button type="submit" size="sm" disabled={busy}>
                {editingGroup === null ? "新增" : "保存"}
              </Button>
              {editingGroup !== null ? (
                <Button size="sm" variant="ghost" onClick={() => { setEditingGroup(null); setGroupName(""); }}>
                  取消
                </Button>
              ) : null}
            </form>
            {groups.length === 0 ? (
              <p className={emptyStateClassName}>还没有项目组。</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>名称</TableHead>
                    <TableHead>成员</TableHead>
                    <TableHead>项目</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {groups.map((group) => (
                    <TableRow key={group.id}>
                      <TableCell>
                        {group.name} {group.enabled ? null : <Badge variant="outline">停用</Badge>}
                      </TableCell>
                      <TableCell>{catalog?.members.filter((member) => member.group_id === group.id).length ?? 0}</TableCell>
                      <TableCell>{catalog?.projects.filter((item) => item.group_id === group.id).length ?? 0}</TableCell>
                      <TableCell className="space-x-1 text-right">
                        <Button size="sm" variant="ghost" onClick={() => { setEditingGroup(group.id); setGroupName(group.name); setGroupEnabled(group.enabled); }}>
                          编辑
                        </Button>
                        <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(() => client.org.deleteGroup(group.id), "项目组已删除。")}>
                          删除
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>成员与主体分类</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => client.org.setMember(Number(memberUser), Number(memberGroup)), "成员已保存（每人只属于一个组）。");
              }}
            >
              <Select aria-label="NewAPI 用户" value={memberUser} required onChange={(event) => setMemberUser(event.target.value)} className="min-w-0 flex-1">
                <option value="">选择用户</option>
                {users.map((user) => (
                  <option key={user.id} value={user.id}>
                    {userLabel(users, user.id)}
                  </option>
                ))}
              </Select>
              <Select aria-label="项目组" value={memberGroup} required onChange={(event) => setMemberGroup(event.target.value)}>
                <option value="">选择组</option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))}
              </Select>
              <Button type="submit" size="sm" disabled={busy}>
                加入
              </Button>
            </form>
            {(catalog?.members.length ?? 0) > 0 ? (
              <ul className="space-y-1 text-body-sm">
                {catalog?.members.map((member) => (
                  <li key={member.user_id} className="flex items-center justify-between gap-2">
                    <span>
                      {userLabel(users, member.user_id)} → {groups.find((group) => group.id === member.group_id)?.name ?? `#${member.group_id}`}
                    </span>
                    <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(() => client.org.deleteMember(member.user_id), "已移出项目组。")}>
                      移出
                    </Button>
                  </li>
                ))}
              </ul>
            ) : null}
            <form
              className="flex flex-wrap items-end gap-2 border-t pt-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => client.org.setPrincipal(principalKind, Number(principalID), principalClass), "主体分类已保存。");
              }}
            >
              <Select aria-label="主体类型" value={principalKind} onChange={(event) => setPrincipalKind(event.target.value as PrincipalKind)}>
                <option value="user">用户 ID</option>
                <option value="token">Token ID</option>
              </Select>
              <Input aria-label="主体 ID" inputMode="numeric" pattern="[0-9]+" required placeholder="ID" value={principalID} onChange={(event) => setPrincipalID(event.target.value)} className="w-28" />
              <Select aria-label="分类" value={principalClass} onChange={(event) => setPrincipalClass(event.target.value as PrincipalClass)}>
                <option value="service">服务/系统</option>
                <option value="human">员工</option>
              </Select>
              <Button type="submit" size="sm" disabled={busy}>
                保存分类
              </Button>
            </form>
            {(catalog?.principals.length ?? 0) > 0 ? (
              <ul className="space-y-1 text-body-sm">
                {catalog?.principals.map((principal) => (
                  <li key={`${principal.kind}-${principal.id}`} className="flex items-center justify-between gap-2">
                    <span>
                      {principal.kind === "user" ? `用户 ${userLabel(users, principal.id)}` : `Token #${principal.id}`}{" "}
                      <Badge variant={principal.class === "service" ? "warning" : "neutral"}>{principal.class === "service" ? "服务" : "员工"}</Badge>
                    </span>
                    <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(() => client.org.deletePrincipal(principal.kind, principal.id), "分类已移除。")}>
                      移除
                    </Button>
                  </li>
                ))}
              </ul>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{editingProject === null ? "新增项目" : "编辑项目"}</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="space-y-3" onSubmit={saveProject}>
            <div className="flex flex-wrap items-end gap-2">
              <Input aria-label="项目名称" placeholder="项目名称" required maxLength={128} value={project.name} onChange={(event) => setProject((current) => ({ ...current, name: event.target.value }))} className="min-w-0 flex-1" />
              <Select aria-label="项目范围" value={project.groupID} onChange={(event) => setProject((current) => ({ ...current, groupID: event.target.value }))}>
                <option value="">全员统一项目</option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    组内：{group.name}
                  </option>
                ))}
              </Select>
              <label className="flex items-center gap-1 text-body-sm">
                <input type="checkbox" checked={project.enabled} onChange={(event) => setProject((current) => ({ ...current, enabled: event.target.checked }))} /> 启用
              </label>
            </div>
            {project.rules.map((rule, index) => (
              <div key={index} className="flex flex-wrap items-center gap-2">
                <Select aria-label={`规则 ${index + 1} 类型`} value={rule.kind} onChange={(event) => updateRule(index, { kind: event.target.value as RuleKind })}>
                  {RULE_KINDS.map((kind) => (
                    <option key={kind.value} value={kind.value}>
                      {kind.label}
                    </option>
                  ))}
                </Select>
                <Input
                  aria-label={`规则 ${index + 1} 内容`}
                  value={rule.pattern}
                  maxLength={512}
                  placeholder={RULE_KINDS.find((kind) => kind.value === rule.kind)?.placeholder}
                  onChange={(event) => updateRule(index, { pattern: event.target.value })}
                  className="min-w-0 flex-1 font-mono"
                />
                <Button size="sm" variant="ghost" onClick={() => setProject((current) => ({ ...current, rules: current.rules.filter((_, position) => position !== index) }))}>
                  删除
                </Button>
              </div>
            ))}
            {ruleError ? <p className="text-body-sm text-danger-fg">{ruleError}</p> : null}
            {preview ? (
              <Alert variant="info">
                <AlertDescription>
                  本周命中 {preview.requests} 次请求、{preview.identities} 个不同来源、{preview.users} 位用户；其中 {preview.from_unattributed} 次原本未归属，{preview.from_other_projects} 次原本属于其他项目。
                </AlertDescription>
              </Alert>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={project.rules.length >= MAX_RULES_PER_PROJECT}
                onClick={() => setProject((current) => ({ ...current, rules: [...current.rules, { kind: "repo_name", pattern: "" }] }))}
              >
                添加规则
              </Button>
              <Button size="sm" variant="outline" onClick={() => void runPreview()}>
                预览命中
              </Button>
              <Button type="submit" size="sm" disabled={busy}>
                保存项目
              </Button>
              {editingProject !== null ? (
                <Button size="sm" variant="ghost" onClick={resetProject}>
                  取消
                </Button>
              ) : null}
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>项目列表</CardTitle>
        </CardHeader>
        <CardContent>
          {(catalog?.projects.length ?? 0) === 0 ? (
            <p className={emptyStateClassName}>还没有项目。先从下方“未归属 Top N”生成规则草稿。</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>项目</TableHead>
                  <TableHead>范围</TableHead>
                  <TableHead>规则</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {catalog?.projects.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      {item.name} {item.enabled ? null : <Badge variant="outline">停用</Badge>}
                    </TableCell>
                    <TableCell>{scopeLabel(item, groups)}</TableCell>
                    <TableCell className="max-w-md truncate font-mono text-label" title={ruleSummary(item.rules)}>
                      {ruleSummary(item.rules)}
                    </TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button size="sm" variant="ghost" onClick={() => editProject(item)}>
                        编辑
                      </Button>
                      <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(() => client.org.deleteProject(item.id), "项目已删除；已冻结的周保留原名称。")}>
                        删除
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>本周未归属 Top 20</CardTitle>
        </CardHeader>
        <CardContent>
          {unattributed.length === 0 ? (
            <p className={emptyStateClassName}>本周没有未归属的仓库或目录。</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>来源</TableHead>
                  <TableHead>请求</TableHead>
                  <TableHead>用户</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {unattributed.map((entry) => (
                  <TableRow key={`${entry.kind}-${entry.value}`}>
                    <TableCell className="max-w-md truncate font-mono text-label" title={entry.value}>
                      <Badge variant="outline">{ruleKindLabel(entry.kind)}</Badge> {entry.value}
                    </TableCell>
                    <TableCell>{entry.requests}</TableCell>
                    <TableCell>{entry.users}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="ghost" onClick={() => applyDraft(entry)}>
                        生成规则草稿
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
