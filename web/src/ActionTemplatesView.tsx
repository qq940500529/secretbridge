// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Pencil, Plus, ShieldCheck, Trash2, X } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";
import { CommandEditor, emptyCommand } from "./CommandEditor";

import {
  type ActionTemplate,
  type ApprovalOperation,
  type ApprovalResultScope,
  createActionTemplate,
  deleteActionTemplate,
  listActionTemplates,
  listTargets,
  SecretBridgeApiError,
  type Target,
  type CommandConfig,
  type CredentialReference,
  listCredentialReferences,
  updateActionTemplate,
} from "./api";

type Language = "zh-CN" | "en";

export function ActionTemplatesView({ language, sessionToken }: { language: Language; sessionToken: string }) {
  const text = language === "zh-CN"
    ? {
        title: "把授权约束固化为模板",
        subtitle: "配置内置检查或固定程序任务，凭据通过命名插槽绑定。审批保存模板版本，修改模板后需重新授权。",
        safety: "PostgreSQL 连接检查仅执行内置 SELECT 1，只返回结构化状态；合成操作继续用于离线验证。",
        formCreate: "新建操作模板",
        formEdit: "编辑操作模板",
        name: "模板名称",
        namePlaceholder: "例如：测试目标元数据检查",
        target: "逻辑目标",
        choose: "请选择目标",
        operation: "内置受控操作",
        scope: "结果范围",
        description: "用途说明（可选）",
        descriptionPlaceholder: "说明使用场景，不要填写命令、地址或秘密",
        timeout: "拟定超时（秒）",
        enabled: "允许用于新审批",
        add: "添加模板",
        save: "保存修改",
        cancel: "取消",
        templates: "已配置模板",
        noTargets: "请先建立逻辑目标。",
        empty: "尚无操作模板。",
        loading: "正在读取模板…",
        loadError: "模板读取失败，请稍后重试。",
        saveError: "模板保存失败，请检查字段后重试。",
        deleteError: "模板删除失败；已被审批引用的模板会保留。",
        conflict: "模板已被其他页面修改，列表已刷新。",
        deleteConfirm: "确定删除这个未被审批引用的模板吗？",
        active: "可申请",
        inactive: "已停用",
        version: "版本",
        seconds: "秒",
        operationLabels: { inspect_metadata: "查看非秘密元数据", synthetic_health_check: "合成健康检查", postgres_connection_check: "PostgreSQL 只读连接检查", command_execution: "凭据命令任务" },
        scopeLabels: { status_only: "仅状态", metadata_summary: "元数据摘要", sanitized_output: "脱敏输出" },
      }
    : {
        title: "Make authorization constraints reusable",
        subtitle: "Configure built-in checks or fixed program tasks with named credential slots. Approvals snapshot the template version; changes require new authorization.",
        safety: "The PostgreSQL connection check runs only a fixed SELECT 1 and returns structured status; synthetic operations remain available for offline validation.",
        formCreate: "New action template",
        formEdit: "Edit action template",
        name: "Template name",
        namePlaceholder: "Example: test-target metadata inspection",
        target: "Logical target",
        choose: "Choose a target",
        operation: "Built-in controlled operation",
        scope: "Result scope",
        description: "Purpose (optional)",
        descriptionPlaceholder: "Describe the use; do not enter commands, addresses or secrets",
        timeout: "Planned timeout (seconds)",
        enabled: "Available for new approvals",
        add: "Add template",
        save: "Save changes",
        cancel: "Cancel",
        templates: "Configured templates",
        noTargets: "Create a logical target first.",
        empty: "No action templates yet.",
        loading: "Loading templates…",
        loadError: "Templates could not be loaded. Try again later.",
        saveError: "The template could not be saved. Check the fields and retry.",
        deleteError: "The template could not be deleted. Referenced templates are preserved.",
        conflict: "The template changed elsewhere. The list has been refreshed.",
        deleteConfirm: "Delete this template if it is not referenced by an approval?",
        active: "Available",
        inactive: "Disabled",
        version: "Version",
        seconds: "seconds",
        operationLabels: { inspect_metadata: "Inspect non-secret metadata", synthetic_health_check: "Synthetic health check", postgres_connection_check: "PostgreSQL read-only connection check", command_execution: "Credential command task" },
        scopeLabels: { status_only: "Status only", metadata_summary: "Metadata summary", sanitized_output: "Sanitized output" },
      };
  const [items, setItems] = useState<ActionTemplate[]>([]);
  const [credentials,setCredentials]=useState<CredentialReference[]>([]);
  const [command,setCommand]=useState<CommandConfig>(emptyCommand);
  const [targets, setTargets] = useState<Target[]>([]);
  const [editing, setEditing] = useState<ActionTemplate | null>(null);
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState("");
  const [operation, setOperation] = useState<ApprovalOperation>("inspect_metadata");
  const [scope, setScope] = useState<ApprovalResultScope>("metadata_summary");
  const [description, setDescription] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(15);
  const [enabled, setEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targetNames = useMemo(() => new Map(targets.map((target) => [target.id, target.name])), [targets]);

  async function reload() {
    const [templates, targetResponse] = await Promise.all([listActionTemplates(sessionToken), listTargets(sessionToken)]);
    setItems(templates.items);
    setTargets(targetResponse.items);
    setTargetId((current) => current || targetResponse.items[0]?.id || "");
  }

  useEffect(() => {
    void listCredentialReferences(sessionToken).then(response=>setCredentials(response.items)).catch(()=>setError(text.loadError));
    let active = true;
    Promise.all([listActionTemplates(sessionToken), listTargets(sessionToken)])
      .then(([templates, targetResponse]) => {
        if (!active) return;
        setItems(templates.items);
        setTargets(targetResponse.items);
        setTargetId(targetResponse.items[0]?.id ?? "");
      })
      .catch(() => { if (active) setError(text.loadError); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [sessionToken, text.loadError]);

  function reset() {
    setCommand(emptyCommand);
    setEditing(null);
    setName("");
    setTargetId(targets[0]?.id ?? "");
    setOperation("inspect_metadata");
    setScope("metadata_summary");
    setDescription("");
    setTimeoutSeconds(15);
    setEnabled(true);
  }

  function edit(item: ActionTemplate) {
    setCommand(item.command??emptyCommand);
    setEditing(item);
    setName(item.name);
    setTargetId(item.target_id);
    setOperation(item.operation);
    setScope(item.result_scope);
    setDescription(item.description ?? "");
    setTimeoutSeconds(item.timeout_seconds);
    setEnabled(item.enabled);
    setError(null);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!targetId) return;
    setBusy(true);
    setError(null);
    const base = { target_id: targetId, name, operation, result_scope: operation==="command_execution"?"sanitized_output" as const:scope, ...(operation==="command_execution"?{command}:{}), ...(description.trim() ? { description } : {}), timeout_seconds: timeoutSeconds };
    try {
      const saved = editing
        ? await updateActionTemplate(sessionToken, editing.id, { ...base, enabled, expected_version: editing.version })
        : await createActionTemplate(sessionToken, base);
      setItems((current) => editing ? current.map((item) => item.id === saved.id ? saved : item) : [...current, saved]);
      reset();
    } catch (caught) {
      if (caught instanceof SecretBridgeApiError && caught.code === "version_conflict") {
        try { await reload(); } catch { /* Keep conflict message. */ }
        reset();
        setError(text.conflict);
      } else {
        setError(text.saveError);
      }
    } finally { setBusy(false); }
  }

  async function remove(id: string) {
    if (!window.confirm(text.deleteConfirm)) return;
    setError(null);
    try {
      await deleteActionTemplate(sessionToken, id);
      setItems((current) => current.filter((item) => item.id !== id));
      if (editing?.id === id) reset();
    } catch { setError(text.deleteError); }
  }

  return (
    <section className="space-y-6">
      <header><h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1><p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">{text.subtitle}</p></header>
      <div className="flex gap-3 border-l-4 border-cyan-500 bg-cyan-50 px-4 py-3 text-sm leading-6 text-cyan-900"><ShieldCheck className="mt-0.5 size-5 shrink-0" /><p className="m-0 font-medium">{text.safety}</p></div>
      <details className="enterprise-disclosure enterprise-surface" open={editing ? true : undefined}>
        <summary className="flex cursor-pointer items-center justify-between border-b border-slate-200 px-5 py-3 text-sm font-semibold text-slate-800 hover:bg-slate-50"><span className="inline-flex items-center gap-2"><Plus className="size-4 text-cyan-700" />{editing ? text.formEdit : text.formCreate}</span><span className="text-slate-400">+</span></summary>
        <form onSubmit={submit} className="max-w-5xl p-5">
          {!loading && targets.length === 0 && <p className="mb-0 mt-4 rounded-xl bg-amber-50 p-3 text-sm text-amber-800">{text.noTargets}</p>}
          <div className="mt-2 grid gap-4 md:grid-cols-2">
            <Field label={text.name}><input required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder={text.namePlaceholder} className={inputClass} /></Field>
            <Field label={text.target}><select required value={targetId} onChange={(event) => setTargetId(event.target.value)} className={inputClass}><option value="">{text.choose}</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}</select></Field>
            <div className="grid gap-4 sm:grid-cols-2"><Field label={text.operation}><select value={operation} onChange={(event) => setOperation(event.target.value as ApprovalOperation)} className={inputClass}>{Object.entries(text.operationLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field><Field label={text.scope}><select disabled={operation === "command_execution"} value={operation === "command_execution" ? "sanitized_output" : scope} onChange={(event) => setScope(event.target.value as ApprovalResultScope)} className={inputClass}>{Object.entries(text.scopeLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field></div>
            <Field label={text.timeout}><input required type="number" min={1} max={300} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} className={inputClass} /></Field>
            <Field label={text.description}><textarea rows={3} maxLength={240} value={description} onChange={(event) => setDescription(event.target.value)} placeholder={text.descriptionPlaceholder} className={inputClass} /></Field>
            {editing && <label className="flex items-center gap-3 rounded-xl bg-slate-50 p-3 text-sm font-semibold text-slate-700"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} className="size-4 accent-cyan-700" />{text.enabled}</label>}
            {operation==="command_execution"&&<div className="md:col-span-2"><CommandEditor value={command} onChange={setCommand} credentials={credentials} language={language}/></div>}
          </div>
          <div className="mt-5 flex justify-end gap-2">{editing && <button type="button" onClick={reset} className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-700"><X className="size-4" />{text.cancel}</button>}<button type="submit" disabled={!targetId || busy || (operation === "command_execution" && command.slots.length === 0)} className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-700 px-5 py-2.5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50">{editing ? <Pencil className="size-4" /> : <Plus className="size-4" />}{editing ? text.save : text.add}</button></div>
        </form>
      </details>
      <div><div className="mb-3 flex items-center justify-between"><h2 className="m-0 text-base font-semibold text-slate-950">{text.templates}</h2><span className="text-xs tabular-nums text-slate-500">{items.length}</span></div>{error && <p role="alert" className="border-l-4 border-rose-400 bg-rose-50 px-4 py-3 text-sm text-rose-800">{error}</p>}{loading ? <p className={emptyClass}>{text.loading}</p> : items.length === 0 ? <p className={emptyClass}>{text.empty}</p> : <div className="enterprise-surface enterprise-table">{items.map((item) => <article key={item.id} className="p-5"><div className="flex items-start justify-between gap-4"><div className="min-w-0"><div className="flex flex-wrap gap-2"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${item.enabled ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"}`}>{item.enabled ? text.active : text.inactive}</span><span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600">{text.operationLabels[item.operation]}</span></div><h3 className="mb-0 mt-2 text-sm font-semibold text-slate-950">{item.name}</h3><p className="mb-0 mt-1 text-sm text-slate-600">{targetNames.get(item.target_id) ?? item.target_id} · {text.scopeLabels[item.result_scope]} · {item.timeout_seconds} {text.seconds} · {text.version} {item.version}</p>{item.description && <p className="mb-0 mt-1 text-sm leading-6 text-slate-500">{item.description}</p>}</div><div className="flex shrink-0 gap-2"><button type="button" aria-label={text.formEdit} onClick={() => edit(item)} className={iconClass}><Pencil className="size-4" /></button><button type="button" aria-label={text.deleteConfirm} onClick={() => void remove(item.id)} className={`${iconClass} hover:text-rose-700`}><Trash2 className="size-4" /></button></div></div></article>)}</div>}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="block text-sm font-semibold text-slate-700"><span className="mb-2 block">{label}</span>{children}</label>; }

const inputClass = "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";
const iconClass = "grid size-9 place-items-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-cyan-300 hover:text-cyan-700";
const emptyClass = "enterprise-surface p-6 text-sm text-slate-500";
