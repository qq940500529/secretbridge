// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Pencil, Plus, ShieldOff, Trash2, X } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";

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
  updateActionTemplate,
} from "./api";

type Language = "zh-CN" | "en";

export function ActionTemplatesView({ language, sessionToken }: { language: Language; sessionToken: string }) {
  const text = language === "zh-CN"
    ? {
        eyebrow: "M1 · 受控操作模板",
        title: "把授权约束固化为模板",
        subtitle: "模板只允许选择内置合成操作和返回范围，不接受命令、脚本、参数、地址或凭据。审批创建时会保存模板版本与范围快照。",
        safety: "操作执行仍处于硬禁用状态；这些模板只用于验证配置、版本与审批绑定。",
        formCreate: "新建操作模板",
        formEdit: "编辑操作模板",
        name: "模板名称",
        namePlaceholder: "例如：测试目标元数据检查",
        target: "逻辑目标",
        choose: "请选择目标",
        operation: "内置合成操作",
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
        operationLabels: { inspect_metadata: "查看非秘密元数据", synthetic_health_check: "合成健康检查" },
        scopeLabels: { status_only: "仅状态", metadata_summary: "元数据摘要" },
      }
    : {
        eyebrow: "M1 · Controlled action templates",
        title: "Make authorization constraints reusable",
        subtitle: "Templates select only built-in synthetic operations and result scopes. They accept no commands, scripts, arguments, addresses or credentials. Approvals snapshot the template version and scope.",
        safety: "Operation execution remains hard-disabled. Templates currently validate configuration, versioning and approval binding only.",
        formCreate: "New action template",
        formEdit: "Edit action template",
        name: "Template name",
        namePlaceholder: "Example: test-target metadata inspection",
        target: "Logical target",
        choose: "Choose a target",
        operation: "Built-in synthetic operation",
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
        operationLabels: { inspect_metadata: "Inspect non-secret metadata", synthetic_health_check: "Synthetic health check" },
        scopeLabels: { status_only: "Status only", metadata_summary: "Metadata summary" },
      };
  const [items, setItems] = useState<ActionTemplate[]>([]);
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
    const base = { target_id: targetId, name, operation, result_scope: scope, ...(description.trim() ? { description } : {}), timeout_seconds: timeoutSeconds };
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
      <header><p className="m-0 text-xs font-bold uppercase tracking-[0.18em] text-cyan-700">{text.eyebrow}</p><h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1><p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">{text.subtitle}</p></header>
      <div className="flex gap-3 rounded-2xl border border-cyan-200 bg-cyan-50 p-4 text-sm leading-6 text-cyan-900"><ShieldOff className="mt-0.5 size-5 shrink-0" /><p className="m-0 font-medium">{text.safety}</p></div>
      <div className="grid gap-6 lg:grid-cols-[minmax(300px,0.85fr)_minmax(0,1.35fr)]">
        <form onSubmit={submit} className="h-fit rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="m-0 text-lg font-semibold text-slate-950">{editing ? text.formEdit : text.formCreate}</h2>
          {!loading && targets.length === 0 && <p className="mb-0 mt-4 rounded-xl bg-amber-50 p-3 text-sm text-amber-800">{text.noTargets}</p>}
          <div className="mt-5 space-y-4">
            <Field label={text.name}><input required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder={text.namePlaceholder} className={inputClass} /></Field>
            <Field label={text.target}><select required value={targetId} onChange={(event) => setTargetId(event.target.value)} className={inputClass}><option value="">{text.choose}</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}</select></Field>
            <div className="grid gap-4 sm:grid-cols-2"><Field label={text.operation}><select value={operation} onChange={(event) => setOperation(event.target.value as ApprovalOperation)} className={inputClass}>{Object.entries(text.operationLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field><Field label={text.scope}><select value={scope} onChange={(event) => setScope(event.target.value as ApprovalResultScope)} className={inputClass}>{Object.entries(text.scopeLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field></div>
            <Field label={text.timeout}><input required type="number" min={1} max={300} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} className={inputClass} /></Field>
            <Field label={text.description}><textarea rows={3} maxLength={240} value={description} onChange={(event) => setDescription(event.target.value)} placeholder={text.descriptionPlaceholder} className={inputClass} /></Field>
            {editing && <label className="flex items-center gap-3 rounded-xl bg-slate-50 p-3 text-sm font-semibold text-slate-700"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} className="size-4 accent-cyan-700" />{text.enabled}</label>}
          </div>
          <div className="mt-5 flex gap-2"><button type="submit" disabled={!targetId || busy} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-950 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50">{editing ? <Pencil className="size-4" /> : <Plus className="size-4" />}{editing ? text.save : text.add}</button>{editing && <button type="button" onClick={reset} className="inline-flex items-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-600"><X className="size-4" />{text.cancel}</button>}</div>
        </form>
        <div><div className="mb-4 flex items-center justify-between"><h2 className="m-0 text-lg font-semibold text-slate-950">{text.templates}</h2><span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-slate-500 shadow-sm ring-1 ring-slate-200">{items.length}</span></div>{error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}{loading ? <p className={emptyClass}>{text.loading}</p> : items.length === 0 ? <p className={emptyClass}>{text.empty}</p> : <div className="space-y-4">{items.map((item) => <article key={item.id} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex items-start justify-between gap-4"><div className="min-w-0"><div className="flex flex-wrap gap-2"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${item.enabled ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"}`}>{item.enabled ? text.active : text.inactive}</span><span className="rounded-full bg-cyan-50 px-2.5 py-1 text-xs font-semibold text-cyan-700">{text.operationLabels[item.operation]}</span><span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">{text.scopeLabels[item.result_scope]}</span></div><h3 className="mb-0 mt-3 text-base font-semibold text-slate-950">{item.name}</h3><p className="mb-0 mt-2 text-sm text-slate-600">{targetNames.get(item.target_id) ?? item.target_id} · {item.timeout_seconds} {text.seconds} · {text.version} {item.version}</p>{item.description && <p className="mb-0 mt-2 text-sm leading-6 text-slate-600">{item.description}</p>}</div><div className="flex shrink-0 gap-2"><button type="button" aria-label={text.formEdit} onClick={() => edit(item)} className={iconClass}><Pencil className="size-4" /></button><button type="button" aria-label={text.deleteConfirm} onClick={() => void remove(item.id)} className={`${iconClass} hover:text-rose-700`}><Trash2 className="size-4" /></button></div></div></article>)}</div>}</div>
      </div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="block text-sm font-semibold text-slate-700"><span className="mb-2 block">{label}</span>{children}</label>; }

const inputClass = "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";
const iconClass = "grid size-9 place-items-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-cyan-300 hover:text-cyan-700";
const emptyClass = "rounded-2xl bg-white p-6 text-sm text-slate-500 shadow-sm";
