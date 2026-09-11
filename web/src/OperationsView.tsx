// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Ban, CircleDot, Clock3, PlayCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";

import {
  type ActionTemplate,
  type Approval,
  type RunState,
  type SafeEvent,
  SecretBridgeApiError,
  type SyntheticRun,
  type Target,
  cancelSyntheticRun,
  createSyntheticRun,
  listActionTemplates,
  listApprovals,
  listRunSafeEvents,
  listSyntheticRuns,
  listTargets,
} from "./api";

type Language = "zh-CN" | "en";

const stateStyles: Record<RunState, string> = {
  queued: "bg-amber-50 text-amber-700",
  running: "bg-cyan-50 text-cyan-700",
  succeeded: "bg-emerald-50 text-emerald-700",
  cancelled: "bg-slate-100 text-slate-600",
  failed: "bg-rose-50 text-rose-700",
};

export function OperationsView({ language, sessionToken }: { language: Language; sessionToken: string }) {
  const text = language === "zh-CN"
    ? {
        eyebrow: "M1 · 合成运行",
        title: "提交并观察受控运行",
        subtitle: "每个已批准且未使用的审批只能创建一个运行。请求使用幂等键去重，运行状态和固定安全事件可持续查询。",
        safety: "当前运行只执行密桥内部的短时状态模拟，不启动进程、不访问网络、不读取凭据，也不接收参数或自由文本。",
        request: "新建运行请求",
        approval: "已批准的单次授权",
        choose: "请选择可用审批",
        none: "没有可用审批；请先批准一条尚未使用的申请。",
        submit: "启动合成运行",
        submitting: "正在提交…",
        runs: "运行记录",
        empty: "尚无运行记录。",
        loading: "正在读取运行状态…",
        loadError: "运行状态读取失败，请稍后重试。",
        requestError: "运行请求失败，请检查审批是否仍有效。",
        consumed: "该审批已被使用；列表已经刷新。",
        conflict: "运行已发生变化，列表已经刷新。",
        cancel: "取消运行",
        events: "安全事件",
        hideEvents: "收起事件",
        noEvents: "暂无安全事件。",
        version: "版本",
        approvalVersion: "审批版本",
        states: { queued: "已排队", running: "运行中", succeeded: "已成功", cancelled: "已取消", failed: "已中断" } satisfies Record<RunState, string>,
        results: { synthetic_ok: "合成检查正常", cancelled: "用户取消", service_restarted: "服务重启时中断", authorization_revoked: "授权已失效，运行安全停止" } as Record<string, string>,
      }
    : {
        eyebrow: "M1 · Synthetic runs",
        title: "Submit and observe controlled runs",
        subtitle: "Each approved, unused approval creates at most one run. Idempotency keys deduplicate requests, while run status and fixed safe events remain queryable.",
        safety: "Runs currently perform only a short internal state simulation. They start no process, access no network, read no credential and accept no arguments or free text.",
        request: "New run request",
        approval: "Approved single-use authorization",
        choose: "Choose an available approval",
        none: "No approval is available. Approve an unused request first.",
        submit: "Start synthetic run",
        submitting: "Submitting…",
        runs: "Run records",
        empty: "No run records yet.",
        loading: "Loading run status…",
        loadError: "Run status could not be loaded. Try again later.",
        requestError: "The run request failed. Check that the approval is still active.",
        consumed: "That approval was already used. The list has been refreshed.",
        conflict: "The run changed. The list has been refreshed.",
        cancel: "Cancel run",
        events: "Safe events",
        hideEvents: "Hide events",
        noEvents: "No safe events yet.",
        version: "Version",
        approvalVersion: "Approval version",
        states: { queued: "Queued", running: "Running", succeeded: "Succeeded", cancelled: "Cancelled", failed: "Interrupted" } satisfies Record<RunState, string>,
        results: { synthetic_ok: "Synthetic check OK", cancelled: "Cancelled by user", service_restarted: "Interrupted by service restart", authorization_revoked: "Stopped because authorization is no longer active" } as Record<string, string>,
      };
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [approvalId, setApprovalId] = useState("");
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [events, setEvents] = useState<Record<string, SafeEvent[]>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const templateNames = useMemo(() => new Map(templates.map((item) => [item.id, item.name])), [templates]);
  const targetNames = useMemo(() => new Map(targets.map((item) => [item.id, item.name])), [targets]);
  const usedApprovals = useMemo(() => new Set(runs.map((run) => run.approval_id)), [runs]);
  const availableApprovals = useMemo(
    () => approvals.filter((approval) => approval.state === "approved" && approval.action_template_id && !usedApprovals.has(approval.id)),
    [approvals, usedApprovals],
  );
  const hasActiveRuns = runs.some((run) => run.state === "queued" || run.state === "running");

  async function refresh() {
    const [runResponse, approvalResponse, templateResponse, targetResponse] = await Promise.all([
      listSyntheticRuns(sessionToken),
      listApprovals(sessionToken),
      listActionTemplates(sessionToken),
      listTargets(sessionToken),
    ]);
    setRuns(runResponse.items);
    setApprovals(approvalResponse.items);
    setTemplates(templateResponse.items);
    setTargets(targetResponse.items);
    const used = new Set(runResponse.items.map((run) => run.approval_id));
    setApprovalId((current) => approvalResponse.items.some((item) => item.id === current && item.state === "approved" && !used.has(item.id)) ? current : approvalResponse.items.find((item) => item.state === "approved" && item.action_template_id && !used.has(item.id))?.id ?? "");
  }

  useEffect(() => {
    let active = true;
    refresh().catch(() => { if (active) setError(text.loadError); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [sessionToken, text.loadError]);

  useEffect(() => {
    if (!hasActiveRuns) return;
    const timer = window.setInterval(() => { void refresh().catch(() => setError(text.loadError)); }, 500);
    return () => window.clearInterval(timer);
  }, [hasActiveRuns, sessionToken, text.loadError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!approvalId) return;
    setBusy(true);
    setError(null);
    try {
      const response = await createSyntheticRun(sessionToken, approvalId, crypto.randomUUID());
      setRuns((current) => [response.run, ...current.filter((item) => item.id !== response.run.id)]);
      setApprovalId("");
      await refresh();
    } catch (caught) {
      if (caught instanceof SecretBridgeApiError && ["approval_consumed", "idempotency_conflict"].includes(caught.code)) {
        await refresh().catch(() => undefined);
        setError(text.consumed);
      } else { setError(text.requestError); }
    } finally { setBusy(false); }
  }

  async function cancel(run: SyntheticRun) {
    setBusy(true);
    setError(null);
    try {
      const updated = await cancelSyntheticRun(sessionToken, run.id, run.version);
      setRuns((current) => current.map((item) => item.id === updated.id ? updated : item));
      if (expandedRunId === run.id) await loadEvents(run.id);
    } catch (caught) {
      if (caught instanceof SecretBridgeApiError && ["version_conflict", "invalid_run_transition"].includes(caught.code)) {
        await refresh().catch(() => undefined);
        setError(text.conflict);
      } else { setError(text.requestError); }
    } finally { setBusy(false); }
  }

  async function loadEvents(runId: string) {
    const response = await listRunSafeEvents(sessionToken, runId);
    setEvents((current) => ({ ...current, [runId]: response.items }));
  }

  async function toggleEvents(runId: string) {
    if (expandedRunId === runId) { setExpandedRunId(null); return; }
    setExpandedRunId(runId);
    try { await loadEvents(runId); } catch { setError(text.loadError); }
  }

  return (
    <section className="space-y-6">
      <header><p className="m-0 text-xs font-bold uppercase tracking-[0.18em] text-cyan-700">{text.eyebrow}</p><h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1><p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">{text.subtitle}</p></header>
      <div className="flex gap-3 rounded-2xl border border-cyan-200 bg-cyan-50 p-4 text-sm leading-6 text-cyan-950"><ShieldCheck className="mt-0.5 size-5 shrink-0" /><p className="m-0 font-medium">{text.safety}</p></div>
      <form onSubmit={submit} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="m-0 text-lg font-semibold text-slate-950">{text.request}</h2><div className="mt-4 flex flex-col gap-3 sm:flex-row"><label className="flex-1 text-sm font-semibold text-slate-700"><span className="mb-2 block">{text.approval}</span><select required value={approvalId} onChange={(event) => setApprovalId(event.target.value)} className={inputClass}><option value="">{text.choose}</option>{availableApprovals.map((approval) => <option key={approval.id} value={approval.id}>{approval.action_template_id ? templateNames.get(approval.action_template_id) : approval.operation} · {targetNames.get(approval.target_id)} · {text.approvalVersion} {approval.version}</option>)}</select></label><button type="submit" disabled={!approvalId || busy} className="mt-auto inline-flex h-[42px] items-center justify-center gap-2 rounded-xl bg-slate-950 px-5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50"><PlayCircle className="size-4" />{busy ? text.submitting : text.submit}</button></div>{availableApprovals.length === 0 && !loading && <p className="mb-0 mt-3 text-sm text-amber-700">{text.none}</p>}</form>
      <div><div className="mb-4 flex items-center justify-between"><h2 className="m-0 text-lg font-semibold text-slate-950">{text.runs}</h2><button type="button" onClick={() => void refresh()} className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600"><RefreshCw className="size-3.5" />{runs.length}</button></div>{error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}{loading ? <p className={emptyClass}>{text.loading}</p> : runs.length === 0 ? <p className={emptyClass}>{text.empty}</p> : <div className="space-y-4">{runs.map((run) => <article key={run.id} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex flex-wrap items-center gap-2"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${stateStyles[run.state]}`}><CircleDot className={`mr-1 inline size-3 ${run.state === "running" ? "animate-pulse" : ""}`} />{text.states[run.state]}</span><span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">{templateNames.get(run.action_template_id) ?? run.operation}</span></div><h3 className="mb-0 mt-3 text-base font-semibold text-slate-950">{targetNames.get(run.target_id) ?? run.target_id}</h3><p className="mb-0 mt-2 text-xs text-slate-500"><Clock3 className="mr-1 inline size-3.5" />{new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "medium" }).format(run.updated_at_unix_ms)} · {text.version} {run.version}</p>{run.result_status && <p className="mb-0 mt-2 text-sm font-medium text-slate-600">{text.results[run.result_status]}</p>}</div>{(run.state === "queued" || run.state === "running") && <button type="button" disabled={busy} onClick={() => void cancel(run)} className="inline-flex items-center gap-2 rounded-xl bg-rose-600 px-3.5 py-2 text-sm font-semibold text-white hover:bg-rose-700 disabled:opacity-50"><Ban className="size-4" />{text.cancel}</button>}</div><button type="button" onClick={() => void toggleEvents(run.id)} className="mt-4 text-sm font-semibold text-cyan-700">{expandedRunId === run.id ? text.hideEvents : text.events}</button>{expandedRunId === run.id && <div className="mt-3 space-y-2 border-t border-slate-100 pt-3">{(events[run.id] ?? []).length === 0 ? <p className="m-0 text-sm text-slate-500">{text.noEvents}</p> : events[run.id].map((item) => <div key={item.id} className="flex items-start gap-3 rounded-xl bg-slate-50 p-3 text-sm"><span className="rounded-full bg-white px-2 py-0.5 text-xs font-bold text-slate-500">#{item.sequence}</span><div><p className="m-0 font-medium text-slate-700">{item.message}</p><p className="mb-0 mt-1 text-xs text-slate-400">{new Intl.DateTimeFormat(language, { timeStyle: "medium" }).format(item.created_at_unix_ms)}</p></div></div>)}</div>}</article>)}</div>}</div>
    </section>
  );
}

const inputClass = "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";
const emptyClass = "rounded-2xl bg-white p-6 text-sm text-slate-500 shadow-sm";
