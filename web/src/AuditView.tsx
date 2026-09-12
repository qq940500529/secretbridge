// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FileClock, Filter, LockKeyhole, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  type ActionTemplate,
  type SafeEvent,
  type SafeEventKind,
  type SyntheticRun,
  type Target,
  listActionTemplates,
  listSafeEvents,
  listSyntheticRuns,
  listTargets,
} from "./api";

type Language = "zh-CN" | "en";

export function AuditView({ language, sessionToken }: { language: Language; sessionToken: string }) {
  const text = language === "zh-CN"
    ? {
        eyebrow: "M2 · 安全事件",
        title: "可审查的受控运行记录",
        subtitle: "审计流只包含服务端生成的固定安全消息、状态、序号和关联标识，不接收终端输出、业务数据、请求参数或凭据。",
        policy: "当前载荷策略：仅允许固定安全消息。事件记录运行结果，但不会包含数据库错误原文、业务数据、参数或凭据。",
        all: "全部事件",
        empty: "尚无安全事件。创建一条受控运行后会在此显示生命周期。",
        loading: "正在读取安全事件…",
        error: "安全事件读取失败，请稍后重试。",
        run: "运行",
        target: "目标",
        template: "模板",
        sequence: "序号",
        kinds: { authorization_revoked: "授权或策略失效后安全停止", requested: "请求已接受", started: "受控运行已开始", succeeded: "受控运行已完成", failed: "受控运行未通过", cancelled: "运行已取消", interrupted: "服务重启导致中断" } satisfies Record<SafeEventKind, string>,
      }
    : {
        eyebrow: "M1 · Safe events",
        title: "Reviewable controlled run history",
        subtitle: "The audit stream contains only server-generated fixed safe messages, states, sequences and relationship identifiers. It accepts no terminal output, business data, request arguments or credentials.",
        policy: "Current payload policy: fixed safe messages only. Events record outcomes without exposing raw database errors, business data, arguments, or credentials.",
        all: "All events",
        empty: "No safe events yet. Create a controlled run to see its lifecycle here.",
        loading: "Loading safe events…",
        error: "Safe events could not be loaded. Try again later.",
        run: "Run",
        target: "Target",
        template: "Template",
        sequence: "Sequence",
        kinds: { authorization_revoked: "Stopped after authorization or policy became inactive", requested: "Request accepted", started: "Controlled run started", succeeded: "Controlled run completed", failed: "Controlled run did not pass", cancelled: "Run cancelled", interrupted: "Interrupted by service restart" } satisfies Record<SafeEventKind, string>,
      };
  const [events, setEvents] = useState<SafeEvent[]>([]);
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [filter, setFilter] = useState<SafeEventKind | "all">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const runMap = useMemo(() => new Map(runs.map((run) => [run.id, run])), [runs]);
  const templateMap = useMemo(() => new Map(templates.map((item) => [item.id, item.name])), [templates]);
  const targetMap = useMemo(() => new Map(targets.map((item) => [item.id, item.name])), [targets]);
  const visibleEvents = filter === "all" ? events : events.filter((event) => event.kind === filter);

  async function refresh() {
    const [eventResponse, runResponse, templateResponse, targetResponse] = await Promise.all([
      listSafeEvents(sessionToken),
      listSyntheticRuns(sessionToken),
      listActionTemplates(sessionToken),
      listTargets(sessionToken),
    ]);
    setEvents(eventResponse.items);
    setRuns(runResponse.items);
    setTemplates(templateResponse.items);
    setTargets(targetResponse.items);
  }

  useEffect(() => {
    let active = true;
    refresh().catch(() => { if (active) setError(text.error); }).finally(() => { if (active) setLoading(false); });
    const timer = window.setInterval(() => { void refresh().catch(() => { if (active) setError(text.error); }); }, 2_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [sessionToken, text.error]);

  return (
    <section className="space-y-6">
      <header><p className="m-0 text-xs font-bold uppercase tracking-[0.18em] text-cyan-700">{text.eyebrow}</p><h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1><p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">{text.subtitle}</p></header>
      <div className="flex gap-3 rounded-2xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-950"><LockKeyhole className="mt-0.5 size-5 shrink-0" /><p className="m-0 font-medium">{text.policy}</p></div>
      <div className="flex flex-wrap items-center justify-between gap-3"><label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700"><Filter className="size-4" /><select value={filter} onChange={(event) => setFilter(event.target.value as SafeEventKind | "all")} className="rounded-xl border border-slate-200 bg-white px-3 py-2 outline-none focus:border-cyan-500"><option value="all">{text.all}</option>{Object.entries(text.kinds).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}</select></label><button type="button" onClick={() => void refresh()} className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-600"><RefreshCw className="size-4" />{events.length}</button></div>
      {error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}
      {loading ? <p className={emptyClass}>{text.loading}</p> : visibleEvents.length === 0 ? <p className={emptyClass}>{text.empty}</p> : <ol className="m-0 space-y-3 p-0">{visibleEvents.map((event) => { const run = runMap.get(event.run_id); return <li key={event.id} className="list-none rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex items-start gap-4"><div className="grid size-10 shrink-0 place-items-center rounded-xl bg-slate-950 text-cyan-300"><FileClock className="size-5" /></div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><h2 className="m-0 text-base font-semibold text-slate-950">{text.kinds[event.kind]}</h2><time className="text-xs text-slate-400">{new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "medium" }).format(event.created_at_unix_ms)}</time></div><div className="mt-3 grid gap-2 text-xs text-slate-500 sm:grid-cols-2 lg:grid-cols-4"><span><strong>{text.sequence}：</strong>#{event.sequence}</span><span className="truncate"><strong>{text.run}：</strong>{event.run_id}</span><span className="truncate"><strong>{text.template}：</strong>{run ? (templateMap.get(run.action_template_id) ?? run.action_template_id) : "—"}</span><span className="truncate"><strong>{text.target}：</strong>{run ? (targetMap.get(run.target_id) ?? run.target_id) : "—"}</span></div></div></div></li>; })}</ol>}
    </section>
  );
}

const emptyClass = "rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500 shadow-sm";
