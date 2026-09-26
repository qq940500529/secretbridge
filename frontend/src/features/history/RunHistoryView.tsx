// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState } from "react";
import {
  listActionTemplates,
  listSafeEvents,
  listSyntheticRuns,
  listTargets,
  type ActionTemplate,
  type SafeEvent,
  type SyntheticRun,
  type Target,
} from "../../api/index";
import { RunOutputView } from "../tasks/runs/RunOutputView";

export function RunHistoryView({
  language,
  sessionToken,
  requestedRunId,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
  requestedRunId: string | null;
}) {
  const zh = language === "zh-CN";
  const stateText = zh
    ? {
        queued: "排队中",
        running: "运行中",
        succeeded: "进程已完成",
        failed: "失败",
        cancelled: "已取消",
      }
    : {
        queued: "Queued",
        running: "Running",
        succeeded: "Process completed",
        failed: "Failed",
        cancelled: "Cancelled",
      };
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [events, setEvents] = useState<SafeEvent[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(requestedRunId);
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [error, setError] = useState(false);
  useEffect(() => {
    let active = true;
    void Promise.all([
      listSyntheticRuns(sessionToken),
      listSafeEvents(sessionToken),
      listActionTemplates(sessionToken),
      listTargets(sessionToken),
    ])
      .then(([runList, eventList, templateList, targetList]) => {
        if (!active) return;
        setRuns(runList.items);
        setEvents(eventList.items);
        setTemplates(templateList.items);
        setTargets(targetList.items);
        setError(false);
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
    };
  }, [sessionToken]);
  useEffect(() => {
    if (requestedRunId) setSelectedId(requestedRunId);
  }, [requestedRunId]);
  const templateNames = useMemo(
    () => new Map(templates.map((item) => [item.id, item.name])),
    [templates],
  );
  const targetNames = useMemo(
    () => new Map(targets.map((item) => [item.id, item.name])),
    [targets],
  );
  const terminalByRun = useMemo(() => {
    const result = new Map<string, string>();
    for (const event of events)
      if (event.terminal_id) result.set(event.run_id, event.terminal_id);
    return result;
  }, [events]);
  const filtered = useMemo(
    () =>
      runs
        .filter((run) => {
          const term = query.trim().toLowerCase();
          return (
            (stateFilter === "all" || run.state === stateFilter) &&
            (!term ||
              [
                run.id,
                run.approval_id,
                terminalByRun.get(run.id),
                templateNames.get(run.action_template_id),
                targetNames.get(run.target_id),
                new Date(run.created_at_unix_ms).toLocaleString(language),
              ].some((value) => value?.toLowerCase().includes(term)))
          );
        })
        .sort((a, b) => b.created_at_unix_ms - a.created_at_unix_ms),
    [
      runs,
      query,
      stateFilter,
      terminalByRun,
      templateNames,
      targetNames,
      language,
    ],
  );
  const selected = runs.find((run) => run.id === selectedId) ?? null;
  return (
    <section className="space-y-5">
      <header>
        <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
          {zh ? "运行与终端历史" : "Run & terminal history"}
        </h1>
        <p className="mb-0 mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          {zh
            ? "按运行、审批、目标、终端或时间查找受控执行。这里保留的是脱敏运行输出；普通交互终端的即时缓冲区不是持久审计记录。"
            : "Find controlled runs by run, approval, target, terminal or time. Retained output is sanitized; a live terminal's ordinary interaction buffer is not a durable audit record."}
        </p>
      </header>
      {error && (
        <p role="alert" className="text-rose-700">
          {zh
            ? "历史读取失败，请重新打开此页。"
            : "Could not load history. Reopen this page."}
        </p>
      )}
      <div className="flex flex-wrap gap-3 rounded-xl border border-slate-200 bg-white p-3">
        <input
          className="min-w-64 flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm"
          aria-label={
            zh
              ? "搜索运行、审批、终端或时间"
              : "Search run, approval, terminal or time"
          }
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={zh ? "搜索名称或标识…" : "Search name or identifier…"}
        />
        <select
          className="rounded-lg border border-slate-200 px-3 py-2 text-sm"
          aria-label={zh ? "运行状态" : "Run status"}
          value={stateFilter}
          onChange={(event) => setStateFilter(event.target.value)}
        >
          <option value="all">{zh ? "全部状态" : "All states"}</option>
          <option value="succeeded">
            {zh ? "进程已完成" : "Process completed"}
          </option>
          <option value="failed">{zh ? "失败" : "Failed"}</option>
          <option value="running">{zh ? "运行中" : "Running"}</option>
          <option value="cancelled">{zh ? "已取消" : "Cancelled"}</option>
        </select>
      </div>
      <div className="grid min-h-[28rem] overflow-hidden rounded-2xl border border-slate-200 bg-white lg:grid-cols-[19rem_minmax(0,1fr)]">
        <aside
          aria-label={zh ? "运行列表" : "Run list"}
          className="max-h-[70dvh] overflow-y-auto border-b border-slate-200 lg:border-b-0 lg:border-r"
        >
          <p className="m-0 border-b border-slate-100 px-4 py-3 text-xs font-semibold text-slate-500">
            {zh ? `匹配 ${filtered.length} 条` : `${filtered.length} matches`}
          </p>
          {filtered.map((run) => (
            <button
              key={run.id}
              type="button"
              aria-current={selectedId === run.id ? "true" : undefined}
              className={`w-full border-b border-slate-100 px-4 py-3 text-left hover:bg-slate-50 ${selectedId === run.id ? "border-l-2 border-l-cyan-600 bg-cyan-50" : ""}`}
              onClick={() => setSelectedId(run.id)}
            >
              <span className="block truncate text-sm font-semibold text-slate-900">
                {templateNames.get(run.action_template_id) ??
                  (zh ? "一次性操作" : "One-time operation")}
              </span>
              <span className="mt-1 block truncate text-xs text-slate-500">
                {targetNames.get(run.target_id) ?? run.target_id} ·{" "}
                {stateText[run.state]}
              </span>
              <time className="mt-1 block text-xs text-slate-400">
                {new Date(run.created_at_unix_ms).toLocaleString(language)}
              </time>
            </button>
          ))}
          {!filtered.length && (
            <p className="px-4 py-6 text-sm text-slate-500">
              {zh ? "没有匹配的运行。" : "No matching runs."}
            </p>
          )}
        </aside>
        <article className="min-w-0 p-5">
          {selected ? (
            <>
              <div className="border-b border-slate-100 pb-4">
                <h2 className="m-0 text-lg font-semibold text-slate-950">
                  {templateNames.get(selected.action_template_id) ??
                    (zh ? "一次性操作" : "One-time operation")}
                </h2>
                <p className="mb-0 mt-1 text-sm text-slate-600">
                  {targetNames.get(selected.target_id) ?? selected.target_id} ·{" "}
                  {stateText[selected.state]} ·{" "}
                  {new Date(selected.created_at_unix_ms).toLocaleString(
                    language,
                  )}
                </p>
                <details className="mt-3 text-xs text-slate-500">
                  <summary className="cursor-pointer">
                    {zh ? "关联标识" : "Related identifiers"}
                  </summary>
                  <p className="break-all">
                    {zh ? "运行" : "Run"}: {selected.id}
                  </p>
                  <p className="break-all">
                    {zh ? "审批" : "Approval"}: {selected.approval_id}
                  </p>
                  <p className="break-all">
                    {zh ? "终端" : "Terminal"}:{" "}
                    {terminalByRun.get(selected.id) ?? "—"}
                  </p>
                </details>
              </div>
              <RunOutputView
                id={selected.id}
                sessionToken={sessionToken}
                language={language}
              />
            </>
          ) : (
            <p className="m-0 py-10 text-center text-sm text-slate-500">
              {zh
                ? "选择左侧运行查看脱敏输出。"
                : "Select a run to inspect sanitized output."}
            </p>
          )}
        </article>
      </div>
    </section>
  );
}
