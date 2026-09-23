// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FileClock, Filter, LockKeyhole, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { saveDownload } from "./DataMaintenanceView";

import {
  type ActionTemplate,
  type BrowserAuthEvent,
  type BrowserAuthEventKind,
  type SafeEvent,
  type SafeEventKind,
  type SyntheticRun,
  type Target,
  listActionTemplates,
  listBrowserAuthEvents,
  listSafeEvents,
  listSyntheticRuns,
  listTargets,
} from "./api";

type Language = "zh-CN" | "en";

export function AuditView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const text =
    language === "zh-CN"
      ? {
          title: "事件记录",
          subtitle:
            "审计流只包含服务端生成的固定安全消息、状态、序号和关联标识，不接收终端输出、业务数据、请求参数或凭据。",
          policy:
            "当前载荷策略：仅允许固定安全消息。事件记录运行结果，但不会包含数据库错误原文、业务数据、参数或凭据。",
          authTitle: "身份验证事件",
          authEmpty:
            "尚无身份验证事件。绑定、验证、限流和停用会在此留下固定记录。",
          authKinds: {
            enrollment_started: "开始绑定身份验证器",
            enrollment_succeeded: "身份验证器绑定成功",
            verification_succeeded: "一次性验证码验证成功",
            verification_failed: "一次性验证码验证失败",
            rate_limited: "验证尝试已限流",
            disabled: "身份验证器已停用",
          } satisfies Record<BrowserAuthEventKind, string>,
          channels: { browser: "浏览器", mcp: "MCP 审批", settings: "设置" },
          approval: "审批",
          all: "全部事件",
          empty: "尚无安全事件。创建一条受控运行后会在此显示生命周期。",
          loading: "正在读取安全事件…",
          error: "安全事件读取失败，请稍后重试。",
          run: "运行",
          target: "目标",
          template: "模板",
          sequence: "序号",
          search: "搜索事件、运行或关联 ID",
          source: "来源",
          authSource: "身份验证",
          runSource: "运行",
          download: "下载已筛选安全日志",
          result: "运行结果",
          timeout: "超时",
          period: "时间范围",
          lastDay: "最近 24 小时",
          lastWeek: "最近 7 天",
          privacy:
            "导出前请检查关联标识；文件不含凭据，但可能反映你的操作时间与关系。",
          technical: "技术标识",
          kinds: {
            authorization_revoked: "授权或策略失效后安全停止",
            requested: "请求已接受",
            started: "受控运行已开始",
            succeeded: "受控运行已完成",
            failed: "受控运行未通过",
            cancelled: "运行已取消",
            interrupted: "服务重启导致中断",
          } satisfies Record<SafeEventKind, string>,
        }
      : {
          title: "Events",
          subtitle:
            "The audit stream contains only server-generated fixed safe messages, states, sequences and relationship identifiers. It accepts no terminal output, business data, request arguments or credentials.",
          policy:
            "Current payload policy: fixed safe messages only. Events record outcomes without exposing raw database errors, business data, arguments, or credentials.",
          authTitle: "Authentication events",
          authEmpty:
            "No authentication events yet. Enrollment, verification, throttling and disablement appear here as fixed records.",
          authKinds: {
            enrollment_started: "Authenticator enrollment started",
            enrollment_succeeded: "Authenticator enrollment succeeded",
            verification_succeeded: "One-time code verified",
            verification_failed: "One-time code rejected",
            rate_limited: "Verification attempt rate-limited",
            disabled: "Authenticator disabled",
          } satisfies Record<BrowserAuthEventKind, string>,
          channels: {
            browser: "Browser",
            mcp: "MCP approval",
            settings: "Settings",
          },
          approval: "Approval",
          all: "All events",
          empty:
            "No safe events yet. Create a controlled run to see its lifecycle here.",
          loading: "Loading safe events…",
          error: "Safe events could not be loaded. Try again later.",
          run: "Run",
          target: "Target",
          template: "Template",
          sequence: "Sequence",
          search: "Search event, run or related ID",
          source: "Source",
          authSource: "Authentication",
          runSource: "Runs",
          download: "Download filtered safe log",
          result: "Run result",
          timeout: "Timed out",
          period: "Time range",
          lastDay: "Last 24 hours",
          lastWeek: "Last 7 days",
          privacy:
            "Review related identifiers before sharing. The file contains no credentials, but may reveal activity times and relationships.",
          technical: "Technical identifiers",
          kinds: {
            authorization_revoked:
              "Stopped after authorization or policy became inactive",
            requested: "Request accepted",
            started: "Controlled run started",
            succeeded: "Controlled run completed",
            failed: "Controlled run did not pass",
            cancelled: "Run cancelled",
            interrupted: "Interrupted by service restart",
          } satisfies Record<SafeEventKind, string>,
        };
  const [events, setEvents] = useState<SafeEvent[]>([]);
  const [authEvents, setAuthEvents] = useState<BrowserAuthEvent[]>([]);
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [filter, setFilter] = useState<SafeEventKind | "all">("all");
  const [source, setSource] = useState<"all" | "auth" | "run">("all");
  const [query, setQuery] = useState("");
  const [period, setPeriod] = useState<"all" | "day" | "week">("all");
  const [result, setResult] = useState<
    "all" | "succeeded" | "failed" | "cancelled" | "timed_out"
  >("all");
  const [targetFilter, setTargetFilter] = useState("all");
  const [templateFilter, setTemplateFilter] = useState("all");
  const [visibleCount, setVisibleCount] = useState(100);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const formatEventTime = (value: number) =>
    new Intl.DateTimeFormat(language, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    }).format(value);
  const runMap = useMemo(
    () => new Map(runs.map((run) => [run.id, run])),
    [runs],
  );
  const templateMap = useMemo(
    () => new Map(templates.map((item) => [item.id, item.name])),
    [templates],
  );
  const targetMap = useMemo(
    () => new Map(targets.map((item) => [item.id, item.name])),
    [targets],
  );
  const needle = query.trim().toLocaleLowerCase();
  const since =
    period === "all"
      ? 0
      : Date.now() - (period === "day" ? 1 : 7) * 24 * 60 * 60 * 1000;
  const visibleEvents = events.filter(
    (event) =>
      event.created_at_unix_ms >= since &&
      (filter === "all" || event.kind === filter) &&
      (targetFilter === "all" ||
        runMap.get(event.run_id)?.target_id === targetFilter) &&
      (templateFilter === "all" ||
        (templateFilter === "one_time"
          ? !!runMap.get(event.run_id) &&
            !templateMap.has(runMap.get(event.run_id)!.action_template_id)
          : runMap.get(event.run_id)?.action_template_id === templateFilter)) &&
      (result === "all" ||
        (result === "timed_out"
          ? runMap.get(event.run_id)?.result_status === "timed_out"
          : runMap.get(event.run_id)?.state === result)) &&
      (!needle ||
        [
          event.kind,
          event.run_id,
          String(event.sequence),
          runMap.get(event.run_id)?.result_status ?? "",
          templateMap.get(runMap.get(event.run_id)?.action_template_id ?? "") ??
            "",
          targetMap.get(runMap.get(event.run_id)?.target_id ?? "") ?? "",
        ].some((value) => value.toLocaleLowerCase().includes(needle))),
  );
  const visibleAuthEvents = authEvents.filter(
    (event) =>
      result === "all" &&
      targetFilter === "all" &&
      templateFilter === "all" &&
      filter === "all" &&
      event.created_at_unix_ms >= since &&
      (!needle ||
        [event.kind, event.channel, event.approval_id ?? ""].some((value) =>
          value.toLocaleLowerCase().includes(needle),
        )),
  );

  async function refresh() {
    const [
      eventResponse,
      authResponse,
      runResponse,
      templateResponse,
      targetResponse,
    ] = await Promise.all([
      listSafeEvents(sessionToken),
      listBrowserAuthEvents(sessionToken),
      listSyntheticRuns(sessionToken),
      listActionTemplates(sessionToken),
      listTargets(sessionToken),
    ]);
    setEvents(eventResponse.items);
    setAuthEvents(authResponse.items);
    setRuns(runResponse.items);
    setTemplates(templateResponse.items);
    setTargets(targetResponse.items);
  }

  useEffect(() => {
    let active = true;
    refresh()
      .catch(() => {
        if (active) setError(text.error);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    const timer = window.setInterval(() => {
      void refresh().catch(() => {
        if (active) setError(text.error);
      });
    }, 2_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [sessionToken, text.error]);

  return (
    <section className="space-y-6">
      <header>
        <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
          {text.title}
        </h1>
        <p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">
          {text.subtitle}
        </p>
      </header>
      <div className="flex gap-3 border-l-4 border-indigo-400 bg-indigo-50 px-5 py-4 text-sm leading-6 text-indigo-950">
        <LockKeyhole className="mt-0.5 size-5 shrink-0" />
        <p className="m-0 font-medium">{text.policy}</p>
      </div>
      {source !== "run" &&
        result === "all" &&
        targetFilter === "all" &&
        templateFilter === "all" &&
        filter === "all" && (
          <section className="space-y-3">
            <h2 className="m-0 text-lg font-semibold text-slate-950">
              {text.authTitle}
            </h2>
            {visibleAuthEvents.length === 0 ? (
              <p className={emptyClass}>{text.authEmpty}</p>
            ) : (
              <ol className="enterprise-surface enterprise-table m-0 p-0">
                {visibleAuthEvents.slice(0, visibleCount).map((event) => (
                  <li key={event.id} className="list-none p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-950">
                        {text.authKinds[event.kind]}
                      </span>
                      <time className="text-xs text-slate-400">
                        {formatEventTime(event.created_at_unix_ms)}
                      </time>
                    </div>
                    <p className="mb-0 mt-2 text-xs text-slate-500">
                      {text.channels[event.channel]}
                    </p>
                    {event.approval_id && (
                      <details className="mt-2 text-xs text-slate-500">
                        <summary>{text.technical}</summary>
                        {text.approval}: {event.approval_id}
                      </details>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </section>
        )}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <label className="text-sm font-semibold text-slate-700">
          {text.source}
          <select
            value={source}
            onChange={(event) => setSource(event.target.value as typeof source)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            <option value="auth">{text.authSource}</option>
            <option value="run">{text.runSource}</option>
          </select>
        </label>
        <input
          aria-label={text.search}
          placeholder={text.search}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          className="min-w-64 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
        />
        <label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
          <Filter className="size-4" />
          <select
            value={filter}
            onChange={(event) =>
              setFilter(event.target.value as SafeEventKind | "all")
            }
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 outline-none focus:border-cyan-500"
          >
            <option value="all">{text.all}</option>
            {Object.entries(text.kinds).map(([kind, label]) => (
              <option key={kind} value={kind}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm font-semibold text-slate-700">
          {text.period}
          <select
            value={period}
            onChange={(event) => setPeriod(event.target.value as typeof period)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            <option value="day">{text.lastDay}</option>
            <option value="week">{text.lastWeek}</option>
          </select>
        </label>
        <label className="text-sm font-semibold text-slate-700">
          {text.result}
          <select
            value={result}
            onChange={(event) => setResult(event.target.value as typeof result)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            <option value="succeeded">{text.kinds.succeeded}</option>
            <option value="failed">{text.kinds.failed}</option>
            <option value="cancelled">{text.kinds.cancelled}</option>
            <option value="timed_out">{text.timeout}</option>
          </select>
        </label>
        <label className="text-sm font-semibold text-slate-700">
          {text.target}
          <select
            value={targetFilter}
            onChange={(event) => setTargetFilter(event.target.value)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            {targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm font-semibold text-slate-700">
          {text.template}
          <select
            value={templateFilter}
            onChange={(event) => setTemplateFilter(event.target.value)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            <option value="one_time">
              {zh ? "一次性操作" : "One-time operations"}
            </option>
            {templates.map((template) => (
              <option key={template.id} value={template.id}>
                {template.name}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => void refresh()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-600"
        >
          <RefreshCw className="size-4" />
          {events.length}
        </button>
        <button
          type="button"
          className="workbench-button"
          onClick={() => {
            const entries = [
              ...(source === "run"
                ? []
                : visibleAuthEvents.map((event) => ({
                    source: "authentication",
                    kind: event.kind,
                    channel: event.channel,
                    approval_id: event.approval_id,
                    created_at_unix_ms: event.created_at_unix_ms,
                  }))),
              ...(source === "auth"
                ? []
                : visibleEvents.map((event) => ({
                    source: "run",
                    kind: event.kind,
                    run_id: event.run_id,
                    sequence: event.sequence,
                    state: runMap.get(event.run_id)?.state ?? null,
                    result_status:
                      runMap.get(event.run_id)?.result_status ?? null,
                    created_at_unix_ms: event.created_at_unix_ms,
                  }))),
            ].sort((a, b) => a.created_at_unix_ms - b.created_at_unix_ms);
            saveDownload(
              new Blob(
                [
                  JSON.stringify(
                    {
                      format: "secretbridge-safe-log",
                      schema_version: 1,
                      exported_at_unix_ms: Date.now(),
                      filters: {
                        source,
                        kind: filter,
                        period,
                        result,
                        target_id: targetFilter === "all" ? null : targetFilter,
                        template_id:
                          templateFilter === "all" ? null : templateFilter,
                        keyword_applied: needle.length > 0,
                      },
                      entries,
                    },
                    null,
                    2,
                  ),
                ],
                { type: "application/json" },
              ),
              "secretbridge-safe-log.json",
            );
          }}
        >
          {text.download}
        </button>
      </div>
      <p className="text-xs text-slate-600">{text.privacy}</p>
      {error && (
        <p
          role="alert"
          className="border-l-4 border-rose-400 bg-rose-50 p-3 text-sm text-rose-800"
        >
          {error}
        </p>
      )}
      {source === "auth" ? null : loading ? (
        <p className={emptyClass}>{text.loading}</p>
      ) : visibleEvents.length === 0 ? (
        <p className={emptyClass}>{text.empty}</p>
      ) : (
        <ol className="enterprise-surface enterprise-table m-0 p-0">
          {visibleEvents.slice(0, visibleCount).map((event) => {
            const run = runMap.get(event.run_id);
            return (
              <li key={event.id} className="list-none p-5">
                <div className="flex items-start gap-4">
                  <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-slate-100 text-slate-600">
                    <FileClock className="size-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h2 className="m-0 text-sm font-semibold text-slate-950">
                        {event.kind === "failed" &&
                        run?.result_status === "timed_out"
                          ? text.timeout
                          : text.kinds[event.kind]}
                      </h2>
                      <time className="text-xs text-slate-400">
                        {formatEventTime(event.created_at_unix_ms)}
                      </time>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-500 sm:grid-cols-2">
                      <span className="truncate">
                        <strong>{text.template}：</strong>
                        {run
                          ? (templateMap.get(run.action_template_id) ??
                            (zh ? "一次性操作" : "One-time operation"))
                          : "—"}
                      </span>
                      <span className="truncate">
                        <strong>{text.target}：</strong>
                        {run ? (targetMap.get(run.target_id) ?? "—") : "—"}
                      </span>
                    </div>
                    <details className="mt-2 text-xs text-slate-500">
                      <summary>{text.technical}</summary>
                      {text.run}: {event.run_id} · {text.sequence}: #
                      {event.sequence}
                    </details>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {((source !== "auth" && visibleEvents.length > visibleCount) ||
        (source !== "run" && visibleAuthEvents.length > visibleCount)) && (
        <button
          type="button"
          className="workbench-button"
          onClick={() => setVisibleCount((count) => count + 100)}
        >
          {zh ? "加载更多" : "Load more"}
        </button>
      )}
    </section>
  );
}

const emptyClass = "enterprise-surface p-8 text-center text-sm text-slate-500";
