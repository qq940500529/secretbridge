// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FileClock, Filter, LockKeyhole, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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
  const visibleEvents =
    filter === "all" ? events : events.filter((event) => event.kind === filter);

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
      <section className="space-y-3">
        <h2 className="m-0 text-lg font-semibold text-slate-950">
          {text.authTitle}
        </h2>
        {authEvents.length === 0 ? (
          <p className={emptyClass}>{text.authEmpty}</p>
        ) : (
          <ol className="enterprise-surface enterprise-table m-0 p-0">
            {authEvents.map((event) => (
              <li key={event.id} className="list-none p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-950">
                    {text.authKinds[event.kind]}
                  </span>
                  <time className="text-xs text-slate-400">
                    {new Intl.DateTimeFormat(language, {
                      dateStyle: "medium",
                      timeStyle: "medium",
                    }).format(event.created_at_unix_ms)}
                  </time>
                </div>
                <p className="mb-0 mt-2 text-xs text-slate-500">
                  {text.channels[event.channel]}
                  {event.approval_id
                    ? ` · ${text.approval}: ${event.approval_id}`
                    : ""}
                </p>
              </li>
            ))}
          </ol>
        )}
      </section>
      <div className="flex flex-wrap items-center justify-between gap-3">
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
        <button
          type="button"
          onClick={() => void refresh()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-600"
        >
          <RefreshCw className="size-4" />
          {events.length}
        </button>
      </div>
      {error && (
        <p
          role="alert"
          className="border-l-4 border-rose-400 bg-rose-50 p-3 text-sm text-rose-800"
        >
          {error}
        </p>
      )}
      {loading ? (
        <p className={emptyClass}>{text.loading}</p>
      ) : visibleEvents.length === 0 ? (
        <p className={emptyClass}>{text.empty}</p>
      ) : (
        <ol className="enterprise-surface enterprise-table m-0 p-0">
          {visibleEvents.map((event) => {
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
                        {text.kinds[event.kind]}
                      </h2>
                      <time className="text-xs text-slate-400">
                        {new Intl.DateTimeFormat(language, {
                          dateStyle: "medium",
                          timeStyle: "medium",
                        }).format(event.created_at_unix_ms)}
                      </time>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-500 sm:grid-cols-2 lg:grid-cols-4">
                      <span>
                        <strong>{text.sequence}：</strong>#{event.sequence}
                      </span>
                      <span className="truncate">
                        <strong>{text.run}：</strong>
                        {event.run_id}
                      </span>
                      <span className="truncate">
                        <strong>{text.template}：</strong>
                        {run
                          ? (templateMap.get(run.action_template_id) ??
                            run.action_template_id)
                          : "—"}
                      </span>
                      <span className="truncate">
                        <strong>{text.target}：</strong>
                        {run
                          ? (targetMap.get(run.target_id) ?? run.target_id)
                          : "—"}
                      </span>
                    </div>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

const emptyClass = "enterprise-surface p-8 text-center text-sm text-slate-500";
