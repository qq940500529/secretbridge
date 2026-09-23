// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FileClock, Filter, LockKeyhole, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { saveDownload } from "./DataMaintenanceView";
import { RunOutputView } from "./RunOutputView";
import {
  renderSafeLog,
  type SafeLogEntry,
  type SafeLogFormat,
  type SafeLogMetadata,
} from "./safeLogExport";

import {
  type ActionTemplate,
  type Approval,
  type ApprovalState,
  type AuthorizationMode,
  type BrowserAuthEvent,
  type BrowserAuthEventKind,
  type SafeEvent,
  type SafeEventKind,
  type SyntheticRun,
  type Target,
  listActionTemplates,
  listApprovals,
  listBrowserAuthEvents,
  listSafeEvents,
  listSyntheticRuns,
  listTargets,
} from "./api";

type Language = "zh-CN" | "en";
type LogKind = SafeEventKind | BrowserAuthEventKind | ApprovalState | "all";
type TimelineItem =
  | { source: "authentication"; event: BrowserAuthEvent; at: number }
  | { source: "approval"; event: Approval; at: number }
  | { source: "run"; event: SafeEvent; at: number };

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
          title: "安全日志",
          subtitle:
            "按时间查看审批当前状态、身份验证事件和运行事件；运行输出可在对应记录中单独展开。",
          policy:
            "安全日志导出只包含固定状态、代码、时间和关联 ID，不包含命令、业务数据、验证码或凭据。审批行是当前状态快照，不代表完整的审批状态变更历史。",
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
          all: "全部",
          empty: "当前筛选范围内没有安全日志。",
          loading: "正在读取安全事件…",
          error: "安全事件读取失败，请稍后重试。",
          run: "运行",
          target: "目标",
          template: "模板",
          sequence: "序号",
          search: "搜索事件、运行或关联 ID",
          source: "来源",
          authSource: "身份验证",
          approvalSource: "审批",
          runSource: "运行",
          approvalStates: {
            pending: "待审批",
            approved: "已批准",
            denied: "已拒绝",
            revoked: "已撤销",
            expired: "已过期",
          },
          download: "下载已筛选安全日志",
          exportFormat: "导出格式",
          result: "运行结果",
          errorCode: "错误代码",
          timeout: "超时",
          period: "时间范围",
          lastDay: "最近 24 小时",
          lastWeek: "最近 7 天",
          privacy:
            "导出前请检查关联标识；文件不含凭据，但可能反映你的操作时间与关系。",
          technical: "技术标识",
          approvalMode: "授权方式",
          approvalModes: {
            once: "单次",
            every_run: "逐次",
            time_window: "限时",
          },
          output: "查看此运行输出",
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
          title: "Safe log",
          subtitle:
            "Browse current approval states, authentication events and run events by time. Open retained run output from its event.",
          policy:
            "Safe log exports contain only fixed states, codes, times and related IDs, without commands, business data, one-time codes or credentials. Approval rows show current snapshots rather than every state transition.",
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
          all: "All",
          empty: "No safe log entries match the current filters.",
          loading: "Loading safe events…",
          error: "Safe events could not be loaded. Try again later.",
          run: "Run",
          target: "Target",
          template: "Template",
          sequence: "Sequence",
          search: "Search event, run or related ID",
          source: "Source",
          authSource: "Authentication",
          approvalSource: "Approvals",
          runSource: "Runs",
          approvalStates: {
            pending: "Pending",
            approved: "Approved",
            denied: "Denied",
            revoked: "Revoked",
            expired: "Expired",
          },
          download: "Download filtered safe log",
          exportFormat: "Export format",
          result: "Run result",
          errorCode: "Error code",
          timeout: "Timed out",
          period: "Time range",
          lastDay: "Last 24 hours",
          lastWeek: "Last 7 days",
          privacy:
            "Review related identifiers before sharing. The file contains no credentials, but may reveal activity times and relationships.",
          technical: "Technical identifiers",
          approvalMode: "Approval mode",
          approvalModes: {
            once: "Once",
            every_run: "Every run",
            time_window: "Time window",
          },
          output: "View this run's output",
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
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [filter, setFilter] = useState<LogKind>("all");
  const [source, setSource] = useState<"all" | "auth" | "approval" | "run">(
    "all",
  );
  const [query, setQuery] = useState("");
  const [period, setPeriod] = useState<"all" | "day" | "week">("all");
  const [result, setResult] = useState<
    "all" | "succeeded" | "failed" | "cancelled" | "timed_out"
  >("all");
  const [targetFilter, setTargetFilter] = useState("all");
  const [templateFilter, setTemplateFilter] = useState("all");
  const [errorCodeFilter, setErrorCodeFilter] = useState("all");
  const [approvalModeFilter, setApprovalModeFilter] = useState<
    AuthorizationMode | "all"
  >("all");
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);
  const [authRetentionTruncated, setAuthRetentionTruncated] = useState(false);
  const [visibleCount, setVisibleCount] = useState(100);
  const [exportFormat, setExportFormat] = useState<SafeLogFormat>("json");
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
  const approvalRunMap = useMemo(() => {
    const related = new Map<string, SyntheticRun | null>();
    for (const run of runs) {
      related.set(run.approval_id, related.has(run.approval_id) ? null : run);
    }
    return related;
  }, [runs]);
  const approvalMap = useMemo(
    () => new Map(approvals.map((approval) => [approval.id, approval])),
    [approvals],
  );
  const templateMap = useMemo(
    () => new Map(templates.map((item) => [item.id, item.name])),
    [templates],
  );
  const targetMap = useMemo(
    () => new Map(targets.map((item) => [item.id, item.name])),
    [targets],
  );
  const errorCodes = useMemo(
    () =>
      [
        ...new Set(
          runs
            .filter((run) => run.state === "failed")
            .map((run) => run.result_status)
            .filter((code) => code !== null),
        ),
      ].sort(),
    [runs],
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
      (approvalModeFilter === "all" ||
        approvalMap.get(runMap.get(event.run_id)?.approval_id ?? "")
          ?.authorization_mode === approvalModeFilter) &&
      (errorCodeFilter === "all" ||
        runMap.get(event.run_id)?.result_status === errorCodeFilter) &&
      (!needle ||
        [
          event.kind,
          event.run_id,
          runMap.get(event.run_id)?.approval_id ?? "",
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
      errorCodeFilter === "all" &&
      targetFilter === "all" &&
      templateFilter === "all" &&
      approvalModeFilter === "all" &&
      (filter === "all" || event.kind === filter) &&
      event.created_at_unix_ms >= since &&
      (!needle ||
        [
          event.kind,
          event.channel,
          event.approval_id ?? "",
          event.approval_id
            ? (approvalRunMap.get(event.approval_id)?.id ?? "")
            : "",
        ].some((value) => value.toLocaleLowerCase().includes(needle))),
  );
  const visibleApprovals = approvals.filter(
    (approval) =>
      result === "all" &&
      errorCodeFilter === "all" &&
      (filter === "all" || approval.state === filter) &&
      approval.updated_at_unix_ms >= since &&
      (targetFilter === "all" || approval.target_id === targetFilter) &&
      (templateFilter === "all" ||
        approval.action_template_id === templateFilter ||
        (templateFilter === "one_time" && !approval.action_template_id)) &&
      (approvalModeFilter === "all" ||
        approval.authorization_mode === approvalModeFilter) &&
      (!needle ||
        [
          approval.id,
          approval.state,
          approval.action_template_id ?? "",
          templateMap.get(approval.action_template_id ?? "") ?? "",
          targetMap.get(approval.target_id) ?? "",
        ].some((value) => value.toLocaleLowerCase().includes(needle))),
  );
  const timeline: TimelineItem[] = [
    ...(source === "run" || source === "approval"
      ? []
      : visibleAuthEvents.map((event) => ({
          source: "authentication" as const,
          event,
          at: event.created_at_unix_ms,
        }))),
    ...(source === "auth" || source === "approval"
      ? []
      : visibleEvents.map((event) => ({
          source: "run" as const,
          event,
          at: event.created_at_unix_ms,
        }))),
    ...(source === "auth" || source === "run"
      ? []
      : visibleApprovals.map((event) => ({
          source: "approval" as const,
          event,
          at: event.updated_at_unix_ms,
        }))),
  ].sort((a, b) => b.at - a.at);

  async function refresh() {
    const [
      eventResponse,
      authResponse,
      runResponse,
      templateResponse,
      targetResponse,
      approvalResponse,
    ] = await Promise.all([
      listSafeEvents(sessionToken),
      listBrowserAuthEvents(sessionToken),
      listSyntheticRuns(sessionToken),
      listActionTemplates(sessionToken),
      listTargets(sessionToken),
      listApprovals(sessionToken),
    ]);
    setEvents(eventResponse.items);
    setAuthEvents(authResponse.items);
    setAuthRetentionTruncated(authResponse.retention_truncated);
    setRuns(runResponse.items);
    setTemplates(templateResponse.items);
    setTargets(targetResponse.items);
    setApprovals(approvalResponse.items);
    setError(null);
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
    }, 10_000);
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
            <option value="approval">{text.approvalSource}</option>
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
            onChange={(event) => setFilter(event.target.value as LogKind)}
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 outline-none focus:border-cyan-500"
          >
            <option value="all">{text.all}</option>
            {Object.entries(text.kinds).map(([kind, label]) => (
              <option key={kind} value={kind}>
                {label}
              </option>
            ))}
            {Object.entries(text.authKinds).map(([kind, label]) => (
              <option key={kind} value={kind}>
                {label}
              </option>
            ))}
            {Object.entries(text.approvalStates).map(([kind, label]) => (
              <option key={kind} value={kind}>
                {text.approval}: {label}
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
          {text.errorCode}
          <select
            value={errorCodeFilter}
            onChange={(event) => setErrorCodeFilter(event.target.value)}
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            {errorCodes.map((code) => (
              <option key={code} value={code}>
                {code}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm font-semibold text-slate-700">
          {text.approvalMode}
          <select
            value={approvalModeFilter}
            onChange={(event) =>
              setApprovalModeFilter(
                event.target.value as typeof approvalModeFilter,
              )
            }
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="all">{text.all}</option>
            {Object.entries(text.approvalModes).map(([mode, label]) => (
              <option key={mode} value={mode}>
                {label}
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
          aria-label={zh ? "刷新安全事件" : "Refresh safe events"}
          onClick={() => void refresh().catch(() => setError(text.error))}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-600"
        >
          <RefreshCw className="size-4" />
          {events.length}
        </button>
        <label className="text-sm font-semibold text-slate-700">
          {text.exportFormat}
          <select
            value={exportFormat}
            onChange={(event) =>
              setExportFormat(event.target.value as typeof exportFormat)
            }
            className="ml-2 rounded-xl border border-slate-200 bg-white px-3 py-2"
          >
            <option value="json">JSON</option>
            <option value="jsonl">JSONL</option>
            <option value="csv">CSV</option>
          </select>
        </label>
        <button
          type="button"
          className="workbench-button"
          onClick={() => {
            const entries: SafeLogEntry[] = timeline
              .map((item): SafeLogEntry => {
                if (item.source === "authentication") {
                  const event = item.event;
                  return {
                    source: "authentication",
                    kind: event.kind,
                    channel: event.channel,
                    approval_id: event.approval_id ?? null,
                    run_id: event.approval_id
                      ? (approvalRunMap.get(event.approval_id)?.id ?? null)
                      : null,
                    terminal_id: null,
                    sequence: null,
                    state: null,
                    result_status: null,
                    authorization_mode: event.approval_id
                      ? (approvalMap.get(event.approval_id)
                          ?.authorization_mode ?? null)
                      : null,
                    created_at_unix_ms: item.at,
                  };
                }
                if (item.source === "approval") {
                  const approval = item.event;
                  return {
                    source: "approval",
                    kind: approval.state,
                    channel: null,
                    approval_id: approval.id,
                    run_id: approvalRunMap.get(approval.id)?.id ?? null,
                    terminal_id: null,
                    sequence: null,
                    state: approval.state,
                    result_status: null,
                    authorization_mode: approval.authorization_mode,
                    created_at_unix_ms: item.at,
                  };
                }
                const event = item.event;
                const run = runMap.get(event.run_id);
                return {
                  source: "run",
                  kind: event.kind,
                  channel: null,
                  approval_id: run?.approval_id ?? null,
                  run_id: event.run_id,
                  terminal_id: event.terminal_id,
                  sequence: event.sequence,
                  state: run?.state ?? null,
                  result_status: run?.result_status ?? null,
                  authorization_mode:
                    approvalMap.get(run?.approval_id ?? "")
                      ?.authorization_mode ?? null,
                  created_at_unix_ms: item.at,
                };
              })
              .reverse();
            const metadata: SafeLogMetadata = {
              format: "secretbridge-safe-log",
              schema_version: 3,
              exported_at_unix_ms: Date.now(),
              fetched_event_counts: {
                authentication: authEvents.length,
                approval: approvals.length,
                run: events.length,
              },
              truncation: authRetentionTruncated
                ? "authentication_retention_window"
                : "complete",
              filters: {
                source,
                kind: filter,
                period,
                result,
                authorization_mode: approvalModeFilter,
                error_code: errorCodeFilter === "all" ? null : errorCodeFilter,
                target_id: targetFilter === "all" ? null : targetFilter,
                template_id: templateFilter === "all" ? null : templateFilter,
                keyword_applied: needle.length > 0,
              },
            };
            const content = renderSafeLog(exportFormat, metadata, entries);
            saveDownload(
              new Blob([content], {
                type: exportFormat === "csv" ? "text/csv" : "application/json",
              }),
              `secretbridge-safe-log.${exportFormat}`,
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
      {loading ? (
        <p className={emptyClass}>{text.loading}</p>
      ) : timeline.length === 0 ? (
        <p className={emptyClass}>{text.empty}</p>
      ) : (
        <ol
          className="enterprise-surface enterprise-table m-0 p-0"
          aria-label={zh ? "安全日志时间线" : "Safe log timeline"}
        >
          {timeline.slice(0, visibleCount).map((item) => {
            if (item.source === "authentication") {
              const event = item.event;
              const negative =
                event.kind === "verification_failed" ||
                event.kind === "rate_limited";
              return (
                <li key={`auth-${event.id}`} className="list-none p-5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <strong
                      className={
                        negative ? "text-rose-700" : "text-emerald-700"
                      }
                    >
                      {text.authKinds[event.kind]}
                    </strong>
                    <time className="text-xs text-slate-500">
                      {formatEventTime(item.at)}
                    </time>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    {text.channels[event.channel]}
                  </p>
                  {event.approval_id && (
                    <details className="text-xs text-slate-500">
                      <summary>{text.technical}</summary>
                      {text.approval}: {event.approval_id} · {text.run}:{" "}
                      {approvalRunMap.get(event.approval_id)?.id ?? "—"}
                    </details>
                  )}
                </li>
              );
            }
            if (item.source === "approval") {
              const approval = item.event;
              const tone =
                approval.state === "approved"
                  ? "text-emerald-700"
                  : approval.state === "pending"
                    ? "text-amber-700"
                    : "text-rose-700";
              return (
                <li key={`approval-${approval.id}`} className="list-none p-5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <strong className={tone}>
                      {text.approval}: {text.approvalStates[approval.state]}
                    </strong>
                    <time className="text-xs text-slate-500">
                      {formatEventTime(item.at)}
                    </time>
                  </div>
                  <p className="mt-2 text-xs text-slate-600">
                    {templateMap.get(approval.action_template_id ?? "") ??
                      (zh ? "一次性操作" : "One-time operation")}
                    {" · "}
                    {targetMap.get(approval.target_id) ?? "—"}
                    {" · "}
                    {text.approvalModes[approval.authorization_mode]}
                  </p>
                  <details className="text-xs text-slate-500">
                    <summary>{text.technical}</summary>
                    {text.approval}: {approval.id} · {text.run}:{" "}
                    {approvalRunMap.get(approval.id)?.id ?? "—"}
                  </details>
                </li>
              );
            }
            const event = item.event;
            const run = runMap.get(event.run_id);
            const tone =
              run?.result_status === "timed_out"
                ? "text-amber-700"
                : event.kind === "succeeded"
                  ? "text-emerald-700"
                  : event.kind === "failed" ||
                      event.kind === "authorization_revoked"
                    ? "text-rose-700"
                    : "text-slate-700";
            return (
              <li key={`run-${event.id}`} className="list-none p-5">
                <div className="flex items-start gap-4">
                  <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-slate-100 text-slate-600">
                    <FileClock className="size-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h2 className={`m-0 text-sm font-semibold ${tone}`}>
                        {event.kind === "failed" &&
                        run?.result_status === "timed_out"
                          ? text.timeout
                          : text.kinds[event.kind]}
                      </h2>
                      <time className="text-xs text-slate-400">
                        {formatEventTime(item.at)}
                      </time>
                    </div>
                    <div className="mt-2 grid gap-2 text-xs text-slate-500 sm:grid-cols-2">
                      <span>
                        <strong>{text.template}：</strong>
                        {run
                          ? (templateMap.get(run.action_template_id) ??
                            (zh ? "一次性操作" : "One-time operation"))
                          : "—"}
                      </span>
                      <span>
                        <strong>{text.target}：</strong>
                        {run ? (targetMap.get(run.target_id) ?? "—") : "—"}
                      </span>
                    </div>
                    <details className="mt-2 text-xs text-slate-500">
                      <summary>{text.technical}</summary>
                      {text.run}: {event.run_id} · {text.sequence}: #
                      {event.sequence} · {text.approval}:{" "}
                      {run?.approval_id ?? "—"}
                      {event.terminal_id && (
                        <>
                          {" · "}
                          {zh ? "终端" : "Terminal"}: {event.terminal_id}
                        </>
                      )}
                    </details>
                    {run?.operation === "command_execution" && (
                      <button
                        type="button"
                        className="mt-2 text-xs font-semibold text-cyan-700 underline"
                        onClick={() =>
                          setExpandedEventId(
                            expandedEventId === event.id ? null : event.id,
                          )
                        }
                      >
                        {text.output}
                      </button>
                    )}
                    {run && expandedEventId === event.id && (
                      <RunOutputView
                        id={run.id}
                        sessionToken={sessionToken}
                        language={language}
                      />
                    )}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {timeline.length > visibleCount && (
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
