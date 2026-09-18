// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Ban, CircleDot, Clock3, PlayCircle, RefreshCw } from "lucide-react";
import { EditorDialog, MasterDetail } from "./Workbench";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useServiceChanges } from "./service-events";
import { RunOutputView } from "./RunOutputView";
import { authorizationLabel, retryGuidance } from "./parameters";
import { RunRequestKeys } from "./run-request";

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

export function OperationsView({
  language,
  sessionToken,
  initialTemplateId,
  historyOnly = false,
}: {
  language: Language;
  sessionToken: string;
  initialTemplateId?: string;
  historyOnly?: boolean;
}) {
  const text =
    language === "zh-CN"
      ? {
          title: "提交并观察受控运行",
          subtitle:
            "单次授权仅执行一次，限时授权可重复执行已确认的同一组参数。请求使用幂等键去重，运行状态和固定运行详情可持续查询。",
          safety:
            "PostgreSQL 运行只从本机凭据库读取密码，强制 TLS 完整验证和只读事务，执行固定 SELECT 1，并只返回结构化状态；命令任务按固定模板执行，返回过滤后的 stdout/stderr。",
          request: "新建运行请求",
          approval: "已批准的授权",
          choose: "请选择可用审批",
          none: "没有可用审批；请先批准一条尚未使用的申请。",
          submit: "启动受控运行",
          submitting: "正在提交…",
          runs: "运行记录",
          empty: "尚无运行记录。",
          loading: "正在读取运行状态…",
          loadError: "运行状态读取失败，请稍后重试。",
          requestError:
            "运行请求未完成或结果尚未确认，请检查运行记录；再次提交同一授权会复用请求键，不重复执行已受理请求。",
          cancelError: "取消结果尚未确认，请查询运行状态后再决定是否重试。",
          consumed: "该审批已被使用；列表已经刷新。",
          conflict: "运行已发生变化，列表已经刷新。",
          policyDenied:
            "模板或目标已变化，策略拒绝使用旧审批；请重新提交审批。",
          cancel: "取消运行",
          events: "运行详情",
          hideEvents: "收起事件",
          noEvents: "暂无运行详情。",
          version: "版本",
          approvalVersion: "审批版本",
          states: {
            queued: "已排队",
            running: "运行中",
            succeeded: "已成功",
            cancelled: "已取消",
            failed: "已中断",
          } satisfies Record<RunState, string>,
          results: {
            command_ok: "程序执行成功",
            command_failed: "程序执行失败",
            command_cleanup_failed: "临时凭据文件清理失败，请检查本机权限",
            synthetic_ok: "合成检查正常",
            postgres_connection_ok: "PostgreSQL 只读连接检查正常",
            postgres_connection_failed: "PostgreSQL 连接或固定探测失败",
            postgres_configuration_invalid: "PostgreSQL 安全配置无效",
            credential_unavailable: "凭据当前不可用",
            timed_out: "检查已超时",
            cancelled: "用户取消",
            service_restarted: "服务重启时中断",
            authorization_revoked: "授权或策略已失效，运行安全停止",
          } as Record<string, string>,
        }
      : {
          title: "Submit and observe controlled runs",
          subtitle:
            "Single-use approvals create one run; time-limited approvals repeat the same confirmed parameters. Idempotency keys deduplicate requests, while run status and fixed safe events remain queryable.",
          safety:
            "PostgreSQL runs read the password only from the local credential store, require full TLS verification and a read-only transaction, execute a fixed SELECT 1, and return structured status only. Command tasks execute the fixed template and return filtered stdout/stderr.",
          request: "New run request",
          approval: "Approved authorization",
          choose: "Choose an available approval",
          none: "No approval is available. Approve an unused request first.",
          submit: "Start controlled run",
          submitting: "Submitting…",
          runs: "Run records",
          empty: "No run records yet.",
          loading: "Loading run status…",
          loadError: "Run status could not be loaded. Try again later.",
          requestError:
            "The request did not complete or its outcome is unconfirmed. Check run records; resubmitting the same approval reuses its request key rather than repeating accepted work.",
          cancelError:
            "The cancellation outcome is unconfirmed. Check run status before retrying.",
          consumed:
            "That approval was already used. The list has been refreshed.",
          conflict: "The run changed. The list has been refreshed.",
          policyDenied:
            "The template or target changed. Policy denied the stale approval; submit a new approval.",
          cancel: "Cancel run",
          events: "Run details",
          hideEvents: "Hide events",
          noEvents: "No safe events yet.",
          version: "Version",
          approvalVersion: "Approval version",
          states: {
            queued: "Queued",
            running: "Running",
            succeeded: "Succeeded",
            cancelled: "Cancelled",
            failed: "Interrupted",
          } satisfies Record<RunState, string>,
          results: {
            command_ok: "Program completed",
            command_failed: "Program failed",
            command_cleanup_failed:
              "Temporary credential cleanup failed; check local permissions",
            synthetic_ok: "Synthetic check OK",
            postgres_connection_ok: "PostgreSQL read-only connection check OK",
            postgres_connection_failed:
              "PostgreSQL connection or fixed probe failed",
            postgres_configuration_invalid:
              "PostgreSQL security configuration is invalid",
            credential_unavailable: "Credential is unavailable",
            timed_out: "Check timed out",
            cancelled: "Cancelled by user",
            service_restarted: "Interrupted by service restart",
            authorization_revoked:
              "Stopped because authorization or policy is no longer active",
          } as Record<string, string>,
        };
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [requestOpen, setRequestOpen] = useState(false);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [approvalId, setApprovalId] = useState("");
  const requestKeys = useRef(new RunRequestKeys());
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [events, setEvents] = useState<Record<string, SafeEvent[]>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const templateNames = useMemo(
    () => new Map(templates.map((item) => [item.id, item.name])),
    [templates],
  );
  const targetNames = useMemo(
    () => new Map(targets.map((item) => [item.id, item.name])),
    [targets],
  );
  const usedApprovals = useMemo(
    () => new Set(runs.map((run) => run.approval_id)),
    [runs],
  );
  const availableApprovals = useMemo(
    () =>
      approvals.filter(
        (approval) =>
          approval.state === "approved" &&
          approval.expires_at_unix_ms > now &&
          (!initialTemplateId ||
            approval.action_template_id === initialTemplateId) &&
          approval.action_template_id &&
          (approval.authorization_mode === "time_window" ||
            !usedApprovals.has(approval.id)),
      ),
    [approvals, usedApprovals, now, initialTemplateId],
  );

  const selectedApproval = availableApprovals.find((a) => a.id === approvalId);

  async function refresh() {
    const [runResponse, approvalResponse, templateResponse, targetResponse] =
      await Promise.all([
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
    setApprovalId((current) =>
      approvalResponse.items.some(
        (item) =>
          item.id === current &&
          item.state === "approved" &&
          item.expires_at_unix_ms > Date.now() &&
          (!initialTemplateId ||
            item.action_template_id === initialTemplateId) &&
          (item.authorization_mode === "time_window" || !used.has(item.id)),
      )
        ? current
        : (approvalResponse.items.find(
            (item) =>
              item.state === "approved" &&
              item.expires_at_unix_ms > Date.now() &&
              (!initialTemplateId ||
                item.action_template_id === initialTemplateId) &&
              item.action_template_id &&
              (item.authorization_mode === "time_window" || !used.has(item.id)),
          )?.id ?? ""),
    );
  }

  useEffect(() => {
    let active = true;
    refresh()
      .catch(() => {
        if (active) setError(text.loadError);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [sessionToken, text.loadError]);

  useServiceChanges(sessionToken, () => {
    void refresh().catch(() => setError(text.loadError));
    if (expandedRunId)
      void loadEvents(expandedRunId).catch(() => setError(text.loadError));
  });

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!selectedApproval) return;
    setBusy(true);
    setError(null);
    try {
      const response = await createSyntheticRun(
        sessionToken,
        approvalId,
        requestKeys.current.forApproval(approvalId),
      );
      requestKeys.current.acknowledge(approvalId);
      setRuns((current) => [
        response.run,
        ...current.filter((item) => item.id !== response.run.id),
      ]);
      setApprovalId("");
      setRequestOpen(false);
      setExpandedRunId(response.run.id);
      void loadEvents(response.run.id).catch(() => setError(text.loadError));
      await refresh().catch(() => setError(text.loadError));
    } catch (caught) {
      if (
        caught instanceof SecretBridgeApiError &&
        ["approval_consumed", "idempotency_conflict"].includes(caught.code)
      ) {
        await refresh().catch(() => undefined);
        setError(text.consumed);
      } else if (
        caught instanceof SecretBridgeApiError &&
        caught.code === "policy_denied"
      ) {
        await refresh().catch(() => undefined);
        setError(text.policyDenied);
      } else {
        setError(text.requestError);
      }
    } finally {
      setBusy(false);
    }
  }

  async function cancel(run: SyntheticRun) {
    setBusy(true);
    setError(null);
    try {
      const updated = await cancelSyntheticRun(
        sessionToken,
        run.id,
        run.version,
      );
      setRuns((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      if (expandedRunId === run.id) await loadEvents(run.id);
    } catch (caught) {
      if (
        caught instanceof SecretBridgeApiError &&
        ["version_conflict", "invalid_run_transition"].includes(caught.code)
      ) {
        await refresh().catch(() => undefined);
        setError(text.conflict);
      } else {
        setError(text.cancelError);
      }
    } finally {
      setBusy(false);
    }
  }

  async function loadEvents(runId: string) {
    const response = await listRunSafeEvents(sessionToken, runId);
    setEvents((current) => ({ ...current, [runId]: response.items }));
  }

  async function toggleEvents(runId: string) {
    if (expandedRunId === runId) {
      setExpandedRunId(null);
      return;
    }
    setExpandedRunId(runId);
    try {
      await loadEvents(runId);
    } catch {
      setError(text.loadError);
    }
  }

  return (
    <section className="space-y-6">
      <header>
        <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
          {historyOnly
            ? language === "zh-CN"
              ? "执行历史"
              : "Run history"
            : language === "zh-CN"
              ? "执行与结果"
              : "Execution & results"}
        </h1>
        <p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">
          {text.subtitle}
        </p>
      </header>
      {!historyOnly && (
        <EditorDialog
          title={text.request}
          open={requestOpen}
          onOpen={() => setRequestOpen(true)}
          onClose={() => setRequestOpen(false)}
          busy={busy}
        >
          {error && (
            <p role="alert" className="px-5 text-sm text-rose-700">
              {error}
            </p>
          )}
          <form
            onSubmit={submit}
            className="border-t border-slate-200 px-5 py-5"
          >
            <div className="flex flex-col gap-3 sm:flex-row">
              <label className="flex-1 text-sm font-semibold text-slate-700">
                <span className="mb-2 block">{text.approval}</span>
                <select
                  required
                  value={approvalId}
                  onChange={(event) => setApprovalId(event.target.value)}
                  className={inputClass}
                >
                  <option value="">{text.choose}</option>
                  {availableApprovals.map((approval) => (
                    <option key={approval.id} value={approval.id}>
                      {approval.action_template_id
                        ? templateNames.get(approval.action_template_id)
                        : approval.operation}{" "}
                      · {targetNames.get(approval.target_id)} ·{" "}
                      {text.approvalVersion} {approval.version}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="submit"
                disabled={!selectedApproval || busy}
                className="mt-auto inline-flex h-[42px] items-center justify-center gap-2 rounded-lg bg-slate-950 px-5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50"
              >
                <PlayCircle className="size-4" />
                {busy ? text.submitting : text.submit}
              </button>
            </div>
            {selectedApproval && (
              <div className="mt-3 text-xs text-slate-600">
                <p>
                  {authorizationLabel(
                    selectedApproval.authorization_mode,
                    language === "zh-CN",
                  )}
                </p>
                <pre className="whitespace-pre-wrap break-all">
                  {JSON.stringify(selectedApproval.parameters, null, 2)}
                </pre>
              </div>
            )}
            {availableApprovals.length === 0 && !loading && (
              <p className="mb-0 mt-3 text-sm text-amber-700">{text.none}</p>
            )}
          </form>
        </EditorDialog>
      )}

      <div>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="m-0 text-lg font-semibold text-slate-950">
            {text.runs}
          </h2>
          <button
            type="button"
            onClick={() => void refresh().catch(() => setError(text.loadError))}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-600"
          >
            <RefreshCw className="size-3.5" />
            {runs.length}
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
        ) : runs.length === 0 ? (
          <p className={emptyClass}>{text.empty}</p>
        ) : (
          <MasterDetail
            language={language}
            selectedId={expandedRunId ?? undefined}
            onSelect={(id) => {
              setExpandedRunId(id);
              void loadEvents(id).catch(() => setError(text.loadError));
            }}
            items={runs.map((run) => ({
              id: run.id,
              name: templateNames.get(run.action_template_id) ?? run.operation,
              detail: `${targetNames.get(run.target_id) ?? run.target_id} · ${text.states[run.state]}`,
            }))}
          >
            {runs.map((run) => (
              <article key={run.id} className="p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded-full px-2.5 py-1 text-xs font-semibold ${stateStyles[run.state]}`}
                      >
                        <CircleDot
                          className={`mr-1 inline size-3 ${run.state === "running" ? "animate-pulse" : ""}`}
                        />
                        {text.states[run.state]}
                      </span>
                      <span className="text-xs font-medium text-slate-500">
                        {templateNames.get(run.action_template_id) ??
                          run.operation}
                      </span>
                    </div>
                    <h3 className="mb-0 mt-2 text-base font-semibold text-slate-950">
                      {targetNames.get(run.target_id) ?? run.target_id}
                    </h3>
                    <p className="mb-0 mt-2 text-xs text-slate-500">
                      <Clock3 className="mr-1 inline size-3.5" />
                      {new Intl.DateTimeFormat(language, {
                        dateStyle: "medium",
                        timeStyle: "medium",
                      }).format(run.updated_at_unix_ms)}{" "}
                      · {text.version} {run.version}
                    </p>
                    {run.started_at_unix_ms && (
                      <p className="mt-2 text-xs text-slate-500">
                        {language === "zh-CN" ? "耗时" : "Duration"} ·{" "}
                        {Math.max(
                          0,
                          ((run.finished_at_unix_ms ?? now) -
                            run.started_at_unix_ms) /
                            1000,
                        ).toFixed(1)}
                        s
                      </p>
                    )}
                    {retryGuidance(run.result_status, language === "zh-CN") && (
                      <p className="mt-2 text-xs leading-5 text-amber-800">
                        {retryGuidance(run.result_status, language === "zh-CN")}
                      </p>
                    )}
                    {run.result_status && (
                      <p className="mb-0 mt-2 text-sm font-medium text-slate-600">
                        {text.results[run.result_status] ?? run.result_status}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => void toggleEvents(run.id)}
                      className="text-sm font-semibold text-cyan-700"
                    >
                      {expandedRunId === run.id ? text.hideEvents : text.events}
                    </button>
                    {(run.state === "queued" || run.state === "running") && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void cancel(run)}
                        className="inline-flex items-center gap-2 rounded-lg border border-rose-300 px-3.5 py-2 text-sm font-semibold text-rose-700 hover:bg-rose-50 disabled:opacity-50"
                      >
                        <Ban className="size-4" />
                        {text.cancel}
                      </button>
                    )}
                  </div>
                </div>
                {expandedRunId === run.id && (
                  <pre className="mt-3 whitespace-pre-wrap break-all text-xs text-slate-600">
                    {JSON.stringify(
                      approvals.find((a) => a.id === run.approval_id)
                        ?.parameters,
                      null,
                      2,
                    )}
                  </pre>
                )}
                {run.operation === "command_execution" &&
                  expandedRunId === run.id && (
                    <RunOutputView
                      key={run.id}
                      id={run.id}
                      sessionToken={sessionToken}
                      language={language}
                    />
                  )}
                {expandedRunId === run.id && (
                  <div className="mt-4 divide-y divide-slate-200 border-t border-slate-200">
                    {(events[run.id] ?? []).length === 0 ? (
                      <p className="m-0 py-3 text-sm text-slate-500">
                        {text.noEvents}
                      </p>
                    ) : (
                      events[run.id].map((item) => (
                        <div
                          key={item.id}
                          className="grid gap-1 py-3 text-sm sm:grid-cols-[4rem_1fr_auto]"
                        >
                          <span className="font-mono text-xs font-bold text-slate-500">
                            #{item.sequence}
                          </span>
                          <p className="m-0 font-medium text-slate-700">
                            {item.message}
                          </p>
                          <p className="m-0 text-xs text-slate-400">
                            {new Intl.DateTimeFormat(language, {
                              timeStyle: "medium",
                            }).format(item.created_at_unix_ms)}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </article>
            ))}
          </MasterDetail>
        )}
      </div>
    </section>
  );
}

const inputClass =
  "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";
const emptyClass = "enterprise-surface p-6 text-sm text-slate-500";
