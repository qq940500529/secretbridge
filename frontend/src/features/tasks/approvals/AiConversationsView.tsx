// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type AiConversation,
  type Approval,
  type ConversationApprovalPolicy,
  type SyntheticRun,
  listAiConversations,
  listApprovals,
  listSyntheticRuns,
  setAiConversationPolicy,
} from "../../../api/index";
import { useServiceChanges } from "../../../app/service-events";

type Language = "zh-CN" | "en";
const RISK_ACK = "allow_all_operations_in_this_ai_conversation";

function activeGrant(item: AiConversation, now: number): boolean {
  return (
    item.approval_policy === "conversation_once" &&
    (item.grant_expires_at_unix_ms ?? 0) > now
  );
}

export function ActiveConversationRisk({
  sessionToken,
  language,
}: {
  sessionToken: string;
  language: Language;
}) {
  const [items, setItems] = useState<AiConversation[]>([]);
  const [now, setNow] = useState(Date.now());
  const reload = useCallback(() => {
    void listAiConversations(sessionToken)
      .then((result) => setItems(result.items))
      .catch(() => setItems([]));
  }, [sessionToken]);
  useEffect(reload, [reload]);
  useServiceChanges(sessionToken, reload);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 10_000);
    return () => window.clearInterval(timer);
  }, []);
  const count = items.filter((item) => activeGrant(item, now)).length;
  if (count === 0) return null;
  return (
    <div
      role="alert"
      className="rounded-lg border-2 border-rose-600 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-900"
    >
      {language === "zh-CN"
        ? `高风险：${count} 个 AI 会话已允许所有操作，直到授权到期或手动撤销。`
        : `HIGH RISK: ${count} AI conversation(s) may perform all operations until expiry or revocation.`}
    </div>
  );
}

export function AiConversationsView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const [conversations, setConversations] = useState<AiConversation[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [riskConfirmed, setRiskConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const reload = useCallback(async () => {
    try {
      const [c, a, r] = await Promise.all([
        listAiConversations(sessionToken),
        listApprovals(sessionToken),
        listSyntheticRuns(sessionToken),
      ]);
      setConversations(c.items);
      setApprovals(a.items);
      setRuns(r.items);
      setError(null);
    } catch {
      setError(
        zh
          ? "会话记录读取失败，请重试。"
          : "Could not load conversations. Retry.",
      );
    } finally {
      setLoading(false);
    }
  }, [sessionToken, zh]);
  useEffect(() => {
    void reload();
  }, [reload]);
  useServiceChanges(sessionToken, () => {
    void reload();
  });
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 10_000);
    return () => window.clearInterval(timer);
  }, []);
  const selected =
    conversations.find((item) => item.id === selectedId) ?? conversations[0];
  const tasks = useMemo(() => {
    if (!selected) return [];
    return approvals
      .filter((item) => item.conversation_id === selected.id)
      .sort((a, b) => a.created_at_unix_ms - b.created_at_unix_ms);
  }, [approvals, selected]);
  const taskIds = useMemo(() => new Set(tasks.map((item) => item.id)), [tasks]);
  const selectedRuns = runs.filter((item) => taskIds.has(item.approval_id));

  async function changePolicy(policy: ConversationApprovalPolicy) {
    if (!selected || busy || (policy === "conversation_once" && !riskConfirmed))
      return;
    setBusy(true);
    setError(null);
    try {
      await setAiConversationPolicy(sessionToken, selected.id, {
        expected_version: selected.version,
        approval_policy: policy,
        ...(policy === "conversation_once"
          ? { risk_acknowledgement: RISK_ACK }
          : {}),
      });
      setRiskConfirmed(false);
      await reload();
    } catch {
      setError(
        zh
          ? "策略未更新；会话状态可能已变化，请重试。"
          : "Policy not updated; the conversation may have changed. Retry.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="space-y-5">
      <div>
        <h2 className="m-0 text-2xl font-semibold text-slate-950">
          {zh ? "AI 会话与任务" : "AI conversations and tasks"}
        </h2>
        <p className="mt-2 text-sm text-slate-600">
          {zh
            ? "每段会话有独立 ID 和摘要；审批及执行记录按会话汇总。审批策略只能在此管理页面由人设置。"
            : "Each conversation has an ID and summary. Approvals and runs are grouped here. Only the human can set policy in this console."}
        </p>
      </div>
      {error && (
        <p role="alert" className="text-sm text-rose-700">
          {error}
        </p>
      )}
      {loading ? (
        <p>{zh ? "正在加载…" : "Loading…"}</p>
      ) : conversations.length === 0 ? (
        <p>
          {zh
            ? "尚无 AI 会话。AI 客户端可调用 secretbridge_begin_conversation 登记摘要。"
            : "No AI conversations yet. The AI client can call secretbridge_begin_conversation with a summary."}
        </p>
      ) : (
        <div className="grid gap-5 lg:grid-cols-[19rem_1fr]">
          <nav
            aria-label={zh ? "AI 会话" : "AI conversations"}
            className="space-y-2"
          >
            {conversations.map((item) => {
              const count = approvals.filter(
                (approval) => approval.conversation_id === item.id,
              ).length;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setSelectedId(item.id);
                    setRiskConfirmed(false);
                  }}
                  className={`w-full rounded-xl border p-3 text-left ${selected?.id === item.id ? "border-cyan-500 bg-cyan-50" : "border-slate-200 bg-white"}`}
                >
                  <span className="block font-semibold text-slate-900">
                    {item.summary}
                  </span>
                  <span className="mt-1 block break-all font-mono text-xs text-slate-500">
                    {item.id}
                  </span>
                  <span className="mt-1 block text-xs text-slate-600">
                    {zh ? `任务 ${count}` : `${count} tasks`}
                  </span>
                  {activeGrant(item, now) && (
                    <span className="mt-2 inline-block rounded bg-rose-700 px-2 py-1 text-xs font-bold text-white">
                      {zh
                        ? "高风险：所有操作已授权"
                        : "HIGH RISK: all operations authorized"}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
          {selected && (
            <article className="enterprise-surface space-y-5 p-5">
              <div>
                <h3 className="m-0 text-xl font-semibold">
                  {selected.summary}
                </h3>
                <p className="mt-1 break-all font-mono text-xs text-slate-600">
                  {selected.id}
                </p>
              </div>
              {activeGrant(selected, now) && (
                <p
                  role="alert"
                  className="rounded-xl border-2 border-rose-600 bg-rose-50 p-4 font-bold text-rose-900"
                >
                  {zh
                    ? `高风险：此 AI 会话的所有操作可直接获批，有效至 ${new Date(selected.grant_expires_at_unix_ms ?? 0).toLocaleString(language)}。`
                    : `HIGH RISK: every operation in this AI conversation may be approved directly until ${new Date(selected.grant_expires_at_unix_ms ?? 0).toLocaleString(language)}.`}
                </p>
              )}
              <fieldset className="space-y-3 border-0 p-0" disabled={busy}>
                <legend className="font-semibold">
                  {zh
                    ? "此会话的审批要求"
                    : "Approval requirement for this conversation"}
                </legend>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="workbench-button"
                    aria-pressed={selected.approval_policy === "every_task"}
                    onClick={() => void changePolicy("every_task")}
                  >
                    {zh
                      ? "逐个任务审批 / 撤销预授权"
                      : "Each task / revoke grant"}
                  </button>
                  <button
                    type="button"
                    className="workbench-button"
                    aria-pressed={selected.approval_policy === "same_task_once"}
                    onClick={() => void changePolicy("same_task_once")}
                  >
                    {zh ? "同样任务审批一次" : "Same task once"}
                  </button>
                </div>
                <div className="rounded-xl border-2 border-rose-300 bg-rose-50 p-4">
                  <p className="m-0 font-bold text-rose-900">
                    {zh
                      ? "高风险：本会话允许所有操作"
                      : "HIGH RISK: allow all operations in this conversation"}
                  </p>
                  <p className="mt-2 text-sm text-rose-800">
                    {zh
                      ? "启用后，AI 在此会话中新提交的任何操作均可直接获批，无需逐项确认。固定 1 小时后到期，也可随时撤销。"
                      : "Once enabled, any new operation in this AI conversation may be approved without individual review. Expires after one hour and can be revoked sooner."}
                  </p>
                  <label className="flex items-start gap-2 text-sm font-semibold text-rose-900">
                    <input
                      type="checkbox"
                      checked={riskConfirmed}
                      onChange={(event) =>
                        setRiskConfirmed(event.target.checked)
                      }
                    />
                    {zh
                      ? "我理解此会话内所有操作可自动获批"
                      : "I understand all operations in this conversation may be approved automatically"}
                  </label>
                  <button
                    type="button"
                    disabled={!riskConfirmed}
                    className="workbench-button mt-3 border-rose-500 text-rose-900 disabled:opacity-50"
                    onClick={() => void changePolicy("conversation_once")}
                  >
                    {zh
                      ? "启用 1 小时全操作授权"
                      : "Enable all operations for one hour"}
                  </button>
                </div>
              </fieldset>
              <div>
                <h4 className="font-semibold">
                  {zh
                    ? `任务与审批（${tasks.length}）`
                    : `Tasks and approvals (${tasks.length})`}
                </h4>
                {tasks.length === 0 ? (
                  <p className="text-sm text-slate-600">
                    {zh ? "暂无任务" : "No tasks"}
                  </p>
                ) : (
                  <ol className="space-y-2 pl-5 text-sm">
                    {tasks.map((item) => (
                      <li key={item.id} className="break-all">
                        <span className="font-medium">
                          {item.operation} · {item.state}
                        </span>
                        {item.preauthorized && (
                          <strong className="ml-2 text-rose-700">
                            {zh ? "预授权" : "Preauthorized"}
                          </strong>
                        )}
                        <div className="text-xs text-slate-500">
                          {item.id} ·{" "}
                          {new Date(item.created_at_unix_ms).toLocaleString(
                            language,
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
              <div>
                <h4 className="font-semibold">
                  {zh
                    ? `执行记录（${selectedRuns.length}）`
                    : `Runs (${selectedRuns.length})`}
                </h4>
                {selectedRuns.length === 0 ? (
                  <p className="text-sm text-slate-600">
                    {zh ? "暂无执行" : "No runs"}
                  </p>
                ) : (
                  <ol className="space-y-2 pl-5 text-sm">
                    {selectedRuns.map((item) => (
                      <li key={item.id} className="break-all">
                        {item.operation} · {item.state}
                        <div className="text-xs text-slate-500">
                          {item.id} ·{" "}
                          {new Date(item.created_at_unix_ms).toLocaleString(
                            language,
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </article>
          )}
        </div>
      )}
    </section>
  );
}
