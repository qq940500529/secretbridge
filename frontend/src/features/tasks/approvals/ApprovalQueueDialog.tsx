// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  type ActionTemplate,
  type AiConversation,
  type ConversationApprovalPolicy,
  listAiConversations,
  type Approval,
  type Target,
  decideApproval,
  getActionTemplate,
  listApprovals,
  listTargets,
} from "../../../api/index";
import { CommandReview } from "../shared/CommandReview";
import { authorizationLabel } from "../shared/parameters";
import { useServiceChanges } from "../../../app/service-events";
import type { ApprovalNotificationChannel } from "../../../app/preferences";
import { noteForApproval, type ApprovalNoteDraft } from "./decision-note";

type Language = "zh-CN" | "en";

export function ApprovalQueueDialog({
  language,
  sessionToken,
  enabled,
  notificationChannel,
}: {
  language: Language;
  sessionToken: string;
  enabled: boolean;
  notificationChannel: ApprovalNotificationChannel;
}) {
  const zh = language === "zh-CN";
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const dismissed = useRef(new Set<string>());
  const notified = useRef(new Set<string>());
  const requestNumber = useRef(0);
  const titleId = useId();
  const [pending, setPending] = useState<Approval[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [template, setTemplate] = useState<ActionTemplate | null>(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [noteDraft, setNoteDraft] = useState<ApprovalNoteDraft | null>(null);
  const [conversation, setConversation] = useState<AiConversation | null>(null);
  const [policy, setPolicy] =
    useState<ConversationApprovalPolicy>("every_task");
  const [riskAccepted, setRiskAccepted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = pending[0];
  const note = noteForApproval(noteDraft, current);

  useEffect(() => {
    const original = document.title;
    if (pending.length > 0) document.title = `(${pending.length}) ${original}`;
    return () => {
      document.title = original;
    };
  }, [pending.length]);

  const reload = useCallback(async () => {
    const number = ++requestNumber.current;
    const [approvalResponse, targetResponse] = await Promise.all([
      listApprovals(sessionToken),
      listTargets(sessionToken),
    ]);
    if (number !== requestNumber.current) return;
    const next = approvalResponse.items
      .filter((item) => item.state === "pending")
      .sort(
        (a, b) =>
          a.created_at_unix_ms - b.created_at_unix_ms ||
          a.id.localeCompare(b.id),
      );
    setPending(next);
    setTargets(targetResponse.items);
    if (
      enabled &&
      notificationChannel === "browser" &&
      document.visibilityState !== "visible" &&
      "Notification" in window &&
      Notification.permission === "granted"
    ) {
      const unseen = next.filter((item) => !notified.current.has(item.id));
      if (unseen.length > 0) {
        for (const item of unseen) notified.current.add(item.id);
        try {
          const notice = new Notification(
            zh ? "SecretBridge 待审批" : "SecretBridge approval pending",
            {
              body: zh
                ? `当前共有 ${next.length} 项待审批，点击查看。`
                : `${next.length} approval(s) pending. Click to review.`,
              tag: "secretbridge-pending-approvals",
            },
          );
          notice.onclick = () => {
            window.focus();
            setOpen(true);
            notice.close();
          };
        } catch {
          setOpen(true);
        }
      }
    }
    if (
      enabled &&
      document.visibilityState === "visible" &&
      next.some((item) => !dismissed.current.has(item.id))
    ) {
      setOpen(true);
    }
    if (next.length === 0) setOpen(false);
  }, [enabled, notificationChannel, sessionToken, zh]);

  useEffect(() => {
    void reload().catch(() => {
      setError(
        zh
          ? "待审批列表读取失败，请重试。"
          : "Could not load approvals. Retry.",
      );
    });
    return () => {
      requestNumber.current += 1;
    };
  }, [reload, zh]);

  useServiceChanges(sessionToken, () => {
    void reload().catch(() => {
      setError(
        zh
          ? "待审批列表读取失败，请重试。"
          : "Could not load approvals. Retry.",
      );
    });
  });

  useEffect(() => {
    function reconcileOnReturn() {
      if (document.visibilityState === "visible") {
        void reload().catch(() => {
          setError(
            zh
              ? "待审批列表读取失败，请重试。"
              : "Could not load approvals. Retry.",
          );
        });
      }
    }
    document.addEventListener("visibilitychange", reconcileOnReturn);
    window.addEventListener("focus", reconcileOnReturn);
    // Background event streams may be suspended by the browser. Polling is a
    // recovery path; the pending badge remains available even without OS
    // notification permission or foreground focus.
    const poll = window.setInterval(() => {
      void reload().catch(() => undefined);
    }, 15_000);
    return () => {
      document.removeEventListener("visibilitychange", reconcileOnReturn);
      window.removeEventListener("focus", reconcileOnReturn);
      window.clearInterval(poll);
    };
  }, [reload, zh]);

  useEffect(() => {
    let active = true;
    setConversation(null);
    setPolicy("every_task");
    setRiskAccepted(false);
    if (current?.conversation_id)
      void listAiConversations(sessionToken)
        .then((result) => {
          const value = result.items.find(
            (item) => item.id === current.conversation_id,
          );
          if (active && value) {
            setConversation(value);
            setPolicy(value.approval_policy);
          }
        })
        .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [current?.id, current?.conversation_id, current?.version, sessionToken]);

  useEffect(() => {
    if (!current?.action_template_id) {
      setTemplate(null);
      setTemplateLoading(false);
      return;
    }
    let active = true;
    setTemplate(null);
    setTemplateLoading(true);
    void getActionTemplate(sessionToken, current.action_template_id)
      .then((value) => {
        if (active) setTemplate(value);
      })
      .catch(() => {
        if (active) setTemplate(null);
      })
      .finally(() => {
        if (active) setTemplateLoading(false);
      });
    return () => {
      active = false;
    };
  }, [current?.action_template_id, current?.version, sessionToken]);

  useEffect(() => {
    const element = dialog.current;
    if (open && enabled && element && !element.open) element.showModal();
    if ((!open || !enabled) && element?.open) {
      element.close();
      requestAnimationFrame(() => trigger.current?.focus());
    }
  }, [enabled, open]);

  function defer() {
    for (const item of pending) dismissed.current.add(item.id);
    setOpen(false);
  }

  async function decide(decision: "approve" | "deny") {
    if (
      !current ||
      (decision === "approve" &&
        (!canApprove || (policy === "conversation_once" && !riskAccepted)))
    )
      return;
    setBusy(true);
    setError(null);
    try {
      await decideApproval(sessionToken, current.id, decision, {
        expected_version: current.version,
        ...(decision === "approve" && conversation
          ? {
              conversation_policy: {
                expected_version: conversation.version,
                approval_policy: policy,
                ...(policy === "conversation_once"
                  ? {
                      risk_acknowledgement:
                        "allow_all_operations_in_this_ai_conversation",
                    }
                  : {}),
              },
            }
          : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
      });
      setNoteDraft((draft) =>
        draft?.approvalId === current.id && draft.version === current.version
          ? null
          : draft,
      );
      // Re-read the server state so another page's decisions and new requests are included.
      await reload();
    } catch {
      setError(
        zh
          ? "决定未完成。审批可能已变化，请重新检查后重试。"
          : "Decision not completed. The approval may have changed; review and retry.",
      );
      try {
        await reload();
        if (current.conversation_id) {
          const result = await listAiConversations(sessionToken);
          const value = result.items.find(
            (item) => item.id === current.conversation_id,
          );
          if (value) {
            setConversation(value);
            setPolicy(value.approval_policy);
            setRiskAccepted(false);
          }
        }
      } catch {
        // Keep the actionable error and the current review visible.
      }
    } finally {
      setBusy(false);
    }
  }

  const target = targets.find((item) => item.id === current?.target_id);
  const canApprove =
    !templateLoading &&
    template?.id === current?.action_template_id &&
    template?.version === current?.action_template_version &&
    template?.target_id === current?.target_id &&
    target?.version === current?.target_version &&
    template?.enabled === true &&
    template?.terminal_available !== false;

  return (
    <>
      {pending.length > 0 && (
        <button
          ref={trigger}
          type="button"
          className="flex h-10 items-center rounded-xl border border-amber-300 bg-amber-50 px-3 text-sm font-semibold text-amber-950"
          onClick={() => {
            setError(null);
            setOpen(true);
          }}
        >
          {zh
            ? `待审批 ${pending.length}`
            : `Pending approvals ${pending.length}`}
        </button>
      )}
      <dialog
        ref={dialog}
        aria-labelledby={titleId}
        className="fixed inset-0 m-auto h-[min(90dvh,60rem)] max-h-[min(90dvh,60rem)] w-[min(96vw,68rem)] max-w-none overflow-hidden rounded-2xl border border-slate-200 bg-white p-0 shadow-2xl backdrop:bg-slate-950/60"
        onCancel={(event) => {
          event.preventDefault();
          if (!busy) defer();
        }}
      >
        {current && (
          <div className="flex h-full min-h-0 min-w-0 flex-col">
            <header className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-5 py-4">
              <div>
                <h2
                  id={titleId}
                  className="m-0 text-lg font-semibold text-slate-950"
                >
                  {zh ? "待审批请求" : "Pending approval"}
                </h2>
                <p role="status" className="mb-0 mt-1 text-sm text-slate-600">
                  {zh
                    ? `共 ${pending.length} 项，正在处理第 1 项；按申请时间排序`
                    : `${pending.length} pending; reviewing the oldest first`}
                </p>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={defer}
                className="workbench-button"
              >
                {zh ? "稍后处理" : "Review later"}
              </button>
            </header>
            <section className="min-h-0 min-w-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-5 py-5 text-sm">
              <p className="m-0 font-semibold text-slate-950">
                {canApprove
                  ? template?.name
                  : templateLoading
                    ? zh
                      ? "读取操作快照中…"
                      : "Loading operation snapshot…"
                    : zh
                      ? "操作快照不可用或已变化"
                      : "Operation snapshot unavailable or changed"}
              </p>
              <dl className="grid min-w-0 gap-2 sm:grid-cols-[8rem_1fr]">
                <dt>{zh ? "目标" : "Target"}</dt>
                <dd className="m-0 break-words">
                  {target?.version === current.target_version
                    ? target.name
                    : current.target_id}
                </dd>
                <dt>{zh ? "申请时间" : "Requested"}</dt>
                <dd className="m-0">
                  {new Intl.DateTimeFormat(language, {
                    dateStyle: "medium",
                    timeStyle: "medium",
                  }).format(current.created_at_unix_ms)}
                </dd>
                <dt>{zh ? "到期时间" : "Expires"}</dt>
                <dd className="m-0">
                  {new Intl.DateTimeFormat(language, {
                    dateStyle: "medium",
                    timeStyle: "medium",
                  }).format(current.expires_at_unix_ms)}
                </dd>
                <dt>{zh ? "授权范围" : "Authorization"}</dt>
                <dd className="m-0">
                  {authorizationLabel(current.authorization_mode, zh)}
                </dd>
                <dt>{zh ? "操作与结果" : "Operation and result"}</dt>
                <dd className="m-0 break-words">
                  {current.operation} · {current.result_scope}
                </dd>
                <dt>{zh ? "申请原因" : "Reason"}</dt>
                <dd className="m-0 whitespace-pre-wrap break-words">
                  {current.reason || (zh ? "未填写" : "Not supplied")}
                </dd>
              </dl>
              {canApprove && template && (
                <CommandReview
                  key={current.id}
                  template={template}
                  expectedVersion={current.action_template_version}
                  language={language}
                  parameters={current.parameters}
                  expanded
                />
              )}
              {!canApprove && !templateLoading && (
                <p role="alert" className="text-sm text-amber-800">
                  {zh
                    ? "当前操作快照不可用或已变化，不能批准；可拒绝并重新申请。"
                    : "The operation snapshot is unavailable or changed. Deny and request again."}
                </p>
              )}
              <details className="text-xs text-slate-600">
                <summary>{zh ? "技术标识" : "Technical identifiers"}</summary>
                <p className="break-all">{current.id}</p>
              </details>
              <label className="block text-sm font-semibold text-slate-700">
                {zh
                  ? "决定备注 / 拒绝反馈（可选）"
                  : "Decision note / rejection feedback (optional)"}
                <textarea
                  rows={2}
                  placeholder={
                    zh
                      ? "要求 AI 更换方式或补充信息；不要填写秘密"
                      : "Ask the AI to change approach or supply information; never include secrets"
                  }
                  maxLength={240}
                  value={note}
                  onChange={(event) =>
                    setNoteDraft({
                      approvalId: current.id,
                      version: current.version,
                      value: event.target.value,
                    })
                  }
                  className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2"
                />
              </label>
              {error && (
                <p role="alert" className="text-sm text-rose-700">
                  {error}
                </p>
              )}
            </section>
            <footer className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-slate-200 bg-white px-5 py-4 shadow-[0_-8px_24px_-20px_rgba(15,23,42,0.45)]">
              <span className="text-xs text-slate-500">
                {zh
                  ? "决定前请核对上方操作快照"
                  : "Review the operation snapshot before deciding"}
              </span>
              <div className="grid w-full min-w-0 gap-2 sm:flex sm:w-auto sm:flex-wrap sm:items-center">
                {policy === "conversation_once" && (
                  <label className="max-w-60 text-xs text-rose-700">
                    <input
                      type="checkbox"
                      checked={riskAccepted}
                      onChange={(event) =>
                        setRiskAccepted(event.target.checked)
                      }
                    />
                    {zh
                      ? "我理解：此会话后续所有操作将自动批准，可随时撤销。"
                      : "I understand: all subsequent operations in this chat will be approved automatically. Revocable at any time."}
                  </label>
                )}
                <div className="inline-flex min-w-0 items-stretch rounded-lg bg-cyan-700">
                  <button
                    type="button"
                    disabled={
                      busy ||
                      !canApprove ||
                      (current.conversation_id != null && !conversation) ||
                      (policy === "conversation_once" && !riskAccepted)
                    }
                    onClick={() => void decide("approve")}
                    className="workbench-primary shrink-0"
                    style={
                      conversation
                        ? {
                            borderTopRightRadius: 0,
                            borderBottomRightRadius: 0,
                          }
                        : undefined
                    }
                  >
                    {zh ? "批准当前项" : "Approve current"}
                  </button>
                  {conversation && (
                    <label className="flex min-w-0 flex-1 items-center border-l border-cyan-500">
                      <span className="sr-only">
                        {zh
                          ? "此 AI 会话的审批要求"
                          : "Approval policy for this AI chat"}
                      </span>
                      <select
                        aria-label={zh ? "审批要求" : "Approval policy"}
                        className="h-10 min-w-0 w-full sm:w-56 max-w-64 rounded-r-lg border-0 bg-cyan-700 px-3 text-sm font-semibold text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-700 disabled:opacity-60"
                        value={policy}
                        disabled={busy}
                        onChange={(event) => {
                          setPolicy(
                            event.target.value as ConversationApprovalPolicy,
                          );
                          setRiskAccepted(false);
                        }}
                      >
                        <option value="every_task">
                          {zh ? "逐项确认" : "Review every task"}
                        </option>
                        <option value="same_task_once">
                          {zh
                            ? "同一操作批准一次（1 小时）"
                            : "Same operation once (1 hour)"}
                        </option>
                        <option value="conversation_once">
                          {zh
                            ? "本会话所有操作（1 小时）"
                            : "All operations in this chat (1 hour)"}
                        </option>
                      </select>
                    </label>
                  )}
                </div>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void decide("deny")}
                  className="workbench-button"
                >
                  {zh ? "拒绝当前项" : "Deny current"}
                </button>
              </div>
            </footer>
          </div>
        )}
      </dialog>
    </>
  );
}
