// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  type ActionTemplate,
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
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const current = pending[0];

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
    if (enabled && next.some((item) => !dismissed.current.has(item.id))) {
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
    if (!current || (decision === "approve" && !canApprove)) return;
    setBusy(true);
    setError(null);
    try {
      await decideApproval(sessionToken, current.id, decision, {
        expected_version: current.version,
        ...(note.trim() ? { note: note.trim() } : {}),
      });
      setNote("");
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
        className="max-h-[min(90vh,60rem)] w-[min(96vw,68rem)] max-w-none overflow-y-auto rounded-2xl border border-slate-200 bg-white p-0 shadow-2xl backdrop:bg-slate-950/60"
        onCancel={(event) => {
          event.preventDefault();
          if (!busy) defer();
        }}
      >
        {current && (
          <div className="min-w-0">
            <header className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-5 py-4">
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
            <section className="min-w-0 space-y-4 px-5 py-5 text-sm">
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
                {zh ? "决定备注（可选）" : "Decision note (optional)"}
                <input
                  maxLength={240}
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2"
                />
              </label>
              {error && (
                <p role="alert" className="text-sm text-rose-700">
                  {error}
                </p>
              )}
              <div className="flex flex-wrap gap-2 border-t border-slate-200 pt-4">
                <button
                  type="button"
                  disabled={busy || !canApprove}
                  onClick={() => void decide("approve")}
                  className="workbench-primary"
                >
                  {zh ? "批准当前项" : "Approve current"}
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void decide("deny")}
                  className="workbench-button"
                >
                  {zh ? "拒绝当前项" : "Deny current"}
                </button>
              </div>
            </section>
          </div>
        )}
      </dialog>
    </>
  );
}
