// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  Ban,
  Check,
  ClipboardCheck,
  Clock3,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";

import {
  type Approval,
  type ActionTemplate,
  type ApprovalOperation,
  type ApprovalResultScope,
  type ApprovalState,
  type PolicyEvaluation,
  type PolicyRequirement,
  createApproval,
  decideApproval,
  evaluateActionTemplate,
  listApprovals,
  listActionTemplates,
  listTargets,
  SecretBridgeApiError,
  type Target,
} from "./api";

type Language = "zh-CN" | "en";

const operationLabels: Record<Language, Record<ApprovalOperation, string>> = {
  "zh-CN": {
    inspect_metadata: "查看非秘密元数据",
    synthetic_health_check: "合成健康检查",
  },
  en: {
    inspect_metadata: "Inspect non-secret metadata",
    synthetic_health_check: "Synthetic health check",
  },
};

const scopeLabels: Record<Language, Record<ApprovalResultScope, string>> = {
  "zh-CN": { status_only: "仅状态", metadata_summary: "元数据摘要" },
  en: { status_only: "Status only", metadata_summary: "Metadata summary" },
};

const stateStyles: Record<ApprovalState, string> = {
  pending: "bg-amber-50 text-amber-700 ring-amber-200",
  approved: "bg-emerald-50 text-emerald-700 ring-emerald-200",
  denied: "bg-rose-50 text-rose-700 ring-rose-200",
  revoked: "bg-slate-100 text-slate-600 ring-slate-200",
  expired: "bg-violet-50 text-violet-700 ring-violet-200",
};

export function ApprovalView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const text = language === "zh-CN"
    ? {
        eyebrow: "M1 · 审批中心",
        title: "范围化审批与撤销",
        subtitle: "授权通过已启用的受控操作模板绑定合成操作、逻辑目标、返回范围和模板版本，并以有效期与记录版本防止越界或过期决定。",
        safety: "本页只记录授权意图，不会执行命令、发起网络连接或读取真实凭据。",
        create: "新建审批请求",
        target: "逻辑目标",
        template: "受控操作模板",
        chooseTemplate: "请选择已启用模板",
        chooseTarget: "请选择目标",
        operation: "允许的合成操作",
        scope: "允许的结果范围",
        reason: "申请原因（可选）",
        reasonPlaceholder: "说明为什么需要这项授权，不要填写秘密或地址",
        ttl: "有效期",
        minutes: "分钟",
        submit: "提交审批",
        saving: "正在提交…",
        records: "审批记录",
        empty: "尚无审批记录。",
        noTargets: "请先在“连接目标”页面建立一个逻辑目标。",
        noTemplates: "请先在“执行策略”页面建立并启用一个受控操作模板。",
        loading: "正在读取审批记录…",
        loadError: "审批记录读取失败，请稍后重试。",
        saveError: "审批请求保存失败，请检查字段后重试。",
        conflict: "这条审批已经变化，列表已刷新，请按最新状态重新操作。",
        invalid: "当前状态不允许执行这个审批动作，列表已刷新。",
        policyChanged: "模板或目标已变化，策略拒绝使用旧快照；请重新创建审批。",
        policyTitle: "服务端策略预检",
        policyChecking: "正在核对模板、目标与安全要求…",
        policyEligible: "符合合成审批条件",
        policyDenied: "当前策略拒绝创建审批",
        policyVersion: "策略版本",
        templateSnapshot: "模板／目标版本",
        requirements: {
          explicit_approval: "必须显式审批",
          no_parameters: "不接收参数",
          single_use: "审批单次使用",
          synthetic_only: "仅内部模拟",
          transition_revalidation: "每次转换复核",
        } satisfies Record<PolicyRequirement, string>,
        approve: "批准",
        deny: "拒绝",
        revoke: "撤销",
        note: "决定备注（可选）",
        notePlaceholder: "记录批准、拒绝或撤销原因",
        reasonLabel: "申请原因",
        decisionLabel: "决定备注",
        expires: "到期时间",
        version: "版本",
        states: {
          pending: "待审批",
          approved: "已批准",
          denied: "已拒绝",
          revoked: "已撤销",
          expired: "已过期",
        } satisfies Record<ApprovalState, string>,
      }
    : {
        eyebrow: "M1 · Approval center",
        title: "Scoped approvals and revocation",
        subtitle: "Authorization binds a synthetic operation, logical target, result scope and template version through an enabled controlled-action template, with expiry and record versions preventing stale decisions.",
        safety: "This page records authorization intent only. It never runs commands, opens network connections or reads real credentials.",
        create: "New approval request",
        target: "Logical target",
        template: "Controlled action template",
        chooseTemplate: "Choose an enabled template",
        chooseTarget: "Choose a target",
        operation: "Allowed synthetic operation",
        scope: "Allowed result scope",
        reason: "Request reason (optional)",
        reasonPlaceholder: "Explain the need; do not enter secrets or addresses",
        ttl: "Lifetime",
        minutes: "minutes",
        submit: "Submit request",
        saving: "Submitting…",
        records: "Approval records",
        empty: "No approval records yet.",
        noTargets: "Create a logical target on the Targets page first.",
        noTemplates: "Create and enable a controlled action template on the Policies page first.",
        loading: "Loading approval records…",
        loadError: "Approval records could not be loaded. Try again later.",
        saveError: "The approval request could not be saved. Check the fields and retry.",
        conflict: "This approval changed. The list has been refreshed; decide from its current state.",
        invalid: "That decision is not allowed from the current state. The list has been refreshed.",
        policyChanged: "The template or target changed. Policy denied the stale snapshot; create a new approval.",
        policyTitle: "Server policy preflight",
        policyChecking: "Checking template, target and safety requirements…",
        policyEligible: "Eligible for synthetic approval",
        policyDenied: "Current policy denies approval creation",
        policyVersion: "Policy version",
        templateSnapshot: "Template / target versions",
        requirements: {
          explicit_approval: "Explicit approval",
          no_parameters: "No parameters",
          single_use: "Single use",
          synthetic_only: "Synthetic only",
          transition_revalidation: "Revalidate transitions",
        } satisfies Record<PolicyRequirement, string>,
        approve: "Approve",
        deny: "Deny",
        revoke: "Revoke",
        note: "Decision note (optional)",
        notePlaceholder: "Record why this was approved, denied or revoked",
        reasonLabel: "Request reason",
        decisionLabel: "Decision note",
        expires: "Expires",
        version: "Version",
        states: {
          pending: "Pending",
          approved: "Approved",
          denied: "Denied",
          revoked: "Revoked",
          expired: "Expired",
        } satisfies Record<ApprovalState, string>,
      };
  const [items, setItems] = useState<Approval[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [templateId, setTemplateId] = useState("");
  const [reason, setReason] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState(5);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [policyEvaluation, setPolicyEvaluation] = useState<PolicyEvaluation | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const targetNames = useMemo(
    () => new Map(targets.map((target) => [target.id, target.name])),
    [targets],
  );
  const templateNames = useMemo(
    () => new Map(templates.map((template) => [template.id, template.name])),
    [templates],
  );
  const enabledTemplates = useMemo(
    () => templates.filter((template) => template.enabled),
    [templates],
  );

  async function reload() {
    const [approvals, targetsResponse, templatesResponse] = await Promise.all([
      listApprovals(sessionToken),
      listTargets(sessionToken),
      listActionTemplates(sessionToken),
    ]);
    setItems(approvals.items);
    setTargets(targetsResponse.items);
    setTemplates(templatesResponse.items);
    setTemplateId((current) =>
      templatesResponse.items.some((template) => template.id === current && template.enabled)
        ? current
        : templatesResponse.items.find((template) => template.enabled)?.id ?? "",
    );
  }

  useEffect(() => {
    let active = true;
    Promise.all([listApprovals(sessionToken), listTargets(sessionToken), listActionTemplates(sessionToken)])
      .then(([approvals, targetsResponse, templatesResponse]) => {
        if (!active) return;
        setItems(approvals.items);
        setTargets(targetsResponse.items);
        setTemplates(templatesResponse.items);
        setTemplateId(templatesResponse.items.find((template) => template.enabled)?.id ?? "");
      })
      .catch(() => { if (active) setError(text.loadError); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [sessionToken, text.loadError]);

  useEffect(() => {
    if (!templateId) {
      setPolicyEvaluation(null);
      return;
    }
    let active = true;
    setPolicyLoading(true);
    evaluateActionTemplate(sessionToken, templateId)
      .then((evaluation) => { if (active) setPolicyEvaluation(evaluation); })
      .catch(() => { if (active) setPolicyEvaluation(null); })
      .finally(() => { if (active) setPolicyLoading(false); });
    return () => { active = false; };
  }, [sessionToken, templateId]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!templateId || policyEvaluation?.decision !== "eligible_for_approval") return;
    setBusyId("create");
    setError(null);
    try {
      const item = await createApproval(sessionToken, {
        action_template_id: templateId,
        ...(reason.trim() ? { reason } : {}),
        expires_in_seconds: ttlMinutes * 60,
      });
      setItems((current) => [item, ...current]);
      setReason("");
    } catch {
      setError(text.saveError);
    } finally {
      setBusyId(null);
    }
  }

  async function decide(
    item: Approval,
    decision: "approve" | "deny" | "revoke",
  ) {
    setBusyId(item.id);
    setError(null);
    try {
      const note = notes[item.id]?.trim();
      const updated = await decideApproval(sessionToken, item.id, decision, {
        expected_version: item.version,
        ...(note ? { note } : {}),
      });
      setItems((current) => current.map((entry) => entry.id === updated.id ? updated : entry));
      setNotes((current) => ({ ...current, [item.id]: "" }));
    } catch (caught) {
      if (caught instanceof SecretBridgeApiError &&
          ["version_conflict", "invalid_approval_transition", "policy_denied"].includes(caught.code)) {
        try { await reload(); } catch { /* Keep the actionable conflict message. */ }
        setError(caught.code === "version_conflict" ? text.conflict : caught.code === "policy_denied" ? text.policyChanged : text.invalid);
      } else {
        setError(text.saveError);
      }
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="space-y-6">
      <header>
        <p className="m-0 text-xs font-bold uppercase tracking-[0.18em] text-cyan-700">{text.eyebrow}</p>
        <h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1>
        <p className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-600">{text.subtitle}</p>
      </header>

      <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">
        <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden="true" />
        <p className="m-0 font-medium">{text.safety}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.4fr)]">
        <form onSubmit={submit} className="h-fit rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="m-0 text-lg font-semibold text-slate-950">{text.create}</h2>
          {targets.length === 0 && !loading && <p className="mb-0 mt-4 rounded-xl bg-cyan-50 p-3 text-sm text-cyan-800">{text.noTargets}</p>}
          {targets.length > 0 && enabledTemplates.length === 0 && !loading && <p className="mb-0 mt-4 rounded-xl bg-cyan-50 p-3 text-sm text-cyan-800">{text.noTemplates}</p>}
          <div className="mt-5 space-y-4">
            <Field label={text.template} htmlFor="approval-template">
              <select id="approval-template" required value={templateId} onChange={(event) => setTemplateId(event.target.value)} className={inputClass}>
                <option value="">{text.chooseTemplate}</option>
                {enabledTemplates.map((template) => <option key={template.id} value={template.id}>{template.name} · {targetNames.get(template.target_id) ?? template.target_id}</option>)}
              </select>
            </Field>
            {templateId && (
              <div className={`rounded-2xl border p-4 ${policyEvaluation?.decision === "eligible_for_approval" ? "border-emerald-200 bg-emerald-50" : "border-amber-200 bg-amber-50"}`}>
                <div className="flex items-start gap-3">
                  <ShieldCheck className={`mt-0.5 size-5 shrink-0 ${policyEvaluation?.decision === "eligible_for_approval" ? "text-emerald-700" : "text-amber-700"}`} aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="m-0 text-xs font-bold uppercase tracking-[0.12em] text-slate-500">{text.policyTitle}</p>
                    <p className="mb-0 mt-1 text-sm font-semibold text-slate-900">{policyLoading ? text.policyChecking : policyEvaluation?.decision === "eligible_for_approval" ? text.policyEligible : text.policyDenied}</p>
                    {policyEvaluation && <><p className="mb-0 mt-2 text-xs text-slate-600">{text.policyVersion}：{policyEvaluation.policy_version} · {text.templateSnapshot}：{policyEvaluation.action_template_version}/{policyEvaluation.target_version}</p><div className="mt-3 flex flex-wrap gap-1.5">{policyEvaluation.requirements.map((requirement) => <span key={requirement} className="rounded-full bg-white px-2 py-1 text-[11px] font-semibold text-slate-600 ring-1 ring-slate-200">{text.requirements[requirement]}</span>)}</div></>}
                  </div>
                </div>
              </div>
            )}
            <Field label={text.reason} htmlFor="approval-reason">
              <textarea id="approval-reason" rows={3} maxLength={240} value={reason} onChange={(event) => setReason(event.target.value)} placeholder={text.reasonPlaceholder} className={inputClass} />
            </Field>
            <Field label={text.ttl} htmlFor="approval-ttl">
              <select id="approval-ttl" value={ttlMinutes} onChange={(event) => setTtlMinutes(Number(event.target.value))} className={inputClass}>
                {[1, 5, 15, 30, 60].map((minutes) => <option key={minutes} value={minutes}>{minutes} {text.minutes}</option>)}
              </select>
            </Field>
          </div>
          <button type="submit" disabled={!templateId || policyLoading || policyEvaluation?.decision !== "eligible_for_approval" || busyId !== null} className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-xl bg-slate-950 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-cyan-800 disabled:cursor-not-allowed disabled:opacity-50">
            <ClipboardCheck className="size-4" aria-hidden="true" />
            {busyId === "create" ? text.saving : text.submit}
          </button>
        </form>

        <div>
          <div className="mb-4 flex items-center justify-between gap-4">
            <h2 className="m-0 text-lg font-semibold text-slate-950">{text.records}</h2>
            <span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-slate-500 shadow-sm ring-1 ring-slate-200">{items.length}</span>
          </div>
          {error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}
          {loading ? (
            <p className="rounded-2xl bg-white p-6 text-sm text-slate-500 shadow-sm">{text.loading}</p>
          ) : items.length === 0 ? (
            <p className="rounded-2xl bg-white p-6 text-sm text-slate-500 shadow-sm">{text.empty}</p>
          ) : (
            <div className="space-y-4">
              {items.map((item) => (
                <article key={item.id} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${stateStyles[item.state]}`}>{text.states[item.state]}</span>
                        <span className="rounded-full bg-cyan-50 px-2.5 py-1 text-xs font-semibold text-cyan-700">{operationLabels[language][item.operation]}</span>
                        <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">{scopeLabels[language][item.result_scope]}</span>
                      </div>
                      <h3 className="mb-0 mt-3 text-base font-semibold text-slate-950">{item.action_template_id ? (templateNames.get(item.action_template_id) ?? item.action_template_id) : operationLabels[language][item.operation]}</h3>
                      <p className="mb-0 mt-2 text-sm text-slate-500">{targetNames.get(item.target_id) ?? item.target_id}{item.action_template_version ? ` · ${text.version} ${item.action_template_version}/${item.target_version}` : ""}</p>
                    </div>
                    <span className="text-xs font-medium text-slate-400">{text.version} {item.version}</span>
                  </div>
                  {item.reason && <p className="mb-0 mt-3 text-sm leading-6 text-slate-600"><strong>{text.reasonLabel}：</strong>{item.reason}</p>}
                  {item.decision_note && <p className="mb-0 mt-2 text-sm leading-6 text-slate-600"><strong>{text.decisionLabel}：</strong>{item.decision_note}</p>}
                  <p className="mb-0 mt-3 inline-flex items-center gap-2 text-xs text-slate-500"><Clock3 className="size-3.5" />{text.expires} · {new Intl.DateTimeFormat(language, { dateStyle: "medium", timeStyle: "short" }).format(item.expires_at_unix_ms)}</p>
                  {(item.state === "pending" || item.state === "approved") && (
                    <div className="mt-4 border-t border-slate-100 pt-4">
                      <label htmlFor={`approval-note-${item.id}`} className="text-xs font-semibold text-slate-600">{text.note}</label>
                      <input id={`approval-note-${item.id}`} maxLength={240} value={notes[item.id] ?? ""} onChange={(event) => setNotes((current) => ({ ...current, [item.id]: event.target.value }))} placeholder={text.notePlaceholder} className={`${inputClass} mt-2`} />
                      <div className="mt-3 flex flex-wrap gap-2">
                        {item.state === "pending" ? (
                          <>
                            <ActionButton disabled={busyId !== null} onClick={() => void decide(item, "approve")} icon={Check} label={text.approve} style="bg-emerald-600 hover:bg-emerald-700" />
                            <ActionButton disabled={busyId !== null} onClick={() => void decide(item, "deny")} icon={Ban} label={text.deny} style="bg-rose-600 hover:bg-rose-700" />
                          </>
                        ) : (
                          <ActionButton disabled={busyId !== null} onClick={() => void decide(item, "revoke")} icon={RotateCcw} label={text.revoke} style="bg-slate-700 hover:bg-slate-800" />
                        )}
                      </div>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: ReactNode }) {
  return <div><label htmlFor={htmlFor} className="mb-2 block text-sm font-semibold text-slate-700">{label}</label>{children}</div>;
}

function ActionButton({ disabled, onClick, icon: Icon, label, style }: { disabled: boolean; onClick: () => void; icon: typeof Check; label: string; style: string }) {
  return <button type="button" disabled={disabled} onClick={onClick} className={`inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-sm font-semibold text-white transition disabled:cursor-not-allowed disabled:opacity-50 ${style}`}><Icon className="size-4" aria-hidden="true" />{label}</button>;
}

const inputClass = "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";
