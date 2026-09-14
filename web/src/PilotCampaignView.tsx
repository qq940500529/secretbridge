// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Download,
  FileJson2,
  History,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldAlert,
  Square,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";

import {
  createPilotCampaign,
  getPilotCampaignReport,
  listActionTemplates,
  listCredentialReferences,
  listPilotCampaigns,
  listPilotReadiness,
  listPlatformBoundary,
  listTargets,
  transitionPilotCampaign,
  updatePilotScenario,
  type ActionTemplate,
  type CredentialReference,
  type PilotCampaign,
  type PilotCampaignState,
  type PilotReadinessSnapshot,
  type PilotScenarioEvidence,
  type PilotScenarioResult,
  type PlatformBoundarySnapshot,
  type Target,
} from "./api";

type Language = "zh-CN" | "en";
type Draft = { result: PilotScenarioResult; evidence: string; reviewer: string };

const scenarioZh: Record<string, [string, string]> = {
  connection_success: ["授权连接成功", "获批的固定连接检查成功"],
  authentication_rejected: ["认证拒绝", "无效或已撤销凭据以固定安全状态失败"],
  connection_timeout: ["连接超时", "连接超时有界且可观察"],
  dns_failure: ["DNS 失败", "DNS 失败不暴露解析器细节"],
  tls_untrusted_certificate: ["TLS 不受信证书", "不受信证书被拒绝且不披露原始错误"],
  tls_hostname_mismatch: ["TLS 主机名不匹配", "证书主机名不匹配被拒绝"],
  network_unreachable: ["网络不可达", "网络中断得到有界固定结果"],
  credential_rotation: ["凭据轮换", "凭据轮换使旧授权失效"],
  approval_revocation: ["授权撤销", "授权撤销会停止排队或活动工作"],
  service_restart_unknown_result: ["服务重启与未知结果", "服务重启保留明确的未知或中断结果"],
  credential_revoked_on_close: ["结项凭据清除", "临时试点凭据在结项前清除"],
};

export function PilotCampaignView({ language, sessionToken }: { language: Language; sessionToken: string }) {
  const zh = language === "zh-CN";
  const t = zh ? zhText : enText;
  const [campaigns, setCampaigns] = useState<PilotCampaign[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [readiness, setReadiness] = useState<PilotReadinessSnapshot[]>([]);
  const [platform, setPlatform] = useState<PlatformBoundarySnapshot[]>([]);
  const [credentials, setCredentials] = useState<CredentialReference[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);

  const selected = campaigns.find((item) => item.id === selectedId) ?? campaigns[0] ?? null;
  const targetById = useMemo(() => new Map(targets.map((item) => [item.id, item])), [targets]);
  const eligibleTemplates = useMemo(
    () => templates.filter((template) => {
      const target = targetById.get(template.target_id);
      return template.enabled && template.operation === "postgres_connection_check" && template.result_scope === "status_only" && target?.kind === "database" && target.environment === "test" && Boolean(target.postgres);
    }),
    [templates, targetById],
  );
  const usableReadiness = readiness.filter((item) => item.digest_verified && item.eligible_test_targets > 0 && !item.checks.some((check) => check.status === "failed"));
  const usablePlatform = platform.filter((item) => item.digest_verified && item.status !== "blocked");

  async function refresh() {
    const [campaignResult, targetResult, templateResult, readinessResult, platformResult, credentialResult] = await Promise.all([
      listPilotCampaigns(sessionToken),
      listTargets(sessionToken),
      listActionTemplates(sessionToken),
      listPilotReadiness(sessionToken),
      listPlatformBoundary(sessionToken),
      listCredentialReferences(sessionToken),
    ]);
    setCampaigns(campaignResult.items);
    setTargets(targetResult.items);
    setTemplates(templateResult.items);
    setReadiness(readinessResult.items);
    setPlatform(platformResult.items);
    setCredentials(credentialResult.items);
    setSelectedId((current) => current && campaignResult.items.some((item) => item.id === current) ? current : (campaignResult.items[0]?.id ?? null));
  }

  useEffect(() => {
    let active = true;
    refresh().catch(() => active && setError(t.failure)).finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [sessionToken, zh]);

  function replaceCampaign(next: PilotCampaign) {
    setCampaigns((current) => [next, ...current.filter((item) => item.id !== next.id)]);
    setSelectedId(next.id);
  }

  async function mutate(action: "activate" | "begin-closure" | "close" | "revoke") {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      replaceCampaign(await transitionPilotCampaign(sessionToken, selected.id, action, selected.version));
      await refresh();
    } catch { setError(t.failure); } finally { setBusy(false); }
  }

  async function download(format: "markdown" | "json") {
    if (!selected) return;
    try {
      const report = await getPilotCampaignReport(sessionToken, selected.id);
      const body = format === "markdown" ? report.markdown : JSON.stringify(report, null, 2);
      const url = URL.createObjectURL(new Blob([body], { type: format === "markdown" ? "text/markdown;charset=utf-8" : "application/json" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `secretbridge-pilot-${selected.id}.${format === "markdown" ? "md" : "json"}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch { setError(t.failure); }
  }

  const selectedTarget = selected ? targetById.get(selected.target_id) : undefined;
  const selectedCredential = credentials.find((item) => item.id === selectedTarget?.credential_reference_id);

  return <section className="space-y-6">
    <header className="flex flex-wrap items-end justify-between gap-5">
      <div className="max-w-3xl"><h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">{t.title}</h1><p className="mb-0 mt-3 text-sm leading-6 text-slate-600">{t.subtitle}</p></div>
      <button type="button" onClick={() => setFormOpen((value) => !value)} className="inline-flex h-11 items-center gap-2 rounded-lg bg-slate-950 px-5 text-sm font-semibold text-white hover:bg-cyan-800"><ChevronDown className={`size-4 transition ${formOpen ? "rotate-180" : ""}`} />{t.register}</button>
    </header>

    <div className="flex gap-3 border-l-4 border-amber-500 bg-amber-50 px-5 py-4 text-sm leading-6 text-amber-950"><ShieldAlert className="mt-0.5 size-5 shrink-0" /><div><strong>{t.boundaryTitle}</strong><p className="mb-0 mt-1">{t.boundary}</p></div></div>
    {formOpen && <RegistrationForm t={t} sessionToken={sessionToken} templates={eligibleTemplates} readiness={usableReadiness} platform={usablePlatform} targetById={targetById} onCreated={(campaign) => { replaceCampaign(campaign); setFormOpen(false); }} onError={() => setError(t.failure)} />}
    {error && <p role="alert" className="border-l-4 border-rose-400 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}

    <div className="grid gap-6 xl:grid-cols-[310px_minmax(0,1fr)]">
      <aside className="enterprise-surface p-4">
        <div className="mb-3 flex items-center justify-between"><h2 className="m-0 inline-flex items-center gap-2 text-sm font-semibold text-slate-900"><History className="size-4" />{t.history}</h2><button type="button" onClick={() => void refresh()} aria-label={t.refresh} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-cyan-700"><RefreshCw className="size-4" /></button></div>
        {loading ? <LoaderCircle className="mx-auto my-10 size-6 animate-spin text-cyan-600" /> : campaigns.length === 0 ? <p className="my-8 text-center text-sm leading-6 text-slate-500">{t.empty}</p> : <ol className="m-0 divide-y divide-slate-200 border-y border-slate-200 p-0">{campaigns.map((campaign) => <li key={campaign.id} className="list-none"><button type="button" onClick={() => setSelectedId(campaign.id)} className={`w-full border-l-2 px-3 py-3 text-left ${selected?.id === campaign.id ? "border-cyan-500 bg-cyan-50" : "border-transparent hover:bg-slate-50"}`}><div className="flex items-center justify-between gap-2"><StateBadge state={campaign.state} t={t} /><time className="text-[11px] text-slate-400">{new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "short" }).format(campaign.expires_at_unix_ms)}</time></div><p className="mb-0 mt-2 truncate text-sm font-semibold text-slate-800">{campaign.name}</p><p className="mb-0 mt-1 truncate font-mono text-[11px] text-slate-500">{campaign.id}</p></button></li>)}</ol>}
      </aside>
      {selected ? <CampaignDetail campaign={selected} target={selectedTarget} credential={selectedCredential} t={t} zh={zh} busy={busy} onMutate={mutate} onDownload={download} onUpdated={replaceCampaign} sessionToken={sessionToken} onError={() => setError(t.failure)} /> : <div className="grid min-h-80 place-items-center border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500">{t.empty}</div>}
    </div>
  </section>;
}

function RegistrationForm({ t, sessionToken, templates, readiness, platform, targetById, onCreated, onError }: { t: Record<string, string>; sessionToken: string; templates: ActionTemplate[]; readiness: PilotReadinessSnapshot[]; platform: PlatformBoundarySnapshot[]; targetById: Map<string, Target>; onCreated: (value: PilotCampaign) => void; onError: () => void }) {
  const [saving, setSaving] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setSaving(true);
    const values = new FormData(event.currentTarget);
    try {
      onCreated(await createPilotCampaign(sessionToken, {
        name: String(values.get("name")), action_template_id: String(values.get("template")), readiness_snapshot_id: String(values.get("readiness")), platform_snapshot_id: String(values.get("platform")), authorization_reference: String(values.get("authorization")), least_privilege_reference: String(values.get("leastPrivilege")), expires_in_seconds: Number(values.get("hours")) * 3600,
      }));
    } catch { onError(); } finally { setSaving(false); }
  }
  const ready = templates.length > 0 && readiness.length > 0 && platform.length > 0;
  return <form onSubmit={(event) => void submit(event)} className="enterprise-surface border-t-4 border-cyan-500 p-6">
    <div className="mb-5"><h2 className="m-0 text-lg font-semibold text-slate-950">{t.registrationTitle}</h2><p className="mb-0 mt-2 text-sm leading-6 text-slate-600">{t.registrationHelp}</p></div>
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <Field label={t.name}><input required name="name" maxLength={80} className={inputClass} /></Field>
      <Field label={t.template}><select required name="template" className={inputClass} defaultValue=""><option value="" disabled>{t.choose}</option>{templates.map((item) => <option key={item.id} value={item.id}>{item.name} · {targetById.get(item.target_id)?.name}</option>)}</select></Field>
      <Field label={t.readiness}><select required name="readiness" className={inputClass} defaultValue=""><option value="" disabled>{t.choose}</option>{readiness.map((item) => <option key={item.id} value={item.id}>{item.status} · {new Date(item.created_at_unix_ms).toLocaleString()}</option>)}</select></Field>
      <Field label={t.platform}><select required name="platform" className={inputClass} defaultValue=""><option value="" disabled>{t.choose}</option>{platform.map((item) => <option key={item.id} value={item.id}>{item.status} · {new Date(item.created_at_unix_ms).toLocaleString()}</option>)}</select></Field>
      <Field label={t.authorization}><input required name="authorization" maxLength={96} pattern="[A-Za-z0-9_.:/#-]+" className={inputClass} placeholder="AUTH-2026-001" /></Field>
      <Field label={t.leastPrivilege}><input required name="leastPrivilege" maxLength={96} pattern="[A-Za-z0-9_.:/#-]+" className={inputClass} placeholder="REVIEW-2026-001" /></Field>
      <Field label={t.duration}><input required name="hours" type="number" min="1" max="168" defaultValue="24" className={inputClass} /></Field>
    </div>
    {!ready && <p className="mb-0 mt-4 text-sm text-amber-700">{t.prerequisites}</p>}
    <div className="mt-5 flex justify-end"><button disabled={!ready || saving} className="inline-flex h-10 items-center gap-2 rounded-lg bg-cyan-700 px-5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:cursor-not-allowed disabled:opacity-50">{saving && <LoaderCircle className="size-4 animate-spin" />}{t.create}</button></div>
  </form>;
}

function CampaignDetail({ campaign, target, credential, t, zh, busy, onMutate, onDownload, onUpdated, sessionToken, onError }: { campaign: PilotCampaign; target?: Target; credential?: CredentialReference; t: Record<string, string>; zh: boolean; busy: boolean; onMutate: (action: "activate" | "begin-closure" | "close" | "revoke") => Promise<void>; onDownload: (format: "markdown" | "json") => Promise<void>; onUpdated: (value: PilotCampaign) => void; sessionToken: string; onError: () => void }) {
  const passed = campaign.scenarios.filter((item) => item.result === "passed").length;
  const mutable = campaign.state === "active" || campaign.state === "closing";
  return <article className="enterprise-surface overflow-hidden">
    <div className="border-b border-slate-200 bg-slate-950 p-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><StateBadge state={campaign.state} t={t} inverse /><h2 className="mb-0 mt-3 text-xl font-semibold">{campaign.name}</h2><p className="mb-0 mt-2 font-mono text-xs text-slate-400">{campaign.id}</p></div><div className="flex flex-wrap gap-2"><button onClick={() => void onDownload("markdown")} className={darkButton}><Download className="size-4" />{t.markdown}</button><button onClick={() => void onDownload("json")} className={darkButton}><FileJson2 className="size-4" />{t.json}</button></div></div>
      <dl className="mt-6 grid gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4"><Datum label={t.target} value={target?.name ?? campaign.target_id} /><Datum label={t.authorization} value={campaign.authorization_reference} /><Datum label={t.leastPrivilege} value={campaign.least_privilege_reference} /><Datum label={t.expires} value={new Date(campaign.expires_at_unix_ms).toLocaleString()} /></dl>
    </div>
    <div className="border-b border-slate-200 px-6 py-4"><div className="flex flex-wrap items-center justify-between gap-4"><div><p className="m-0 text-sm font-semibold text-slate-900">{t.progress}: {passed} / {campaign.scenarios.length}</p><p className={`mb-0 mt-1 text-xs ${credential?.secret_state === "not_configured" ? "text-emerald-700" : "text-amber-700"}`}>{t.credential}: {credential?.secret_state === "not_configured" ? t.cleared : t.mustClear}</p></div><div className="flex flex-wrap gap-2">{campaign.state === "registered" && <ActionButton label={t.activate} icon={Play} disabled={busy} onClick={() => onMutate("activate")} />}{campaign.state === "active" && <ActionButton label={t.beginClosure} icon={Square} disabled={busy} onClick={() => onMutate("begin-closure")} />}{campaign.state === "closing" && <ActionButton label={t.close} icon={CheckCircle2} disabled={busy || passed !== campaign.scenarios.length || credential?.secret_state !== "not_configured"} onClick={() => onMutate("close")} />}{["registered", "active", "closing"].includes(campaign.state) && <ActionButton label={t.revoke} icon={XCircle} danger disabled={busy} onClick={() => onMutate("revoke")} />}</div></div></div>
    <div className="overflow-x-auto"><table className="w-full min-w-[880px] border-collapse text-left text-sm"><thead><tr className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500"><th className="px-5 py-3">#</th><th className="px-3 py-3">{t.scenario}</th><th className="px-3 py-3">{t.result}</th><th className="px-3 py-3">{t.evidence}</th><th className="px-3 py-3">{t.reviewer}</th><th className="px-5 py-3 text-right">{t.action}</th></tr></thead><tbody>{campaign.scenarios.map((scenario) => <ScenarioRow key={`${scenario.code}-${scenario.version}`} campaign={campaign} scenario={scenario} mutable={mutable} t={t} zh={zh} sessionToken={sessionToken} onUpdated={onUpdated} onError={onError} />)}</tbody></table></div>
  </article>;
}

function ScenarioRow({ campaign, scenario, mutable, t, zh, sessionToken, onUpdated, onError }: { campaign: PilotCampaign; scenario: PilotScenarioEvidence; mutable: boolean; t: Record<string, string>; zh: boolean; sessionToken: string; onUpdated: (value: PilotCampaign) => void; onError: () => void }) {
  const [draft, setDraft] = useState<Draft>({ result: scenario.result, evidence: scenario.evidence_reference ?? "", reviewer: scenario.reviewer_reference ?? "" });
  const [saving, setSaving] = useState(false);
  async function save() {
    setSaving(true);
    try { onUpdated(await updatePilotScenario(sessionToken, campaign.id, scenario.code, draft.result, draft.result === "not_run" ? null : draft.evidence, draft.result === "not_run" ? null : draft.reviewer, scenario.version)); } catch { onError(); } finally { setSaving(false); }
  }
  const localized = zh ? scenarioZh[scenario.code] : undefined;
  const referencesValid = draft.result === "not_run" || (validReference(draft.evidence) && validReference(draft.reviewer));
  return <tr className="border-b border-slate-100 align-top"><td className="px-5 py-4 font-mono text-xs text-slate-400">{scenario.ordinal}</td><td className="max-w-xs px-3 py-4"><strong className="text-slate-900">{localized?.[0] ?? scenario.code}</strong><p className="mb-0 mt-1 text-xs leading-5 text-slate-500">{localized?.[1] ?? scenario.expected_behavior}</p></td><td className="px-3 py-4"><select disabled={!mutable} value={draft.result} onChange={(event) => setDraft({ ...draft, result: event.target.value as PilotScenarioResult })} className={tableInput}><option value="not_run">{t.not_run}</option><option value="passed">{t.passed}</option><option value="failed">{t.failed}</option><option value="not_applicable">{t.not_applicable}</option></select></td><td className="px-3 py-4"><input disabled={!mutable || draft.result === "not_run"} required={draft.result !== "not_run"} value={draft.evidence} onChange={(event) => setDraft({ ...draft, evidence: event.target.value })} maxLength={96} pattern="[A-Za-z0-9_.:/#-]+" className={tableInput} /></td><td className="px-3 py-4"><input disabled={!mutable || draft.result === "not_run"} required={draft.result !== "not_run"} value={draft.reviewer} onChange={(event) => setDraft({ ...draft, reviewer: event.target.value })} maxLength={96} pattern="[A-Za-z0-9_.:/#-]+" className={tableInput} /></td><td className="px-5 py-4 text-right"><button disabled={!mutable || saving || !referencesValid} onClick={() => void save()} className="rounded-lg border border-slate-300 px-3 py-2 text-xs font-semibold text-slate-700 hover:border-cyan-500 hover:text-cyan-700 disabled:opacity-40">{saving ? t.saving : t.save}</button></td></tr>;
}

function StateBadge({ state, t, inverse = false }: { state: PilotCampaignState; t: Record<string, string>; inverse?: boolean }) {
  const Icon = state === "closed" ? CheckCircle2 : state === "revoked" || state === "expired" ? XCircle : state === "closing" ? AlertTriangle : Play;
  const style = inverse ? "bg-white/10 text-white ring-white/15" : state === "closed" ? "bg-emerald-100 text-emerald-800 ring-emerald-200" : state === "revoked" || state === "expired" ? "bg-rose-100 text-rose-800 ring-rose-200" : state === "closing" ? "bg-amber-100 text-amber-800 ring-amber-200" : "bg-cyan-100 text-cyan-800 ring-cyan-200";
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${style}`}><Icon className="size-3.5" />{t[state]}</span>;
}

function ActionButton({ label, icon: Icon, onClick, disabled, danger = false }: { label: string; icon: LucideIcon; onClick: () => Promise<void>; disabled: boolean; danger?: boolean }) { return <button type="button" disabled={disabled} onClick={() => void onClick()} className={`inline-flex h-9 items-center gap-2 rounded-lg px-3 text-xs font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40 ${danger ? "bg-rose-700 hover:bg-rose-800" : "bg-cyan-700 hover:bg-cyan-800"}`}><Icon className="size-4" />{label}</button>; }
function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="grid gap-2 text-xs font-semibold text-slate-700"><span>{label}</span>{children}</label>; }
function Datum({ label, value }: { label: string; value: string }) { return <div><dt className="text-slate-400">{label}</dt><dd className="mb-0 ml-0 mt-1 truncate font-medium text-slate-100">{value}</dd></div>; }

const inputClass = "h-10 rounded-lg border border-slate-300 bg-white px-3 text-sm font-normal text-slate-900 outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-100";
const tableInput = "h-9 w-full min-w-32 rounded-lg border border-slate-300 bg-white px-2 text-xs text-slate-800 disabled:bg-slate-50 disabled:text-slate-500";
const darkButton = "inline-flex items-center gap-2 rounded-lg bg-white/10 px-3 py-2 text-xs font-semibold text-white ring-1 ring-inset ring-white/15 hover:bg-white/20";
const referencePattern = /^[A-Za-z0-9_.:/#-]{1,96}$/u;
function validReference(value: string): boolean { return referencePattern.test(value.trim()); }

const zhText: Record<string, string> = {
  title: "低权限试点工作台", subtitle: "把测试目标、固定检查模板、准入快照、平台证据和外部授权编号绑定为限时试点记录，并以固定场景矩阵完成复核与结项。", register: "登记新试点", boundaryTitle: "执行边界", boundary: "这里管理授权与证据，不会自动连接远端目标。授权编号由操作人员录入，系统不会将其误称为已验证的目标方授权。", failure: "操作未完成。请检查前置门槛、记录版本和本地服务状态后重试。", history: "试点记录", refresh: "刷新", empty: "尚无试点记录。完成目标、模板、准入和平台证据后可登记。", registrationTitle: "登记受控试点", registrationHelp: "仅列出非生产 PostgreSQL 状态检查和未被阻断的证据快照。引用字段只允许字母、数字及 -_.:/#。", name: "试点名称", template: "固定检查模板", readiness: "准入快照", platform: "平台证据", authorization: "目标方授权编号", leastPrivilege: "最小权限复核编号", duration: "有效期（小时）", choose: "请选择", prerequisites: "缺少可用前置项，请先在连接目标、执行策略、试点准入或平台证据中补齐。", create: "登记试点", target: "测试目标", expires: "到期时间", progress: "验证进度", credential: "临时凭据", cleared: "已清除", mustClear: "结项前必须在凭据页清除", activate: "激活", beginClosure: "进入结项", close: "确认结项", revoke: "撤销", markdown: "下载 Markdown", json: "下载 JSON", scenario: "必测场景", result: "结论", evidence: "证据编号", reviewer: "复核人编号", action: "操作", save: "保存", saving: "保存中…", registered: "已登记", active: "进行中", closing: "结项中", closed: "已结项", revoked: "已撤销", expired: "已过期", not_run: "未执行", passed: "通过", failed: "失败", not_applicable: "不适用",
};
const enText: Record<string, string> = {
  title: "Low-privilege pilot workspace", subtitle: "Bind a test target, fixed check template, readiness snapshot, platform evidence and external authorization references into a time-bounded pilot record with a fixed verification matrix.", register: "Register pilot", boundaryTitle: "Execution boundary", boundary: "This workspace governs authorization and evidence; it does not automatically contact a remote target. Operator-entered references are not represented as independently verified authority.", failure: "The operation did not complete. Check prerequisites, record versions and the local service, then retry.", history: "Pilot records", refresh: "Refresh", empty: "No pilot record yet. Establish the target, template, readiness and platform evidence first.", registrationTitle: "Register controlled pilot", registrationHelp: "Only non-production PostgreSQL status checks and non-blocked evidence snapshots are listed. References allow letters, digits and -_.:/# only.", name: "Pilot name", template: "Fixed check template", readiness: "Readiness snapshot", platform: "Platform evidence", authorization: "Target-owner authorization reference", leastPrivilege: "Least-privilege review reference", duration: "Duration (hours)", choose: "Select", prerequisites: "Eligible prerequisites are missing. Complete targets, policies, readiness or platform evidence first.", create: "Register", target: "Test target", expires: "Expires", progress: "Verification progress", credential: "Temporary credential", cleared: "Cleared", mustClear: "Must be cleared on the Credentials page before closure", activate: "Activate", beginClosure: "Begin closure", close: "Close", revoke: "Revoke", markdown: "Download Markdown", json: "Download JSON", scenario: "Required scenario", result: "Result", evidence: "Evidence reference", reviewer: "Reviewer reference", action: "Action", save: "Save", saving: "Saving…", registered: "Registered", active: "Active", closing: "Closing", closed: "Closed", revoked: "Revoked", expired: "Expired", not_run: "Not run", passed: "Passed", failed: "Failed", not_applicable: "Not applicable",
};
