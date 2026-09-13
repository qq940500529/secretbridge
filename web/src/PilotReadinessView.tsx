// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  ClipboardList,
  Database,
  Download,
  FileJson2,
  Fingerprint,
  History,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldQuestion,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  createPilotReadiness,
  getPilotReadinessReport,
  listPilotReadiness,
  type PilotReadinessCheck,
  type PilotReadinessSnapshot,
  type PilotReadinessStatus,
} from "./api";

type Language = "zh-CN" | "en";

const zhChecks: Record<string, [string, string, string]> = {
  test_target_available: ["测试目标", "已登记专用测试数据库目标", "找到的测试数据库目标"],
  postgres_configuration_complete: ["连接配置", "测试目标具备完整的 PostgreSQL TLS 配置", "完整配置的测试目标"],
  credential_available: ["凭据状态", "测试目标已关联可用的系统凭据", "凭据就绪的测试目标"],
  controlled_template_available: ["受控模板", "已启用仅返回状态的固定 PostgreSQL 检查", "技术条件就绪的测试目标"],
  latest_validation_digest: ["证据完整性", "最近安全自检的证据指纹完整", "最近证据已重新计算并核对"],
  latest_validation_result: ["安全自检结论", "最近一次完整安全自检已纳入准入判断", "安全自检结果"],
  identity_boundary_evidence: ["身份边界", "安装后的操作系统身份控制仍需平台证据", "当前运行时仍声明同用户隔离未验证"],
  pilot_authorization_record: ["试点授权", "目标负责人须批准限时、非生产试点", "本机自检不能代替目标负责人的授权记录"],
  least_privilege_review: ["最小权限", "数据库授权集须由独立人员确认", "凭据可用不等于远端账号权限已经合规"],
  independent_security_review: ["独立复核", "安全敏感实现仍需独立评审", "产品自生成证据不构成独立认证"],
};

export function PilotReadinessView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const text = zh
    ? {
        eyebrow: "M3 · 安全试点准入",
        title: "把“能运行”与“允许试点”分开证明",
        subtitle:
          "汇总测试目标、凭据状态、受控模板和最近安全自检，生成不可静默篡改的准入快照。快照不读取秘密、不连接远端，也不代替业务授权或独立评审。",
        create: "生成完整准入快照",
        creating: "正在核对全部门槛…",
        refresh: "刷新快照",
        empty: "尚无准入快照。先完成安全自检，再生成首份试点评估。",
        failure: "准入评估未能完成，请检查本地服务后重试。",
        disclosureTitle: "准入边界",
        disclosure:
          "“技术条件就绪”只说明本机配置链完整。目标方授权、远端最小权限、安装后身份隔离和独立安全复核必须留下外部证据，系统不会自动替你勾选。",
        history: "评估历史",
        ready: "可进入试点",
        attention: "待人工门槛",
        blocked: "技术条件阻断",
        candidate: "测试目标",
        eligible: "技术就绪",
        checks: "准入检查",
        passed: "通过",
        warning: "待验证",
        failed: "阻断",
        configuration: "配置",
        evidence: "证据",
        manualGate: "人工门槛",
        digest: "证据指纹",
        verified: "已校验",
        mismatch: "不匹配",
        latestValidation: "最近安全自检",
        noValidation: "未建立",
        profile: "准入规则",
        platform: "平台",
        markdown: "下载 Markdown",
        json: "下载 JSON",
      }
    : {
        eyebrow: "M3 · Security pilot readiness",
        title: "Prove that runnable is not the same as authorized",
        subtitle:
          "Aggregate test targets, credential state, controlled templates and the latest security validation into a tamper-evident readiness snapshot. No secret is read and no remote target is contacted.",
        create: "Create full readiness snapshot",
        creating: "Evaluating every gate…",
        refresh: "Refresh snapshots",
        empty: "No readiness snapshot yet. Run security validation, then establish the first pilot assessment.",
        failure: "The readiness assessment failed. Check the local service and retry.",
        disclosureTitle: "Readiness boundary",
        disclosure:
          "Technically eligible means only that the local configuration chain is complete. Target-owner authorization, remote least privilege, installed identity isolation and independent review require external evidence.",
        history: "Assessment history",
        ready: "Pilot ready",
        attention: "Manual gates open",
        blocked: "Technically blocked",
        candidate: "Test targets",
        eligible: "Technically eligible",
        checks: "Readiness checks",
        passed: "Passed",
        warning: "Needs evidence",
        failed: "Blocked",
        configuration: "Configuration",
        evidence: "Evidence",
        manualGate: "Manual gate",
        digest: "Evidence fingerprint",
        verified: "Verified",
        mismatch: "Mismatch",
        latestValidation: "Latest validation",
        noValidation: "Not established",
        profile: "Readiness profile",
        platform: "Platform",
        markdown: "Download Markdown",
        json: "Download JSON",
      };
  const [items, setItems] = useState<PilotReadinessSnapshot[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? items[0] ?? null,
    [items, selectedId],
  );

  async function refresh() {
    const result = await listPilotReadiness(sessionToken);
    setItems(result.items);
    setSelectedId((current) =>
      current && result.items.some((item) => item.id === current)
        ? current
        : (result.items[0]?.id ?? null),
    );
  }

  useEffect(() => {
    let active = true;
    refresh()
      .catch(() => active && setError(text.failure))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sessionToken, zh]);

  async function createSnapshot() {
    setCreating(true);
    setError(null);
    try {
      const snapshot = await createPilotReadiness(sessionToken);
      setItems((current) => [snapshot, ...current.filter((item) => item.id !== snapshot.id)]);
      setSelectedId(snapshot.id);
    } catch {
      setError(text.failure);
    } finally {
      setCreating(false);
    }
  }

  async function download(format: "markdown" | "json") {
    if (!selected) return;
    try {
      const report = await getPilotReadinessReport(sessionToken, selected.id);
      const content =
        format === "markdown"
          ? report.markdown
          : JSON.stringify(
              {
                snapshot: report.snapshot,
                digest_verified: report.digest_verified,
                disclosure: report.disclosure,
              },
              null,
              2,
            );
      const blob = new Blob([content], {
        type: format === "markdown" ? "text/markdown;charset=utf-8" : "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `secretbridge-pilot-readiness-${selected.id}.${format === "markdown" ? "md" : "json"}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(text.failure);
    }
  }

  return (
    <section className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-5">
        <div className="max-w-3xl">
          <p className="m-0 text-xs font-bold uppercase tracking-[0.18em] text-cyan-700">{text.eyebrow}</p>
          <h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1>
          <p className="mb-0 mt-3 text-sm leading-6 text-slate-600">{text.subtitle}</p>
        </div>
        <button type="button" onClick={() => void createSnapshot()} disabled={creating} className="inline-flex h-11 items-center gap-2 rounded-xl bg-slate-950 px-5 text-sm font-semibold text-white shadow-lg shadow-slate-300 transition hover:bg-cyan-800 disabled:cursor-wait disabled:opacity-70">
          {creating ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
          {creating ? text.creating : text.create}
        </button>
      </header>

      <div className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
        <ShieldQuestion className="mt-0.5 size-5 shrink-0" />
        <div><strong>{text.disclosureTitle}</strong><p className="mb-0 mt-1">{text.disclosure}</p></div>
      </div>
      {error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}

      <div className="grid gap-6 xl:grid-cols-[300px_minmax(0,1fr)]">
        <aside className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="m-0 inline-flex items-center gap-2 text-sm font-semibold text-slate-900"><History className="size-4" />{text.history}</h2>
            <button type="button" onClick={() => void refresh()} aria-label={text.refresh} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-cyan-700"><RefreshCw className="size-4" /></button>
          </div>
          {loading ? <LoaderCircle className="mx-auto my-10 size-6 animate-spin text-cyan-600" /> : items.length === 0 ? <p className="my-8 text-center text-sm leading-6 text-slate-500">{text.empty}</p> : <ol className="m-0 space-y-2 p-0">{items.map((item) => <li key={item.id} className="list-none"><button type="button" onClick={() => setSelectedId(item.id)} className={`w-full rounded-xl border p-3 text-left transition ${selected?.id === item.id ? "border-cyan-300 bg-cyan-50" : "border-transparent bg-slate-50 hover:border-slate-200"}`}><div className="flex items-center justify-between gap-2"><ReadinessBadge status={item.status} text={text} /><time className="text-[11px] text-slate-400">{new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "short" }).format(item.created_at_unix_ms)}</time></div><p className="mb-0 mt-2 truncate font-mono text-[11px] text-slate-500">{item.id}</p></button></li>)}</ol>}
        </aside>
        {selected ? <ReadinessDetail snapshot={selected} language={language} text={text} onDownload={download} /> : <div className="grid min-h-80 place-items-center rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500"><div><ClipboardList className="mx-auto mb-4 size-9 text-slate-300" />{text.empty}</div></div>}
      </div>
    </section>
  );
}

function ReadinessDetail({ snapshot, language, text, onDownload }: { snapshot: PilotReadinessSnapshot; language: Language; text: Record<string, string>; onDownload: (format: "markdown" | "json") => Promise<void> }) {
  return <article className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
    <div className="border-b border-slate-200 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950 p-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><ReadinessBadge status={snapshot.status} text={text} inverse /><h2 className="mb-0 mt-3 text-xl font-semibold">{snapshot.checks.length} {text.checks}</h2><p className="mb-0 mt-2 font-mono text-xs text-slate-400">{snapshot.id}</p></div><div className="flex flex-wrap gap-2"><button type="button" onClick={() => void onDownload("markdown")} className={downloadClass}><Download className="size-4" />{text.markdown}</button><button type="button" onClick={() => void onDownload("json")} className={downloadClass}><FileJson2 className="size-4" />{text.json}</button></div></div>
      <div className="mt-6 grid gap-3 sm:grid-cols-2"><Metric icon={Database} label={text.candidate} value={snapshot.candidate_test_targets} /><Metric icon={CheckCircle2} label={text.eligible} value={snapshot.eligible_test_targets} /></div>
      <dl className="mt-5 grid gap-3 text-xs sm:grid-cols-3"><Datum label={text.latestValidation} value={snapshot.latest_validation_id ?? text.noValidation} /><Datum label={text.profile} value={snapshot.profile_version} /><Datum label={text.platform} value={snapshot.platform} /></dl>
    </div>
    <div className="p-6">
      <div className={`mb-5 rounded-xl border p-4 ${snapshot.digest_verified ? "border-emerald-200 bg-emerald-50" : "border-rose-200 bg-rose-50"}`}><div className={`flex items-center gap-2 text-sm font-semibold ${snapshot.digest_verified ? "text-emerald-800" : "text-rose-800"}`}><Fingerprint className="size-4" />{text.digest} · {snapshot.digest_verified ? text.verified : text.mismatch}</div><p className="mb-0 mt-2 break-all font-mono text-[11px] leading-5 text-slate-600">{snapshot.evidence_digest_sha256}</p></div>
      <ol className="m-0 space-y-3 p-0">{snapshot.checks.map((check) => <CheckCard key={check.code} check={check} language={language} text={text} />)}</ol>
    </div>
  </article>;
}

function CheckCard({ check, language, text }: { check: PilotReadinessCheck; language: Language; text: Record<string, string> }) {
  const Icon = check.status === "passed" ? CheckCircle2 : check.status === "warning" ? AlertTriangle : Ban;
  const localized = language === "zh-CN" ? zhChecks[check.code] : undefined;
  const title = localized?.[0] ?? check.code;
  const summary = localized?.[1] ?? check.summary;
  const evidence = localized
    ? evidenceCount(check.evidence)
      ? `${localized[2]}：${evidenceCount(check.evidence)}`
      : localized[2]
    : check.evidence;
  const category = check.category === "configuration" ? text.configuration : check.category === "evidence" ? text.evidence : text.manualGate;
  const style = check.status === "passed" ? "border-emerald-200 bg-emerald-50/50 text-emerald-700" : check.status === "warning" ? "border-amber-200 bg-amber-50/50 text-amber-700" : "border-rose-200 bg-rose-50/50 text-rose-700";
  return <li className={`list-none rounded-xl border p-4 ${style}`}><div className="flex items-start gap-3"><Icon className="mt-0.5 size-5 shrink-0" /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="m-0 text-sm font-semibold text-slate-900">{title}</h3><span className="rounded-full bg-white/70 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide">{category}</span></div><p className="mb-0 mt-1 text-xs leading-5 text-slate-600">{summary}</p><p className="mb-0 mt-2 text-xs leading-5">{evidence}</p></div></div></li>;
}

function evidenceCount(evidence: string): string | null {
  return evidence.match(/^\d+/)?.[0] ?? null;
}

function ReadinessBadge({ status, text, inverse = false }: { status: PilotReadinessStatus; text: Record<string, string>; inverse?: boolean }) {
  const Icon = status === "ready" ? CheckCircle2 : status === "attention" ? AlertTriangle : Ban;
  const style = inverse ? "bg-white/10 text-white ring-white/15" : status === "ready" ? "bg-emerald-100 text-emerald-800 ring-emerald-200" : status === "attention" ? "bg-amber-100 text-amber-800 ring-amber-200" : "bg-rose-100 text-rose-800 ring-rose-200";
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${style}`}><Icon className="size-3.5" />{text[status]}</span>;
}

function Metric({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: number }) {
  return <div className="flex items-center gap-3 rounded-xl bg-white/10 p-4 ring-1 ring-inset ring-white/10"><div className="grid size-10 place-items-center rounded-lg bg-cyan-400/15 text-cyan-200"><Icon className="size-5" /></div><div><p className="m-0 text-xs text-slate-400">{label}</p><p className="m-0 mt-1 text-2xl font-bold">{value}</p></div></div>;
}

function Datum({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-slate-400">{label}</dt><dd className="mb-0 ml-0 mt-1 truncate font-mono text-slate-100">{value}</dd></div>;
}

const downloadClass = "inline-flex items-center gap-2 rounded-lg bg-white/10 px-3 py-2 text-xs font-semibold text-white ring-1 ring-inset ring-white/15 transition hover:bg-white/20";
