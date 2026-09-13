// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileJson2,
  Fingerprint,
  FlaskConical,
  History,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  createSecurityValidation,
  getSecurityValidationReport,
  listSecurityValidations,
  type SecurityValidationCheck,
  type SecurityValidationRun,
  type SecurityValidationStatus,
} from "./api";

type Language = "zh-CN" | "en";

const zhCheckCopy: Record<string, [title: string, summary: string, evidence: string]> = {
  catalog_integrity: ["配置库完整性", "SQLite配置库完整性检查已完成", "完整性检查返回预期结果"],
  foreign_key_integrity: ["数据关系完整性", "配置记录之间不存在外键违规", "外键检查没有返回违规记录"],
  credential_metadata_only: ["凭据值不落配置库", "凭据目录只保存状态与描述元数据", "凭据表中没有用于保存秘密值的列"],
  bounded_audit_payloads: ["审计载荷白名单", "安全事件均使用服务端固定消息", "现有事件没有超出消息白名单"],
  approval_bypass_blocked: ["未审批执行阻断", "未获批准的执行请求被拒绝", "隔离场景中的待审批记录不能创建运行"],
  single_use_and_replay: ["单次授权与幂等重放", "批准单次消费与同请求重放均按策略执行", "同键重放返回原运行，第二次消费被拒绝"],
  rotation_invalidates_authorization: ["变更后旧授权失效", "目标变更使旧授权失效", "目标版本变化后，策略复核拒绝继续执行"],
  revocation_blocks_execution: ["撤销后执行阻断", "已撤销的批准不能创建受控运行", "隔离场景在创建运行前拒绝已撤销批准"],
  interrupted_run_recovery: ["中断任务恢复", "中断运行恢复为明确的失败终态", "恢复产生服务重启状态与固定中断事件"],
  identity_boundary_review: ["操作系统身份边界", "操作系统身份隔离需要外部独立验证", "运行时仍为同用户兼容且未验证隔离"],
};

export function SecurityValidationView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const text = zh
    ? {
        title: "进入真实试点前，先让安全结论可重复",
        subtitle:
          "一次运行同时检查当前配置库，并在隔离内存中重演审批绕过、重复消费、配置轮换、授权撤销和异常恢复。过程不读取凭据值，也不连接业务系统。",
        run: "运行完整验证",
        running: "正在执行隔离验证…",
        refresh: "刷新记录",
        noRuns: "尚无验证证据。运行一次完整验证以建立首份基线。",
        failed: "安全验证未能完成，请检查本地服务后重试。",
        disclosureTitle: "证据边界",
        disclosure:
          "这是可重复的产品自检，不是第三方认证。操作系统身份隔离仍需独立验证；真实低权限试点也必须另行批准。",
        history: "验证历史",
        checks: "检查项",
        passed: "通过",
        warning: "待人工验证",
        failedStatus: "失败",
        instance: "当前实例",
        isolated: "隔离攻防场景",
        manual: "人工门槛",
        digest: "证据指纹",
        verified: "指纹已校验",
        mismatch: "指纹不匹配，证据可能已变更",
        version: "应用版本",
        suite: "验证套件",
        platform: "运行平台",
        markdown: "下载 Markdown",
        json: "下载 JSON",
        detail: "证据",
      }
    : {
        title: "Make security conclusions repeatable before a real pilot",
        subtitle:
          "One run inspects the current catalog and replays approval bypass, duplicate consumption, rotation, revocation and recovery in isolated memory. It reads no secret values and connects to no business system.",
        run: "Run full validation",
        running: "Running isolated validation…",
        refresh: "Refresh history",
        noRuns: "No validation evidence yet. Run the complete suite to establish a baseline.",
        failed: "Security validation could not complete. Check the local service and retry.",
        disclosureTitle: "Evidence boundary",
        disclosure:
          "This is repeatable product self-validation, not third-party certification. OS identity isolation still needs independent verification, and a real least-privilege pilot requires separate approval.",
        history: "Validation history",
        checks: "Checks",
        passed: "Passed",
        warning: "Manual verification",
        failedStatus: "Failed",
        instance: "Current instance",
        isolated: "Isolated attack scenario",
        manual: "Manual gate",
        digest: "Evidence fingerprint",
        verified: "Digest verified",
        mismatch: "Digest mismatch; evidence may have changed",
        version: "Application version",
        suite: "Validation suite",
        platform: "Platform",
        markdown: "Download Markdown",
        json: "Download JSON",
        detail: "Evidence",
      };
  const [runs, setRuns] = useState<SecurityValidationRun[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selected = useMemo(
    () => runs.find((run) => run.id === selectedId) ?? runs[0] ?? null,
    [runs, selectedId],
  );

  async function refresh() {
    const response = await listSecurityValidations(sessionToken);
    setRuns(response.items);
    setSelectedId((current) =>
      current && response.items.some((run) => run.id === current)
        ? current
        : (response.items[0]?.id ?? null),
    );
  }

  useEffect(() => {
    let active = true;
    refresh()
      .catch(() => {
        if (active) setError(text.failed);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [sessionToken, text.failed]);

  async function runValidation() {
    setRunning(true);
    setError(null);
    try {
      const result = await createSecurityValidation(sessionToken);
      setRuns((current) => [result, ...current.filter((run) => run.id !== result.id)]);
      setSelectedId(result.id);
    } catch {
      setError(text.failed);
    } finally {
      setRunning(false);
    }
  }

  async function download(format: "markdown" | "json") {
    if (!selected) return;
    try {
      const report = await getSecurityValidationReport(sessionToken, selected.id);
      const content =
        format === "markdown"
          ? report.markdown
          : JSON.stringify(
              {
                run: report.run,
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
      anchor.download = `secretbridge-security-${selected.id}.${format === "markdown" ? "md" : "json"}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(text.failed);
    }
  }

  return (
    <section className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-5">
        <div className="max-w-3xl">
          <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1>
          <p className="mb-0 mt-3 text-sm leading-6 text-slate-600">{text.subtitle}</p>
        </div>
        <button
          type="button"
          onClick={() => void runValidation()}
          disabled={running}
          className="inline-flex h-11 items-center gap-2 rounded-lg bg-slate-950 px-5 text-sm font-semibold text-white transition hover:bg-cyan-800 disabled:cursor-wait disabled:opacity-70"
        >
          {running ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
          {running ? text.running : text.run}
        </button>
      </header>

      <div className="flex gap-3 border-l-4 border-amber-400 bg-amber-50 px-5 py-4 text-sm leading-6 text-amber-950">
        <ShieldAlert className="mt-0.5 size-5 shrink-0" />
        <div><strong>{text.disclosureTitle}</strong><p className="mb-0 mt-1">{text.disclosure}</p></div>
      </div>
      {error && <p role="alert" className="border-l-4 border-rose-400 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}

      <div className="grid gap-6 xl:grid-cols-[300px_minmax(0,1fr)]">
        <aside className="enterprise-surface p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="m-0 inline-flex items-center gap-2 text-sm font-semibold text-slate-900"><History className="size-4" />{text.history}</h2>
            <button type="button" onClick={() => void refresh()} aria-label={text.refresh} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-cyan-700"><RefreshCw className="size-4" /></button>
          </div>
          {loading ? <LoaderCircle className="mx-auto my-10 size-6 animate-spin text-cyan-600" /> : runs.length === 0 ? <p className="my-8 text-center text-sm leading-6 text-slate-500">{text.noRuns}</p> : <ol className="m-0 divide-y divide-slate-200 border-y border-slate-200 p-0">{runs.map((run) => <li key={run.id} className="list-none"><button type="button" onClick={() => setSelectedId(run.id)} className={`w-full border-l-2 px-3 py-3 text-left transition ${selected?.id === run.id ? "border-cyan-500 bg-cyan-50" : "border-transparent hover:bg-slate-50"}`}><div className="flex items-center justify-between gap-2"><StatusBadge status={run.status} labels={text} /><time className="text-[11px] text-slate-400">{new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "short" }).format(run.finished_at_unix_ms)}</time></div><p className="mb-0 mt-2 truncate font-mono text-[11px] text-slate-500">{run.id}</p></button></li>)}</ol>}
        </aside>

        {selected ? <ValidationDetail run={selected} language={language} text={text} onDownload={download} /> : <div className="grid min-h-80 place-items-center border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500"><div><FlaskConical className="mx-auto mb-4 size-9 text-slate-300" />{text.noRuns}</div></div>}
      </div>
    </section>
  );
}

function ValidationDetail({ run, language, text, onDownload }: { run: SecurityValidationRun; language: Language; text: Record<string, string>; onDownload: (format: "markdown" | "json") => Promise<void> }) {
  const passed = run.checks.filter((check) => check.status === "passed").length;
  return <article className="enterprise-surface">
    <div className="border-b border-slate-200 bg-slate-950 p-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><StatusBadge status={run.status} labels={text} inverse /><h2 className="mb-0 mt-3 text-xl font-semibold">{passed}/{run.checks.length} {text.checks}</h2><p className="mb-0 mt-2 font-mono text-xs text-slate-400">{run.id}</p></div><div className="flex flex-wrap gap-2"><button type="button" onClick={() => void onDownload("markdown")} className={downloadClass}><Download className="size-4" />{text.markdown}</button><button type="button" onClick={() => void onDownload("json")} className={downloadClass}><FileJson2 className="size-4" />{text.json}</button></div></div>
      <dl className="mt-6 grid gap-3 text-xs sm:grid-cols-3"><Datum label={text.version} value={run.application_version} /><Datum label={text.suite} value={run.suite_version} /><Datum label={text.platform} value={run.platform} /></dl>
    </div>
    <div className="p-6">
      <div className={`mb-5 border-l-4 p-4 ${run.digest_verified ? "border-emerald-400 bg-emerald-50" : "border-rose-400 bg-rose-50"}`}><div className={`flex items-center gap-2 text-sm font-semibold ${run.digest_verified ? "text-emerald-800" : "text-rose-800"}`}><Fingerprint className="size-4" />{text.digest} · {run.digest_verified ? text.verified : text.mismatch}</div><p className={`mb-0 mt-2 break-all font-mono text-[11px] leading-5 ${run.digest_verified ? "text-emerald-700" : "text-rose-700"}`}>{run.evidence_digest_sha256}</p></div>
      <ol className="enterprise-checklist m-0 border-y border-slate-200 p-0">{run.checks.map((check) => <CheckCard key={check.code} check={check} language={language} text={text} />)}</ol>
    </div>
  </article>;
}

function CheckCard({ check, language, text }: { check: SecurityValidationCheck; language: Language; text: Record<string, string> }) {
  const Icon = check.status === "passed" ? CheckCircle2 : check.status === "warning" ? AlertTriangle : XCircle;
  const localized = language === "zh-CN" ? zhCheckCopy[check.code] : undefined;
  const title = localized?.[0] ?? check.code;
  const summary = localized?.[1] ?? check.summary;
  const evidence = localized?.[2] ?? check.evidence;
  const category = check.category === "instance" ? text.instance : check.category === "isolated_scenario" ? text.isolated : text.manual;
  const color = check.status === "passed" ? "text-emerald-700" : check.status === "warning" ? "text-amber-700" : "text-rose-700";
  return <li className="list-none py-4"><div className="flex items-start gap-3"><Icon className={`mt-0.5 size-5 shrink-0 ${color}`} /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="m-0 text-sm font-semibold text-slate-900">{title}</h3><span className="text-[10px] font-bold uppercase tracking-wide text-slate-500">{category}</span></div><p className="mb-0 mt-1 text-xs leading-5 text-slate-600">{summary}</p><p className="mb-0 mt-2 text-xs leading-5 text-slate-600"><strong>{text.detail}：</strong>{evidence}</p></div></div></li>;
}

function StatusBadge({ status, labels, inverse = false }: { status: SecurityValidationStatus; labels: Record<string, string>; inverse?: boolean }) {
  const Icon = status === "passed" ? ShieldCheck : status === "warning" ? AlertTriangle : XCircle;
  const label = status === "passed" ? labels.passed : status === "warning" ? labels.warning : labels.failedStatus;
  const style = inverse ? "bg-white/10 text-white ring-white/15" : status === "passed" ? "bg-emerald-100 text-emerald-800 ring-emerald-200" : status === "warning" ? "bg-amber-100 text-amber-800 ring-amber-200" : "bg-rose-100 text-rose-800 ring-rose-200";
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${style}`}><Icon className="size-3.5" />{label}</span>;
}

function Datum({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-slate-400">{label}</dt><dd className="mb-0 ml-0 mt-1 font-mono text-slate-100">{value}</dd></div>;
}

const downloadClass = "inline-flex items-center gap-2 rounded-lg bg-white/10 px-3 py-2 text-xs font-semibold text-white ring-1 ring-inset ring-white/15 transition hover:bg-white/20";
