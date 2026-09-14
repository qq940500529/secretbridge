// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Download,
  FileJson2,
  Fingerprint,
  History,
  Info,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  createPlatformBoundary,
  getPlatformBoundaryReport,
  listPlatformBoundary,
  type PlatformBoundaryCheck,
  type PlatformBoundarySnapshot,
  type PlatformBoundaryStatus,
  type PlatformCheckStatus,
} from "./api";

type Language = "zh-CN" | "en";

const zhChecks: Record<string, [string, string]> = {
  persistent_runtime_directory: ["运行目录", "当前会话没有可检查的持久化运行目录"],
  runtime_directory_type: ["目录类型", "运行目录必须是真实目录，不能由符号链接替代"],
  runtime_directory_permissions: ["目录权限", "运行目录不得向组用户或其他用户开放"],
  runtime_directory_acl: ["目录 ACL", "运行目录应只允许预期的服务身份访问"],
  connection_document_type: ["连接文档类型", "连接文档必须是普通文件，不能由符号链接替代"],
  connection_document_permissions: ["连接文档权限", "连接文档不得向组用户或其他用户开放"],
  connection_document_acl: ["连接文档 ACL", "连接文档应只允许预期的服务身份访问"],
  ipc_endpoint_permissions: ["IPC 端点权限", "Unix 套接字必须是私有套接字节点"],
  ipc_owner_consistency: ["IPC 所有者一致性", "运行目录、连接文档和套接字必须属于同一身份"],
  local_transport_scope: ["本地传输", "原生桥接只使用本机 Unix 域套接字"],
  remote_pipe_clients_rejected: ["远程客户端", "命名管道拒绝来自远程计算机的客户端"],
  first_pipe_instance: ["首实例约束", "代理必须取得命名管道的首个服务实例"],
  named_pipe_explicit_dacl: ["管道 DACL", "命名管道仍需绑定明确的服务身份访问控制"],
  peer_identity_enforcement: ["对端身份", "每个 IPC 客户端都应核对操作系统身份"],
  native_credential_store: ["系统凭据库", "持久化运行应使用操作系统原生凭据库"],
  installed_service_identity: ["安装身份", "安装后的服务身份需要独立证据确认"],
  hostile_subject_denial: ["拒绝未授权主体", "需要在已安装环境验证越权主体确实无法连接"],
};

export function PlatformBoundaryView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const text = zh
    ? {
        title: "平台身份与 IPC 证据",
        subtitle:
          "检查运行目录、连接文档、本地 IPC 和系统凭据库的固定安全事实，并保存可复算的证据快照。探针不会返回用户名、系统标识、路径、端点名称或秘密。",
        run: "采集当前证据",
        running: "正在采集…",
        refresh: "刷新历史",
        empty: "尚无平台证据。采集后可查看每项检查及完整性指纹。",
        failure: "平台证据采集失败，请检查本地服务后重试。",
        boundaryTitle: "证据边界",
        boundary:
          "产品自检不能替代安装后身份审计和越权主体测试。只有本机可重复事实会自动通过；外部证据未完成时，公开身份边界继续保持为同用户隔离未验证。",
        history: "证据历史",
        verified: "边界已验证",
        attention: "仍需外部证据",
        blocked: "本机检查阻断",
        checks: "项平台检查",
        passed: "通过",
        warning: "待验证",
        failed: "阻断",
        not_applicable: "不适用",
        runtime_directory: "运行目录",
        ipc_transport: "IPC 传输",
        credential_store: "凭据库",
        installation: "安装环境",
        external_evidence: "外部证据",
        digest: "证据指纹",
        digestOk: "已重新计算并匹配",
        digestBad: "与已保存证据不匹配",
        platform: "平台",
        context: "运行上下文",
        persistent: "持久化服务",
        ephemeral: "临时测试",
        boundaryLabel: "公开身份边界",
        boundaryValue: "同用户隔离未验证",
        profile: "检查规则",
        markdown: "下载 Markdown",
        json: "下载 JSON",
      }
    : {
        title: "Platform identity and IPC evidence",
        subtitle:
          "Inspect fixed security facts for the runtime directory, connection document, local IPC and native credential store, then retain a digest-verifiable snapshot without exposing identities, paths, endpoint names or secrets.",
        run: "Collect current evidence",
        running: "Collecting…",
        refresh: "Refresh history",
        empty: "No platform evidence yet. Collect a snapshot to inspect each check and its evidence digest.",
        failure: "Platform evidence collection failed. Check the local service and retry.",
        boundaryTitle: "Evidence boundary",
        boundary:
          "A product self-check cannot replace installed identity review or hostile-subject testing. The public identity boundary remains unverified for same-user isolation while external evidence is incomplete.",
        history: "Evidence history",
        verified: "Boundary verified",
        attention: "External evidence required",
        blocked: "Local check blocked",
        checks: "platform checks",
        passed: "Passed",
        warning: "Needs evidence",
        failed: "Blocked",
        not_applicable: "Not applicable",
        runtime_directory: "Runtime directory",
        ipc_transport: "IPC transport",
        credential_store: "Credential store",
        installation: "Installation",
        external_evidence: "External evidence",
        digest: "Evidence fingerprint",
        digestOk: "Recomputed and matched",
        digestBad: "Does not match stored evidence",
        platform: "Platform",
        context: "Runtime context",
        persistent: "Persistent service",
        ephemeral: "Ephemeral test",
        boundaryLabel: "Public identity boundary",
        boundaryValue: "Same-user isolation unverified",
        profile: "Evidence profile",
        markdown: "Download Markdown",
        json: "Download JSON",
      };
  const [items, setItems] = useState<PlatformBoundarySnapshot[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? items[0] ?? null,
    [items, selectedId],
  );

  async function refresh() {
    const result = await listPlatformBoundary(sessionToken);
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

  async function collect() {
    setRunning(true);
    setError(null);
    try {
      const snapshot = await createPlatformBoundary(sessionToken);
      setItems((current) => [snapshot, ...current.filter((item) => item.id !== snapshot.id)]);
      setSelectedId(snapshot.id);
    } catch {
      setError(text.failure);
    } finally {
      setRunning(false);
    }
  }

  async function download(format: "markdown" | "json") {
    if (!selected) return;
    try {
      const report = await getPlatformBoundaryReport(sessionToken, selected.id);
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
      anchor.download = `secretbridge-platform-evidence-${selected.id}.${format === "markdown" ? "md" : "json"}`;
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
          <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">{text.title}</h1>
          <p className="mb-0 mt-3 text-sm leading-6 text-slate-600">{text.subtitle}</p>
        </div>
        <button type="button" onClick={() => void collect()} disabled={running} className="inline-flex h-11 items-center gap-2 rounded-lg bg-slate-950 px-5 text-sm font-semibold text-white transition hover:bg-cyan-800 disabled:cursor-wait disabled:opacity-70">
          {running ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
          {running ? text.running : text.run}
        </button>
      </header>

      <div className="flex gap-3 border-l-4 border-cyan-500 bg-cyan-50 px-5 py-4 text-sm leading-6 text-cyan-950">
        <Info className="mt-0.5 size-5 shrink-0" />
        <div><strong>{text.boundaryTitle}</strong><p className="mb-0 mt-1">{text.boundary}</p></div>
      </div>
      {error && <p role="alert" className="border-l-4 border-rose-400 bg-rose-50 p-3 text-sm text-rose-800">{error}</p>}

      <div className="grid gap-6 xl:grid-cols-[300px_minmax(0,1fr)]">
        <aside className="enterprise-surface p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="m-0 inline-flex items-center gap-2 text-sm font-semibold text-slate-900"><History className="size-4" />{text.history}</h2>
            <button type="button" onClick={() => void refresh()} aria-label={text.refresh} className="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-cyan-700"><RefreshCw className="size-4" /></button>
          </div>
          {loading ? <LoaderCircle className="mx-auto my-10 size-6 animate-spin text-cyan-600" /> : items.length === 0 ? <p className="my-8 text-center text-sm leading-6 text-slate-500">{text.empty}</p> : <ol className="m-0 divide-y divide-slate-200 border-y border-slate-200 p-0">{items.map((item) => <li key={item.id} className="list-none"><button type="button" onClick={() => setSelectedId(item.id)} className={`w-full border-l-2 px-3 py-3 text-left transition ${selected?.id === item.id ? "border-cyan-500 bg-cyan-50" : "border-transparent hover:bg-slate-50"}`}><div className="flex items-center justify-between gap-2"><BoundaryBadge status={item.status} text={text} /><time className="text-[11px] text-slate-400">{new Intl.DateTimeFormat(language, { dateStyle: "short", timeStyle: "short" }).format(item.created_at_unix_ms)}</time></div><p className="mb-0 mt-2 truncate font-mono text-[11px] text-slate-500">{item.id}</p></button></li>)}</ol>}
        </aside>
        {selected ? <BoundaryDetail snapshot={selected} language={language} text={text} onDownload={download} /> : <div className="grid min-h-80 place-items-center border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500"><div><ShieldCheck className="mx-auto mb-4 size-9 text-slate-300" />{text.empty}</div></div>}
      </div>
    </section>
  );
}

function BoundaryDetail({ snapshot, language, text, onDownload }: { snapshot: PlatformBoundarySnapshot; language: Language; text: Record<string, string>; onDownload: (format: "markdown" | "json") => Promise<void> }) {
  return <article className="enterprise-surface">
    <div className="border-b border-slate-200 bg-slate-950 p-6 text-white">
      <div className="flex flex-wrap items-start justify-between gap-4"><div><BoundaryBadge status={snapshot.status} text={text} inverse /><h2 className="mb-0 mt-3 text-xl font-semibold">{snapshot.checks.length} {text.checks}</h2><p className="mb-0 mt-2 font-mono text-xs text-slate-400">{snapshot.id}</p></div><div className="flex flex-wrap gap-2"><button type="button" onClick={() => void onDownload("markdown")} className={downloadClass}><Download className="size-4" />{text.markdown}</button><button type="button" onClick={() => void onDownload("json")} className={downloadClass}><FileJson2 className="size-4" />{text.json}</button></div></div>
      <dl className="mt-6 grid gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4"><Datum label={text.platform} value={snapshot.platform} /><Datum label={text.context} value={text[snapshot.runtime_context]} /><Datum label={text.boundaryLabel} value={text.boundaryValue} /><Datum label={text.profile} value={snapshot.profile_version} /></dl>
    </div>
    <div className="p-6">
      <div className={`mb-5 border-l-4 p-4 ${snapshot.digest_verified ? "border-emerald-400 bg-emerald-50" : "border-rose-400 bg-rose-50"}`}><div className={`flex items-center gap-2 text-sm font-semibold ${snapshot.digest_verified ? "text-emerald-800" : "text-rose-800"}`}><Fingerprint className="size-4" />{text.digest} · {snapshot.digest_verified ? text.digestOk : text.digestBad}</div><p className="mb-0 mt-2 break-all font-mono text-[11px] leading-5 text-slate-600">{snapshot.evidence_digest_sha256}</p></div>
      <ol className="enterprise-checklist m-0 border-y border-slate-200 p-0">{snapshot.checks.map((check) => <CheckRow key={check.code} check={check} language={language} text={text} />)}</ol>
    </div>
  </article>;
}

function CheckRow({ check, language, text }: { check: PlatformBoundaryCheck; language: Language; text: Record<string, string> }) {
  const Icon = check.status === "passed" ? CheckCircle2 : check.status === "failed" ? Ban : AlertTriangle;
  const localized = language === "zh-CN" ? zhChecks[check.code] : undefined;
  const style = check.status === "passed" ? "text-emerald-700" : check.status === "failed" ? "text-rose-700" : check.status === "not_applicable" ? "text-slate-500" : "text-amber-700";
  return <li className="list-none py-4"><div className="flex items-start gap-3"><Icon className={`mt-0.5 size-5 shrink-0 ${style}`} /><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><h3 className="m-0 text-sm font-semibold text-slate-900">{localized?.[0] ?? check.code}</h3><span className="text-[10px] font-bold uppercase tracking-wide text-slate-500">{text[check.category]}</span><span className={`text-[10px] font-semibold ${style}`}>{text[check.status as PlatformCheckStatus]}</span></div><p className="mb-0 mt-1 text-xs leading-5 text-slate-600">{localized?.[1] ?? check.summary}</p><p className="mb-0 mt-2 text-xs leading-5 text-slate-500">{check.evidence}</p></div></div></li>;
}

function BoundaryBadge({ status, text, inverse = false }: { status: PlatformBoundaryStatus; text: Record<string, string>; inverse?: boolean }) {
  const Icon = status === "verified" ? CheckCircle2 : status === "attention" ? AlertTriangle : Ban;
  const style = inverse ? "bg-white/10 text-white ring-white/15" : status === "verified" ? "bg-emerald-100 text-emerald-800 ring-emerald-200" : status === "attention" ? "bg-amber-100 text-amber-800 ring-amber-200" : "bg-rose-100 text-rose-800 ring-rose-200";
  return <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${style}`}><Icon className="size-3.5" />{text[status]}</span>;
}

function Datum({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-slate-400">{label}</dt><dd className="mb-0 ml-0 mt-1 truncate font-medium text-slate-100">{value}</dd></div>;
}

const downloadClass = "inline-flex items-center gap-2 rounded-lg bg-white/10 px-3 py-2 text-xs font-semibold text-white ring-1 ring-inset ring-white/15 transition hover:bg-white/20";
