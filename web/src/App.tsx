// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  ClipboardCheck,
  Command,
  FileClock,
  Gauge,
  KeyRound,
  Languages,
  LockKeyhole,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  ServerCog,
  Settings,
  ShieldCheck,
  Sparkles,
  SquareTerminal,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { lazy, Suspense, useEffect, useMemo, useState } from "react";

import { getSession, getStatus, pair, type ServiceStatus } from "./api";
import { consumePairingToken } from "./pairing";

const TerminalView = lazy(() =>
  import("./TerminalView").then((module) => ({ default: module.TerminalView })),
);
const CredentialReferencesView = lazy(() =>
  import("./CatalogView").then((module) => ({
    default: module.CredentialReferencesView,
  })),
);
const TargetsView = lazy(() =>
  import("./CatalogView").then((module) => ({ default: module.TargetsView })),
);
const ApprovalView = lazy(() =>
  import("./ApprovalView").then((module) => ({ default: module.ApprovalView })),
);
const ActionTemplatesView = lazy(() =>
  import("./ActionTemplatesView").then((module) => ({
    default: module.ActionTemplatesView,
  })),
);

type Language = "zh-CN" | "en";
type Connection = "checking" | "online" | "offline";
type Authentication = "unpaired" | "pairing" | "paired" | "error";

interface Copy {
  dashboard: string;
  credentials: string;
  targets: string;
  approvals: string;
  policies: string;
  terminal: string;
  audit: string;
  settings: string;
  overview: string;
  subtitle: string;
  stage: string;
  syntheticTitle: string;
  syntheticBody: string;
  boundaryTitle: string;
  boundaryBody: string;
  sessionTitle: string;
  sessionBody: string;
  platformTitle: string;
  platformBody: string;
  service: string;
  online: string;
  offline: string;
  checking: string;
  paired: string;
  unpaired: string;
  pairing: string;
  authError: string;
  localOnly: string;
  nextTitle: string;
  nextBody: string;
  learnMore: string;
  statusTitle: string;
  apiVersion: string;
  runtimeMode: string;
  identityBoundary: string;
  unverifiedSameUser: string;
  configurationStorage: string;
  memoryOnly: string;
  localDatabase: string;
  realCredentials: string;
  disabled: string;
  enabled: string;
  futureModule: string;
  futureBody: string;
  collapse: string;
  expand: string;
  skipContent: string;
  primaryNavigation: string;
  switchLanguage: string;
  connectionStatus: string;
}

const copy: Record<Language, Copy> = {
  "zh-CN": {
    dashboard: "总览",
    credentials: "凭据",
    targets: "连接目标",
    approvals: "审批中心",
    policies: "执行策略",
    terminal: "安全终端",
    audit: "审计记录",
    settings: "系统设置",
    overview: "安全执行总览",
    subtitle: "凭据留在本机，自动化只获得脱敏后的执行结果。",
    stage: "M1 工作流开发",
    syntheticTitle: "当前仅允许合成凭据",
    syntheticBody:
      "这一版本用于验证本地配对、安全边界和合成PTY；真实凭据、业务系统访问和系统命令执行均未启用。",
    boundaryTitle: "本机安全边界",
    boundaryBody: "服务只监听回环地址，不接受局域网或公网连接。",
    sessionTitle: "一次性浏览器配对",
    sessionBody: "启动令牌使用后立即失效，会话令牌仅保留在当前页面内存。",
    platformTitle: "跨平台基线",
    platformBody: "同一套 Web 管理端与 Rust 服务面向 Windows、Linux 和 macOS。",
    service: "本地服务",
    online: "在线",
    offline: "未连接",
    checking: "检查中",
    paired: "已安全配对",
    unpaired: "等待启动配对",
    pairing: "正在配对",
    authError: "配对失败",
    localOnly: "仅限本机",
    nextTitle: "下一阶段",
    nextBody:
      "下一阶段连接合成操作请求、状态、取消与安全事件；真实凭据接入仍须先完成 M0 三平台身份隔离验证。",
    learnMore: "查看开发路线",
    statusTitle: "运行状态",
    apiVersion: "接口版本",
    runtimeMode: "运行模式",
    identityBoundary: "身份边界",
    unverifiedSameUser: "同用户兼容模式（未验证隔离）",
    configurationStorage: "配置存储",
    memoryOnly: "仅内存（重启清空）",
    localDatabase: "本机 SQLite 数据库",
    realCredentials: "真实凭据",
    disabled: "未启用",
    enabled: "已启用",
    futureModule: "模块骨架已就绪",
    futureBody: "此功能将在完成安全模型与威胁建模复核后逐步开放。",
    collapse: "收起导航",
    expand: "展开导航",
    skipContent: "跳到主要内容",
    primaryNavigation: "主导航",
    switchLanguage: "切换到英文",
    connectionStatus: "连接状态",
  },
  en: {
    dashboard: "Overview",
    credentials: "Credentials",
    targets: "Targets",
    approvals: "Approvals",
    policies: "Policies",
    terminal: "Secure terminal",
    audit: "Audit log",
    settings: "Settings",
    overview: "Secure execution overview",
    subtitle:
      "Credentials remain local while automation receives sanitized results.",
    stage: "M1 workflow development",
    syntheticTitle: "Synthetic credentials only",
    syntheticBody:
      "This release validates local pairing, trust boundaries, and a synthetic PTY. Real credentials, business targets, and system commands are disabled.",
    boundaryTitle: "Local trust boundary",
    boundaryBody:
      "The service binds only to loopback and rejects LAN or public access.",
    sessionTitle: "One-time browser pairing",
    sessionBody:
      "The bootstrap token expires after use; the session token stays only in page memory.",
    platformTitle: "Cross-platform baseline",
    platformBody:
      "One Web console and Rust service target Windows, Linux, and macOS.",
    service: "Local service",
    online: "Online",
    offline: "Disconnected",
    checking: "Checking",
    paired: "Securely paired",
    unpaired: "Awaiting startup pairing",
    pairing: "Pairing",
    authError: "Pairing failed",
    localOnly: "Loopback only",
    nextTitle: "Next milestone",
    nextBody:
      "Next, connect synthetic operation requests, status, cancellation and safe events. Real credential integration remains gated on M0 cross-platform identity validation.",
    learnMore: "View roadmap",
    statusTitle: "Runtime status",
    apiVersion: "API version",
    runtimeMode: "Runtime mode",
    identityBoundary: "Identity boundary",
    unverifiedSameUser: "Same-user compatibility (not isolated)",
    configurationStorage: "Configuration storage",
    memoryOnly: "Memory-only (cleared on restart)",
    localDatabase: "Local SQLite database",
    realCredentials: "Real credentials",
    disabled: "Disabled",
    enabled: "Enabled",
    futureModule: "Module shell ready",
    futureBody:
      "This capability will open progressively after the security model and threat model are reviewed.",
    collapse: "Collapse navigation",
    expand: "Expand navigation",
    skipContent: "Skip to main content",
    primaryNavigation: "Primary navigation",
    switchLanguage: "Switch to Chinese",
    connectionStatus: "Connection status",
  },
};

const navItems: Array<{ id: keyof Copy; icon: LucideIcon }> = [
  { id: "dashboard", icon: Gauge },
  { id: "credentials", icon: KeyRound },
  { id: "targets", icon: ServerCog },
  { id: "approvals", icon: ClipboardCheck },
  { id: "policies", icon: Workflow },
  { id: "terminal", icon: SquareTerminal },
  { id: "audit", icon: FileClock },
  { id: "settings", icon: Settings },
];

function stateLabel(
  value: Connection | Authentication,
  text: Copy,
): string {
  return text[value === "error" ? "authError" : value];
}

export function App() {
  const [language, setLanguage] = useState<Language>(() =>
    navigator.language.toLowerCase().startsWith("zh") ? "zh-CN" : "en",
  );
  const [connection, setConnection] = useState<Connection>("checking");
  const [authentication, setAuthentication] =
    useState<Authentication>("unpaired");
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<keyof Copy>("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const text = copy[language];

  useEffect(() => {
    let active = true;

    async function initialize() {
      // Remove the one-time capability before the first network round-trip.
      const bootstrapToken = consumePairingToken();
      try {
        const status = await getStatus();
        if (!active) return;
        setServiceStatus(status);
        setConnection("online");

        if (!bootstrapToken) return;

        setAuthentication("pairing");
        const pairedSession = await pair(bootstrapToken);
        const session = await getSession(pairedSession.session_token);
        if (!active) return;
        setAuthentication(session.authenticated ? "paired" : "error");
        if (session.authenticated) setSessionToken(pairedSession.session_token);
        const refreshedStatus = await getStatus();
        if (active) setServiceStatus(refreshedStatus);
      } catch {
        if (!active) return;
        setConnection("offline");
        setAuthentication((current) =>
          current === "pairing" ? "error" : current,
        );
      }
    }

    void initialize();
    return () => {
      active = false;
    };
  }, []);

  const featureCards = useMemo(
    () => [
      {
        icon: LockKeyhole,
        title: text.boundaryTitle,
        body: text.boundaryBody,
        accent: "bg-cyan-50 text-cyan-700",
      },
      {
        icon: Network,
        title: text.sessionTitle,
        body: text.sessionBody,
        accent: "bg-indigo-50 text-indigo-700",
      },
      {
        icon: Command,
        title: text.platformTitle,
        body: text.platformBody,
        accent: "bg-emerald-50 text-emerald-700",
      },
    ],
    [text],
  );

  return (
    <Tooltip.Provider delayDuration={250}>
      <div className="min-h-screen bg-[#f4f7fb] text-slate-800">
        <a
          href="#main-content"
          className="fixed left-4 top-3 z-50 -translate-y-20 rounded-lg bg-slate-950 px-4 py-2 text-sm font-semibold text-white shadow-lg transition-transform focus:translate-y-0"
        >
          {text.skipContent}
        </a>
        <aside
          className={`fixed inset-y-0 left-0 z-20 flex flex-col border-r border-slate-200 bg-slate-950 text-slate-200 shadow-xl transition-[width] duration-200 ${collapsed ? "w-20" : "w-20 md:w-64"}`}
        >
          <div className="flex h-20 items-center gap-3 border-b border-white/10 px-5">
            <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 shadow-lg shadow-cyan-950/40">
              <ShieldCheck className="size-6 text-white" aria-hidden="true" />
            </div>
            {!collapsed && (
              <div className="hidden md:block">
                <p className="m-0 text-base font-semibold tracking-wide text-white">
                  SecretBridge
                </p>
                <p className="m-0 text-xs text-slate-400">密桥</p>
              </div>
            )}
          </div>

          <nav
            className="flex-1 space-y-1.5 px-3 py-5"
            aria-label={text.primaryNavigation}
          >
            {navItems.map(({ id, icon: Icon }) => {
              const selected = activePage === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setActivePage(id)}
                  className={`flex h-11 w-full items-center gap-3 rounded-xl px-3 text-left text-sm font-medium transition ${
                    selected
                      ? "bg-cyan-400/15 text-cyan-300 ring-1 ring-inset ring-cyan-400/20"
                      : "text-slate-400 hover:bg-white/5 hover:text-white"
                  }`}
                  aria-current={selected ? "page" : undefined}
                  aria-label={text[id]}
                >
                  <Icon className="size-5 shrink-0" aria-hidden="true" />
                  {!collapsed && <span className="hidden md:inline">{text[id]}</span>}
                </button>
              );
            })}
          </nav>

          <div className="border-t border-white/10 p-3">
            <button
              type="button"
              onClick={() => setCollapsed((value) => !value)}
              className="flex h-10 w-full items-center gap-3 rounded-xl px-3 text-sm text-slate-400 hover:bg-white/5 hover:text-white"
              aria-label={collapsed ? text.expand : text.collapse}
            >
              {collapsed ? (
                <PanelLeftOpen className="size-5" aria-hidden="true" />
              ) : (
                <PanelLeftClose className="size-5" aria-hidden="true" />
              )}
              {!collapsed && <span className="hidden md:inline">{text.collapse}</span>}
            </button>
          </div>
        </aside>

        <div
          className={`min-h-screen transition-[margin] duration-200 ${collapsed ? "ml-20" : "ml-20 md:ml-64"}`}
        >
          <header className="sticky top-0 z-10 flex min-h-20 flex-wrap items-center justify-between gap-3 border-b border-slate-200/80 bg-white/85 px-4 py-3 backdrop-blur-xl sm:px-8">
            <div
              className="flex items-center gap-3 text-sm"
              role="status"
              aria-live="polite"
              aria-label={text.connectionStatus}
            >
              <StatusPill
                ok={connection === "online"}
                pending={connection === "checking"}
                label={`${text.service} · ${stateLabel(connection, text)}`}
              />
              <StatusPill
                ok={authentication === "paired"}
                pending={authentication === "pairing"}
                label={stateLabel(authentication, text)}
              />
            </div>
            <Tooltip.Root>
              <Tooltip.Trigger asChild>
                <button
                  type="button"
                  onClick={() =>
                    setLanguage((current) =>
                      current === "zh-CN" ? "en" : "zh-CN",
                    )
                  }
                  className="flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-600 shadow-sm transition hover:border-cyan-300 hover:text-cyan-700"
                  aria-label={text.switchLanguage}
                >
                  <Languages className="size-4" aria-hidden="true" />
                  {language === "zh-CN" ? "EN" : "中文"}
                </button>
              </Tooltip.Trigger>
              <Tooltip.Portal>
                <Tooltip.Content
                  sideOffset={8}
                  className="rounded-lg bg-slate-900 px-3 py-2 text-xs text-white shadow-xl"
                >
                  {text.switchLanguage}
                  <Tooltip.Arrow className="fill-slate-900" />
                </Tooltip.Content>
              </Tooltip.Portal>
            </Tooltip.Root>
          </header>

          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto max-w-7xl px-4 py-8 sm:px-8 sm:py-10"
          >
            {activePage === "dashboard" ? (
              <Dashboard
                text={text}
                status={serviceStatus}
                featureCards={featureCards}
              />
            ) : activePage === "terminal" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <TerminalView language={language} sessionToken={sessionToken} />
              </Suspense>
            ) : activePage === "credentials" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <CredentialReferencesView
                  language={language}
                  sessionToken={sessionToken}
                />
              </Suspense>
            ) : activePage === "targets" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <TargetsView language={language} sessionToken={sessionToken} />
              </Suspense>
            ) : activePage === "approvals" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <ApprovalView language={language} sessionToken={sessionToken} />
              </Suspense>
            ) : activePage === "policies" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <ActionTemplatesView
                  language={language}
                  sessionToken={sessionToken}
                />
              </Suspense>
            ) : (
              <ComingSoon text={text} page={text[activePage]} />
            )}
          </main>
        </div>
      </div>
    </Tooltip.Provider>
  );
}

function TerminalLoading({ text }: { text: Copy }) {
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
      <div>
        <Activity className="mx-auto size-8 animate-pulse text-cyan-600" />
        <p className="mb-0 mt-4 text-sm font-medium text-slate-600">{text.checking}</p>
      </div>
    </section>
  );
}

function StatusPill({
  ok,
  pending,
  label,
}: {
  ok: boolean;
  pending: boolean;
  label: string;
}) {
  const Icon = pending ? Activity : ok ? CheckCircle2 : CircleAlert;
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 font-medium ${
        pending
          ? "bg-amber-50 text-amber-700"
          : ok
            ? "bg-emerald-50 text-emerald-700"
            : "bg-slate-100 text-slate-600"
      }`}
    >
      <Icon className={`size-4 ${pending ? "animate-pulse" : ""}`} />
      {label}
    </span>
  );
}

function Dashboard({
  text,
  status,
  featureCards,
}: {
  text: Copy;
  status: ServiceStatus | null;
  featureCards: Array<{
    icon: LucideIcon;
    title: string;
    body: string;
    accent: string;
  }>;
}) {
  return (
    <>
      <div className="mb-8 flex flex-wrap items-end justify-between gap-5">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-cyan-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">
            <Sparkles className="size-3.5" />
            {text.stage}
          </div>
          <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
            {text.overview}
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">
            {text.subtitle}
          </p>
        </div>
        <span className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-600 shadow-sm">
          <span className="size-2 rounded-full bg-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.12)]" />
          {text.localOnly}
        </span>
      </div>

      <section className="mb-6 overflow-hidden rounded-2xl border border-amber-200 bg-gradient-to-r from-amber-50 to-orange-50 shadow-sm">
        <div className="flex items-start gap-4 p-5">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-amber-100 text-amber-700">
            <CircleAlert className="size-5" aria-hidden="true" />
          </div>
          <div>
            <h2 className="m-0 text-base font-semibold text-amber-950">
              {text.syntheticTitle}
            </h2>
            <p className="mb-0 mt-1.5 max-w-4xl text-sm leading-6 text-amber-900/75">
              {text.syntheticBody}
            </p>
          </div>
        </div>
      </section>

      <section className="grid gap-5 md:grid-cols-3">
        {featureCards.map(({ icon: Icon, title, body, accent }) => (
          <article
            key={title}
            className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md"
          >
            <div className={`mb-5 grid size-11 place-items-center rounded-xl ${accent}`}>
              <Icon className="size-5" aria-hidden="true" />
            </div>
            <h2 className="m-0 text-base font-semibold text-slate-900">{title}</h2>
            <p className="mb-0 mt-2 text-sm leading-6 text-slate-600">{body}</p>
          </article>
        ))}
      </section>

      <section className="mt-6 grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <article className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-5 flex items-center justify-between">
            <h2 className="m-0 text-base font-semibold text-slate-900">
              {text.statusTitle}
            </h2>
            <Activity className="size-5 text-cyan-600" aria-hidden="true" />
          </div>
          <dl className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            <StatusDatum label={text.apiVersion} value={status?.api_version ?? "—"} />
            <StatusDatum
              label={text.runtimeMode}
              value={status?.mode === "synthetic_only" ? "Synthetic only" : "—"}
            />
            <StatusDatum
              label={text.identityBoundary}
              value={
                status?.identity_boundary === "unverified_same_user"
                  ? text.unverifiedSameUser
                  : "—"
              }
            />
            <StatusDatum
              label={text.configurationStorage}
              value={
                status?.configuration_storage === "sqlite"
                  ? text.localDatabase
                  : status?.configuration_storage === "memory_only"
                    ? text.memoryOnly
                    : "—"
              }
            />
            <StatusDatum
              label={text.realCredentials}
              value={status?.real_credentials_enabled ? text.enabled : text.disabled}
            />
          </dl>
        </article>

        <article className="relative overflow-hidden rounded-2xl bg-slate-950 p-6 text-white shadow-lg">
          <div className="absolute -right-8 -top-8 size-36 rounded-full bg-cyan-400/10 blur-2xl" />
          <div className="relative">
            <p className="m-0 text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">
              Roadmap
            </p>
            <h2 className="mb-0 mt-2 text-lg font-semibold">{text.nextTitle}</h2>
            <p className="mb-5 mt-2 text-sm leading-6 text-slate-300">
              {text.nextBody}
            </p>
            <a
              href="https://github.com/qq940500529/secretbridge/blob/main/ROADMAP.md"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200"
            >
              {text.learnMore}
              <ArrowRight className="size-4" aria-hidden="true" />
            </a>
          </div>
        </article>
      </section>
    </>
  );
}

function StatusDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl bg-slate-50 p-4">
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </dt>
      <dd className="mb-0 mt-2 text-sm font-semibold text-slate-900">{value}</dd>
    </div>
  );
}

function ComingSoon({ text, page }: { text: Copy; page: string }) {
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-dashed border-slate-300 bg-white/65 p-10 text-center">
      <div className="max-w-lg">
        <div className="mx-auto grid size-14 place-items-center rounded-2xl bg-cyan-50 text-cyan-700">
          <ShieldCheck className="size-7" aria-hidden="true" />
        </div>
        <p className="mb-0 mt-5 text-sm font-semibold uppercase tracking-[0.14em] text-cyan-700">
          {page}
        </p>
        <h1 className="mb-0 mt-2 text-2xl font-bold text-slate-950">
          {text.futureModule}
        </h1>
        <p className="mb-0 mt-3 leading-7 text-slate-600">{text.futureBody}</p>
      </div>
    </section>
  );
}
