// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  CheckCircle2,
  CircleAlert,
  ClipboardCheck,
  FileClock,
  Gauge,
  KeyRound,
  Languages,
  PanelLeftClose,
  PanelLeftOpen,
  PlayCircle,
  ServerCog,
  Settings,
  ShieldCheck,
  SquareTerminal,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { lazy, Suspense, useEffect, useState } from "react";

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
const OperationsView = lazy(() =>
  import("./OperationsView").then((module) => ({ default: module.OperationsView })),
);
const AuditView = lazy(() =>
  import("./AuditView").then((module) => ({ default: module.AuditView })),
);

type Language = "zh-CN" | "en";
type Connection = "checking" | "online" | "offline";
type Authentication = "unpaired" | "pairing" | "paired" | "error";

interface Copy {
  dashboard: string;
  credentials: string;
  targets: string;
  approvals: string;
  operations: string;
  policies: string;
  terminal: string;
  audit: string;
  settings: string;
  overview: string;
  subtitle: string;
  syntheticTitle: string;
  syntheticBody: string;
  service: string;
  online: string;
  offline: string;
  checking: string;
  paired: string;
  unpaired: string;
  pairing: string;
  authError: string;
  localOnly: string;
  statusTitle: string;
  apiVersion: string;
  runtimeMode: string;
  syntheticOnly: string;
  credentialConfiguration: string;
  controlledOperations: string;
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
    operations: "运行任务",
    policies: "执行策略",
    terminal: "终端",
    audit: "审计记录",
    settings: "系统设置",
    overview: "任务与连接总览",
    subtitle: "凭据留在本机，自动化只获得脱敏后的执行结果。",
    syntheticTitle: "PostgreSQL 连接检查可用",
    syntheticBody:
      "密码保留在操作系统凭据库中。获批运行可执行固定的 PostgreSQL 只读连接检查，只向页面返回结构化状态；普通终端不会获得凭据。",
    service: "本地服务",
    online: "在线",
    offline: "未连接",
    checking: "检查中",
    paired: "已配对",
    unpaired: "等待启动配对",
    pairing: "正在配对",
    authError: "配对失败",
    localOnly: "仅限本机",
    statusTitle: "运行状态",
    apiVersion: "接口版本",
    runtimeMode: "运行模式",
    syntheticOnly: "仅合成运行",
    credentialConfiguration: "凭据配置",
    controlledOperations: "受控操作",
    configurationStorage: "配置存储",
    memoryOnly: "仅内存（重启清空）",
    localDatabase: "本机 SQLite 数据库",
    realCredentials: "凭据代用",
    disabled: "未启用",
    enabled: "已启用",
    futureModule: "模块骨架已就绪",
    futureBody: "此功能将在后续核心功能包中提供。",
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
    operations: "Runs",
    policies: "Policies",
    terminal: "Terminal",
    audit: "Audit log",
    settings: "Settings",
    overview: "Tasks and connections",
    subtitle:
      "Credentials remain local while automation receives sanitized results.",
    syntheticTitle: "PostgreSQL connection check is available",
    syntheticBody:
      "Passwords remain in the operating-system credential store. Approved runs can perform the fixed PostgreSQL read-only connection check and return structured status only; ordinary terminals never receive credentials.",
    service: "Local service",
    online: "Online",
    offline: "Disconnected",
    checking: "Checking",
    paired: "Paired",
    unpaired: "Awaiting startup pairing",
    pairing: "Pairing",
    authError: "Pairing failed",
    localOnly: "Loopback only",
    statusTitle: "Runtime status",
    apiVersion: "API version",
    runtimeMode: "Runtime mode",
    syntheticOnly: "Synthetic only",
    credentialConfiguration: "Credential configuration",
    controlledOperations: "Controlled operations",
    configurationStorage: "Configuration storage",
    memoryOnly: "Memory-only (cleared on restart)",
    localDatabase: "Local SQLite database",
    realCredentials: "Credential use",
    disabled: "Disabled",
    enabled: "Enabled",
    futureModule: "Module shell ready",
    futureBody: "This capability will be delivered in a future core feature package.",
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
  { id: "operations", icon: PlayCircle },
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
              <Dashboard text={text} status={serviceStatus} />
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
            ) : activePage === "operations" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <OperationsView language={language} sessionToken={sessionToken} />
              </Suspense>
            ) : activePage === "audit" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <AuditView language={language} sessionToken={sessionToken} />
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
}: {
  text: Copy;
  status: ServiceStatus | null;
}) {
  return (
    <>
      <div className="mb-7 flex flex-wrap items-end justify-between gap-5">
        <div>
          <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
            {text.overview}
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">
            {text.subtitle}
          </p>
        </div>
        <span className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-600">
          <span className="size-2 rounded-full bg-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.12)]" />
          {text.localOnly}
        </span>
      </div>

      <section className="mb-6 border-l-4 border-amber-400 bg-amber-50 px-5 py-4">
        <div className="flex items-start gap-3">
          <CircleAlert className="mt-0.5 size-5 shrink-0 text-amber-700" aria-hidden="true" />
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

      <section className="enterprise-surface">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-slate-900">
            {text.statusTitle}
          </h2>
          <Activity className="size-5 text-cyan-600" aria-hidden="true" />
        </div>
        <dl className="divide-y divide-slate-200">
          <StatusDatum label={text.apiVersion} value={status?.api_version ?? "—"} />
          <StatusDatum
            label={text.runtimeMode}
            value={status?.mode === "controlled_operations" ? text.controlledOperations : status?.mode === "credential_configuration" ? text.credentialConfiguration : status?.mode === "synthetic_only" ? text.syntheticOnly : "—"}
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
      </section>
    </>
  );
}

function StatusDatum({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 px-5 py-3 sm:grid-cols-[14rem_1fr] sm:items-center">
      <dt className="text-sm font-medium text-slate-500">
        {label}
      </dt>
      <dd className="m-0 text-sm font-semibold text-slate-900">{value}</dd>
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
