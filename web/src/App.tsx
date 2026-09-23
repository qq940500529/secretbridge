// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Activity,
  CheckCircle2,
  CircleAlert,
  FileClock,
  KeyRound,
  Languages,
  MessageSquareWarning,
  PanelLeftClose,
  PanelLeftOpen,
  PlayCircle,
  ServerCog,
  Settings,
  ShieldCheck,
  SquareTerminal,
  type LucideIcon,
} from "lucide-react";
import { lazy, Suspense, useCallback, useEffect, useState } from "react";

import {
  getBrowserAuthMethods,
  getApprovalNotificationSettings,
  getSession,
  getStatus,
  pair,
  pairWithPin,
  pairWithTotp,
  revokePageSession,
  setApprovalNotificationSettings,
  type BrowserAuthMethods,
  type ServiceStatus,
} from "./api";
import {
  BrowserAuthenticationSettings,
  type AuthMethodStatus,
} from "./BrowserAuthenticationSettings";
import { consumePairingToken } from "./pairing";
import { BackgroundServiceView } from "./BackgroundServiceView";
import { ISSUE_URL, LegalConsent } from "./LegalConsent";
import {
  hasCurrentLegalConsent,
  initialLanguage,
  initialApprovalNotificationChannel,
  storeApprovalNotificationChannel,
  storeLanguage,
  storeLegalConsent,
  type Language,
  type ApprovalNotificationChannel,
} from "./preferences";
import { SettingsView } from "./SettingsView";
import { ApprovalQueueDialog } from "./ApprovalQueueDialog";
import { ActiveConversationRisk } from "./AiConversationsView";

const TerminalView = lazy(() =>
  import("./TerminalView").then((module) => ({ default: module.TerminalView })),
);
const DataMaintenanceView = lazy(() =>
  import("./DataMaintenanceView").then((module) => ({
    default: module.DataMaintenanceView,
  })),
);
const CredentialReferencesView = lazy(() =>
  import("./CatalogView").then((module) => ({
    default: module.CredentialReferencesView,
  })),
);
const TargetsView = lazy(() =>
  import("./CatalogView").then((module) => ({ default: module.TargetsView })),
);
const TaskWorkspace = lazy(() =>
  import("./TaskWorkspace").then((module) => ({
    default: module.TaskWorkspace,
  })),
);
const HistoryWorkspace = lazy(() =>
  import("./TaskWorkspace").then((module) => ({
    default: module.HistoryWorkspace,
  })),
);

type Connection = "checking" | "online" | "offline";
type Authentication = "unpaired" | "pairing" | "paired" | "error";
type Page =
  "credentials" | "targets" | "operations" | "terminal" | "audit" | "settings";
type TaskSection = "templates" | "approvals" | "runs";

interface Copy {
  credentials: string;
  targets: string;
  operations: string;
  taskTemplates: string;
  taskApprovals: string;
  taskRuns: string;
  terminal: string;
  audit: string;
  settings: string;
  overview: string;
  subtitle: string;
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
  feedback: string;
}

const copy: Record<Language, Copy> = {
  "zh-CN": {
    credentials: "凭据",
    targets: "连接",
    operations: "任务",
    taskTemplates: "任务模板",
    taskApprovals: "授权与确认",
    taskRuns: "执行与结果",
    terminal: "终端",
    audit: "历史",
    settings: "设置",
    overview: "服务与页面设置",
    subtitle: "检查本机服务、存储方式和当前页面的配对状态。",
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
    futureModule: "请先配对本机服务",
    futureBody:
      "请使用后台服务启动时提供的一次性配对链接打开控制台。如果配对失败，请获取新的链接重试；刷新当前链接不会恢复已消费的令牌。",
    collapse: "收起导航",
    expand: "展开导航",
    skipContent: "跳到主要内容",
    primaryNavigation: "主导航",
    switchLanguage: "切换到英文",
    connectionStatus: "连接状态",
    feedback: "反馈问题",
  },
  en: {
    credentials: "Credentials",
    targets: "Connections",
    operations: "Tasks",
    taskTemplates: "Templates",
    taskApprovals: "Authorization",
    taskRuns: "Execution & results",
    terminal: "Terminal",
    audit: "History",
    settings: "Settings",
    overview: "Service and page settings",
    subtitle:
      "Inspect the local service, configuration storage and this page's pairing status.",
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
    futureModule: "Pair with the local service",
    futureBody:
      "Open the console using the one-time pairing link from the running broker. If pairing fails, request a fresh link; reloading a consumed link cannot restore its token.",
    collapse: "Collapse navigation",
    expand: "Expand navigation",
    skipContent: "Skip to main content",
    primaryNavigation: "Primary navigation",
    switchLanguage: "Switch to Chinese",
    connectionStatus: "Connection status",
    feedback: "Feedback",
  },
};

const navItems: Array<{ id: Page; icon: LucideIcon }> = [
  { id: "credentials", icon: KeyRound },
  { id: "targets", icon: ServerCog },
  { id: "operations", icon: PlayCircle },
  { id: "terminal", icon: SquareTerminal },
  { id: "audit", icon: FileClock },
  { id: "settings", icon: Settings },
];

const PAGE_SESSION_KEY = "secretbridge.page-session.v1";

function stateLabel(value: Connection | Authentication, text: Copy): string {
  return text[value === "error" ? "authError" : value];
}

export function App() {
  const [language, setLanguage] = useState<Language>(initialLanguage);
  const [notificationChannel, setNotificationChannel] =
    useState<ApprovalNotificationChannel>(initialApprovalNotificationChannel);
  const [legalAccepted, setLegalAccepted] = useState(hasCurrentLegalConsent);
  const [legalOpen, setLegalOpen] = useState(() => !hasCurrentLegalConsent());
  const [connection, setConnection] = useState<Connection>("checking");
  const [authentication, setAuthentication] =
    useState<Authentication>("unpaired");
  const [serviceStatus, setServiceStatus] = useState<ServiceStatus | null>(
    null,
  );
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [browserAuthMethods, setBrowserAuthMethods] =
    useState<BrowserAuthMethods | null>(null);
  const [authMethodStatus, setAuthMethodStatus] =
    useState<AuthMethodStatus>("loading");
  const [activePage, setActivePage] = useState<Page>("operations");
  const [taskSection, setTaskSection] = useState<TaskSection>("templates");
  const [taskContext, setTaskContext] = useState<{
    targetId?: string;
    templateId?: string;
  }>({});
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const text = copy[language];
  const pinEnabled = browserAuthMethods?.pin_enabled ?? false;
  const totpEnabled = browserAuthMethods?.totp_enabled ?? false;

  const refreshBrowserAuthMethods = useCallback(async () => {
    setAuthMethodStatus("loading");
    try {
      setBrowserAuthMethods(await getBrowserAuthMethods());
      setAuthMethodStatus("ready");
    } catch {
      setBrowserAuthMethods(null);
      setAuthMethodStatus("error");
    }
  }, []);

  function changeLanguage(nextLanguage: Language) {
    setLanguage(nextLanguage);
    storeLanguage(nextLanguage);
  }

  async function changeNotificationChannel(
    next: ApprovalNotificationChannel,
  ): Promise<boolean> {
    if (!sessionToken) return false;
    if (next === "browser") {
      if (!("Notification" in window)) return false;
      const permission =
        Notification.permission === "granted"
          ? "granted"
          : await Notification.requestPermission();
      if (permission !== "granted") return false;
    }
    try {
      await setApprovalNotificationSettings(sessionToken, next);
    } catch {
      return false;
    }
    setNotificationChannel(next);
    storeApprovalNotificationChannel(next);
    return true;
  }

  useEffect(() => {
    if (!sessionToken) return;
    let active = true;
    void getApprovalNotificationSettings(sessionToken)
      .then(({ channel }) => {
        if (active) {
          setNotificationChannel(channel);
          storeApprovalNotificationChannel(channel);
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [sessionToken]);

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  useEffect(() => {
    let active = true;
    void refreshBrowserAuthMethods();

    async function initialize() {
      // Remove the one-time capability before the first network round-trip.
      const bootstrapToken = consumePairingToken();
      try {
        const status = await getStatus();
        if (!active) return;
        setServiceStatus(status);
        setConnection("online");

        const savedSession = window.sessionStorage.getItem(PAGE_SESSION_KEY);
        if (savedSession) {
          try {
            const session = await getSession(savedSession);
            if (!active) return;
            if (session.authenticated) {
              setAuthentication("paired");
              setSessionToken(savedSession);
              return;
            }
          } catch {
            window.sessionStorage.removeItem(PAGE_SESSION_KEY);
          }
        }

        if (bootstrapToken) {
          setAuthentication("pairing");
          const pairedSession = await pair(bootstrapToken);
          const session = await getSession(pairedSession.session_token);
          if (!active) return;
          setAuthentication(session.authenticated ? "paired" : "error");
          if (session.authenticated) {
            setSessionToken(pairedSession.session_token);
            window.sessionStorage.setItem(
              PAGE_SESSION_KEY,
              pairedSession.session_token,
            );
          }
          const refreshedStatus = await getStatus();
          if (active) setServiceStatus(refreshedStatus);
          return;
        }
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
  }, [refreshBrowserAuthMethods]);

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
          className={`app-sidebar fixed inset-y-0 left-0 z-20 flex flex-col border-r border-slate-200 bg-slate-950 text-slate-200 shadow-xl transition-[width] duration-200 ${collapsed ? "w-20" : "w-20 md:w-64"}`}
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
                <div key={id}>
                  <button
                    type="button"
                    onClick={() => {
                      setActivePage(id);
                      if (id === "operations") {
                        setTaskContext({});
                        setTaskSection("templates");
                      }
                    }}
                    className={`flex h-11 w-full items-center gap-3 rounded-xl px-3 text-left text-sm font-medium transition ${
                      selected
                        ? "bg-cyan-400/15 text-cyan-300 ring-1 ring-inset ring-cyan-400/20"
                        : "text-slate-400 hover:bg-white/5 hover:text-white"
                    }`}
                    aria-current={selected ? "page" : undefined}
                    aria-label={text[id]}
                  >
                    <Icon className="size-5 shrink-0" aria-hidden="true" />
                    {!collapsed && (
                      <span className="hidden md:inline">{text[id]}</span>
                    )}
                  </button>
                  {id === "operations" && selected && (
                    <div
                      role="group"
                      aria-label={text.operations}
                      className="mt-1 space-y-1 pl-2"
                    >
                      {(
                        [
                          ["templates", text.taskTemplates, FileClock],
                          ["approvals", text.taskApprovals, ShieldCheck],
                          ["runs", text.taskRuns, PlayCircle],
                        ] as const
                      ).map(([section, label, SectionIcon]) => (
                        <button
                          key={section}
                          type="button"
                          aria-label={label}
                          aria-current={
                            taskSection === section ? "page" : undefined
                          }
                          onClick={() => {
                            setTaskContext({});
                            setTaskSection(section);
                          }}
                          className={`flex h-10 w-full items-center gap-3 rounded-lg px-3 text-left text-xs font-medium ${taskSection === section ? "bg-cyan-400/10 text-cyan-200" : "text-slate-400 hover:bg-white/5 hover:text-white"}`}
                        >
                          <SectionIcon
                            className="size-4 shrink-0"
                            aria-hidden="true"
                          />
                          {!collapsed && (
                            <span className="hidden md:inline">{label}</span>
                          )}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
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
              {!collapsed && (
                <span className="hidden md:inline">{text.collapse}</span>
              )}
            </button>
          </div>
        </aside>

        <div
          className={`app-shell min-h-screen transition-[margin] duration-200 ${collapsed ? "ml-20" : "ml-20 md:ml-64"}`}
        >
          <header className="sticky top-0 z-10 flex min-h-20 flex-wrap items-center justify-between gap-3 border-b border-slate-200/80 bg-white/85 px-4 py-3 backdrop-blur-xl sm:px-8">
            <div
              className="flex flex-wrap items-center gap-3 text-sm"
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
            <div className="flex items-center gap-2">
              {sessionToken && legalAccepted && (
                <ApprovalQueueDialog
                  language={language}
                  sessionToken={sessionToken}
                  enabled={!legalOpen}
                  notificationChannel={notificationChannel}
                />
              )}
              <a
                href={ISSUE_URL}
                target="_blank"
                rel="noreferrer"
                className="flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-600 no-underline shadow-sm transition hover:border-cyan-300 hover:text-cyan-700"
                aria-label={text.feedback}
              >
                <MessageSquareWarning className="size-4" aria-hidden="true" />
                <span className="hidden sm:inline">{text.feedback}</span>
              </a>
              <Tooltip.Root>
                <Tooltip.Trigger asChild>
                  <button
                    type="button"
                    onClick={() =>
                      changeLanguage(language === "zh-CN" ? "en" : "zh-CN")
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
            </div>
          </header>

          <main
            id="main-content"
            tabIndex={-1}
            className="mx-auto max-w-[104rem] px-4 py-8 sm:px-8 sm:py-10"
          >
            {sessionToken && (
              <div className="mb-5">
                <ActiveConversationRisk
                  sessionToken={sessionToken}
                  language={language}
                />
              </div>
            )}
            {activePage === "settings" ? (
              <>
                <SettingsView
                  text={text}
                  status={serviceStatus}
                  language={language}
                  onLanguageChange={changeLanguage}
                  notificationChannel={notificationChannel}
                  onNotificationChannelChange={changeNotificationChannel}
                  onReviewLegal={() => setLegalOpen(true)}
                />
                {sessionToken && serviceStatus?.background_control_enabled && (
                  <BackgroundServiceView
                    sessionToken={sessionToken}
                    language={language}
                    onStopped={() => {
                      setSessionToken(null);
                      window.sessionStorage.removeItem(PAGE_SESSION_KEY);
                      setAuthentication("unpaired");
                      setConnection("offline");
                      setServiceStatus(null);
                    }}
                  />
                )}
                {sessionToken && (
                  <BrowserAuthenticationSettings
                    language={language}
                    sessionToken={sessionToken}
                    pinEnabled={pinEnabled}
                    totpEnabled={totpEnabled}
                    authMethodStatus={authMethodStatus}
                    onRetry={() => void refreshBrowserAuthMethods()}
                    onChanged={() => void refreshBrowserAuthMethods()}
                  />
                )}
                {sessionToken && (
                  <Suspense
                    fallback={
                      <p>
                        {language === "zh-CN"
                          ? "加载数据维护…"
                          : "Loading maintenance…"}
                      </p>
                    }
                  >
                    <DataMaintenanceView
                      sessionToken={sessionToken}
                      language={language}
                    />
                  </Suspense>
                )}
                {sessionToken && (
                  <div className="mt-6 border-t border-slate-200 pt-5">
                    <button
                      type="button"
                      disabled={disconnecting}
                      className="workbench-button"
                      onClick={async () => {
                        setDisconnecting(true);
                        setDisconnectError(false);
                        try {
                          await revokePageSession(sessionToken);
                          setSessionToken(null);
                          window.sessionStorage.removeItem(PAGE_SESSION_KEY);
                          setAuthentication("unpaired");
                        } catch {
                          setDisconnectError(true);
                        } finally {
                          setDisconnecting(false);
                        }
                      }}
                    >
                      {language === "zh-CN"
                        ? "解除当前页面配对"
                        : "Unpair this page"}
                    </button>
                    <p className="text-sm text-slate-500">
                      {language === "zh-CN"
                        ? "仅撤销当前页面会话，不停止后台服务或已存在的终端。"
                        : "Revokes only this page session; the broker and existing terminals remain available."}
                    </p>
                    {disconnectError && (
                      <p role="alert" className="text-sm text-rose-700">
                        {language === "zh-CN"
                          ? "撤销失败，请确认服务在线后重试。"
                          : "Could not revoke the session. Check the service and retry."}
                      </p>
                    )}
                  </div>
                )}
              </>
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
                <TargetsView
                  language={language}
                  sessionToken={sessionToken}
                  onTask={(targetId, templateId) => {
                    setTaskContext({ targetId, templateId });
                    setTaskSection(templateId ? "approvals" : "templates");
                    setActivePage("operations");
                  }}
                />
              </Suspense>
            ) : activePage === "operations" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <TaskWorkspace
                  key={`${taskContext.targetId ?? ""}:${taskContext.templateId ?? ""}`}
                  language={language}
                  sessionToken={sessionToken}
                  section={taskSection}
                  onRequestTemplate={(id) => {
                    setTaskContext({ templateId: id });
                    setTaskSection("approvals");
                  }}
                  {...taskContext}
                />
              </Suspense>
            ) : activePage === "audit" && sessionToken ? (
              <Suspense fallback={<TerminalLoading text={text} />}>
                <HistoryWorkspace
                  language={language}
                  sessionToken={sessionToken}
                />
              </Suspense>
            ) : (
              <PairingRequired
                text={text}
                page={text[activePage]}
                language={language}
                pinEnabled={pinEnabled}
                totpEnabled={totpEnabled}
                authMethodStatus={authMethodStatus}
                onRetry={() => void refreshBrowserAuthMethods()}
                onPin={async (pin) => {
                  setAuthentication("pairing");
                  try {
                    const response = await pairWithPin(pin);
                    await getSession(response.session_token);
                    setSessionToken(response.session_token);
                    window.sessionStorage.setItem(
                      PAGE_SESSION_KEY,
                      response.session_token,
                    );
                    setAuthentication("paired");
                  } catch {
                    setAuthentication("error");
                    throw new Error("pin_failed");
                  }
                }}
                onTotp={async (code) => {
                  setAuthentication("pairing");
                  try {
                    const response = await pairWithTotp(code);
                    await getSession(response.session_token);
                    setSessionToken(response.session_token);
                    window.sessionStorage.setItem(
                      PAGE_SESSION_KEY,
                      response.session_token,
                    );
                    setAuthentication("paired");
                  } catch {
                    setAuthentication("error");
                    throw new Error("totp_failed");
                  }
                }}
              />
            )}
          </main>
        </div>
        {legalOpen && (
          <LegalConsent
            language={language}
            canClose={legalAccepted}
            onLanguageChange={changeLanguage}
            onAccept={() => {
              storeLegalConsent();
              setLegalAccepted(true);
              setLegalOpen(false);
            }}
            onClose={() => setLegalOpen(false)}
          />
        )}
      </div>
    </Tooltip.Provider>
  );
}

function TerminalLoading({ text }: { text: Copy }) {
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
      <div>
        <Activity className="mx-auto size-8 animate-pulse text-cyan-600" />
        <p className="mb-0 mt-4 text-sm font-medium text-slate-600">
          {text.checking}
        </p>
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

function PairingRequired({
  text,
  page,
  language,
  pinEnabled,
  totpEnabled,
  authMethodStatus,
  onRetry,
  onPin,
  onTotp,
}: {
  text: Copy;
  page: string;
  language: Language;
  pinEnabled: boolean;
  totpEnabled: boolean;
  authMethodStatus: AuthMethodStatus;
  onRetry: () => void;
  onPin: (pin: string) => Promise<void>;
  onTotp: (code: string) => Promise<void>;
}) {
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const zh = language === "zh-CN";
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
        {authMethodStatus === "loading" && (
          <p role="status" className="mt-5 text-sm text-slate-600">
            {zh ? "正在检查身份验证方式…" : "Checking verification methods…"}
          </p>
        )}
        {authMethodStatus === "error" && (
          <div role="alert" className="mt-5 text-sm text-rose-700">
            {zh
              ? "无法读取身份验证配置。请重试；不会将其视为未配置。"
              : "Could not load verification settings. Retry; they are not assumed unset."}
            <button
              type="button"
              className="workbench-button ml-3"
              onClick={onRetry}
            >
              {zh ? "重试" : "Retry"}
            </button>
          </div>
        )}
        {authMethodStatus === "ready" && (pinEnabled || totpEnabled) && (
          <form
            className="mx-auto mt-6 max-w-sm space-y-3 text-left"
            onSubmit={async (event) => {
              event.preventDefault();
              setBusy(true);
              setFailed(false);
              try {
                if (totpEnabled) await onTotp(pin);
                else await onPin(pin);
                setPin("");
              } catch {
                setFailed(true);
              } finally {
                setBusy(false);
              }
            }}
          >
            <label
              htmlFor="browser-pin"
              className="block text-sm font-semibold text-slate-700"
            >
              {totpEnabled
                ? zh
                  ? "身份验证器验证码"
                  : "Authenticator code"
                : zh
                  ? "本机 PIN 或口令"
                  : "Local PIN or passphrase"}
            </label>
            <input
              id="browser-pin"
              type={totpEnabled ? "text" : "password"}
              minLength={6}
              maxLength={totpEnabled ? 6 : 64}
              inputMode={totpEnabled ? "numeric" : undefined}
              pattern={totpEnabled ? "[0-9]{6}" : undefined}
              required
              autoComplete={totpEnabled ? "one-time-code" : "current-password"}
              value={pin}
              onChange={(event) => setPin(event.target.value)}
              className="w-full rounded-xl border border-slate-200 px-3.5 py-2.5"
            />
            <button
              type="submit"
              disabled={busy}
              className="workbench-button w-full"
            >
              {busy
                ? zh
                  ? "验证中…"
                  : "Verifying…"
                : zh
                  ? "验证并进入"
                  : "Verify and continue"}
            </button>
            {failed && (
              <p role="alert" className="text-sm text-rose-700">
                {zh
                  ? "验证失败。连续错误会触发一分钟冷却。"
                  : "Verification failed. Repeated failures trigger a one-minute cooldown."}
              </p>
            )}
          </form>
        )}
      </div>
    </section>
  );
}
