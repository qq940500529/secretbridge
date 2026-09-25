// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import * as Tooltip from "@radix-ui/react-tooltip";
import { copy, type Copy } from "./copy";
import {
  PairingRequired,
  StatusPill,
  TerminalLoading,
} from "./ShellComponents";
import {
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
} from "../api/index";
import {
  BrowserAuthenticationSettings,
  type AuthMethodStatus,
} from "../features/auth/BrowserAuthenticationSettings";
import { consumePairingToken } from "./pairing";
import { BackgroundServiceView } from "../features/settings/BackgroundServiceView";
import { ISSUE_URL, LegalConsent } from "../features/auth/LegalConsent";
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
import { SettingsView } from "../features/settings/SettingsView";
import { ApprovalQueueDialog } from "../features/tasks/approvals/ApprovalQueueDialog";
import { ActiveConversationRisk } from "../features/tasks/approvals/AiConversationsView";

const TerminalView = lazy(() =>
  import("../features/terminal/TerminalView").then((module) => ({
    default: module.TerminalView,
  })),
);
const DataMaintenanceView = lazy(() =>
  import("../features/settings/DataMaintenanceView").then((module) => ({
    default: module.DataMaintenanceView,
  })),
);
const CredentialReferencesView = lazy(() =>
  import("../features/catalog/CatalogView").then((module) => ({
    default: module.CredentialReferencesView,
  })),
);
const TargetsView = lazy(() =>
  import("../features/catalog/CatalogView").then((module) => ({
    default: module.TargetsView,
  })),
);
const TaskWorkspace = lazy(() =>
  import("./TaskWorkspace").then((module) => ({
    default: module.TaskWorkspace,
  })),
);
const HistoryWorkspace = lazy(() =>
  import("../features/history/HistoryWorkspace").then((module) => ({
    default: module.HistoryWorkspace,
  })),
);

type Connection = "checking" | "online" | "offline";
type Authentication = "unpaired" | "pairing" | "paired" | "error";
type Page =
  "credentials" | "targets" | "operations" | "terminal" | "audit" | "settings";
type TaskSection = "templates" | "approvals" | "runs";

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
            {sessionToken && authMethodStatus === "ready" && !pinEnabled ? (
              <div className="max-w-3xl">
                <h1 className="text-2xl font-bold text-slate-950">
                  {language === "zh-CN"
                    ? "完成首次初始化"
                    : "Finish first-time setup"}
                </h1>
                <BrowserAuthenticationSettings
                  language={language}
                  sessionToken={sessionToken}
                  pinEnabled={pinEnabled}
                  totpEnabled={totpEnabled}
                  authMethodStatus={authMethodStatus}
                  onRetry={() => void refreshBrowserAuthMethods()}
                  onChanged={() => {
                    setActivePage("settings");
                    void refreshBrowserAuthMethods();
                  }}
                />
              </div>
            ) : activePage === "settings" ? (
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
