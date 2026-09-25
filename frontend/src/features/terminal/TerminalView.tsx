// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { CircleStop, Link2Off, PlugZap, Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  createTerminal,
  deleteTerminal,
  getTerminalCapabilities,
  listTerminals,
  terminalWebSocketUrl,
  type TerminalCapabilities,
  type TerminalShell,
  type TerminalStatus,
  type TerminalSummary,
} from "../../api/index";
import { parseTerminalEnvironment } from "./environment";
import { useServiceChanges } from "../../app/service-events";

type Language = "zh-CN" | "en";
type SocketState = "disconnected" | "connecting" | "connected" | "error";

interface ServerMessage {
  type: "ready" | "exited" | "terminated" | "error" | "output_lagged";
  status?: TerminalStatus;
  exit_code?: number;
  code?: string;
  message?: string;
  replay_from?: number;
  next_cursor?: number;
  replay_truncated?: boolean;
  retained_bytes?: number;
  retention_capacity?: number;
  input_granted?: boolean;
  oldest_cursor?: number;
}

const labels = {
  "zh-CN": {
    title: "安全连续终端",
    subtitle:
      "普通命令与经人工批准的凭据命令可在同一进程中连续执行。输出由本机代理先脱敏，再提供给页面或 MCP；关闭页面不会结束进程。",
    create: "新建终端",
    createTitle: "启动系统终端",
    name: "会话名称",
    namePlaceholder: "例如：本地构建",
    shell: "Shell",
    workingDirectory: "初始工作目录（绝对路径）",
    workingDirectoryPlaceholder: "留空则使用 SecretBridge 启动目录",
    environment: "普通环境变量",
    environmentPlaceholder:
      "每行一个，例如：\nNODE_ENV=development\nLANG=zh_CN.UTF-8",
    environmentHint: "仅用于本次进程，不会保存。请不要在这里填写密码或令牌。",
    reconnect: "连接",
    disconnect: "断开窗口",
    stop: "终止并移除",
    sessions: "终端会话",
    empty: "还没有终端会话。请在上方选择 Shell 后创建。",
    unavailable: "当前系统没有探测到可用的受支持 Shell。",
    disconnected: "窗口已断开",
    connecting: "连接中",
    connected: "实时连接",
    error: "连接异常",
    running: "运行中",
    exited: "已退出",
    terminated: "已终止",
    failed: "失败",
    loadingError: "无法读取终端能力或会话，请确认本页仍处于已配对状态。",
    operationError: "终端操作失败，请检查 Shell、工作目录和环境变量。",
    environmentError:
      "普通环境变量必须按 KEY=value 每行一个填写，名称只能包含字母、数字和下划线。",
    writeAccess: "已取得输入权",
    readOnly: "只读连接",
    olderOutputDiscarded: "更早的输出已超过保留上限，当前从最早可用位置恢复。",
    recoveringOutput: "检测到输出缺口，正在按游标恢复。",
    process: "PID",
    variables: "环境变量",
    exitCode: "退出码",
  },
  en: {
    title: "Secure continuous terminals",
    subtitle:
      "Ordinary commands and human-approved credential commands can share one continuous process. The local broker redacts output before exposing it to the page or MCP, and closing the page does not stop the process.",
    create: "Create terminal",
    createTitle: "Start a system terminal",
    name: "Session name",
    namePlaceholder: "For example: Local build",
    shell: "Shell",
    workingDirectory: "Initial working directory (absolute path)",
    workingDirectoryPlaceholder:
      "Leave empty to use the SecretBridge startup directory",
    environment: "Ordinary environment variables",
    environmentPlaceholder:
      "One per line, for example:\nNODE_ENV=development\nLANG=en_US.UTF-8",
    environmentHint:
      "Used only by this process and not saved. Do not enter passwords or tokens here.",
    reconnect: "Connect",
    disconnect: "Detach window",
    stop: "Terminate and remove",
    sessions: "Terminal sessions",
    empty: "No terminal sessions yet. Select a shell above and create one.",
    unavailable: "No supported shell was detected on this system.",
    disconnected: "Window detached",
    connecting: "Connecting",
    connected: "Live",
    error: "Connection error",
    running: "Running",
    exited: "Exited",
    terminated: "Terminated",
    failed: "Failed",
    loadingError:
      "Unable to read terminal capabilities or sessions. Confirm that this page is still paired.",
    operationError:
      "The terminal operation failed. Check the shell, working directory, and environment variables.",
    environmentError:
      "Environment variables must use one KEY=value entry per line; names may contain only letters, numbers, and underscores.",
    writeAccess: "Input lease granted",
    readOnly: "Read-only connection",
    olderOutputDiscarded:
      "Older output exceeded the retention limit; replay starts at the oldest available cursor.",
    recoveringOutput:
      "An output gap was detected. Reconnecting from the last cursor.",
    process: "PID",
    variables: "variables",
    exitCode: "exit code",
  },
} as const;

function shellName(
  shell: TerminalShell,
  capabilities: TerminalCapabilities | null,
): string {
  return (
    capabilities?.shells.find((item) => item.shell === shell)?.display_name ??
    shell
  );
}

export function TerminalView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const text = labels[language];
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const selectedRef = useRef<string | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAllowedRef = useRef(false);
  const readyRef = useRef(false);
  const inputGrantedRef = useRef(false);
  const cursorByTerminalRef = useRef(new Map<string, number>());
  const clientIdRef = useRef(crypto.randomUUID());
  const textRef = useRef(text);
  const mountedRef = useRef(true);
  const [capabilities, setCapabilities] = useState<TerminalCapabilities | null>(
    null,
  );
  const [terminals, setTerminals] = useState<TerminalSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedShell, setSelectedShell] = useState<TerminalShell | "">("");
  const [sessionName, setSessionName] = useState("");
  const [workingDirectory, setWorkingDirectory] = useState("");
  const [environment, setEnvironment] = useState("");
  const [socketState, setSocketState] = useState<SocketState>("disconnected");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inputGranted, setInputGranted] = useState(false);

  textRef.current = text;

  useEffect(() => {
    selectedRef.current = selectedId;
  }, [selectedId]);

  const updateStatus = useCallback(
    (id: string, status: TerminalStatus, exitCode?: number) => {
      setTerminals((current) =>
        current.map((terminal) =>
          terminal.id === id
            ? { ...terminal, status, exit_code: exitCode ?? terminal.exit_code }
            : terminal,
        ),
      );
    },
    [],
  );

  const detach = useCallback(() => {
    reconnectAllowedRef.current = false;
    readyRef.current = false;
    inputGrantedRef.current = false;
    setInputGranted(false);
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    const socket = socketRef.current;
    socketRef.current = null;
    if (socket) {
      socket.onclose = null;
      socket.close();
    }
    setSocketState("disconnected");
  }, []);

  const connect = useCallback(
    (terminalId: string, resume = false) => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      const previousSocket = socketRef.current;
      socketRef.current = null;
      if (previousSocket) {
        previousSocket.onclose = null;
        previousSocket.close();
      }
      readyRef.current = false;
      inputGrantedRef.current = false;
      setInputGranted(false);
      reconnectAllowedRef.current = true;
      if (!resume) {
        cursorByTerminalRef.current.delete(terminalId);
        terminalRef.current?.reset();
      }
      setSelectedId(terminalId);
      selectedRef.current = terminalId;
      setSocketState("connecting");
      setError(null);

      const socket = new WebSocket(terminalWebSocketUrl(terminalId));
      socket.binaryType = "arraybuffer";
      socketRef.current = socket;
      socket.onopen = () => {
        socket.send(
          JSON.stringify({
            type: "authenticate",
            token: sessionToken,
            client_id: clientIdRef.current,
            request_input: true,
            cursor: cursorByTerminalRef.current.get(terminalId) ?? null,
          }),
        );
      };
      socket.onmessage = (event) => {
        if (typeof event.data !== "string") {
          const bytes = new Uint8Array(event.data as ArrayBuffer);
          const cursor = cursorByTerminalRef.current.get(terminalId) ?? 0;
          cursorByTerminalRef.current.set(
            terminalId,
            cursor + bytes.byteLength,
          );
          terminalRef.current?.write(bytes);
          return;
        }
        let message: ServerMessage;
        try {
          message = JSON.parse(event.data) as ServerMessage;
        } catch {
          reconnectAllowedRef.current = false;
          setSocketState("error");
          return;
        }
        if (message.type === "ready") {
          cursorByTerminalRef.current.set(terminalId, message.replay_from ?? 0);
          readyRef.current = true;
          inputGrantedRef.current = message.input_granted === true;
          setInputGranted(inputGrantedRef.current);
          setSocketState("connected");
          if (message.replay_truncated) {
            terminalRef.current?.writeln(
              `\r\n[${textRef.current.olderOutputDiscarded}]\r\n`,
            );
          }
          if (message.status) {
            updateStatus(terminalId, message.status);
            reconnectAllowedRef.current = message.status === "running";
          }
        } else if (message.type === "exited") {
          reconnectAllowedRef.current = false;
          updateStatus(terminalId, "exited", message.exit_code ?? 0);
          terminalRef.current?.writeln(
            `\r\n[${textRef.current.exitCode}: ${message.exit_code ?? 0}]`,
          );
        } else if (message.type === "terminated") {
          reconnectAllowedRef.current = false;
          updateStatus(terminalId, "terminated");
        } else if (message.type === "output_lagged") {
          terminalRef.current?.writeln(
            `\r\n[${textRef.current.recoveringOutput}]`,
          );
          reconnectAllowedRef.current = true;
          socket.close();
        } else if (message.type === "error") {
          const leaseError = message.code === "input_lease_required";
          reconnectAllowedRef.current = leaseError;
          if (!leaseError) setSocketState("error");
          terminalRef.current?.writeln(
            `\r\n[${message.message ?? textRef.current.operationError}]`,
          );
        }
      };
      socket.onerror = () => setSocketState("error");
      socket.onclose = () => {
        readyRef.current = false;
        inputGrantedRef.current = false;
        setInputGranted(false);
        if (socketRef.current !== socket) return;
        socketRef.current = null;
        if (!mountedRef.current || selectedRef.current !== terminalId) return;
        setSocketState("disconnected");
        if (reconnectAllowedRef.current) {
          reconnectTimerRef.current = window.setTimeout(
            () => connect(terminalId, true),
            1200,
          );
        }
      };
    },
    [sessionToken, updateStatus],
  );

  useEffect(() => {
    mountedRef.current = true;
    const terminal = new Terminal({
      convertEol: true,
      cursorBlink: true,
      cursorStyle: "bar",
      fontFamily: '"Cascadia Mono", "JetBrains Mono", Consolas, monospace',
      fontSize: 14,
      theme: {
        background: "#07111f",
        foreground: "#dbeafe",
        cursor: "#22d3ee",
        selectionBackground: "#164e63",
      },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(hostRef.current!);
    fit.fit();
    terminalRef.current = terminal;

    const input = terminal.onData((data) => {
      const socket = socketRef.current;
      if (
        readyRef.current &&
        inputGrantedRef.current &&
        socket?.readyState === WebSocket.OPEN
      ) {
        socket.send(JSON.stringify({ type: "input", data }));
      }
    });
    const resize = new ResizeObserver(() => {
      fit.fit();
      const socket = socketRef.current;
      if (
        readyRef.current &&
        inputGrantedRef.current &&
        socket?.readyState === WebSocket.OPEN
      ) {
        socket.send(
          JSON.stringify({
            type: "resize",
            rows: terminal.rows,
            cols: terminal.cols,
          }),
        );
      }
    });
    resize.observe(hostRef.current!);

    return () => {
      mountedRef.current = false;
      selectedRef.current = null;
      reconnectAllowedRef.current = false;
      if (reconnectTimerRef.current !== null)
        window.clearTimeout(reconnectTimerRef.current);
      const socket = socketRef.current;
      socketRef.current = null;
      if (socket) {
        socket.onclose = null;
        socket.close();
      }
      resize.disconnect();
      input.dispose();
      terminal.dispose();
    };
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([
      getTerminalCapabilities(sessionToken),
      listTerminals(sessionToken),
    ])
      .then(([terminalCapabilities, items]) => {
        if (!active) return;
        setCapabilities(terminalCapabilities);
        setSelectedShell(terminalCapabilities.default_shell ?? "");
        setTerminals(items);
        const candidate = [...items]
          .reverse()
          .find((item) => item.status === "running");
        if (candidate) connect(candidate.id, false);
      })
      .catch(() => active && setError(text.loadingError));
    return () => {
      active = false;
    };
  }, [connect, sessionToken, text.loadingError]);

  useServiceChanges(sessionToken, () => {
    void listTerminals(sessionToken)
      .then((items) => {
        if (mountedRef.current) setTerminals(items);
      })
      .catch(() => undefined);
  });

  async function handleCreate() {
    const terminal = terminalRef.current;
    if (!terminal || !selectedShell) return;
    setBusy(true);
    setError(null);
    try {
      const parsedEnvironment = parseTerminalEnvironment(environment);
      const created = await createTerminal(sessionToken, {
        rows: terminal.rows,
        cols: terminal.cols,
        shell: selectedShell,
        name: sessionName.trim() || undefined,
        working_directory: workingDirectory.trim() || undefined,
        environment: parsedEnvironment,
      });
      setTerminals((current) => [...current, created]);
      setSessionName("");
      connect(created.id, false);
    } catch (caught) {
      setError(
        caught instanceof Error &&
          caught.message === "invalid environment variable"
          ? text.environmentError
          : text.operationError,
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleStop() {
    if (!selectedId) return;
    setBusy(true);
    setError(null);
    const id = selectedId;
    selectedRef.current = null;
    detach();
    setSelectedId(null);
    try {
      await deleteTerminal(sessionToken, id);
      setTerminals((current) =>
        current.filter((terminal) => terminal.id !== id),
      );
      cursorByTerminalRef.current.delete(id);
      terminalRef.current?.reset();
    } catch {
      setError(text.operationError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <div className="mb-6">
        <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
          {text.title}
        </h1>
        <p className="mb-0 mt-2 max-w-3xl leading-7 text-slate-600">
          {text.subtitle}
        </p>
      </div>

      {error && (
        <p
          role="alert"
          className="border-l-4 border-rose-400 bg-rose-50 px-4 py-3 text-sm text-rose-700"
        >
          {error}
        </p>
      )}

      <form
        className="mb-5 border-y border-slate-200 bg-white px-4 py-4"
        onSubmit={(event) => {
          event.preventDefault();
          void handleCreate();
        }}
      >
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="m-0 text-sm font-semibold text-slate-900">
            {text.createTitle}
          </h2>
          <button
            type="submit"
            disabled={busy || !selectedShell}
            className="inline-flex h-9 items-center gap-2 rounded-lg bg-cyan-700 px-4 text-sm font-semibold text-white transition hover:bg-cyan-800 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Plus className="size-4" /> {text.create}
          </button>
        </div>
        {capabilities && capabilities.shells.length === 0 ? (
          <p className="m-0 text-sm text-rose-700">{text.unavailable}</p>
        ) : (
          <div className="grid gap-4 lg:grid-cols-4">
            <label className="text-sm font-medium text-slate-700">
              {text.name}
              <input
                value={sessionName}
                maxLength={80}
                onChange={(event) => setSessionName(event.target.value)}
                placeholder={text.namePlaceholder}
                className="mt-1 block h-10 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-cyan-600 focus:ring-2 focus:ring-cyan-100"
              />
            </label>
            <label className="text-sm font-medium text-slate-700">
              {text.shell}
              <select
                value={selectedShell}
                onChange={(event) =>
                  setSelectedShell(event.target.value as TerminalShell)
                }
                className="mt-1 block h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm outline-none focus:border-cyan-600 focus:ring-2 focus:ring-cyan-100"
              >
                {capabilities?.shells.map((item) => (
                  <option key={item.shell} value={item.shell}>
                    {item.display_name}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm font-medium text-slate-700 lg:col-span-2">
              {text.workingDirectory}
              <input
                value={workingDirectory}
                onChange={(event) => setWorkingDirectory(event.target.value)}
                placeholder={text.workingDirectoryPlaceholder}
                className="mt-1 block h-10 w-full rounded-md border border-slate-300 px-3 font-mono text-sm outline-none focus:border-cyan-600 focus:ring-2 focus:ring-cyan-100"
              />
            </label>
            <label className="text-sm font-medium text-slate-700 lg:col-span-4">
              {text.environment}
              <textarea
                value={environment}
                onChange={(event) => setEnvironment(event.target.value)}
                placeholder={text.environmentPlaceholder}
                rows={2}
                className="mt-1 block w-full resize-y rounded-md border border-slate-300 px-3 py-2 font-mono text-sm outline-none focus:border-cyan-600 focus:ring-2 focus:ring-cyan-100"
              />
              <span className="mt-1 block text-xs font-normal text-slate-500">
                {text.environmentHint}
              </span>
            </label>
          </div>
        )}
      </form>

      <div className="grid gap-5 xl:grid-cols-[20rem_minmax(0,1fr)]">
        <aside className="border border-slate-200 bg-white p-4">
          <h2 className="mb-3 mt-0 text-sm font-semibold text-slate-900">
            {text.sessions}
          </h2>
          <div className="divide-y divide-slate-200 border-y border-slate-200">
            {terminals.map((terminal) => (
              <button
                type="button"
                key={terminal.id}
                onClick={() => connect(terminal.id, false)}
                className={`w-full border-l-2 px-3 py-3 text-left transition ${
                  selectedId === terminal.id
                    ? "border-cyan-500 bg-cyan-50"
                    : "border-transparent hover:bg-slate-50"
                }`}
              >
                <span className="block truncate text-sm font-semibold text-slate-900">
                  {terminal.name}
                </span>
                <span className="mt-1 block truncate font-mono text-xs text-slate-500">
                  {shellName(terminal.shell, capabilities)} ·{" "}
                  {terminal.working_directory}
                </span>
                <span className="mt-1 block text-xs text-slate-500">
                  {text[terminal.status]}
                  {terminal.process_id
                    ? ` · ${text.process} ${terminal.process_id}`
                    : ""}
                  {terminal.environment_variable_count > 0
                    ? ` · ${terminal.environment_variable_count} ${text.variables}`
                    : ""}
                  {terminal.exit_code !== null
                    ? ` · ${text.exitCode} ${terminal.exit_code}`
                    : ""}
                </span>
              </button>
            ))}
            {terminals.length === 0 && (
              <p className="m-0 p-3 text-sm leading-6 text-slate-500">
                {text.empty}
              </p>
            )}
          </div>
        </aside>

        <article className="overflow-hidden rounded-lg border border-slate-800 bg-[#07111f]">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-slate-950 px-4 py-3">
            <span className="inline-flex items-center gap-2 text-xs font-semibold text-slate-300">
              <span
                aria-hidden="true"
                className={`size-2 rounded-full ${
                  socketState === "connected"
                    ? "bg-emerald-400"
                    : socketState === "connecting"
                      ? "animate-pulse bg-amber-400"
                      : "bg-slate-500"
                }`}
              />
              {text[socketState]}
            </span>
            {selectedId && socketState === "connected" && (
              <span
                className={`rounded-full px-2.5 py-1 text-xs font-semibold ${
                  inputGranted
                    ? "bg-emerald-400/15 text-emerald-200"
                    : "bg-amber-400/15 text-amber-200"
                }`}
              >
                {inputGranted ? text.writeAccess : text.readOnly}
              </span>
            )}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={!selectedId || busy || socketState === "connected"}
                onClick={() => selectedId && connect(selectedId, true)}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-white/10 px-3 text-xs font-medium text-slate-200 hover:bg-white/15 disabled:opacity-40"
              >
                {socketState === "connecting" ? (
                  <RefreshCw className="size-3.5 animate-spin" />
                ) : (
                  <PlugZap className="size-3.5" />
                )}
                {text.reconnect}
              </button>
              <button
                type="button"
                disabled={!selectedId || busy || socketState === "disconnected"}
                onClick={detach}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-white/10 px-3 text-xs font-medium text-slate-200 hover:bg-white/15 disabled:opacity-40"
              >
                <Link2Off className="size-3.5" /> {text.disconnect}
              </button>
              <button
                type="button"
                disabled={!selectedId || busy}
                onClick={() => void handleStop()}
                className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-rose-500/15 px-3 text-xs font-medium text-rose-200 hover:bg-rose-500/25 disabled:opacity-40"
              >
                <CircleStop className="size-3.5" /> {text.stop}
              </button>
            </div>
          </div>
          <div
            ref={hostRef}
            role="region"
            className="h-[32rem] p-3"
            aria-label={text.title}
          />
        </article>
      </div>
    </section>
  );
}
