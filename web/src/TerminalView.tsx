// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import {
  CircleStop,
  PlugZap,
  Plus,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  createTerminal,
  deleteTerminal,
  listTerminals,
  terminalWebSocketUrl,
  type TerminalStatus,
  type TerminalSummary,
} from "./api";

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
    title: "合成安全终端",
    subtitle: "用于验证持久化 PTY、实时输入输出和断线重连，不连接系统 Shell 或真实凭据。",
    create: "新建合成终端",
    reconnect: "重新连接",
    stop: "终止并删除",
    sessions: "终端会话",
    empty: "还没有终端会话。新建后可输入 help、status、clear 或 exit。",
    safety: "隔离模式",
    disconnected: "未连接",
    connecting: "连接中",
    connected: "实时连接",
    error: "连接异常",
    running: "运行中",
    exited: "已退出",
    terminated: "已终止",
    failed: "失败",
    loadingError: "无法读取终端会话，请确认本页仍处于已配对状态。",
    operationError: "终端操作失败，请稍后重试。",
    writeAccess: "已取得输入权",
    readOnly: "只读连接",
    olderOutputDiscarded: "更早的输出已超过保留上限，当前从最早可用位置恢复。",
    recoveringOutput: "检测到输出缺口，正在按游标恢复。",
  },
  en: {
    title: "Synthetic secure terminal",
    subtitle: "Validates persistent PTY I/O and reconnection without a system shell or real credentials.",
    create: "Create synthetic terminal",
    reconnect: "Reconnect",
    stop: "Terminate and remove",
    sessions: "Terminal sessions",
    empty: "No terminal sessions yet. Create one, then try help, status, clear, or exit.",
    safety: "Isolated mode",
    disconnected: "Disconnected",
    connecting: "Connecting",
    connected: "Live",
    error: "Connection error",
    running: "Running",
    exited: "Exited",
    terminated: "Terminated",
    failed: "Failed",
    loadingError: "Unable to read terminal sessions. Confirm that this page is still paired.",
    operationError: "The terminal operation failed. Try again.",
    writeAccess: "Input lease granted",
    readOnly: "Read-only connection",
    olderOutputDiscarded: "Older output exceeded the retention limit; replay starts at the oldest available cursor.",
    recoveringOutput: "An output gap was detected. Reconnecting from the last cursor.",
  },
} as const;

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
  const fitRef = useRef<FitAddon | null>(null);
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
  const [terminals, setTerminals] = useState<TerminalSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [socketState, setSocketState] = useState<SocketState>("disconnected");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inputGranted, setInputGranted] = useState(false);

  textRef.current = text;

  useEffect(() => {
    selectedRef.current = selectedId;
  }, [selectedId]);

  const updateStatus = useCallback((id: string, status: TerminalStatus) => {
    setTerminals((current) =>
      current.map((terminal) =>
        terminal.id === id ? { ...terminal, status } : terminal,
      ),
    );
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
          cursorByTerminalRef.current.set(terminalId, cursor + bytes.byteLength);
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
          updateStatus(terminalId, "exited");
          terminalRef.current?.writeln(`\r\n[process exited: ${message.exit_code ?? 0}]`);
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
          reconnectTimerRef.current = window.setTimeout(() => connect(terminalId, true), 1200);
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
    fitRef.current = fit;

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
          JSON.stringify({ type: "resize", rows: terminal.rows, cols: terminal.cols }),
        );
      }
    });
    resize.observe(hostRef.current!);

    return () => {
      mountedRef.current = false;
      selectedRef.current = null;
      reconnectAllowedRef.current = false;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
      }
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
    listTerminals(sessionToken)
      .then((items) => {
        if (!active) return;
        setTerminals(items);
        const candidate = [...items].reverse().find((item) => item.status === "running");
        if (candidate) connect(candidate.id, false);
      })
      .catch(() => active && setError(text.loadingError));
    return () => {
      active = false;
    };
  }, [connect, sessionToken, text.loadingError]);

  async function handleCreate() {
    const terminal = terminalRef.current;
    if (!terminal) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createTerminal(sessionToken, terminal.rows, terminal.cols);
      setTerminals((current) => [...current, created]);
      connect(created.id, false);
    } catch {
      setError(text.operationError);
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
    reconnectAllowedRef.current = false;
    setSelectedId(null);
    const socket = socketRef.current;
    socketRef.current = null;
    if (socket) {
      socket.onclose = null;
      socket.close();
    }
    try {
      await deleteTerminal(sessionToken, id);
      setTerminals((current) => current.filter((terminal) => terminal.id !== id));
      terminalRef.current?.reset();
      setSocketState("disconnected");
    } catch {
      setError(text.operationError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700">
            <ShieldCheck className="size-3.5" /> {text.safety}
          </span>
          <h1 className="mb-0 mt-3 text-3xl font-bold tracking-tight text-slate-950">
            {text.title}
          </h1>
          <p className="mb-0 mt-2 max-w-3xl leading-7 text-slate-600">{text.subtitle}</p>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => void handleCreate()}
          className="inline-flex h-11 items-center gap-2 rounded-xl bg-cyan-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <Plus className="size-4" /> {text.create}
        </button>
      </div>

      {error && (
        <p
          role="alert"
          className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"
        >
          {error}
        </p>
      )}

      <div className="grid gap-5 xl:grid-cols-[18rem_minmax(0,1fr)]">
        <aside className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <h2 className="mb-3 mt-0 text-sm font-semibold text-slate-900">{text.sessions}</h2>
          <div className="space-y-2">
            {terminals.map((terminal) => (
              <button
                type="button"
                key={terminal.id}
                onClick={() => connect(terminal.id, false)}
                className={`w-full rounded-xl border p-3 text-left transition ${
                  selectedId === terminal.id
                    ? "border-cyan-300 bg-cyan-50"
                    : "border-slate-200 hover:border-slate-300 hover:bg-slate-50"
                }`}
              >
                <span className="block truncate font-mono text-xs font-semibold text-slate-800">
                  {terminal.id.slice(0, 12)}
                </span>
                <span className="mt-1 block text-xs text-slate-500">{text[terminal.status]}</span>
              </button>
            ))}
            {terminals.length === 0 && (
              <p className="m-0 rounded-xl bg-slate-50 p-3 text-sm leading-6 text-slate-500">
                {text.empty}
              </p>
            )}
          </div>
        </aside>

        <article className="overflow-hidden rounded-2xl border border-slate-800 bg-[#07111f] shadow-xl">
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
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!selectedId || busy}
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
