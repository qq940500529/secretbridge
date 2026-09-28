// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import {
  listTerminalHistory,
  clearTerminalHistory,
  type TerminalHistoryEntry,
} from "../../api/terminal-history";
import { RunOutputView } from "../tasks/runs/RunOutputView";

export function TerminalHistoryView({
  language,
  sessionToken,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
}) {
  const zh = language === "zh-CN";
  const [items, setItems] = useState<TerminalHistoryEntry[]>([]);
  const [cursor, setCursor] = useState(0);
  const [more, setMore] = useState(true);
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  async function load(reset = false) {
    setBusy(true);
    setError(false);
    try {
      const page = await listTerminalHistory(sessionToken, reset ? 0 : cursor);
      setItems((current) => (reset ? page.items : [...current, ...page.items]));
      setCursor(page.next_cursor);
      setMore(page.items.length === 500);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    void load(true);
  }, [sessionToken]);
  const sessions = [...new Set(items.map((item) => item.terminal_id))];
  const title = (id: string) =>
    String(
      items.find((item) => item.terminal_id === id && item.kind === "created")
        ?.metadata.name ?? id,
    );
  const labels = {
    created: zh ? "已创建" : "Created",
    input: zh ? "交互输入" : "Interactive input",
    output: zh ? "输出" : "Output",
    command: zh ? "受控命令" : "Controlled command",
    result: zh ? "执行结果" : "Result",
    closed: zh ? "已关闭" : "Closed",
  };
  const filtered = items.filter(
    (item) =>
      (!selected || item.terminal_id === selected) &&
      (!search ||
        item.data.toLocaleLowerCase().includes(search.toLocaleLowerCase()) ||
        JSON.stringify(item.metadata)
          .toLocaleLowerCase()
          .includes(search.toLocaleLowerCase())),
  );
  return (
    <section className="workbench-page">
      <header className="workbench-page-header">
        <div>
          <h1>{zh ? "终端历史" : "Terminal history"}</h1>
          <p>
            {zh
              ? "按时间查看输入、数据和脱敏输出。受控命令保留参数、工作目录及退出码；交互输入是提交的键盘内容，不保证还原 Shell 编辑后的命令。全局保留最近 10,000 条事件。"
              : "Timestamped input, data and redacted output. Controlled commands retain parameters, working directory and exit status. Interactive entries are submitted keystrokes, not a reconstructed shell audit. Retains the latest 10,000 events."}
          </p>
        </div>
      </header>
      <div className="flex flex-wrap gap-3 border-y border-slate-200 py-4">
        <select
          aria-label={zh ? "终端会话" : "Terminal session"}
          className="workbench-input"
          value={selected}
          onChange={(event) => setSelected(event.target.value)}
        >
          <option value="">{zh ? "全部会话" : "All sessions"}</option>
          {sessions.map((id) => (
            <option key={id} value={id}>
              {title(id)}
            </option>
          ))}
        </select>
        <input
          className="workbench-input"
          aria-label={zh ? "搜索历史" : "Search history"}
          placeholder={
            zh ? "搜索命令、数据或输出" : "Search commands, data or output"
          }
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <button
          className="workbench-button"
          disabled={busy}
          onClick={() => void load(true)}
        >
          {zh ? "刷新" : "Refresh"}
        </button>
        <button
          className="workbench-button"
          disabled={!filtered.length || busy}
          onClick={() => {
            const blob = new Blob(
              [
                JSON.stringify(
                  { format: "secretbridge-terminal-history", items: filtered },
                  null,
                  2,
                ),
              ],
              { type: "application/json" },
            );
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = url;
            anchor.download = "secretbridge-terminal-history.json";
            anchor.click();
            URL.revokeObjectURL(url);
          }}
        >
          {zh ? "导出当前已加载记录" : "Export loaded records"}
        </button>
        {selected && (
          <button
            className="workbench-button text-rose-700"
            disabled={busy}
            onClick={async () => {
              if (
                !window.confirm(
                  zh
                    ? "永久删除此会话的历史记录？不会停止正在运行的终端。"
                    : "Permanently delete this transcript? The live terminal will not stop.",
                )
              )
                return;
              setBusy(true);
              try {
                await clearTerminalHistory(sessionToken, selected);
                setSelected("");
                await load(true);
              } catch {
                setError(true);
              } finally {
                setBusy(false);
              }
            }}
          >
            {zh ? "清除会话历史" : "Clear session history"}
          </button>
        )}
      </div>
      {error && (
        <p role="alert" className="text-rose-700">
          {zh
            ? "历史读取失败，请重试。"
            : "History could not be loaded. Retry."}
        </p>
      )}
      {!filtered.length && !busy && (
        <p className="py-8 text-slate-500">
          {zh ? "暂无符合条件的终端记录。" : "No matching terminal entries."}
        </p>
      )}
      <ol className="list-none divide-y divide-slate-200 p-0">
        {filtered.map((item) => (
          <li key={item.cursor} className="py-4">
            <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
              <time className="font-mono text-slate-500">
                {new Intl.DateTimeFormat(language, {
                  dateStyle: "short",
                  timeStyle: "medium",
                }).format(item.occurred_at_unix_ms)}
              </time>
              <strong>{labels[item.kind]}</strong>
              <span className="text-slate-500">{title(item.terminal_id)}</span>
            </div>
            {item.data && (
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-950 p-4 font-mono text-sm text-slate-100">
                {item.data}
              </pre>
            )}
            {item.kind !== "output" &&
              Object.keys(item.metadata).length > 0 && (
                <details className="mt-3">
                  <summary className="cursor-pointer text-sm font-semibold text-cyan-700">
                    {zh
                      ? "查看数据、参数与状态"
                      : "Data, parameters and status"}
                  </summary>
                  <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-100 p-4 text-xs">
                    {JSON.stringify(item.metadata, null, 2)}
                  </pre>
                </details>
              )}
            {item.kind === "result" &&
              typeof item.metadata.run_id === "string" && (
                <RunOutputView
                  id={item.metadata.run_id}
                  language={language}
                  sessionToken={sessionToken}
                />
              )}
          </li>
        ))}
      </ol>
      {more && (
        <button
          className="workbench-button"
          disabled={busy}
          onClick={() => void load()}
        >
          {busy
            ? zh
              ? "正在读取…"
              : "Loading…"
            : zh
              ? "加载更多记录"
              : "Load more"}
        </button>
      )}
    </section>
  );
}
