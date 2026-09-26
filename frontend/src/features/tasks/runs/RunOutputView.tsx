// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from "react";
import {
  deleteRunOutput,
  readRunOutput,
  type RunOutput,
} from "../../../api/index";
import { useServiceChanges } from "../../../app/service-events";
import { DatabaseResultView, parseDatabaseResult } from "./DatabaseResultView";
import { saveDownload } from "../../settings/DataMaintenanceView";

export function RunOutputView({
  id,
  sessionToken,
  language,
}: {
  id: string;
  sessionToken: string;
  language: "zh-CN" | "en";
}) {
  const [chunks, setChunks] = useState<RunOutput["items"]>([]);
  const [gap, setGap] = useState(false);
  const [exit, setExit] = useState<number | null>(null);
  const [error, setError] = useState(false);
  const [runState, setRunState] = useState<RunOutput["state"] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [cleared, setCleared] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [query, setQuery] = useState("");
  const [streamFilter, setStreamFilter] = useState<
    "all" | "stdout" | "stderr" | "terminal"
  >("all");
  const [pageFromEnd, setPageFromEnd] = useState(0);
  const [wrap, setWrap] = useState(true);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">(
    "idle",
  );
  const cursor = useRef(0);
  const busy = useRef(false);
  const active = useRef(true);
  const generation = useRef(0);
  const latestRunState = useRef<RunOutput["state"] | null>(null);
  async function load() {
    if (busy.current || !active.current) return;
    const requestedGeneration = generation.current;
    busy.current = true;
    try {
      for (let page = 0; page < 128; page++) {
        const result = await readRunOutput(sessionToken, id, cursor.current);
        if (!active.current || generation.current !== requestedGeneration)
          return;
        cursor.current = result.next_cursor;
        if (result.truncated) setGap(true);
        setChunks((previous) => [...previous, ...result.items].slice(-2048));
        setExit(result.exit_code);
        setRunState(result.state);
        latestRunState.current = result.state;
        setError(false);
        if (!result.has_more) break;
      }
    } catch {
      if (active.current && generation.current === requestedGeneration)
        setError(true);
    } finally {
      if (generation.current === requestedGeneration) busy.current = false;
    }
  }
  async function clearRetainedOutput() {
    const requestedGeneration = generation.current;
    setDeleting(true);
    try {
      await deleteRunOutput(sessionToken, id);
      if (!active.current || generation.current !== requestedGeneration) return;
      generation.current += 1;
      busy.current = false;
      setChunks([]);
      cursor.current = 0;
      setGap(false);
      setCleared(true);
      setPageFromEnd(0);
      setError(false);
      setConfirmDelete(false);
      void load();
    } catch {
      if (active.current && generation.current === requestedGeneration) {
        setError(true);
        setConfirmDelete(false);
      }
    } finally {
      if (
        active.current &&
        (generation.current === requestedGeneration ||
          generation.current === requestedGeneration + 1)
      )
        setDeleting(false);
    }
  }
  useEffect(() => {
    generation.current += 1;
    active.current = true;
    busy.current = false;
    cursor.current = 0;
    setChunks([]);
    setGap(false);
    setCleared(false);
    setExit(null);
    setRunState(null);
    latestRunState.current = null;
    setConfirmDelete(false);
    setDeleting(false);
    setQuery("");
    setStreamFilter("all");
    setPageFromEnd(0);
    void load();
    return () => {
      active.current = false;
      generation.current += 1;
    };
  }, [id, sessionToken]);
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (
        latestRunState.current === null ||
        latestRunState.current === "queued" ||
        latestRunState.current === "running"
      ) {
        void load();
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [id, sessionToken]);
  useServiceChanges(sessionToken, () => void load());
  const zh = language === "zh-CN";
  const databaseResult = gap
    ? null
    : parseDatabaseResult(chunks.map((c) => c.text).join(""));
  const selectedChunks = chunks.filter(
    (chunk) => streamFilter === "all" || chunk.stream === streamFilter,
  );
  const selectedText = selectedChunks.map((chunk) => chunk.text).join("");
  const pageSize = 48_000;
  const pageCount = Math.max(1, Math.ceil(selectedText.length / pageSize));
  const safePageFromEnd = Math.min(pageFromEnd, pageCount - 1);
  const pageEnd = selectedText.length - safePageFromEnd * pageSize;
  const pageStart = Math.max(0, pageEnd - pageSize);
  const previewText = selectedText.slice(pageStart, pageEnd);
  const needle = query.trim();
  const parts = needle
    ? previewText.split(
        new RegExp(`(${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi"),
      )
    : [previewText];
  return (
    <section
      className="mt-4 border-t border-slate-200 pt-4"
      aria-label={zh ? "脱敏运行输出" : "Sanitized run output"}
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3 text-xs font-semibold text-slate-600">
        <span>
          {zh ? "运行输出" : "Run output"}{" "}
          {exit !== null ? `· ${zh ? "退出码" : "Exit code"}: ${exit}` : ""}
        </span>
        <details>
          <summary className="cursor-pointer text-cyan-800">
            {zh ? "下载与管理" : "Download & manage"}
          </summary>
          <div className="mt-2 flex flex-wrap items-center gap-3 rounded-lg border border-slate-200 bg-white p-3">
            {chunks.length > 0 && (
              <>
                <button
                  type="button"
                  className="underline"
                  onClick={() =>
                    saveDownload(
                      new Blob([chunks.map((chunk) => chunk.text).join("")], {
                        type: "text/plain;charset=utf-8",
                      }),
                      `secretbridge-run-${id}.txt`,
                    )
                  }
                >
                  {zh ? "下载脱敏输出" : "Download sanitized output"}
                </button>
                <button
                  type="button"
                  className="underline"
                  onClick={() =>
                    saveDownload(
                      new Blob(
                        [
                          JSON.stringify(
                            {
                              format: "secretbridge-run-output",
                              schema_version: 1,
                              run_id: id,
                              truncated: gap,
                              items: chunks,
                            },
                            null,
                            2,
                          ),
                        ],
                        { type: "application/json" },
                      ),
                      `secretbridge-run-${id}.json`,
                    )
                  }
                >
                  {zh ? "下载结构化记录" : "Download structured record"}
                </button>
              </>
            )}
            {chunks.length > 0 &&
              runState !== "queued" &&
              runState !== "running" && (
                <button
                  type="button"
                  className="underline text-rose-700"
                  onClick={() => setConfirmDelete(true)}
                >
                  {zh ? "删除保留输出" : "Delete retained output"}
                </button>
              )}
          </div>
        </details>
      </div>
      {confirmDelete && (
        <div
          role="alert"
          className="mb-3 rounded-lg border border-rose-200 bg-rose-50 p-3 text-xs text-rose-900"
        >
          <p>
            {zh
              ? "确认永久删除此运行保留的脱敏输出？运行状态和安全事件仍保留。"
              : "Permanently delete this run’s retained sanitized output? Run status and safe events remain."}
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              className="workbench-button"
              disabled={deleting}
              onClick={() => void clearRetainedOutput()}
            >
              {zh ? "确认删除" : "Confirm deletion"}
            </button>
            <button
              type="button"
              className="workbench-button"
              onClick={() => setConfirmDelete(false)}
            >
              {zh ? "取消" : "Cancel"}
            </button>
          </div>
        </div>
      )}
      {gap && (
        <p role="status" className="text-xs text-amber-700">
          {zh
            ? "较早输出已超过保留窗口；当前从可用位置继续。"
            : "Earlier output exceeded the replay window; continuing from available output."}
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs text-rose-700">
          {zh
            ? "输出读取失败，将自动重试。"
            : "Output read failed; reconnect will retry."}
        </p>
      )}
      {runState === "succeeded" && !databaseResult && (
        <p className="text-xs text-amber-800">
          {zh
            ? "进程已正常退出；业务结果尚未验证，请核对实际输出。"
            : "The process exited normally; verify the business result in the output."}
        </p>
      )}
      {databaseResult ? (
        <DatabaseResultView result={databaseResult} zh={zh} />
      ) : (
        <div className="space-y-2">
          {chunks.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <input
                aria-label={zh ? "在输出中查找" : "Find in output"}
                placeholder={zh ? "查找输出" : "Find in output"}
                value={query}
                onChange={(event) => setQuery(event.target.value.slice(0, 100))}
                className="rounded-lg border border-slate-300 px-3 py-2"
              />
              <select
                aria-label={zh ? "输出来源" : "Output stream"}
                value={streamFilter}
                onChange={(event) => {
                  setStreamFilter(event.target.value as typeof streamFilter);
                  setPageFromEnd(0);
                }}
                className="rounded-lg border border-slate-300 px-3 py-2"
              >
                <option value="all">{zh ? "全部输出" : "All output"}</option>
                <option value="stdout">stdout</option>
                <option value="stderr">stderr</option>
                <option value="terminal">{zh ? "终端" : "Terminal"}</option>
              </select>
              <label className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={wrap}
                  onChange={(event) => setWrap(event.target.checked)}
                />
                {zh ? "自动换行" : "Wrap lines"}
              </label>
              <button
                type="button"
                className="workbench-button"
                onClick={() => {
                  void navigator.clipboard.writeText(previewText).then(
                    () => setCopyState("copied"),
                    () => setCopyState("failed"),
                  );
                }}
              >
                {zh ? "复制当前页" : "Copy this page"}
              </button>
              {copyState !== "idle" && (
                <span role="status" className="text-slate-600">
                  {copyState === "copied"
                    ? zh
                      ? "已复制"
                      : "Copied"
                    : zh
                      ? "复制失败，请使用下载"
                      : "Copy failed; use download"}
                </span>
              )}
              <span className="text-slate-500">
                {selectedChunks.length} {zh ? "段" : "chunks"} ·{" "}
                {selectedText.length.toLocaleString(language)}{" "}
                {zh ? "字符" : "characters"}
              </span>
            </div>
          )}
          {pageCount > 1 && (
            <div className="flex items-center gap-3 text-xs text-slate-600">
              <button
                type="button"
                className="workbench-button"
                disabled={safePageFromEnd >= pageCount - 1}
                onClick={() => setPageFromEnd((value) => value + 1)}
              >
                {zh ? "较早输出" : "Older output"}
              </button>
              <span>
                {zh ? "第" : "Page"} {pageCount - safePageFromEnd} / {pageCount}{" "}
                {zh ? "页" : ""}
              </span>
              <button
                type="button"
                className="workbench-button"
                disabled={safePageFromEnd === 0}
                onClick={() =>
                  setPageFromEnd((value) => Math.max(0, value - 1))
                }
              >
                {zh ? "较新输出" : "Newer output"}
              </button>
            </div>
          )}
          <pre
            className={`max-h-96 overflow-auto rounded-lg bg-slate-950 p-4 text-xs leading-6 text-slate-100 ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"}`}
          >
            {chunks.length
              ? parts.map((part, index) =>
                  needle &&
                  part.toLocaleLowerCase() === needle.toLocaleLowerCase() ? (
                    <mark key={index} className="bg-amber-300 text-slate-950">
                      {part}
                    </mark>
                  ) : (
                    <span key={index}>{part}</span>
                  ),
                )
              : cleared
                ? zh
                  ? "保留输出已删除。"
                  : "Retained output was deleted."
                : runState === "queued" ||
                    runState === "running" ||
                    runState === null
                  ? zh
                    ? "等待任务输出…"
                    : "Waiting for task output…"
                  : zh
                    ? "命令未产生输出。"
                    : "The command produced no output."}
          </pre>
        </div>
      )}
    </section>
  );
}
