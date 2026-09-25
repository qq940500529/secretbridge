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
  return (
    <section
      className="mt-4 border-t border-slate-200 pt-4"
      aria-label={zh ? "脱敏运行输出" : "Sanitized run output"}
    >
      <div className="mb-2 flex justify-between text-xs font-semibold text-slate-600">
        <span>{zh ? "运行输出" : "Run output"}</span>
        <span className="flex items-center gap-3">
          {exit !== null ? `${zh ? "退出码" : "Exit code"}: ${exit}` : ""}
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
        </span>
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
      {databaseResult ? (
        <DatabaseResultView result={databaseResult} zh={zh} />
      ) : (
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-slate-950 p-4 text-xs leading-6 text-slate-100">
          {chunks.length
            ? chunks.map((chunk) => (
                <span
                  key={chunk.sequence}
                  title={
                    chunk.created_at_unix_ms > 0
                      ? new Date(chunk.created_at_unix_ms).toLocaleString(
                          language,
                        )
                      : undefined
                  }
                  className={chunk.stream === "stderr" ? "text-amber-300" : ""}
                >
                  {chunk.text}
                </span>
              ))
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
      )}
    </section>
  );
}
