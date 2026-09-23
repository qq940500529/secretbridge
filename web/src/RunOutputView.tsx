// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from "react";
import { readRunOutput, type RunOutput } from "./api";
import { useServiceChanges } from "./service-events";
import { DatabaseResultView, parseDatabaseResult } from "./DatabaseResultView";
import { saveDownload } from "./DataMaintenanceView";

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
  const cursor = useRef(0);
  const busy = useRef(false);
  const active = useRef(true);
  async function load() {
    if (busy.current || !active.current) return;
    busy.current = true;
    try {
      for (let page = 0; page < 128; page++) {
        const result = await readRunOutput(sessionToken, id, cursor.current);
        if (!active.current) return;
        cursor.current = result.next_cursor;
        if (result.truncated) setGap(true);
        setChunks((previous) => [...previous, ...result.items].slice(-2048));
        setExit(result.exit_code);
        setRunState(result.state);
        setError(false);
        if (!result.has_more) break;
      }
    } catch {
      if (active.current) setError(true);
    } finally {
      busy.current = false;
    }
  }
  useEffect(() => {
    active.current = true;
    void load();
    return () => {
      active.current = false;
    };
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
          )}
        </span>
      </div>
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
                  className={chunk.stream === "stderr" ? "text-amber-300" : ""}
                >
                  {chunk.text}
                </span>
              ))
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
