// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from "react";
import {
  listActionTemplates,
  listSyntheticRuns,
  type ActionTemplate,
  type CredentialReference,
  type SyntheticRun,
} from "../../../api/index";
import { useServiceChanges } from "../../../app/service-events";
import { RunOutputView } from "../../tasks/runs/RunOutputView";

export function ConnectionRelations({
  targetId,
  credentials,
  language,
  sessionToken,
  onTask,
}: {
  targetId: string;
  credentials: CredentialReference[];
  language: "zh-CN" | "en";
  sessionToken: string;
  onTask?: (targetId: string, templateId?: string) => void;
}) {
  const [templates, setTemplates] = useState<ActionTemplate[]>([]);
  const [runs, setRuns] = useState<SyntheticRun[]>([]);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedRun, setSelectedRun] = useState<string | null>(null);
  const generation = useRef(0);
  const zh = language === "zh-CN";
  async function refresh() {
    const request = ++generation.current;
    try {
      const [tasks, executions] = await Promise.all([
        listActionTemplates(sessionToken),
        listSyntheticRuns(sessionToken),
      ]);
      if (request !== generation.current) return;
      setTemplates(tasks.items.filter((item) => item.target_id === targetId));
      setRuns(
        executions.items
          .filter((item) => item.target_id === targetId)
          .sort((a, b) => b.created_at_unix_ms - a.created_at_unix_ms)
          .slice(0, 5),
      );
      setError(false);
    } catch {
      if (request === generation.current) setError(true);
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }
  useEffect(() => {
    void refresh();
    return () => {
      generation.current++;
    };
  }, [sessionToken, targetId]);
  useServiceChanges(sessionToken, () => void refresh());
  const credentialIds = new Set(
    templates.flatMap(
      (item) => item.command?.slots.map((slot) => slot.credential_id) ?? [],
    ),
  );
  const relatedCredentials = credentials.filter((item) =>
    credentialIds.has(item.id),
  );
  const labels = {
    queued: zh ? "排队中" : "Queued",
    running: zh ? "执行中" : "Running",
    succeeded: zh ? "完成" : "Completed",
    failed: zh ? "失败" : "Failed",
    cancelled: zh ? "已取消" : "Cancelled",
  };
  const run = runs.find((item) => item.id === selectedRun);
  return (
    <div className="mt-5 space-y-4 border-t border-slate-200 pt-4">
      {loading && (
        <p role="status" className="text-sm text-slate-500">
          {zh ? "正在加载关联任务…" : "Loading related tasks…"}
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-rose-700">
          {zh ? "关联信息读取失败。" : "Could not load related information."}
          <button
            type="button"
            className="ml-2 underline"
            onClick={() => void refresh()}
          >
            {zh ? "重试" : "Retry"}
          </button>
        </p>
      )}
      <div>
        <h3 className="text-sm font-semibold">
          {zh ? "任务使用的凭据" : "Credentials used by tasks"}
        </h3>
        <ul className="m-0 list-none p-0 text-sm text-slate-600">
          {relatedCredentials.map((item) => (
            <li key={item.id} className="py-1">
              {item.name} ·{" "}
              {item.secret_state === "available"
                ? zh
                  ? "已配置"
                  : "Configured"
                : zh
                  ? "待配置"
                  : "Not configured"}
            </li>
          ))}
        </ul>
        {!loading && !error && relatedCredentials.length === 0 && (
          <p className="text-sm text-slate-500">
            {zh ? "尚无任务关联凭据" : "No task-linked credentials"}
          </p>
        )}
      </div>
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold">{zh ? "可用任务" : "Tasks"}</h3>
          {onTask && (
            <button
              type="button"
              onClick={() => onTask(targetId)}
              className="workbench-button"
            >
              {zh ? "新建任务" : "New task"}
            </button>
          )}
        </div>
        <ul className="m-0 list-none divide-y divide-slate-100 p-0">
          {templates.map((item) => (
            <li
              key={item.id}
              className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
            >
              <span>
                {item.name} ·{" "}
                {item.enabled
                  ? zh
                    ? "可用"
                    : "Available"
                  : zh
                    ? "停用"
                    : "Disabled"}
              </span>
              {onTask && item.enabled && (
                <button
                  type="button"
                  onClick={() => onTask(targetId, item.id)}
                  className="font-semibold text-cyan-700"
                >
                  {zh ? "申请授权" : "Request authorization"}
                </button>
              )}
            </li>
          ))}
        </ul>
        {!loading && !error && templates.length === 0 && (
          <p className="text-sm text-slate-500">
            {zh
              ? "尚无任务，请先新建任务。"
              : "No tasks yet. Create a task to continue."}
          </p>
        )}
      </div>
      <div>
        <h3 className="text-sm font-semibold">
          {zh ? "最近执行" : "Recent runs"}
        </h3>
        <ul className="m-0 list-none divide-y divide-slate-100 p-0">
          {runs.map((item) => (
            <li key={item.id} className="py-2">
              <button
                type="button"
                aria-expanded={selectedRun === item.id}
                onClick={() =>
                  setSelectedRun(selectedRun === item.id ? null : item.id)
                }
                className="w-full text-left text-sm text-slate-600"
              >
                {templates.find((task) => task.id === item.action_template_id)
                  ?.name ?? (zh ? "已移除任务" : "Removed task")}{" "}
                · {labels[item.state]} ·{" "}
                {new Intl.DateTimeFormat(language, {
                  dateStyle: "short",
                  timeStyle: "short",
                }).format(item.created_at_unix_ms)}
              </button>
            </li>
          ))}
        </ul>
        {!loading && !error && runs.length === 0 && (
          <p className="text-sm text-slate-500">
            {zh ? "尚无执行记录" : "No runs yet"}
          </p>
        )}
        {run && run.operation === "command_execution" && (
          <RunOutputView
            key={run.id}
            id={run.id}
            sessionToken={sessionToken}
            language={language}
          />
        )}
      </div>
    </div>
  );
}
