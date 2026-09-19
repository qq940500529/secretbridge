// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { Power } from "lucide-react";
import { stopBroker } from "./api";
import { EditorDialog } from "./Workbench";

export function BackgroundServiceView({
  sessionToken,
  language,
  onStopped,
}: {
  sessionToken: string;
  language: "zh-CN" | "en";
  onStopped: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const zh = language === "zh-CN";
  return (
    <section className="mt-6 border-t border-slate-200 pt-5">
      <h2 className="text-base font-semibold">
        {zh ? "后台服务" : "Background service"}
      </h2>
      <p className="text-sm text-slate-600">
        {zh
          ? "关闭浏览器不会停止服务。停止服务会断开 AI 连接，结束终端并取消执行中的任务，已保存的配置仍会保留。"
          : "Closing the browser does not stop the service. Stopping disconnects AI clients, closes terminals and cancels running tasks. Saved configuration is retained."}
      </p>
      <EditorDialog
        triggerIcon={<Power className="size-4" />}
        title={zh ? "停止后台服务" : "Stop background service"}
        open={open}
        onOpen={() => {
          setError(false);
          setOpen(true);
        }}
        onClose={() => setOpen(false)}
        busy={busy}
      >
        <div className="space-y-5 p-5">
          <p>
            {zh
              ? "确认停止？需要再次使用时，请运行 SecretBridge 启动程序。"
              : "Stop now? Run the SecretBridge launcher to start it again."}
          </p>
          {error && (
            <p role="alert">
              {zh
                ? "未能确认停止，请检查连接后重试。"
                : "Stop could not be confirmed. Check the connection and retry."}
            </p>
          )}
          <div className="flex flex-wrap justify-end gap-3">
            <button
              type="button"
              className="workbench-button"
              disabled={busy}
              onClick={() => setOpen(false)}
            >
              {zh ? "取消" : "Cancel"}
            </button>
            <button
              type="button"
              className="workbench-button"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError(false);
                try {
                  await stopBroker(sessionToken);
                  setOpen(false);
                  onStopped();
                } catch {
                  setError(true);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Power className="size-4" />
              {busy
                ? zh
                  ? "停止中…"
                  : "Stopping…"
                : zh
                  ? "确认停止"
                  : "Confirm stop"}
            </button>
          </div>
        </div>
      </EditorDialog>
    </section>
  );
}
