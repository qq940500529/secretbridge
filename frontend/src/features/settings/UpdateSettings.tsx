// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from "react";
import { checkUpdates, type UpdateStatus } from "../../api/index";

export function UpdateSettings({
  status,
  sessionToken,
  language,
}: {
  status?: UpdateStatus | null;
  sessionToken?: string | null;
  language: "zh-CN" | "en";
}) {
  const [latest, setLatest] = useState(status);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    setLatest(status);
  }, [status]);
  const zh = language === "zh-CN";
  const states = zh
    ? {
        not_checked: "尚未检查",
        checking: "正在检查…",
        checked: "检查完成",
        unavailable: "检查不可用，可能离线或 GitHub 限流；保留上次结果",
      }
    : {
        not_checked: "Not checked",
        checking: "Checking…",
        checked: "Check complete",
        unavailable:
          "Check unavailable: offline or GitHub rate-limited; last result retained",
      };
  async function check() {
    if (!sessionToken || busy) return;
    setBusy(true);
    setFailed(false);
    try {
      setLatest(await checkUpdates(sessionToken));
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      className="enterprise-surface mt-6"
      aria-labelledby="updates-heading"
    >
      <div className="border-b border-slate-200 px-5 py-4">
        <h2
          id="updates-heading"
          className="m-0 text-base font-semibold text-slate-900"
        >
          {zh ? "软件更新" : "Software updates"}
        </h2>
      </div>
      <div className="space-y-4 px-5 py-5">
        <p className="m-0 text-sm leading-6 text-slate-600">
          {zh
            ? "启动时及每 6 小时从官方 GitHub Releases 检查公开版本（含预发布），失败后每小时重试。仅发送软件版本和常规网络请求信息，不发送配置或凭据，不下载或安装更新。"
            : "Checks public GitHub releases, including prereleases, at startup and every six hours; retries hourly after failure. Sends only the software version and ordinary network request metadata, never configuration or credentials. No update download or installation."}
        </p>
        <p role="status" className="m-0 text-sm font-medium">
          {states[latest?.check_state ?? "not_checked"]}
          {latest?.update_available
            ? zh
              ? ` · 有新版本 ${latest.latest_version}`
              : ` · Version ${latest.latest_version} available`
            : latest?.check_state === "checked"
              ? zh
                ? " · 未发现新版本"
                : " · No newer release found"
              : ""}
        </p>
        {latest?.checked_at_unix_ms && (
          <p className="m-0 text-sm text-slate-500">
            {zh ? "最近成功检查：" : "Last successful check: "}
            {new Date(latest.checked_at_unix_ms).toLocaleString(language)}
          </p>
        )}
        <p className="m-0 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm leading-6 text-amber-950">
          {zh
            ? "测试版不能保证与旧版兼容。默认保持当前版本，不自动更新。若你决定更新，请先阅读发行说明、保留独立备份，并使用独立空白数据目录；不要直接覆盖已有安装。"
            : "Beta compatibility with earlier versions is not guaranteed. Keep the current version by default; no automatic updates. If you choose to upgrade, review release notes, preserve independent backups and use a separate empty data directory; do not overwrite the existing installation."}
        </p>
        {failed && (
          <p role="alert" className="text-sm text-rose-700">
            {zh
              ? "检查请求失败；不能据此判断已是最新版本。"
              : "Check request failed; this does not mean you are up to date."}
          </p>
        )}
        <div className="flex flex-wrap gap-3">
          <button
            type="button"
            className="workbench-button"
            disabled={!sessionToken || busy}
            onClick={() => void check()}
          >
            {busy ? states.checking : zh ? "检查更新" : "Check for updates"}
          </button>
          <a
            className="workbench-button no-underline"
            href="https://github.com/qq940500529/secretbridge/releases"
            target="_blank"
            rel="noreferrer"
          >
            {zh
              ? "查看发行说明（不安装）"
              : "Review releases (no installation)"}
          </a>
        </div>
      </div>
    </section>
  );
}
