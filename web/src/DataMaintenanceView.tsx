// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { SectionTabs } from "./Workbench";
import {
  downloadBackup,
  exportConfiguration,
  getDiagnostics,
  importConfiguration,
  previewBackup,
  previewConfiguration,
  type BackupReport,
  type ConfigurationBundle,
  type Diagnostics,
  type ImportReport,
} from "./api";

export function saveDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function DataMaintenanceView({
  sessionToken,
  language,
}: {
  sessionToken: string;
  language: "zh-CN" | "en";
}) {
  const zh = language === "zh-CN";
  const [section, setSection] = useState<
    "migration" | "backup" | "diagnostics"
  >("migration");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [notice, setNotice] = useState("");
  const [bundle, setBundle] = useState<ConfigurationBundle | null>(null);
  const [preview, setPreview] = useState<ImportReport | null>(null);
  const [imported, setImported] = useState(false);
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [backupReport, setBackupReport] = useState<BackupReport | null>(null);
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError(false);
    setNotice("");
    try {
      await action();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  const counts = (report: ImportReport | BackupReport) =>
    `${zh ? "凭据引用" : "Credential references"} ${report.credentials} · ${zh ? "连接" : "Connections"} ${report.connections} · ${zh ? "模板" : "Templates"} ${report.templates}`;
  return (
    <section
      className="mt-8 border-t border-slate-200 pt-6"
      aria-label={zh ? "数据维护" : "Data maintenance"}
    >
      <h2 className="text-xl font-semibold">
        {zh ? "数据维护" : "Data maintenance"}
      </h2>
      <SectionTabs
        selected={section}
        onSelect={(id) => {
          if (!busy) {
            setSection(id);
            setError(false);
            setNotice("");
          }
        }}
        items={[
          { id: "migration", label: zh ? "配置迁移" : "Configuration" },
          { id: "backup", label: zh ? "备份与恢复" : "Backup & restore" },
          { id: "diagnostics", label: zh ? "诊断" : "Diagnostics" },
        ]}
      />
      <div className="max-w-3xl space-y-5 py-5">
        {section === "migration" && (
          <>
            <p className="text-sm text-slate-600">
              {zh
                ? "导出连接、任务模板和凭据引用，不包含秘密值、授权或执行历史。普通命令参数和说明会随配置导出，请勿在其中直接填写密码。导入会新增记录，不覆盖现有配置。"
                : "Exports connections, templates and credential references, without secret values, authorizations or history. Ordinary arguments and descriptions are included: do not place passwords in them. Import adds records and never replaces existing configuration."}
            </p>
            <button
              className="workbench-button"
              disabled={busy}
              onClick={() =>
                void perform(async () => {
                  saveDownload(
                    new Blob(
                      [
                        JSON.stringify(
                          await exportConfiguration(sessionToken),
                          null,
                          2,
                        ),
                      ],
                      { type: "application/json" },
                    ),
                    "secretbridge-configuration.json",
                  );
                })
              }
            >
              {zh ? "导出配置" : "Export configuration"}
            </button>
            <div className="border-t border-slate-200 pt-5 space-y-3">
              <label className="block text-sm font-medium">
                {zh
                  ? "选择配置文件（最多 8 MiB）"
                  : "Select configuration (max 8 MiB)"}
                <input
                  className="block mt-2 max-w-full text-sm"
                  type="file"
                  accept=".json,application/json"
                  disabled={busy}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    setBundle(null);
                    setPreview(null);
                    setImported(false);
                    if (file)
                      void perform(async () => {
                        if (file.size > 8 * 1024 * 1024)
                          throw new Error("size");
                        setBundle(
                          JSON.parse(await file.text()) as ConfigurationBundle,
                        );
                      });
                  }}
                />
              </label>
              <button
                className="workbench-button"
                disabled={busy || !bundle}
                onClick={() =>
                  void perform(async () => {
                    setPreview(null);
                    setImported(false);
                    setPreview(
                      await previewConfiguration(sessionToken, bundle!),
                    );
                  })
                }
              >
                {zh ? "检查导入" : "Check import"}
              </button>
              {preview && (
                <div className="space-y-3">
                  <p>{counts(preview)}</p>
                  <p className="text-sm text-slate-600">
                    {zh
                      ? "导入后需要重新录入秘密值并重新授权。重复确认同一文件不会重复新增记录。"
                      : "Enter secret values and grant new authorizations after import. Reconfirming the same file does not add duplicate records."}
                  </p>
                  <button
                    className="workbench-button"
                    disabled={busy || imported || !bundle}
                    onClick={() =>
                      void perform(async () => {
                        const result = await importConfiguration(
                          sessionToken,
                          bundle!,
                          preview.digest,
                        );
                        setImported(true);
                        setNotice(
                          result.replayed
                            ? zh
                              ? "此文件已导入，未重复新增。"
                              : "Already imported; no duplicate records added."
                            : zh
                              ? "导入完成，请前往凭据页重新配置秘密值。"
                              : "Import complete. Configure secret values on the Credentials page.",
                        );
                      })
                    }
                  >
                    {zh ? "确认导入" : "Confirm import"}
                  </button>
                </div>
              )}
            </div>
          </>
        )}
        {section === "backup" && (
          <>
            <p className="text-sm text-slate-600">
              {zh
                ? "一致性备份包含配置与执行历史，不包含系统凭据库的秘密值，但可能包含业务参数和过滤后的结果。请作为私有文件妥善保存，不要将备份作为诊断附件公开。"
                : "A consistent backup includes configuration and history, not OS credential-store secrets. Business parameters and filtered results may remain: keep it private, not as a public diagnostic attachment."}
            </p>
            <button
              className="workbench-button"
              disabled={busy}
              onClick={() =>
                void perform(async () =>
                  saveDownload(
                    await downloadBackup(sessionToken),
                    "secretbridge-backup.sqlite3",
                  ),
                )
              }
            >
              {zh ? "下载 SQLite 备份" : "Download SQLite backup"}
            </button>
            <label className="block text-sm font-medium">
              {zh
                ? "选择备份进行只读预检（最多 256 MiB）"
                : "Select backup for read-only preflight (max 256 MiB)"}
              <input
                className="block mt-2 max-w-full text-sm"
                type="file"
                accept=".sqlite3,.db,application/vnd.sqlite3"
                disabled={busy}
                onChange={(event) => {
                  setBackupFile(event.target.files?.[0] ?? null);
                  setBackupReport(null);
                }}
              />
            </label>
            <button
              className="workbench-button"
              disabled={busy || !backupFile}
              onClick={() =>
                void perform(async () => {
                  setBackupReport(null);
                  if (backupFile!.size > 256 * 1024 * 1024)
                    throw new Error("size");
                  setBackupReport(
                    await previewBackup(sessionToken, backupFile!),
                  );
                })
              }
            >
              {zh ? "检查备份" : "Check backup"}
            </button>
            {backupReport && (
              <div className="space-y-3">
                <p>
                  {counts(backupReport)} · {zh ? "执行记录" : "Runs"}{" "}
                  {backupReport.runs}
                </p>
                <p>
                  {zh
                    ? "完整性检查通过，数据库版本"
                    : "Integrity check passed. Schema"}{" "}
                  {backupReport.schema_version} →{" "}
                  {backupReport.restore_schema_version}
                </p>
                <p className="text-sm">
                  {zh
                    ? "关闭服务，将 SECRETBRIDGE_DATA_DIR 指向一个尚不存在的绝对目录，再运行以下维护命令。原目录保留，可通过切回原目录回退。恢复后所有秘密值需重新录入，待处理授权不会继续生效，未完成任务会标记中断。"
                    : "Stop the broker, set SECRETBRIDGE_DATA_DIR to a new, nonexistent absolute directory, then run the maintenance command below. The original directory remains available for rollback. Re-enter all secrets and create new authorizations; unfinished tasks are marked interrupted."}
                </p>
              </div>
            )}
            <pre className="overflow-x-auto rounded-lg bg-slate-100 p-4 text-sm">
              secretbridge-server --inspect-backup /absolute/path/backup.sqlite3
              {"\n"}secretbridge-server --restore-backup
              /absolute/path/backup.sqlite3
            </pre>
            <p className="text-sm text-slate-600">
              {zh
                ? "维护命令不启动 Web 服务，也不覆盖已有目录。恢复后使用新目录启动服务。"
                : "Maintenance commands do not start a Web server or overwrite existing directories. Start the broker with the new directory afterward."}
            </p>
          </>
        )}
        {section === "diagnostics" && (
          <>
            <p className="text-sm text-slate-600">
              {zh
                ? "精简诊断包含版本、状态计数、固定 MCP 与运行错误类别及首次/最近时间，不包含主机地址、路径、凭据名称、参数或输出。导出前请预览；发生时间和操作规律仍可能属于个人信息。"
                : "Diagnostics include versions, state counts, fixed MCP and run error classes with first/last times, without host addresses, paths, credential names, arguments or output. Preview before export; activity times can still be personal information."}
            </p>
            <button
              className="workbench-button"
              disabled={busy}
              onClick={() =>
                void perform(async () =>
                  setDiagnostics(await getDiagnostics(sessionToken)),
                )
              }
            >
              {zh ? "预览诊断信息" : "Preview diagnostics"}
            </button>
            {diagnostics && (
              <div className="rounded-lg border border-slate-200 p-4 text-sm space-y-2">
                <p>
                  {zh ? "生成时间" : "Generated"}:{" "}
                  {new Intl.DateTimeFormat(language, {
                    dateStyle: "medium",
                    timeStyle: "medium",
                  }).format(diagnostics.generated_at_unix_ms)}
                </p>
                <p>
                  {zh ? "软件版本" : "Version"}: {diagnostics.version} ·{" "}
                  {zh ? "数据库版本" : "Schema"}: {diagnostics.schema_version} ·{" "}
                  {zh ? "诊断格式" : "Diagnostic format"}:{" "}
                  {diagnostics.diagnostic_schema_version}
                </p>
                <p>
                  {zh ? "浏览器认证" : "Browser authentication"}:{" "}
                  {diagnostics.authentication_mode} ·{" "}
                  {zh ? "桥接协议" : "Bridge protocol"}:{" "}
                  {diagnostics.bridge_schema_version}
                </p>
                <p>
                  {zh ? "凭据引用" : "Credentials"}: {diagnostics.credentials} ·{" "}
                  {zh ? "连接" : "Connections"}: {diagnostics.connections} ·{" "}
                  {zh ? "模板" : "Templates"}: {diagnostics.templates}
                </p>
                <p>
                  {zh ? "运行状态" : "Run states"}:{" "}
                  {Object.entries(diagnostics.run_states)
                    .map(([name, count]) => `${name} ${count}`)
                    .join(" · ") || "—"}
                </p>
                <p>
                  {zh ? "失败阶段" : "Failure stages"}:{" "}
                  {Object.entries(diagnostics.failure_stages)
                    .map(([name, count]) => `${name} ${count}`)
                    .join(" · ") || "—"}
                </p>
                <p>
                  {zh ? "错误分类" : "Error classes"}:{" "}
                  {Object.entries(diagnostics.error_codes)
                    .map(([name, count]) => `${name} ${count}`)
                    .join(" · ") || "—"}
                </p>
                <p>
                  {zh ? "终端状态" : "Terminal states"}:{" "}
                  {Object.entries(diagnostics.terminal_states)
                    .map(([name, count]) => `${name} ${count}`)
                    .join(" · ") || "—"}{" "}
                  · {zh ? "失效终端引用" : "Stale terminal references"}{" "}
                  {diagnostics.stale_terminal_references}
                </p>
                <ul aria-label={zh ? "MCP 失败摘要" : "MCP failure summary"}>
                  {diagnostics.mcp_failures.map((failure) => (
                    <li key={failure.code}>
                      {failure.stage} / {failure.code}: {failure.occurrences} ·{" "}
                      {new Intl.DateTimeFormat(language).format(
                        failure.first_at_unix_ms,
                      )}{" "}
                      →{" "}
                      {new Intl.DateTimeFormat(language).format(
                        failure.last_at_unix_ms,
                      )}
                    </li>
                  ))}
                </ul>
                <ul aria-label={zh ? "运行失败摘要" : "Run failure summary"}>
                  {diagnostics.run_failures.map((failure) => (
                    <li key={failure.code}>
                      {failure.stage} / {failure.code}: {failure.occurrences} ·{" "}
                      {new Intl.DateTimeFormat(language).format(
                        failure.first_at_unix_ms,
                      )}{" "}
                      →{" "}
                      {new Intl.DateTimeFormat(language).format(
                        failure.last_at_unix_ms,
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <button
              className="workbench-button"
              disabled={busy}
              onClick={() =>
                void perform(async () =>
                  saveDownload(
                    new Blob(
                      [
                        JSON.stringify(
                          await getDiagnostics(sessionToken),
                          null,
                          2,
                        ),
                      ],
                      { type: "application/json" },
                    ),
                    "secretbridge-diagnostics.json",
                  ),
                )
              }
            >
              {zh ? "下载诊断信息" : "Download diagnostics"}
            </button>
          </>
        )}
        {busy && (
          <p role="status">{zh ? "正在处理，请稍候…" : "Processing…"}</p>
        )}
        {error && (
          <p role="alert" className="text-sm text-rose-700">
            {zh
              ? "操作失败。请检查文件格式、容量和页面配对状态。若导入请求中断，可保留当前文件和预检结果重试确认。"
              : "Operation failed. Check format, size and pairing. If import was interrupted, retry confirmation with the same file and preflight."}
          </p>
        )}
        {notice && (
          <p role="status" className="text-sm text-emerald-700">
            {notice}
          </p>
        )}
      </div>
    </section>
  );
}
