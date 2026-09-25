// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { SectionTabs } from "../../shared/ui/SectionTabs";
import {
  downloadBackup,
  exportConfiguration,
  getDiagnostics,
  unlockDiagnostics,
  importConfiguration,
  previewBackup,
  previewConfiguration,
  type BackupReport,
  type ConfigurationBundle,
  type Diagnostics,
  type DiagnosticExport,
  type ImportReport,
} from "../../api/index";

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

const recoveryLabelsZh: Record<string, string> = {
  split_the_operation: "拆分操作",
  use_bounded_stdin_or_structured_connector: "使用有界标准输入或结构化连接器",
  remove_invalid_stdin_content_or_conflicting_slot:
    "修正输入内容或冲突的凭据插槽",
  review_explicit_secret_slot_syntax: "检查显式凭据插槽语法",
  wait_for_active_run: "等待当前运行完成",
  inspect_terminal_state: "检查终端状态",
  attach_terminal_and_request_input: "连接终端并请求输入",
  create_new_terminal: "新建终端",
  request_new_approval_if_needed: "按需重新请求授权",
  review_current_approval_state: "检查当前授权状态",
  refresh_catalog: "刷新目录",
  ask_human_to_reenter_credential: "请用户重新录入凭据",
  check_shell_and_program_availability: "检查 Shell 与程序是否可用",
  check_local_broker_health: "检查本地代理状态",
  review_private_data_directory: "检查私有数据目录",
  check_request_and_retry_if_safe: "检查请求后安全重试",
  check_os_credential_store: "检查系统凭据库",
  inspect_sanitized_output: "检查过滤后的输出",
  review_timeout_and_target: "检查超时设置与目标",
  inspect_run_state: "检查任务状态",
  check_private_temporary_directory: "检查私有临时目录",
  do_not_retry_until_clean: "清理完成前不要重试",
  ask_human_to_correct_connection_metadata: "请用户修正连接配置",
  check_target_network_and_trust: "检查目标网络与信任配置",
  verify_operation_parameters: "检查操作参数",
  contact_maintainer_with_safe_diagnostics: "携带安全诊断信息联系维护者",
};

function recoveryText(actions: string[], zh: boolean) {
  return actions
    .map((action) =>
      zh ? (recoveryLabelsZh[action] ?? action) : action.replaceAll("_", " "),
    )
    .join(" · ");
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
  const [diagnosticPin, setDiagnosticPin] = useState("");
  const [includeCommands, setIncludeCommands] = useState(false);
  const [includeEvents, setIncludeEvents] = useState(true);
  const [unlockedDiagnostics, setUnlockedDiagnostics] =
    useState<DiagnosticExport | null>(null);
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
              secretbridge --inspect-backup /absolute/path/backup.sqlite3
              {"\n"}secretbridge --restore-backup /absolute/path/backup.sqlite3
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
                ? "精简摘要只含固定错误码、状态计数和时间，不含名称、地址、路径、命令或输出。运行时持续加密保存详细诊断记录。输入初始化时设置的 PIN 后，可选择导出事件和完整命令配置。命令默认不导出。导出的 JSON 是明文，可能包含路径、地址或业务参数，请先预览并谨慎分享；注入的凭据值不写入诊断记录。"
                : "The compact summary contains fixed error codes, state counts and times, without names, addresses, paths, commands or output. Detailed diagnostic records are encrypted continuously. Enter your setup PIN to select events and complete command configurations. Commands are excluded by default. Exported JSON is plaintext and may contain paths, addresses, or business arguments. Preview it before sharing. Injected credential values are not recorded."}
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
                  {zh ? "加密诊断" : "Encrypted diagnostics"}:{" "}
                  {diagnostics.encrypted_diagnostics_ready
                    ? zh
                      ? "已启用"
                      : "ready"
                    : zh
                      ? "待初始化"
                      : "not initialized"}{" "}
                  · {zh ? "桥接协议" : "Bridge protocol"}:{" "}
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
                <p>
                  {zh ? "状态一致性问题" : "State consistency issues"}:{" "}
                  {diagnostics.state_consistency_issues}
                  {diagnostics.state_consistency_issues > 0 && (
                    <>
                      {" "}
                      ·{" "}
                      {Object.entries(diagnostics.state_consistency)
                        .filter(([, count]) => count > 0)
                        .map(([name, count]) => `${name} ${count}`)
                        .join(" · ")}
                    </>
                  )}
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
                      <br />
                      {zh ? "建议" : "Suggested recovery"}:{" "}
                      {recoveryText(failure.recovery_actions, zh)}
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
                      {failure.failures_with_later_same_template_success >
                        0 && (
                        <>
                          {" "}
                          ·{" "}
                          {zh
                            ? "后续出现同模板成功的失败记录"
                            : "Failures followed by a same-template success"}
                          : {failure.failures_with_later_same_template_success}
                        </>
                      )}
                      <br />
                      {zh ? "建议" : "Suggested recovery"}:{" "}
                      {recoveryText(failure.recovery_actions, zh)}
                    </li>
                  ))}
                </ul>
                <p className="text-xs text-slate-600">
                  {zh
                    ? "后续成功仅是时间线索，不能证明此前故障已经修复。"
                    : "A later success is a timeline clue, not proof that the earlier failure was fixed."}
                </p>
              </div>
            )}
            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <label className="block text-sm font-semibold">
                {zh ? "PIN/口令" : "PIN/passphrase"}
                <input
                  type="password"
                  autoComplete="off"
                  minLength={12}
                  maxLength={64}
                  value={diagnosticPin}
                  onChange={(event) => {
                    setDiagnosticPin(event.target.value);
                    setUnlockedDiagnostics(null);
                  }}
                  className="mt-2 w-full rounded-xl border border-slate-200 px-3.5 py-2.5"
                />
              </label>
              <label className="flex gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={includeEvents}
                  onChange={(event) => {
                    setIncludeEvents(event.target.checked);
                    setUnlockedDiagnostics(null);
                  }}
                />
                {zh ? "事件记录" : "Event records"}
              </label>
              <label className="flex gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={includeCommands}
                  onChange={(event) => {
                    setIncludeCommands(event.target.checked);
                    setUnlockedDiagnostics(null);
                  }}
                />
                {zh
                  ? "完整命令配置（可能含敏感参数）"
                  : "Complete command configurations (may contain sensitive arguments)"}
              </label>
              <button
                className="workbench-button"
                disabled={
                  busy ||
                  diagnosticPin.length < 12 ||
                  (!includeEvents && !includeCommands)
                }
                onClick={() =>
                  void perform(async () => {
                    const result = await unlockDiagnostics(
                      sessionToken,
                      diagnosticPin,
                      includeCommands,
                      includeEvents,
                    );
                    setDiagnosticPin("");
                    setUnlockedDiagnostics(result);
                  })
                }
              >
                {zh ? "解锁并预览所选内容" : "Unlock and preview selection"}
              </button>
              {unlockedDiagnostics && (
                <>
                  <p role="status" className="text-sm">
                    {zh ? "已解锁记录" : "Unlocked records"}:{" "}
                    {unlockedDiagnostics.records.length}
                  </p>
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 text-xs">
                    {JSON.stringify(unlockedDiagnostics, null, 2)}
                  </pre>
                  <button
                    className="workbench-button"
                    onClick={() =>
                      saveDownload(
                        new Blob(
                          [JSON.stringify(unlockedDiagnostics, null, 2)],
                          { type: "application/json" },
                        ),
                        "secretbridge-diagnostics-selected.json",
                      )
                    }
                  >
                    {zh ? "下载预览内容" : "Download previewed content"}
                  </button>
                </>
              )}
            </div>
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
