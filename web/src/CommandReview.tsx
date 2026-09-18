// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ActionTemplate, ParameterValue } from "./api";
import { sshCommandPreview } from "./SshEditor";

export function CommandReview({
  template,
  expectedVersion,
  language,
  parameters = {},
}: {
  parameters?: Record<string, ParameterValue>;
  template?: ActionTemplate;
  expectedVersion: number | null;
  language: "zh-CN" | "en";
}) {
  if (!template?.command) return null;
  const zh = language === "zh-CN";
  if (template.version !== expectedVersion)
    return (
      <p className="mt-3 text-sm text-amber-800">
        {zh
          ? "模板已修改，这条审批不能用于当前配置；请重新申请。"
          : "The template changed; request a new approval for the current configuration."}
      </p>
    );
  const config = template.command;
  if (config.git)
    return (
      <details className="mt-3 border-y border-slate-200 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
          {zh ? "查看 Git 仓库与操作" : "Review Git repository and operation"}
        </summary>
        <pre className="mt-3 overflow-auto text-xs">
          {JSON.stringify(
            {
              program: config.program,
              directory: config.working_directory,
              operation: config.git.operation,
              remote_url: config.git.remote_url,
              branch: config.git.branch,
              username: config.git.username,
              credential_slots: config.slots.map((s) => s.name),
            },
            null,
            2,
          )}
        </pre>
        <p className="mt-2 text-xs text-slate-600">
          {zh
            ? "拉取不合并工作区；推送不强制覆盖。取消不能撤回远程更新。"
            : "Fetch does not merge the working tree; push never forces. Cancellation cannot roll back remote updates."}
        </p>
      </details>
    );
  if (config.ssh)
    return (
      <details className="mt-3 border-y border-slate-200 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
          {config.ssh.transfer
            ? zh
              ? "查看 SFTP 主机、认证与传输配置"
              : "Review SFTP host, authentication and transfer"
            : zh
              ? "查看 SSH 主机、认证与命令"
              : "Review SSH host, authentication and command"}
        </summary>
        <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[7rem_1fr]">
          <dt>{zh ? "连接" : "Connection"}</dt>
          <dd className="break-all font-mono">
            {config.ssh.username}@{config.ssh.host}:{config.ssh.port}
          </dd>
          <dt>{zh ? "主机指纹" : "Host fingerprint"}</dt>
          <dd className="break-all font-mono">{config.ssh.host_key_sha256}</dd>
          <dt>{zh ? "认证方式" : "Authentication"}</dt>
          <dd>{config.ssh.authentication.kind}</dd>
          <dt>
            {config.ssh.transfer
              ? zh
                ? "传输配置"
                : "Transfer"
              : zh
                ? "远程命令"
                : "Remote command"}
          </dt>
          <dd className="whitespace-pre-wrap break-all font-mono">
            {config.ssh.transfer
              ? `${zh ? "方向" : "Direction"}: ${config.ssh.transfer.direction}\n${zh ? "本机路径" : "Local path"}: ${config.ssh.transfer.local_path}\n${zh ? "远程路径" : "Remote path"}: ${config.ssh.transfer.remote_path}\n${zh ? "覆盖目标" : "Replacement"}: ${config.ssh.transfer.overwrite ? (zh ? "允许" : "Allowed") : zh ? "不允许" : "Denied"}\n${zh ? "大小上限（字节）" : "Size limit (bytes)"}: ${config.ssh.transfer.max_bytes}`
              : sshCommandPreview(config.ssh, parameters)}
          </dd>
          <dt>{zh ? "凭据插槽" : "Credential slots"}</dt>
          <dd>{config.slots.map((s) => s.name).join(", ")}</dd>
        </dl>
        <p className="mt-2 text-xs text-slate-600">
          {config.ssh.transfer
            ? zh
              ? "固定单文件传输；覆盖开关和大小限制随模板冻结。清理失败会在结果中标记。"
              : "Fixed single-file transfer; overwrite and size limits are frozen with the template. Cleanup failures are marked in results."
            : zh
              ? "普通参数逐项按 POSIX Shell 引用；不分配交互式终端。取消只断开连接，不保证远程任务撤回。"
              : "Arguments are individually POSIX-shell quoted. No interactive terminal is allocated. Cancellation disconnects but cannot guarantee remote rollback."}
        </p>
      </details>
    );
  if (config.http)
    return (
      <details className="mt-3 border-y border-slate-200 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
          {zh ? "查看 HTTP 请求与插槽" : "Review HTTP request and slots"}
        </summary>
        <p className="mt-3 break-all font-mono text-xs">
          {config.http.method} {config.http.url}
        </p>
        <pre className="mt-3 overflow-auto text-xs">
          {JSON.stringify(
            {
              headers: config.http.headers,
              query: config.http.query,
              body: config.http.body,
              response_fields: config.http.response_fields,
              accepted_statuses: config.http.accepted_statuses,
              parameters,
              slots: config.slots.map((s) => ({
                name: s.name,
                injection: s.injection,
              })),
            },
            null,
            2,
          )}
        </pre>
        <p className="mt-2 text-xs text-slate-600">
          {zh
            ? "不跟随重定向；未选择返回字段时只返回状态码。"
            : "Redirects are disabled; no selected fields means status only."}
        </p>
      </details>
    );
  return (
    <details className="mt-3 border-y border-slate-200 py-3">
      <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
        {zh ? "查看将执行的程序与插槽" : "Review program and credential slots"}
      </summary>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[6rem_1fr]">
        <dt className="text-slate-500">{zh ? "程序" : "Program"}</dt>
        <dd className="m-0 break-all font-mono">{config.program}</dd>
        <dt className="text-slate-500">{zh ? "工作目录" : "Directory"}</dt>
        <dd className="m-0 break-all font-mono">{config.working_directory}</dd>
        <dt className="text-slate-500">{zh ? "参数" : "Arguments"}</dt>
        <dd className="m-0 whitespace-pre-wrap break-all font-mono">
          {JSON.stringify(
            config.arguments.map((arg) => {
              const p = config.parameters?.find(
                (p) => arg === `{{param:${p.name}}}`,
              );
              return p && Object.hasOwn(parameters, p.name)
                ? String(parameters[p.name])
                : arg;
            }),
            null,
            2,
          )}
        </dd>
        <dt className="text-slate-500">{zh ? "凭据插槽" : "Slots"}</dt>
        <dd className="m-0 space-y-1">
          {config.slots.map((slot) => (
            <p key={slot.name} className="m-0">
              {slot.name} → {slot.injection}
              {slot.environment_variable
                ? ` (${slot.environment_variable})`
                : ""}
            </p>
          ))}
        </dd>
      </dl>
    </details>
  );
}
