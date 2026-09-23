// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import type { ActionTemplate, ParameterValue } from "./api";
import { sshCommandPreview } from "./SshEditor";

export function CommandReview({
  template,
  expectedVersion,
  language,
  parameters = {},
  expanded = false,
}: {
  parameters?: Record<string, ParameterValue>;
  template?: ActionTemplate;
  expectedVersion: number | null;
  language: "zh-CN" | "en";
  expanded?: boolean;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">(
    "idle",
  );
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
  const reviewedArguments = config.arguments.map((argument) => {
    const parameter = config.parameters?.find(
      (definition) => argument === `{{param:${definition.name}}}`,
    );
    return parameter && Object.hasOwn(parameters, parameter.name)
      ? String(parameters[parameter.name])
      : argument;
  });
  if (config.database)
    return (
      <details open={expanded} className="mt-3 border-y border-slate-200 py-3">
        <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
          {zh
            ? "查看数据库、查询与结果范围"
            : "Review database, query and result scope"}
        </summary>
        <pre className="mt-3 overflow-auto whitespace-pre-wrap break-all text-xs">
          {JSON.stringify(
            {
              ...config.database,
              parameters,
              credential_slots: config.slots.map((s) => s.name),
            },
            null,
            2,
          )}
        </pre>
        <p className="mt-2 text-xs text-slate-600">
          {zh
            ? "普通值使用参数绑定；仅执行登记的只读事务。只返回所选列，截断会在结果中标记。"
            : "Values are bound parameters; registered queries run in read-only transactions. Only selected columns are returned, with explicit truncation."}
        </p>
      </details>
    );
  if (config.git)
    return (
      <details open={expanded} className="mt-3 border-y border-slate-200 py-3">
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
      <details open={expanded} className="mt-3 border-y border-slate-200 py-3">
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
          {config.ssh.working_directory && !config.ssh.transfer && (
            <>
              <dt>{zh ? "远程工作目录" : "Remote working directory"}</dt>
              <dd className="break-all font-mono">
                {config.ssh.working_directory}
              </dd>
            </>
          )}
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
  if (config.telnet)
    return (
      <details
        open={expanded}
        className="mt-3 border-y border-amber-300 bg-amber-50 px-3 py-3"
      >
        <summary className="cursor-pointer text-sm font-semibold text-amber-950">
          {zh
            ? "查看 Telnet 明文连接、登录对话与固定脚本"
            : "Review plaintext Telnet connection, login dialogue and fixed script"}
        </summary>
        <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[7rem_1fr]">
          <dt>{zh ? "连接" : "Connection"}</dt>
          <dd className="break-all font-mono">
            {config.telnet.username}@{config.telnet.host}:{config.telnet.port}
          </dd>
          <dt>{zh ? "登录提示" : "Login prompts"}</dt>
          <dd className="whitespace-pre-wrap break-all font-mono">
            {JSON.stringify({
              username: config.telnet.login_prompt,
              password: config.telnet.password_prompt,
              ready: config.telnet.command_prompt,
              failure: config.telnet.authentication_failure_prompt,
            })}
          </dd>
          <dt>{zh ? "固定脚本" : "Fixed script"}</dt>
          <dd className="whitespace-pre-wrap break-all font-mono">
            {config.telnet.commands.join("\n")}
          </dd>
          <dt>{zh ? "输出上限" : "Output limit"}</dt>
          <dd>{config.telnet.max_output_bytes} bytes</dd>
          <dt>{zh ? "凭据插槽" : "Credential slot"}</dt>
          <dd>{config.telnet.password_slot}</dd>
        </dl>
        <p className="mb-0 mt-3 text-xs leading-5 text-amber-950">
          {zh
            ? "Telnet 不加密凭据、命令或输出，也不能验证服务器身份。只有连接目录中固定地址、账号、凭据均匹配且已显式允许不加密协议时才能执行。请尽快迁移到 SSH 或 TLS。"
            : "Telnet does not encrypt credentials, commands or output and cannot authenticate the server. Execution requires an exact matching connection with plaintext explicitly allowed. Migrate to SSH or TLS as soon as possible."}
        </p>
      </details>
    );
  if (config.http)
    return (
      <details open={expanded} className="mt-3 border-y border-slate-200 py-3">
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
    <details open={expanded} className="mt-3 border-y border-slate-200 py-3">
      <summary className="cursor-pointer text-sm font-semibold text-cyan-800">
        {zh ? "查看将执行的程序与插槽" : "Review program and credential slots"}
      </summary>
      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-[6rem_1fr]">
        {config.terminal_id && (
          <>
            <dt className="text-slate-500">
              {zh ? "安全终端" : "Secure terminal"}
            </dt>
            <dd className="m-0">
              <details>
                <summary className="cursor-pointer text-slate-600">
                  {zh ? "查看内部终端 ID" : "Show internal terminal ID"}
                </summary>
                <code className="break-all">{config.terminal_id}</code>
              </details>
            </dd>
          </>
        )}
        <dt className="text-slate-500">{zh ? "程序" : "Program"}</dt>
        <dd className="m-0 break-all font-mono">{config.program}</dd>
        <dt className="text-slate-500">{zh ? "工作目录" : "Directory"}</dt>
        <dd className="m-0 break-all font-mono">{config.working_directory}</dd>
        <dt className="text-slate-500">{zh ? "参数" : "Arguments"}</dt>
        <dd className="m-0 min-w-0">
          <ol className="m-0 list-decimal space-y-2 pl-5 font-mono">
            {reviewedArguments.map((argument, index) => (
              <li
                key={index}
                className="whitespace-pre-wrap break-all rounded bg-slate-50 px-2 py-1"
              >
                {argument || (zh ? "（空参数）" : "(empty argument)")}
              </li>
            ))}
          </ol>
          <button
            type="button"
            className="workbench-button mt-2"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(
                  reviewedArguments.join("\n"),
                );
                setCopyState("copied");
              } catch {
                setCopyState("failed");
              }
            }}
          >
            {zh ? "复制脱敏参数" : "Copy sanitized arguments"}
          </button>
          {copyState !== "idle" && (
            <span role="status" className="ml-2 text-slate-600">
              {copyState === "copied"
                ? zh
                  ? "已复制"
                  : "Copied"
                : zh
                  ? "复制失败"
                  : "Could not copy"}
            </span>
          )}
        </dd>
        {config.stdin_content != null && (
          <>
            <dt className="text-slate-500">
              {zh ? "标准输入内容" : "Standard input content"}
            </dt>
            <dd className="m-0 min-w-0">
              <details open={expanded}>
                <summary className="cursor-pointer font-semibold">
                  {zh ? "展开核对完整输入" : "Expand and review full input"}
                  {` (${new TextEncoder().encode(config.stdin_content).length} bytes)`}
                </summary>
                <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-2 font-mono text-xs">
                  {config.stdin_content || (zh ? "（空）" : "(empty)")}
                </pre>
              </details>
            </dd>
          </>
        )}
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
      {reviewedArguments.some((argument) => argument.length > 2048) && (
        <p role="status" className="mt-3 text-xs font-semibold text-amber-800">
          {zh
            ? "此操作包含长参数。批准前请展开并逐项核对完整内容。"
            : "This operation has long arguments. Expand and review every item before approval."}
        </p>
      )}
      {config.terminal_id && (
        <p className="mt-2 text-xs text-slate-600">
          {zh
            ? "批准后命令会在这个既有终端进程中继续执行；凭据由代理临时注入，终端回放与 MCP 读取只能看到脱敏结果。"
            : "After approval, the command continues in this existing terminal process. The broker injects credentials temporarily, and terminal replay or MCP reads expose only redacted output."}
        </p>
      )}
    </details>
  );
}
