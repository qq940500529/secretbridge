// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Plus, Trash2 } from "lucide-react";
import type { CommandConfig, CredentialReference, CredentialSlot } from "./api";
import { ParameterEditor } from "./ParameterEditor";
import { HttpEditor, emptyHttp } from "./HttpEditor";
import { SshEditor, emptySsh } from "./SshEditor";
import { TelnetEditor, emptyTelnet } from "./TelnetEditor";
import { GitEditor, emptyGit } from "./GitEditor";
import { DatabaseEditor, emptyDatabase } from "./DatabaseEditor";

export const emptyCommand: CommandConfig = {
  program: "",
  working_directory: "",
  arguments: [],
  slots: [],
};

export function CommandEditor({
  value,
  onChange,
  credentials,
  language,
}: {
  value: CommandConfig;
  onChange: (value: CommandConfig) => void;
  credentials: CredentialReference[];
  language: "zh-CN" | "en";
}) {
  const zh = language === "zh-CN";
  const updateSlot = (index: number, change: Partial<CredentialSlot>) =>
    onChange({
      ...value,
      slots: value.slots.map((slot, i) =>
        i === index ? { ...slot, ...change } : slot,
      ),
    });
  const selector = (
    <label className="block text-sm font-semibold">
      {zh ? "执行方式" : "Execution method"}
      <select
        value={
          value.database
            ? "database"
            : value.git
              ? "git"
              : value.ssh?.transfer
                ? "sftp"
                : value.ssh
                  ? "ssh"
                  : value.telnet
                    ? "telnet"
                    : value.http
                      ? "http"
                      : "program"
        }
        onChange={(e) =>
          onChange({
            ...value,
            database: e.target.value === "database" ? emptyDatabase : null,
            http: e.target.value === "http" ? emptyHttp : null,
            ssh:
              e.target.value === "ssh"
                ? emptySsh
                : e.target.value === "sftp"
                  ? {
                      ...emptySsh,
                      transfer: {
                        direction: "upload",
                        local_path: "",
                        remote_path: "",
                        overwrite: false,
                        max_bytes: 268435456,
                      },
                    }
                  : null,
            telnet: e.target.value === "telnet" ? emptyTelnet : null,
            git: e.target.value === "git" ? emptyGit : null,
            parameters: [],
            program: "",
            working_directory: "",
            arguments: [],
            slots: [],
          })
        }
        className={input}
      >
        <option value="program">{zh ? "本机程序" : "Local program"}</option>
        <option value="http">HTTP / HTTPS</option>
        <option value="ssh">SSH</option>
        <option value="telnet">Telnet</option>
        <option value="sftp">
          {zh ? "SFTP 文件传输" : "SFTP file transfer"}
        </option>
        <option value="git">Git HTTPS</option>
        <option value="database">{zh ? "数据库查询" : "Database query"}</option>
      </select>
    </label>
  );
  if (value.database)
    return (
      <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
        <legend className="px-1 text-sm font-semibold">
          {zh ? "数据库查询" : "Database query"}
        </legend>
        {selector}
        <DatabaseEditor
          config={value}
          onChange={onChange}
          credentials={credentials}
          zh={zh}
        />
        {value.database.operation === "query" && (
          <ParameterEditor
            value={value.parameters ?? []}
            onChange={(parameters) => onChange({ ...value, parameters })}
            zh={zh}
          />
        )}
      </fieldset>
    );
  if (value.git)
    return (
      <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
        <legend className="px-1 text-sm font-semibold">Git HTTPS</legend>
        {selector}
        <GitEditor
          config={value}
          onChange={onChange}
          credentials={credentials}
          zh={zh}
        />
      </fieldset>
    );
  if (value.ssh)
    return (
      <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
        <legend className="px-1 text-sm font-semibold">
          {value.ssh.transfer ? "SFTP" : "SSH"}
        </legend>
        {selector}
        <SshEditor
          config={value}
          onChange={onChange}
          credentials={credentials}
          zh={zh}
        />
        {!value.ssh.transfer && (
          <ParameterEditor
            value={value.parameters ?? []}
            onChange={(parameters) => onChange({ ...value, parameters })}
            zh={zh}
          />
        )}
      </fieldset>
    );
  if (value.telnet)
    return (
      <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
        <legend className="px-1 text-sm font-semibold">Telnet</legend>
        {selector}
        <TelnetEditor
          config={value}
          onChange={onChange}
          credentials={credentials}
          zh={zh}
        />
      </fieldset>
    );
  if (value.http)
    return (
      <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
        <legend className="px-1 text-sm font-semibold">HTTP / HTTPS</legend>
        {selector}
        <HttpEditor
          value={value.http}
          onChange={(http) => onChange({ ...value, http })}
          config={value}
          onConfigChange={onChange}
          credentials={credentials}
          zh={zh}
        />
        <ParameterEditor
          value={value.parameters ?? []}
          onChange={(parameters) => onChange({ ...value, parameters })}
          zh={zh}
        />
      </fieldset>
    );
  return (
    <fieldset className="mt-5 space-y-4 border-t border-slate-200 pt-5">
      <legend className="px-1 text-sm font-semibold">
        {zh ? "程序与凭据插槽" : "Program and credential slots"}
      </legend>
      {selector}
      <p className="text-sm leading-6 text-slate-600">
        {zh
          ? "只配置你信任的程序。按参数顺序逐行填写，空行是空参数；参数或文件插槽使用完整的 {{插槽名}}。标准输入发送原文后关闭，不自动加换行。"
          : "Use only programs you trust. One argument per line, in order; blank lines represent empty arguments. Argument/file slots use an entire {{slot_name}}. Stdin sends exact bytes then closes, without adding a newline."}
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "程序绝对路径" : "Absolute program path"}
          <input
            required
            value={value.program}
            onChange={(e) => onChange({ ...value, program: e.target.value })}
            className={input}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "工作目录（绝对路径）" : "Working directory (absolute)"}
          <input
            required
            value={value.working_directory}
            onChange={(e) =>
              onChange({ ...value, working_directory: e.target.value })
            }
            className={input}
          />
        </label>
      </div>
      <label className="block text-sm font-semibold">
        {zh
          ? "参数（每行一个，非 Shell 命令）"
          : "Arguments (one per line; not a shell command)"}
        <textarea
          rows={4}
          value={value.arguments.join("\n")}
          onChange={(e) =>
            onChange({
              ...value,
              arguments:
                e.target.value === "" ? [] : e.target.value.split("\n"),
            })
          }
          className={`${input} font-mono`}
        />
      </label>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50 text-slate-600">
            <tr>
              {[
                zh ? "插槽名" : "Slot",
                zh ? "凭据引用" : "Credential",
                zh ? "注入方式" : "Injection",
                zh ? "环境变量名" : "Environment variable",
                "",
              ].map((label, i) => (
                <th key={i} className="p-2">
                  {label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {value.slots.map((slot, index) => (
              <tr key={index} className="border-b border-slate-200">
                <td className="p-2">
                  <input
                    required
                    pattern="[A-Za-z_][A-Za-z_0-9]*"
                    maxLength={64}
                    aria-label={zh ? "插槽名" : "Slot name"}
                    value={slot.name}
                    onChange={(e) =>
                      updateSlot(index, { name: e.target.value })
                    }
                    className={input}
                  />
                </td>
                <td className="p-2">
                  <select
                    required
                    aria-label={zh ? "凭据引用" : "Credential reference"}
                    value={slot.credential_id}
                    onChange={(e) =>
                      updateSlot(index, { credential_id: e.target.value })
                    }
                    className={input}
                  >
                    <option value="">
                      {zh ? "选择凭据" : "Choose credential"}
                    </option>
                    {credentials.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                        {c.secret_state !== "available"
                          ? zh
                            ? "（未配置）"
                            : " (not configured)"
                          : ""}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="p-2">
                  <select
                    aria-label={zh ? "注入方式" : "Injection"}
                    value={slot.injection}
                    onChange={(e) =>
                      updateSlot(index, {
                        injection: e.target
                          .value as CredentialSlot["injection"],
                        environment_variable: null,
                      })
                    }
                    className={input}
                  >
                    {[
                      ["stdin", zh ? "标准输入" : "Stdin"],
                      ["environment", zh ? "环境变量" : "Environment"],
                      ["argument", zh ? "命令参数" : "Argument"],
                      ["file", zh ? "临时文件" : "Temporary file"],
                    ].map(([mode, label]) => (
                      <option key={mode} value={mode}>
                        {label}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="p-2">
                  {slot.injection === "environment" ? (
                    <input
                      required
                      aria-label={zh ? "环境变量名" : "Environment variable"}
                      value={slot.environment_variable ?? ""}
                      onChange={(e) =>
                        updateSlot(index, {
                          environment_variable: e.target.value,
                        })
                      }
                      className={input}
                    />
                  ) : (
                    "—"
                  )}
                </td>
                <td className="p-2">
                  <button
                    type="button"
                    aria-label={zh ? "移除插槽" : "Remove slot"}
                    onClick={() =>
                      onChange({
                        ...value,
                        slots: value.slots.filter((_, i) => i !== index),
                      })
                    }
                    className="p-2 text-slate-500 hover:text-rose-700"
                  >
                    <Trash2 className="size-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button
        type="button"
        disabled={value.slots.length >= 8}
        onClick={() =>
          onChange({
            ...value,
            slots: [
              ...value.slots,
              {
                name: `secret_${value.slots.length + 1}`,
                credential_id: "",
                injection: "stdin",
                environment_variable: null,
              },
            ],
          })
        }
        className="inline-flex items-center gap-2 text-sm font-semibold text-cyan-700 disabled:opacity-50"
      >
        <Plus className="size-4" />
        {zh ? "添加凭据插槽" : "Add credential slot"}
      </button>
      <p className="border-l-4 border-amber-400 bg-amber-50 px-3 py-2 text-sm leading-6 text-amber-900">
        {zh
          ? "参数可能被进程查看工具读到，环境变量会传给子进程，临时文件继承本机目录权限。优先使用标准输入或目标工具的原生认证机制。输出过滤不是程序沙箱，不会阻止程序主动向外发送秘密。"
          : "Arguments may be visible to process inspection; environment variables reach descendants; temporary files inherit local directory permissions. Prefer stdin or native authentication. Output filtering is not a sandbox and cannot stop a program transmitting secrets."}
      </p>
      <ParameterEditor
        value={value.parameters ?? []}
        onChange={(parameters) => onChange({ ...value, parameters })}
        zh={zh}
      />
    </fieldset>
  );
}

const input =
  "mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";
