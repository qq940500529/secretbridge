// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  CommandConfig,
  CredentialReference,
  TelnetConfig,
} from "../../../../api/index";

export const emptyTelnet: TelnetConfig = {
  host: "",
  port: 23,
  username: "",
  password_slot: "password",
  login_prompt: "login: ",
  password_prompt: "Password: ",
  command_prompt: "> ",
  authentication_failure_prompt: "Login incorrect",
  commands: [],
  logout_command: "exit",
  max_output_bytes: 65536,
};

const input =
  "mt-1 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-100";

export function TelnetEditor({
  config,
  onChange,
  credentials,
  zh,
}: {
  config: CommandConfig;
  onChange: (value: CommandConfig) => void;
  credentials: CredentialReference[];
  zh: boolean;
}) {
  const telnet = config.telnet!;
  const update = (change: Partial<TelnetConfig>) =>
    onChange({ ...config, telnet: { ...telnet, ...change } });
  const selected =
    config.slots.find((slot) => slot.name === telnet.password_slot)
      ?.credential_id ?? "";
  const selectCredential = (credential_id: string) =>
    onChange({
      ...config,
      slots: credential_id
        ? [
            {
              name: telnet.password_slot,
              credential_id,
              injection: "protocol",
              environment_variable: null,
            },
          ]
        : [],
    });
  return (
    <div className="space-y-5">
      <aside className="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
        <strong>{zh ? "明文协议风险" : "Plaintext protocol risk"}</strong>
        <p className="mb-0 mt-1">
          {zh
            ? "Telnet 不加密账号、密码、命令或输出，也不能验证服务器身份。仅用于无法升级的隔离旧设备；请优先迁移到 SSH 或 TLS，并在连接目录中逐项开启“不加密协议”。"
            : "Telnet encrypts neither credentials, commands nor output and cannot authenticate the server. Use it only for isolated legacy devices that cannot be upgraded. Prefer SSH or TLS and explicitly allow plaintext on the matching connection."}
        </p>
      </aside>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "固定主机地址" : "Fixed host address"}
          <input
            required
            maxLength={253}
            className={input}
            value={telnet.host}
            onChange={(event) => update({ host: event.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "端口" : "Port"}
          <input
            required
            type="number"
            min={1}
            max={65535}
            className={input}
            value={telnet.port || ""}
            onChange={(event) => update({ port: Number(event.target.value) })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "固定登录账号" : "Fixed username"}
          <input
            required
            maxLength={128}
            className={input}
            value={telnet.username}
            onChange={(event) => update({ username: event.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "密码凭据引用" : "Password credential"}
          <select
            required
            className={input}
            value={selected}
            onChange={(event) => selectCredential(event.target.value)}
          >
            <option value="">
              {zh ? "请选择密码凭据" : "Choose a password credential"}
            </option>
            {credentials
              .filter((credential) => credential.kind === "password")
              .map((credential) => (
                <option key={credential.id} value={credential.id}>
                  {credential.name}
                </option>
              ))}
          </select>
        </label>
      </div>
      <fieldset className="grid gap-4 border-t border-slate-200 pt-4 md:grid-cols-2">
        <legend className="px-1 text-sm font-semibold">
          {zh ? "固定登录对话" : "Fixed login dialogue"}
        </legend>
        {(
          [
            ["login_prompt", zh ? "账号提示符" : "Username prompt"],
            ["password_prompt", zh ? "密码提示符" : "Password prompt"],
            ["command_prompt", zh ? "命令提示符" : "Command prompt"],
            [
              "authentication_failure_prompt",
              zh
                ? "认证失败提示（可选）"
                : "Authentication failure text (optional)",
            ],
          ] as const
        ).map(([key, label]) => (
          <label key={key} className="text-sm font-semibold">
            {label}
            <input
              required={key !== "authentication_failure_prompt"}
              maxLength={128}
              className={`${input} font-mono`}
              value={telnet[key] ?? ""}
              onChange={(event) =>
                update({ [key]: event.target.value || null })
              }
            />
          </label>
        ))}
      </fieldset>
      <label className="block text-sm font-semibold">
        {zh
          ? "固定命令脚本（每行一条）"
          : "Fixed command script (one line each)"}
        <textarea
          required
          rows={5}
          className={`${input} font-mono`}
          value={telnet.commands.join("\n")}
          onChange={(event) =>
            update({
              commands:
                event.target.value === "" ? [] : event.target.value.split("\n"),
            })
          }
        />
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "退出命令" : "Logout command"}
          <input
            required
            maxLength={128}
            className={`${input} font-mono`}
            value={telnet.logout_command}
            onChange={(event) => update({ logout_command: event.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "输出上限（字节）" : "Output limit (bytes)"}
          <input
            required
            type="number"
            min={1024}
            max={262144}
            className={input}
            value={telnet.max_output_bytes}
            onChange={(event) =>
              update({ max_output_bytes: Number(event.target.value) })
            }
          />
        </label>
      </div>
    </div>
  );
}
