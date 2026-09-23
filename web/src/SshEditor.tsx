// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Plus, Trash2 } from "lucide-react";
import { TransferEditor } from "./TransferEditor";
import type {
  CommandConfig,
  CredentialReference,
  ParameterValue,
  SshConfig,
} from "./api";

export const emptySsh: SshConfig = {
  host: "",
  port: 22,
  username: "",
  host_key_sha256: "",
  authentication: { kind: "password", slot: "password" },
  remote_program: "",
  working_directory: null,
  arguments: [],
};
const input =
  "mt-1 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-100";

export function sshCommandPreview(
  ssh: SshConfig,
  parameters: Record<string, ParameterValue>,
): string {
  const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
  const command = [
    ssh.remote_program,
    ...ssh.arguments.map((arg) =>
      arg.kind === "literal"
        ? arg.value
        : Object.hasOwn(parameters, arg.name)
          ? String(parameters[arg.name])
          : `{{param:${arg.name}}}`,
    ),
  ]
    .map(quote)
    .join(" ");
  return ssh.working_directory
    ? `cd ${quote(ssh.working_directory)} && exec ${command}`
    : command;
}

export function SshEditor({
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
  const ssh = config.ssh!;
  const update = (change: Partial<SshConfig>) =>
    onChange({ ...config, ssh: { ...ssh, ...change } });
  const selectCredential = (name: string, credential_id: string) =>
    onChange({
      ...config,
      slots: [
        ...config.slots.filter((s) => s.name !== name),
        ...(credential_id
          ? [
              {
                name,
                credential_id,
                injection: "protocol" as const,
                environment_variable: null,
              },
            ]
          : []),
      ],
    });
  const authentication = ssh.authentication;
  const credentialSelect = (name: string, label: string) => (
    <label className="block text-sm font-semibold">
      {label}
      <select
        required
        className={input}
        value={config.slots.find((s) => s.name === name)?.credential_id ?? ""}
        onChange={(e) => selectCredential(name, e.target.value)}
      >
        <option value="">
          {zh ? "请选择凭据引用" : "Choose a credential reference"}
        </option>
        {credentials.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name}
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <div className="space-y-5">
      <p className="text-sm leading-6 text-slate-600">
        {zh
          ? "凭据仅用于协议认证，不写入命令行或临时文件。请通过可信渠道确认 SHA256 主机指纹；不会自动信任首次连接的主机。"
          : "Credentials are used only for protocol authentication, never command-line arguments or temporary files. Confirm the SHA256 host fingerprint through a trusted channel; first use is not automatically trusted."}
        {ssh.transfer
          ? zh
            ? "远程主机需要启用 SFTP 子系统。"
            : "The remote host must enable the SFTP subsystem."
          : zh
            ? "远程主机必须支持 POSIX Shell。"
            : "The remote host must support a POSIX shell."}
      </p>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "固定主机地址" : "Fixed host address"}
          <input
            required
            maxLength={253}
            className={input}
            value={ssh.host}
            onChange={(e) => update({ host: e.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "端口" : "Port"}
          <input
            required
            type="number"
            min={1}
            max={65535}
            step={1}
            className={input}
            value={ssh.port || ""}
            onChange={(e) => update({ port: Number(e.target.value) })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "登录用户名" : "Username"}
          <input
            required
            maxLength={128}
            className={input}
            value={ssh.username}
            onChange={(e) => update({ username: e.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "可信主机指纹（SHA256）" : "Trusted host fingerprint (SHA256)"}
          <input
            required
            placeholder="SHA256:…"
            className={`${input} font-mono`}
            value={ssh.host_key_sha256}
            onChange={(e) => update({ host_key_sha256: e.target.value })}
          />
        </label>
      </div>
      <section className="space-y-3 border-t border-slate-200 pt-4">
        <label className="block text-sm font-semibold">
          {zh ? "认证方式" : "Authentication"}
          <select
            className={input}
            value={authentication.kind}
            onChange={(e) =>
              onChange({
                ...config,
                slots: [],
                ssh: {
                  ...ssh,
                  authentication:
                    e.target.value === "password"
                      ? { kind: "password", slot: "password" }
                      : {
                          kind: "private_key",
                          slot: "private_key",
                          passphrase_slot: null,
                        },
                },
              })
            }
          >
            <option value="password">{zh ? "密码" : "Password"}</option>
            <option value="private_key">{zh ? "私钥" : "Private key"}</option>
          </select>
        </label>
        {credentialSelect(
          authentication.slot,
          authentication.kind === "password"
            ? zh
              ? "密码凭据引用"
              : "Password credential"
            : zh
              ? "私钥凭据引用（Ed25519 / ECDSA）"
              : "Private-key credential (Ed25519 / ECDSA)",
        )}
        {authentication.kind === "private_key" && (
          <>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={authentication.passphrase_slot !== null}
                onChange={(e) =>
                  onChange({
                    ...config,
                    slots: config.slots.filter(
                      (s) => s.name === authentication.slot,
                    ),
                    ssh: {
                      ...ssh,
                      authentication: {
                        ...authentication,
                        passphrase_slot: e.target.checked ? "passphrase" : null,
                      },
                    },
                  })
                }
              />
              {zh ? "私钥有解密口令" : "The private key is encrypted"}
            </label>
            {authentication.passphrase_slot &&
              credentialSelect(
                authentication.passphrase_slot,
                zh ? "解密口令凭据引用" : "Passphrase credential",
              )}
          </>
        )}
      </section>
      {ssh.transfer ? (
        <TransferEditor
          value={ssh.transfer}
          onChange={(transfer) => update({ transfer })}
          zh={zh}
        />
      ) : (
        <section className="space-y-3 border-t border-slate-200 pt-4">
          <label className="block text-sm font-semibold">
            {zh ? "远程程序绝对路径" : "Absolute remote program path"}
            <input
              required
              maxLength={1024}
              className={`${input} font-mono`}
              value={ssh.remote_program}
              onChange={(e) => update({ remote_program: e.target.value })}
              placeholder="/usr/bin/printf"
            />
          </label>
          <label className="block text-sm font-semibold">
            {zh
              ? "远程工作目录（可选绝对路径）"
              : "Remote working directory (optional absolute path)"}
            <input
              maxLength={1024}
              className={`${input} font-mono`}
              value={ssh.working_directory ?? ""}
              onChange={(e) =>
                update({ working_directory: e.target.value || null })
              }
              placeholder="/srv/app"
            />
          </label>
          <p className="text-xs leading-5 text-slate-600">
            {zh
              ? "每行一个参数。普通参数在审批时确定，不替换主机、用户名、指纹或认证插槽；不会递归展开。"
              : "One argument per row. Ordinary values are frozen at approval and cannot replace the host, username, fingerprint or authentication slots; they are never recursively expanded."}
          </p>
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50">
              <tr>
                <th className="p-2">{zh ? "来源" : "Source"}</th>
                <th className="p-2">
                  {zh ? "值 / 参数名" : "Value / parameter"}
                </th>
                <th />
              </tr>
            </thead>
            <tbody>
              {ssh.arguments.map((arg, index) => (
                <tr key={index} className="border-b border-slate-200">
                  <td className="p-2">
                    <select
                      aria-label={zh ? "参数来源" : "Argument source"}
                      className={input}
                      value={arg.kind}
                      onChange={(e) =>
                        update({
                          arguments: ssh.arguments.map((a, i) =>
                            i === index
                              ? e.target.value === "literal"
                                ? { kind: "literal", value: "" }
                                : {
                                    kind: "parameter",
                                    name: config.parameters?.[0]?.name ?? "",
                                  }
                              : a,
                          ),
                        })
                      }
                    >
                      <option value="literal">
                        {zh ? "固定值" : "Literal"}
                      </option>
                      <option value="parameter">
                        {zh ? "普通参数" : "Parameter"}
                      </option>
                    </select>
                  </td>
                  <td className="p-2">
                    {arg.kind === "literal" ? (
                      <input
                        aria-label={zh ? "固定参数值" : "Literal value"}
                        maxLength={8192}
                        className={input}
                        value={arg.value}
                        onChange={(e) =>
                          update({
                            arguments: ssh.arguments.map((a, i) =>
                              i === index
                                ? { kind: "literal", value: e.target.value }
                                : a,
                            ),
                          })
                        }
                      />
                    ) : (
                      <select
                        required
                        aria-label={zh ? "普通参数名" : "Parameter name"}
                        className={input}
                        value={arg.name}
                        onChange={(e) =>
                          update({
                            arguments: ssh.arguments.map((a, i) =>
                              i === index
                                ? { kind: "parameter", name: e.target.value }
                                : a,
                            ),
                          })
                        }
                      >
                        <option value="">
                          {zh ? "请选择参数" : "Choose a parameter"}
                        </option>
                        {config.parameters?.map((p) => (
                          <option key={p.name} value={p.name}>
                            {p.label} ({p.name})
                          </option>
                        ))}
                      </select>
                    )}
                  </td>
                  <td className="p-2">
                    <button
                      type="button"
                      aria-label={zh ? "删除参数" : "Remove argument"}
                      className="rounded-md p-2 text-slate-500 hover:bg-rose-50 hover:text-rose-700"
                      onClick={() =>
                        update({
                          arguments: ssh.arguments.filter(
                            (_, i) => i !== index,
                          ),
                        })
                      }
                    >
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button
            type="button"
            disabled={ssh.arguments.length >= 32}
            className="inline-flex items-center gap-2 text-sm font-semibold text-cyan-800 disabled:opacity-40"
            onClick={() =>
              update({
                arguments: [...ssh.arguments, { kind: "literal", value: "" }],
              })
            }
          >
            <Plus size={16} />
            {zh ? "增加参数" : "Add argument"}
          </button>
        </section>
      )}
    </div>
  );
}
