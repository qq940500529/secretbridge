// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  CommandConfig,
  CredentialReference,
  GitConfig,
} from "../../../../api/index";

export const emptyGit: GitConfig = {
  operation: "inspect",
  remote_url: "",
  branch: "main",
  username: "",
  token_slot: "token",
};
const input =
  "mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";

export function GitEditor({
  config,
  onChange,
  credentials,
  zh,
}: {
  config: CommandConfig;
  onChange: (config: CommandConfig) => void;
  credentials: CredentialReference[];
  zh: boolean;
}) {
  const git = config.git!;
  const update = (change: Partial<GitConfig>) =>
    onChange({ ...config, git: { ...git, ...change } });
  return (
    <div className="space-y-4">
      <label className="block text-sm font-semibold">
        {zh ? "Git 操作" : "Git operation"}
        <select
          className={input}
          value={git.operation}
          onChange={(e) =>
            update({ operation: e.target.value as GitConfig["operation"] })
          }
        >
          <option value="inspect">
            {zh ? "查询远程分支" : "Inspect remote branch"}
          </option>
          <option value="fetch">
            {zh
              ? "拉取分支（不合并工作区）"
              : "Fetch branch (no working-tree merge)"}
          </option>
          <option value="push">
            {zh ? "推送分支（不强制）" : "Push branch (no force)"}
          </option>
        </select>
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "Git 程序绝对路径" : "Absolute Git executable path"}
          <input
            required
            className={input}
            value={config.program}
            onChange={(e) => onChange({ ...config, program: e.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "本机仓库目录" : "Local repository directory"}
          <input
            required
            className={input}
            value={config.working_directory}
            onChange={(e) =>
              onChange({ ...config, working_directory: e.target.value })
            }
          />
        </label>
      </div>
      <label className="block text-sm font-semibold">
        {zh
          ? "远程仓库 URL（不含凭据）"
          : "Remote repository URL (no credentials)"}
        <input
          required
          className={input}
          value={git.remote_url}
          onChange={(e) => update({ remote_url: e.target.value })}
          placeholder="https://github.com/owner/repository.git"
        />
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "固定分支" : "Fixed branch"}
          <input
            required
            maxLength={128}
            className={input}
            value={git.branch}
            onChange={(e) => update({ branch: e.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "认证用户名" : "Authentication username"}
          <input
            required
            maxLength={128}
            className={input}
            value={git.username}
            onChange={(e) => update({ username: e.target.value })}
          />
        </label>
      </div>
      <label className="block text-sm font-semibold">
        {zh ? "令牌凭据引用" : "Token credential reference"}
        <select
          required
          className={input}
          value={
            config.slots.find((s) => s.name === git.token_slot)
              ?.credential_id ?? ""
          }
          onChange={(e) =>
            onChange({
              ...config,
              slots: [
                {
                  name: git.token_slot,
                  credential_id: e.target.value,
                  injection: "protocol",
                  environment_variable: null,
                },
              ],
            })
          }
        >
          <option value="">{zh ? "选择凭据" : "Choose credential"}</option>
          {credentials
            .filter((c) => c.kind === "api_token" || c.kind === "password")
            .map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
        </select>
      </label>
      <p className="border-l-4 border-amber-400 bg-amber-50 px-3 py-2 text-sm leading-6 text-amber-900">
        {zh
          ? "使用你信任的 Git 程序和仓库。令牌通过本次子进程环境中的 HTTP 认证头传递，不写入 URL、参数、文件或凭据助手；环境仍可能被本机进程检查工具读取。只支持 HTTPS（本机回环测试允许 HTTP），不跟随重定向。拉取写入 refs/remotes/secretbridge/分支；推送不会强制覆盖，取消不能撤回已完成的远程更新。"
          : "Use a trusted Git executable and repository. Authentication uses an HTTP header in this child process environment, never a URL, argument, file or credential helper; local process inspection may still read the environment. HTTPS only (HTTP allowed for loopback tests); no redirects. Fetch writes refs/remotes/secretbridge/branch; push never forces an update. Cancellation cannot roll back a completed remote update."}
      </p>
    </div>
  );
}
