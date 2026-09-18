// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { TransferConfig } from "./api";

const input =
  "mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";
export function TransferEditor({
  value,
  onChange,
  zh,
}: {
  value: TransferConfig;
  onChange: (value: TransferConfig) => void;
  zh: boolean;
}) {
  const update = (change: Partial<TransferConfig>) =>
    onChange({ ...value, ...change });
  return (
    <section className="space-y-3 border-t border-slate-200 pt-4">
      <label className="block text-sm font-semibold">
        {zh ? "传输方向" : "Direction"}
        <select
          className={input}
          value={value.direction}
          onChange={(e) =>
            update({ direction: e.target.value as TransferConfig["direction"] })
          }
        >
          <option value="upload">
            {zh ? "上传到服务器" : "Upload to server"}
          </option>
          <option value="download">
            {zh ? "下载到本机" : "Download to local machine"}
          </option>
        </select>
      </label>
      <div className="grid gap-4 md:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "本机文件绝对路径" : "Absolute local file path"}
          <input
            required
            className={input}
            value={value.local_path}
            onChange={(e) => update({ local_path: e.target.value })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "远程文件绝对路径" : "Absolute remote file path"}
          <input
            required
            className={input}
            value={value.remote_path}
            onChange={(e) => update({ remote_path: e.target.value })}
          />
        </label>
      </div>
      <label className="block text-sm font-semibold">
        {zh ? "文件大小上限（字节）" : "Maximum file size (bytes)"}
        <input
          required
          type="number"
          min={1}
          max={1073741824}
          className={input}
          value={value.max_bytes}
          onChange={(e) => update({ max_bytes: Number(e.target.value) })}
        />
      </label>
      <label className="flex items-center gap-2 text-sm font-semibold">
        <input
          type="checkbox"
          checked={value.overwrite}
          onChange={(e) => update({ overwrite: e.target.checked })}
        />
        {zh
          ? "允许替换目标文件（每次审批显示）"
          : "Allow destination replacement (shown at approval)"}
      </label>
      <p className="text-xs leading-5 text-slate-600">
        {zh
          ? "只传输登记的单个普通文件，不返回文件内容。上传替换要求服务端支持 POSIX 原子重命名；下载不覆盖时使用同目录硬链接提交。失败会尝试清理临时文件，进程崩溃或断网可能留下 .secretbridge-*.part 文件。"
          : "Only the registered regular file is transferred; file contents are not returned. Upload replacement requires POSIX rename support. No-overwrite downloads commit using a same-directory hard link. Failure triggers cleanup; a crash or disconnection can leave .secretbridge-*.part files."}
      </p>
    </section>
  );
}
