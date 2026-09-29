// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from "react";
import { LoaderCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import {
  cancelSshHostKeyProbe,
  probeSshHostKey,
  type Resource,
  type SshHostKeyObservation,
} from "../../api";
import { Field, inputClass } from "./shared";

export function SshHostFingerprintField({
  token,
  resource,
  host,
  port,
  value,
  onChange,
  zh,
  disabled,
}: {
  token: string;
  resource: Resource | null;
  host: string;
  port: number;
  value: string;
  onChange: (value: string) => void;
  zh: boolean;
  disabled: boolean;
}) {
  const [observation, setObservation] = useState<SshHostKeyObservation | null>(
    null,
  );
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [filled, setFilled] = useState(false);
  const pending = useRef<{
    controller: AbortController;
    id: string;
    resourceId: string;
  } | null>(null);
  const context = `${resource?.id}:${resource?.version}:${host}:${port}:${token}`;
  const currentContext = useRef(context);
  currentContext.current = context;
  const saved =
    resource?.connection.protocol === "ssh" &&
    resource.address === host.trim() &&
    resource.connection.port === port &&
    !!host.trim();
  function cancel() {
    const request = pending.current;
    pending.current = null;
    if (request) {
      request.controller.abort();
      void cancelSshHostKeyProbe(token, request.resourceId, request.id).catch(
        () => {},
      );
    }
  }
  useEffect(() => {
    setObservation(null);
    setConfirmed(false);
    setFilled(false);
    setError("");
    setBusy(false);
    return cancel;
  }, [context]);
  async function probe() {
    if (!saved || !resource || disabled) return;
    cancel();
    setBusy(true);
    setObservation(null);
    setConfirmed(false);
    setFilled(false);
    setError("");
    const request = {
      controller: new AbortController(),
      id: crypto.randomUUID(),
      resourceId: resource.id,
    };
    pending.current = request;
    try {
      const result = await probeSshHostKey(
        token,
        resource,
        request.id,
        request.controller.signal,
      );
      if (pending.current !== request || currentContext.current !== context)
        return;
      if (
        result.resource_id !== resource.id ||
        result.resource_version !== resource.version
      )
        throw new Error("stale");
      if (
        result.code === "observed_unverified" &&
        result.fingerprint &&
        result.algorithm
      )
        setObservation(result);
      else
        setError(
          result.code === "probe_busy"
            ? zh
              ? "正在获取其他主机的指纹，请稍后重试。"
              : "Other host-key checks are in progress. Try again shortly."
            : zh
              ? "未能获取公开指纹，请检查地址、端口与网络后重试。"
              : "No public fingerprint was received. Check the address, port and network, then retry.",
        );
    } catch {
      if (
        pending.current === request &&
        !request.controller.signal.aborted &&
        currentContext.current === context
      )
        setError(
          zh
            ? "获取失败或资源已更改，请重新打开资源后重试。"
            : "The check failed or the resource changed. Reopen the resource and retry.",
        );
    } finally {
      if (pending.current === request) {
        pending.current = null;
        setBusy(false);
      }
    }
  }
  const previous =
    resource?.connection.protocol === "ssh"
      ? resource.connection.host_key_sha256
      : "";
  const changed =
    !!previous && !!observation && previous !== observation.fingerprint;
  return (
    <div className="space-y-3 sm:col-span-2">
      <Field
        label={
          zh
            ? "已核验的 SSH 主机指纹（SHA256）"
            : "Verified SSH host fingerprint (SHA256)"
        }
        htmlFor="resource-host-key"
      >
        <input
          id="resource-host-key"
          className={`${inputClass} font-mono text-sm`}
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            setFilled(false);
          }}
          aria-describedby="ssh-key-help"
        />
      </Field>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <button
          type="button"
          disabled={!saved || disabled || busy}
          onClick={() => void probe()}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? (
            <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <ShieldCheck className="h-4 w-4" aria-hidden />
          )}
          {busy
            ? zh
              ? "正在获取…"
              : "Fetching…"
            : zh
              ? "获取公开指纹"
              : "Fetch public fingerprint"}
        </button>
        {busy && (
          <button
            type="button"
            onClick={() => {
              cancel();
              setBusy(false);
            }}
            className="rounded px-2 py-2 text-sm text-slate-600 hover:bg-slate-100"
          >
            {zh ? "取消" : "Cancel"}
          </button>
        )}
        <p id="ssh-key-help" className="text-sm text-slate-500">
          {saved
            ? zh
              ? "仅获取公开主机密钥，不登录服务器。"
              : "Reads the public host key only; does not log in."
            : zh
              ? "先保存地址和端口，再获取指纹；也可直接填写已核验的指纹。"
              : "Save the address and port first, or enter an independently verified fingerprint."}
        </p>
      </div>
      <div aria-live="polite" aria-atomic="true">
        {error && (
          <p role="alert" className="text-sm text-rose-700">
            {error}
          </p>
        )}
        {observation && (
          <section
            aria-label={zh ? "公开指纹核对" : "Verify public fingerprint"}
            className="space-y-3 rounded-lg border border-amber-200 bg-amber-50/60 p-4"
          >
            <p className="flex items-center gap-2 text-sm font-semibold text-amber-950">
              <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden />
              {zh
                ? "网络获取 · 尚未确认可信"
                : "Received from the network · Not yet trusted"}
            </p>
            <dl className="space-y-1 text-sm">
              <dt className="text-slate-600">{observation.algorithm}</dt>
              <dd className="break-all font-mono text-slate-950 select-all">
                {observation.fingerprint}
              </dd>
            </dl>
            {changed && (
              <p className="text-sm font-semibold text-rose-800">
                {zh
                  ? "与已保存指纹不同。请先调查密钥变更原因，勿直接替换。"
                  : "Different from the saved fingerprint. Investigate the key change before replacing it."}
              </p>
            )}
            <p className="text-sm leading-6 text-slate-700">
              {zh
                ? "请通过服务器控制台、管理员或其他可信渠道核对。网络获取的指纹本身不能证明服务器身份。"
                : "Compare with the server console, administrator or another trusted channel. A network-observed key alone does not prove server identity."}
            </p>
            <label className="flex items-start gap-2 text-sm text-slate-800">
              <input
                type="checkbox"
                className="mt-1 h-4 w-4 shrink-0 accent-cyan-700"
                checked={confirmed}
                disabled={filled}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              {zh
                ? "我已通过可信渠道核对，确认此指纹属于目标服务器"
                : "I verified through a trusted channel that this fingerprint belongs to the intended server"}
            </label>
            <button
              type="button"
              disabled={!confirmed || disabled || filled}
              onClick={() => {
                onChange(observation.fingerprint!);
                setFilled(true);
              }}
              className="workbench-primary ssh-host-key-confirm"
            >
              {filled
                ? zh
                  ? "已填入 · 保存后生效"
                  : "Filled · Save to apply"
                : zh
                  ? "确认并填入指纹"
                  : "Confirm and fill fingerprint"}
            </button>
          </section>
        )}
      </div>
    </div>
  );
}
