// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Activity, CheckCircle2, CircleAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { SecretBridgeApiError, type RecoveredSessionResponse } from "../api";
import type { Language } from "./preferences";
import type { AuthMethodStatus } from "../features/auth/BrowserAuthenticationSettings";
import type { Copy } from "./copy";

export function TerminalLoading({ text }: { text: Copy }) {
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-slate-200 bg-white p-10 text-center shadow-sm">
      <div>
        <Activity className="mx-auto size-8 animate-pulse text-cyan-600" />
        <p className="mb-0 mt-4 text-sm font-medium text-slate-600">
          {text.checking}
        </p>
      </div>
    </section>
  );
}

export function StatusPill({
  ok,
  pending,
  label,
}: {
  ok: boolean;
  pending: boolean;
  label: string;
}) {
  const Icon = pending ? Activity : ok ? CheckCircle2 : CircleAlert;
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 font-medium ${
        pending
          ? "bg-amber-50 text-amber-700"
          : ok
            ? "bg-emerald-50 text-emerald-700"
            : "bg-slate-100 text-slate-600"
      }`}
    >
      <Icon className={`size-4 ${pending ? "animate-pulse" : ""}`} />
      {label}
    </span>
  );
}

export function PairingRequired({
  text,
  page,
  language,
  pinEnabled,
  totpEnabled,
  authMethodStatus,
  onRetry,
  onPin,
  onTotp,
  onRecover,
  onRecoveredSession,
}: {
  text: Copy;
  page: string;
  language: Language;
  pinEnabled: boolean;
  totpEnabled: boolean;
  authMethodStatus: AuthMethodStatus;
  onRetry: () => void;
  onPin: (pin: string) => Promise<void>;
  onTotp: (code: string) => Promise<void>;
  onRecover: (
    recoveryKey: string,
    newPin: string,
  ) => Promise<RecoveredSessionResponse>;
  onRecoveredSession: (response: RecoveredSessionResponse) => void;
}) {
  const [pin, setPin] = useState("");
  const [loginMethod, setLoginMethod] = useState<"pin" | "totp">("pin");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const [recovering, setRecovering] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [recoveredSession, setRecoveredSession] =
    useState<RecoveredSessionResponse | null>(null);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const zh = language === "zh-CN";
  useEffect(() => {
    if (retryAfter <= 0) return;
    const timer = window.setTimeout(
      () => setRetryAfter((value) => Math.max(0, value - 1)),
      1_000,
    );
    return () => window.clearTimeout(timer);
  }, [retryAfter]);
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-dashed border-slate-300 bg-white/65 p-10 text-center">
      <div className="max-w-lg">
        <div className="mx-auto grid size-14 place-items-center rounded-2xl bg-cyan-50 text-cyan-700">
          <ShieldCheck className="size-7" aria-hidden="true" />
        </div>
        <p className="mb-0 mt-5 text-sm font-semibold uppercase tracking-[0.14em] text-cyan-700">
          {page}
        </p>
        <h1 className="mb-0 mt-2 text-2xl font-bold text-slate-950">
          {pinEnabled || totpEnabled
            ? zh
              ? "登录本机管理页"
              : "Sign in to the local console"
            : text.futureModule}
        </h1>
        <p className="mb-0 mt-3 leading-7 text-slate-600">
          {pinEnabled || totpEnabled
            ? zh
              ? "使用你设置的 PIN 或身份验证器登录，无需再次使用首次配对链接。"
              : "Sign in with your PIN or authenticator. The initial pairing link is no longer needed."
            : text.futureBody}
        </p>
        {authMethodStatus === "loading" && (
          <p role="status" className="mt-5 text-sm text-slate-600">
            {zh ? "正在检查身份验证方式…" : "Checking verification methods…"}
          </p>
        )}
        {authMethodStatus === "error" && (
          <div role="alert" className="mt-5 text-sm text-rose-700">
            {zh
              ? "无法读取身份验证配置。请重试；不会将其视为未配置。"
              : "Could not load verification settings. Retry; they are not assumed unset."}
            <button
              type="button"
              className="workbench-button ml-3"
              onClick={onRetry}
            >
              {zh ? "重试" : "Retry"}
            </button>
          </div>
        )}
        {authMethodStatus === "ready" && (pinEnabled || totpEnabled) && (
          <form
            className="mx-auto mt-6 max-w-sm space-y-3 text-left"
            onSubmit={async (event) => {
              event.preventDefault();
              setBusy(true);
              setFailed(false);
              try {
                if (loginMethod === "totp") await onTotp(pin);
                else await onPin(pin);
                setPin("");
              } catch (error) {
                if (
                  error instanceof SecretBridgeApiError &&
                  error.status === 429
                ) {
                  setRetryAfter(error.retryAfterSeconds);
                }
                setFailed(true);
              } finally {
                setBusy(false);
              }
            }}
          >
            {pinEnabled && totpEnabled && (
              <div className="flex gap-3 text-sm">
                <button
                  type="button"
                  className="workbench-button"
                  aria-pressed={loginMethod === "pin"}
                  onClick={() => {
                    setLoginMethod("pin");
                    setPin("");
                  }}
                >
                  {zh ? "PIN/口令" : "PIN/passphrase"}
                </button>
                <button
                  type="button"
                  className="workbench-button"
                  aria-pressed={loginMethod === "totp"}
                  onClick={() => {
                    setLoginMethod("totp");
                    setPin("");
                  }}
                >
                  {zh ? "验证码" : "Authenticator code"}
                </button>
              </div>
            )}
            <label
              htmlFor="browser-pin"
              className="block text-sm font-semibold text-slate-700"
            >
              {loginMethod === "totp"
                ? zh
                  ? "身份验证器验证码"
                  : "Authenticator code"
                : zh
                  ? "本机 PIN 或口令"
                  : "Local PIN or passphrase"}
            </label>
            <input
              id="browser-pin"
              type={loginMethod === "totp" ? "text" : "password"}
              minLength={6}
              maxLength={loginMethod === "totp" ? 6 : 64}
              inputMode={loginMethod === "totp" ? "numeric" : undefined}
              pattern={loginMethod === "totp" ? "[0-9]{6}" : undefined}
              required
              autoComplete={
                loginMethod === "totp" ? "one-time-code" : "current-password"
              }
              value={pin}
              onChange={(event) => setPin(event.target.value)}
              className="w-full rounded-xl border border-slate-200 px-3.5 py-2.5"
            />
            <button
              type="submit"
              disabled={busy || retryAfter > 0}
              className="workbench-button w-full"
            >
              {busy
                ? zh
                  ? "验证中…"
                  : "Verifying…"
                : zh
                  ? "验证并进入"
                  : "Verify and continue"}
            </button>
            {failed && (
              <p role="alert" className="text-sm text-rose-700">
                {retryAfter > 0
                  ? zh
                    ? `尝试次数过多，请在 ${retryAfter} 秒后重试。等待时间会随连续错误增加。`
                    : `Too many attempts. Try again in ${retryAfter} seconds; repeated failures increase the wait.`
                  : zh
                    ? "验证失败，请检查输入。"
                    : "Verification failed. Check your entry."}
              </p>
            )}
          </form>
        )}
        {authMethodStatus === "ready" && pinEnabled && (
          <div className="mx-auto mt-5 max-w-sm text-left">
            <button
              type="button"
              className="text-sm font-semibold text-cyan-800 hover:underline"
              onClick={() => setRecovering((value) => !value)}
            >
              {zh ? "忘记 PIN？使用恢复密钥" : "Forgot PIN? Use recovery key"}
            </button>
            {recovering && !recoveredSession && (
              <form
                className="mt-4 space-y-3 rounded-2xl border border-cyan-200 bg-cyan-50 p-5"
                onSubmit={async (event) => {
                  event.preventDefault();
                  if (newPin !== confirmPin || newPin.length < 6) return;
                  setBusy(true);
                  setFailed(false);
                  try {
                    const response = await onRecover(
                      recoveryCode.trim(),
                      newPin,
                    );
                    setRecoveredSession(response);
                    setRecoveryCode("");
                    setNewPin("");
                    setConfirmPin("");
                  } catch (error) {
                    if (
                      error instanceof SecretBridgeApiError &&
                      error.status === 429
                    )
                      setRetryAfter(error.retryAfterSeconds);
                    setFailed(true);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <p className="m-0 text-sm leading-6 text-slate-700">
                  {zh
                    ? "输入此前安全保存的恢复密钥。成功后旧密钥立即失效，必须保存新密钥。"
                    : "Enter the recovery key you saved. The old key is invalidated after reset; save the new one."}
                </p>
                <input
                  aria-label={zh ? "恢复密钥" : "Recovery key"}
                  value={recoveryCode}
                  onChange={(event) => setRecoveryCode(event.target.value)}
                  autoComplete="off"
                  className="w-full rounded-xl border border-slate-200 px-3 py-2.5 font-mono text-sm"
                  required
                />
                <input
                  aria-label={zh ? "新 PIN" : "New PIN"}
                  type="password"
                  value={newPin}
                  onChange={(event) => setNewPin(event.target.value)}
                  autoComplete="new-password"
                  minLength={6}
                  maxLength={64}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2.5"
                  required
                />
                <input
                  aria-label={zh ? "确认新 PIN" : "Confirm new PIN"}
                  type="password"
                  value={confirmPin}
                  onChange={(event) => setConfirmPin(event.target.value)}
                  autoComplete="new-password"
                  minLength={6}
                  maxLength={64}
                  className="w-full rounded-xl border border-slate-200 px-3 py-2.5"
                  required
                />
                {newPin && confirmPin && newPin !== confirmPin && (
                  <p role="alert" className="text-sm text-rose-700">
                    {zh ? "两次 PIN 不一致。" : "The PINs do not match."}
                  </p>
                )}
                {failed && (
                  <p role="alert" className="text-sm text-rose-700">
                    {zh
                      ? "恢复失败，请核对密钥。"
                      : "Recovery failed. Check the key."}
                  </p>
                )}
                <button
                  type="submit"
                  className="workbench-primary w-full"
                  disabled={
                    busy ||
                    retryAfter > 0 ||
                    newPin.length < 6 ||
                    newPin !== confirmPin
                  }
                >
                  {zh ? "重置 PIN" : "Reset PIN"}
                </button>
              </form>
            )}
            {recoveredSession && (
              <div className="mt-4 space-y-3 rounded-2xl border border-amber-300 bg-amber-50 p-5">
                <h2 className="m-0 text-lg font-bold text-amber-950">
                  {zh ? "保存新的恢复密钥" : "Save your new recovery key"}
                </h2>
                <p className="text-sm leading-6 text-amber-900">
                  {zh
                    ? "旧密钥已失效。请将新密钥保存到安全位置，不要发送给 AI。"
                    : "The old key is invalid. Save the new one securely; never send it to an AI."}
                </p>
                <code className="block break-all rounded-xl bg-slate-950 p-3 font-mono text-sm text-cyan-100 select-all">
                  {recoveredSession.recovery_key}
                </code>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={recoverySaved}
                    onChange={(event) => setRecoverySaved(event.target.checked)}
                  />
                  {zh ? "我已安全保存" : "I saved it securely"}
                </label>
                <button
                  type="button"
                  disabled={!recoverySaved}
                  className="workbench-primary w-full"
                  onClick={() => onRecoveredSession(recoveredSession)}
                >
                  {zh ? "进入管理页" : "Open management page"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
