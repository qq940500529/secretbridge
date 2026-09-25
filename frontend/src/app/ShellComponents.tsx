// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Activity, CheckCircle2, CircleAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
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
}) {
  const [pin, setPin] = useState("");
  const [loginMethod, setLoginMethod] = useState<"pin" | "totp">("pin");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const zh = language === "zh-CN";
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
          {text.futureModule}
        </h1>
        <p className="mb-0 mt-3 leading-7 text-slate-600">{text.futureBody}</p>
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
              } catch {
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
              disabled={busy}
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
                {zh
                  ? "验证失败。连续错误会触发一分钟冷却。"
                  : "Verification failed. Repeated failures trigger a one-minute cooldown."}
              </p>
            )}
          </form>
        )}
      </div>
    </section>
  );
}
