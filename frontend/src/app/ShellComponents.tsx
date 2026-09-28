// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Activity, CheckCircle2, CircleAlert } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { PinActionDialog } from "../features/auth/PinActionDialog";
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
  reauthenticate = false,
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
  reauthenticate?: boolean;
}) {
  const [pinFailed, setPinFailed] = useState(false);
  const [login, setLogin] = useState<"pin" | "totp" | null>(null);
  const [recovering, setRecovering] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [recoveredSession, setRecoveredSession] =
    useState<RecoveredSessionResponse | null>(null);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const zh = language === "zh-CN";
  const opened = useRef(false);
  useEffect(() => {
    if (
      reauthenticate &&
      authMethodStatus === "ready" &&
      !opened.current &&
      (pinEnabled || totpEnabled)
    ) {
      opened.current = true;
      setLogin(pinEnabled ? "pin" : "totp");
    }
  }, [reauthenticate, authMethodStatus, pinEnabled, totpEnabled]);
  return (
    <section className="grid min-h-[65vh] place-items-center rounded-3xl border border-dashed border-slate-300 bg-white/65 p-10 text-center">
      <div className="max-w-lg">
        <img
          src="/secretbridge-logo.png"
          alt=""
          className="mx-auto size-14 rounded-2xl"
          aria-hidden="true"
        />
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
          <div className="mx-auto mt-6 flex max-w-sm flex-col gap-3">
            {pinEnabled && (
              <button
                className="workbench-primary"
                onClick={() => setLogin("pin")}
              >
                {zh ? "使用 PIN 登录" : "Sign in with PIN"}
              </button>
            )}
            {totpEnabled && (
              <button
                className="workbench-button"
                onClick={() => setLogin("totp")}
              >
                {zh ? "使用验证码登录" : "Sign in with authenticator"}
              </button>
            )}
          </div>
        )}
        {login && (
          <PinActionDialog
            title={zh ? "登录管理页" : "Sign in to console"}
            language={language}
            verificationCode={login === "totp"}
            onClose={() => setLogin(null)}
            onConfirm={async (pin) => {
              try {
                if (login === "totp") await onTotp(pin);
                else await onPin(pin);
              } catch (failure) {
                if (
                  login === "pin" &&
                  failure instanceof SecretBridgeApiError &&
                  [401, 429].includes(failure.status)
                )
                  setPinFailed(true);
                throw failure;
              }
            }}
          />
        )}
        {authMethodStatus === "ready" && pinEnabled && pinFailed && (
          <div className="mx-auto mt-5 max-w-sm text-left">
            <button
              type="button"
              className="text-sm font-semibold text-cyan-800 hover:underline"
              onClick={() => setRecovering((value) => !value)}
            >
              {zh ? "忘记 PIN？使用恢复密钥" : "Forgot PIN? Use recovery key"}
            </button>
            {recovering && !recoveredSession && (
              <PinActionDialog
                title={
                  zh ? "使用恢复密钥重置 PIN" : "Reset PIN with recovery key"
                }
                language={language}
                currentPin={false}
                newPin
                onClose={() => {
                  setRecovering(false);
                  setRecoveryCode("");
                }}
                onConfirm={async (_pin, replacement) => {
                  const response = await onRecover(
                    recoveryCode.trim(),
                    replacement,
                  );
                  setRecoveredSession(response);
                  setRecoveryCode("");
                }}
              >
                <label className="block text-sm font-semibold">
                  {zh ? "恢复密钥" : "Recovery key"}
                  <input
                    autoFocus
                    required
                    type="password"
                    autoComplete="off"
                    aria-label={zh ? "恢复密钥" : "Recovery key"}
                    value={recoveryCode}
                    onChange={(event) => setRecoveryCode(event.target.value)}
                    className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2.5"
                  />
                </label>
              </PinActionDialog>
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
