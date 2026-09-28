// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { KeyRound, X } from "lucide-react";
import { SecretBridgeApiError } from "../../api";
import type { Language } from "../../app/preferences";

/** PIN values live only in the opened action dialog and are cleared on exit. */
export function PinActionDialog({
  title,
  language,
  onConfirm,
  onClose,
  newPin = false,
  currentPin = true,
  verificationCode = false,
  children,
}: {
  title: string;
  language: Language;
  onConfirm: (pin: string, replacement: string) => Promise<void>;
  onClose: () => void;
  newPin?: boolean;
  currentPin?: boolean;
  verificationCode?: boolean;
  children?: ReactNode;
}) {
  const zh = language === "zh-CN";
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [pin, setPin] = useState("");
  const [replacement, setReplacement] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  useEffect(() => {
    const trigger = document.activeElement;
    const element = dialog.current;
    element?.showModal();
    return () => {
      element?.close();
      if (trigger instanceof HTMLElement) trigger.focus();
    };
  }, []);
  useEffect(() => {
    if (!retryAfter) return;
    const timer = window.setTimeout(
      () => setRetryAfter((value) => Math.max(0, value - 1)),
      1000,
    );
    return () => window.clearTimeout(timer);
  }, [retryAfter]);
  const mismatch =
    newPin && confirmation.length > 0 && replacement !== confirmation;
  return (
    <dialog
      ref={dialog}
      aria-labelledby={titleId}
      className="pin-action-dialog"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setBusy(true);
          setError(false);
          try {
            await onConfirm(pin, replacement);
            onClose();
          } catch (failure) {
            setError(true);
            setPin("");
            if (
              failure instanceof SecretBridgeApiError &&
              failure.status === 429
            )
              setRetryAfter(failure.retryAfterSeconds);
          } finally {
            setBusy(false);
          }
        }}
      >
        <header className="flex items-start justify-between gap-4 border-b border-slate-200 p-5">
          <div className="flex items-center gap-3">
            <KeyRound className="size-5 text-cyan-700" />
            <h2 id={titleId} className="m-0 text-lg font-semibold">
              {title}
            </h2>
          </div>
          <button
            type="button"
            className="workbench-button"
            aria-label={zh ? "关闭" : "Close"}
            disabled={busy}
            onClick={onClose}
          >
            <X className="size-4" />
          </button>
        </header>
        <div className="space-y-4 p-5">
          <p className="m-0 text-sm text-slate-600">
            {zh
              ? "仅在本机验证身份，请勿将 PIN 提供给 AI。"
              : "Verify your identity locally. Never share the PIN with an AI."}
          </p>
          {children}
          {currentPin && (
            <label className="block text-sm font-semibold">
              {verificationCode
                ? zh
                  ? "身份验证器验证码"
                  : "Authenticator code"
                : zh
                  ? "当前 PIN / 口令"
                  : "Current PIN / passphrase"}
              <input
                autoFocus
                required
                minLength={6}
                maxLength={verificationCode ? 6 : 64}
                type={verificationCode ? "text" : "password"}
                inputMode={verificationCode ? "numeric" : undefined}
                pattern={verificationCode ? "[0-9]{6}" : undefined}
                autoComplete={
                  verificationCode ? "one-time-code" : "current-password"
                }
                value={pin}
                onChange={(event) => setPin(event.target.value)}
                className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2.5"
              />
            </label>
          )}
          {newPin && (
            <>
              <label className="block text-sm font-semibold">
                {zh ? "新 PIN（至少 6 位）" : "New PIN (at least 6 characters)"}
                <input
                  required
                  minLength={6}
                  maxLength={64}
                  type="password"
                  autoComplete="new-password"
                  value={replacement}
                  onChange={(event) => setReplacement(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2.5"
                />
              </label>
              <label className="block text-sm font-semibold">
                {zh ? "再次输入新 PIN" : "Confirm new PIN"}
                <input
                  required
                  minLength={6}
                  maxLength={64}
                  type="password"
                  autoComplete="new-password"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2.5"
                />
              </label>
            </>
          )}
          <p
            role="status"
            aria-live="polite"
            className="m-0 min-h-12 text-sm text-rose-700"
          >
            {retryAfter > 0
              ? zh
                ? `请在 ${retryAfter} 秒后重试。`
                : `Try again in ${retryAfter} seconds.`
              : mismatch
                ? zh
                  ? "两次输入不一致。"
                  : "The PINs do not match."
                : error
                  ? zh
                    ? "验证或操作未完成，请检查 PIN 并重试。"
                    : "Verification or action failed. Check your PIN and retry."
                  : ""}
          </p>
        </div>
        <footer className="flex justify-end gap-3 border-t border-slate-200 bg-slate-50 p-5">
          <button
            type="button"
            className="workbench-button"
            disabled={busy}
            onClick={onClose}
          >
            {zh ? "取消" : "Cancel"}
          </button>
          <button
            className="workbench-primary"
            disabled={
              busy ||
              retryAfter > 0 ||
              (currentPin && pin.length < 6) ||
              (newPin &&
                (replacement.length < 6 || replacement !== confirmation))
            }
          >
            {busy
              ? zh
                ? "正在验证…"
                : "Verifying…"
              : zh
                ? "验证并继续"
                : "Verify and continue"}
          </button>
        </footer>
      </form>
    </dialog>
  );
}
