// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from "react";

import {
  confirmTotpSetup,
  regenerateRecoveryKey,
  setBrowserAuthMethod,
  startTotpSetup,
  type CurrentBrowserAuthProof,
  type TotpSetup,
} from "../../api/index";
import type { Language } from "../../app/preferences";

export type AuthMethodStatus = "loading" | "ready" | "error";

export function BrowserAuthenticationSettings({
  language,
  sessionToken,
  pinEnabled,
  totpEnabled,
  authMethodStatus,
  onRetry,
  onChanged,
}: {
  language: Language;
  sessionToken: string;
  pinEnabled: boolean;
  totpEnabled: boolean;
  authMethodStatus: AuthMethodStatus;
  onRetry: () => void;
  onChanged: (method: "pairing_link" | "pin" | "totp") => void;
}) {
  const [pin, setPin] = useState("");
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [askTotp, setAskTotp] = useState(true);
  const [confirmation, setConfirmation] = useState<
    "pin" | "replace" | "disable" | null
  >(null);
  const [currentProof, setCurrentProof] = useState("");
  const [recoveryPin, setRecoveryPin] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const zh = language === "zh-CN";

  function proof(): CurrentBrowserAuthProof {
    if (pinEnabled) return { current_pin: currentProof };
    return {};
  }

  function clearConfirmation() {
    setConfirmation(null);
    setCurrentProof("");
  }

  async function savePin() {
    const current = proof();
    clearConfirmation();
    setBusy(true);
    setMessage(null);
    try {
      const result = await setBrowserAuthMethod(
        sessionToken,
        "pin",
        pin,
        current,
      );
      if (result?.recovery_key) setRecoveryKey(result.recovery_key);
      setPin("");
      onChanged("pin");
      setMessage(zh ? "PIN/口令已启用。" : "PIN/passphrase enabled.");
    } catch {
      setMessage(zh ? "保存失败。" : "Could not save.");
    } finally {
      setBusy(false);
    }
  }

  async function beginTotpSetup() {
    const current = proof();
    clearConfirmation();
    setBusy(true);
    setMessage(null);
    try {
      setTotpSetup(await startTotpSetup(sessionToken, current));
      setTotpCode("");
    } catch {
      setMessage(zh ? "无法开始绑定。" : "Could not start enrollment.");
    } finally {
      setBusy(false);
    }
  }

  async function disableTotp() {
    const current = proof();
    clearConfirmation();
    setBusy(true);
    setMessage(null);
    try {
      await setBrowserAuthMethod(
        sessionToken,
        "disable_totp",
        undefined,
        current,
      );
      onChanged("pin");
      setMessage(
        zh
          ? "已解除验证码绑定，PIN 保持有效。"
          : "Authenticator removed; the PIN remains active.",
      );
    } catch {
      setMessage(zh ? "修改失败。" : "Could not change the method.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="mt-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="m-0 text-lg font-semibold text-slate-950">
        {zh ? "浏览器身份验证" : "Browser identity verification"}
      </h2>
      <p className="text-sm leading-6 text-slate-600">
        {zh
          ? "PIN/口令至少 6 位，建议使用更长且不易猜测的口令。连续错误会逐级延长等待时间；遗失 PIN 时可用安全保存的恢复密钥重置，并继续解锁旧诊断记录。请勿向 AI 提供 PIN、恢复密钥或身份验证器密钥。"
          : "A PIN/passphrase needs at least 6 characters; a longer, hard-to-guess passphrase is safer. Repeated failures increase the waiting time. A securely saved recovery key can reset a lost PIN while preserving encrypted diagnostics. Never share it, your PIN or authenticator key with an AI."}
      </p>
      {authMethodStatus === "loading" && (
        <p role="status" className="text-sm text-slate-600">
          {zh ? "正在检查身份验证方式…" : "Checking verification methods…"}
        </p>
      )}
      {authMethodStatus === "error" && (
        <div role="alert" className="text-sm text-rose-700">
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
      {authMethodStatus === "ready" && (
        <p role="status" className="text-sm font-medium text-slate-700">
          {totpEnabled
            ? zh
              ? "已设置 PIN，并绑定身份验证器"
              : "PIN set; authenticator configured"
            : pinEnabled
              ? zh
                ? "已设置 PIN/口令"
                : "PIN/passphrase configured"
              : zh
                ? "初始化待完成：请先设置 PIN"
                : "Initialization pending: set a PIN"}
        </p>
      )}
      {authMethodStatus === "ready" && (
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            type="password"
            minLength={6}
            maxLength={64}
            value={pin}
            onChange={(event) => setPin(event.target.value)}
            placeholder={zh ? "至少 6 位" : "At least 6 characters"}
            className="min-w-0 flex-1 rounded-xl border border-slate-200 px-3.5 py-2.5"
          />
          <button
            type="button"
            disabled={busy || pin.length < 6}
            className="workbench-button"
            onClick={() => {
              if (pinEnabled || totpEnabled) setConfirmation("pin");
              else void savePin();
            }}
          >
            {zh ? "设置或更换" : "Set or change"}
          </button>
          <button
            type="button"
            disabled={busy || !pinEnabled}
            className="workbench-button"
            onClick={() => {
              if (pinEnabled || totpEnabled) setConfirmation("replace");
              else void beginTotpSetup();
            }}
          >
            {totpEnabled
              ? zh
                ? "更换身份验证器"
                : "Replace authenticator"
              : zh
                ? "绑定身份验证器"
                : "Add authenticator"}
          </button>
          {totpEnabled && (
            <button
              type="button"
              disabled={busy}
              className="workbench-button"
              onClick={() => setConfirmation("disable")}
            >
              {zh ? "解除验证码绑定" : "Remove authenticator"}
            </button>
          )}
        </div>
      )}
      {askTotp && pinEnabled && !totpEnabled && (
        <div className="mt-4 rounded-xl border border-cyan-300 bg-cyan-50 p-4 text-sm">
          <p className="mt-0 font-semibold">
            {zh
              ? "是否再绑定身份验证器验证码？"
              : "Would you also like to add an authenticator?"}
          </p>
          <p>
            {zh
              ? "可以增强浏览器登录验证；PIN 仍是诊断记录的解锁密码。"
              : "It adds another browser sign-in option. Your PIN remains the diagnostic unlock password."}
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              className="workbench-button"
              onClick={() => {
                setAskTotp(false);
                setConfirmation("replace");
              }}
            >
              {zh ? "绑定验证码" : "Add authenticator"}
            </button>
            <button
              type="button"
              className="workbench-button"
              onClick={() => setAskTotp(false)}
            >
              {zh ? "暂不绑定" : "Not now"}
            </button>
          </div>
        </div>
      )}
      {confirmation && (
        <div
          role="alert"
          className="mt-4 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950"
        >
          <p className="mt-0">
            {confirmation === "disable"
              ? zh
                ? "确认解除验证码绑定？PIN 仍用于登录和解锁诊断记录。"
                : "Remove the authenticator? Your PIN still signs you in and unlocks diagnostics."
              : zh
                ? "请使用当前 PIN 确认更改。更换 PIN 会重新加密诊断解锁密钥。"
                : "Confirm with your current PIN. Changing it rewraps the diagnostic unlock key."}
          </p>
          {pinEnabled && (
            <input
              type="password"
              aria-label={zh ? "当前 PIN/口令" : "Current PIN/passphrase"}
              value={currentProof}
              onChange={(event) => setCurrentProof(event.target.value)}
              minLength={6}
              maxLength={64}
              autoComplete="off"
              className="mb-3 w-full rounded-xl border border-amber-300 bg-white px-3.5 py-2.5"
            />
          )}
          <div className="flex gap-3">
            <button
              type="button"
              disabled={busy || (pinEnabled && currentProof.length < 6)}
              className="workbench-button"
              onClick={() => {
                if (confirmation === "pin") void savePin();
                else if (confirmation === "replace") void beginTotpSetup();
                else void disableTotp();
              }}
            >
              {zh ? "确认更改" : "Confirm change"}
            </button>
            <button
              type="button"
              disabled={busy}
              className="workbench-button"
              onClick={clearConfirmation}
            >
              {zh ? "取消" : "Cancel"}
            </button>
          </div>
        </div>
      )}
      {totpSetup && (
        <div className="mt-5 grid gap-5 rounded-2xl border border-cyan-200 bg-cyan-50/60 p-5 md:grid-cols-[auto_1fr]">
          <img
            src={totpSetup.qr_code_data_url}
            alt={
              zh
                ? "SecretBridge 身份验证器绑定二维码"
                : "SecretBridge authenticator enrollment QR code"
            }
            className="size-52 rounded-xl border border-white bg-white p-2 shadow-sm"
          />
          <div>
            <h3 className="m-0 text-base font-semibold text-slate-950">
              {zh ? "扫码或手动输入密钥" : "Scan or enter the key manually"}
            </h3>
            <p className="text-sm leading-6 text-slate-600">
              {zh
                ? "在身份验证器中添加基于时间的一次性密码（TOTP），然后输入生成的六位验证码完成绑定。绑定内容将在十分钟后失效。"
                : "Add a time-based one-time password (TOTP) in your authenticator, then enter its six-digit code. This enrollment expires after ten minutes."}
            </p>
            <code className="block break-all rounded-lg bg-white px-3 py-2 text-sm font-semibold tracking-wider text-slate-900">
              {totpSetup.manual_key.match(/.{1,4}/g)?.join(" ")}
            </code>
            <div className="mt-3 flex flex-col gap-3 sm:flex-row">
              <input
                aria-label={zh ? "六位验证码" : "Six-digit code"}
                value={totpCode}
                onChange={(event) =>
                  setTotpCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                }
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoComplete="one-time-code"
                className="rounded-xl border border-slate-200 px-3.5 py-2.5"
                placeholder={zh ? "六位验证码" : "Six-digit code"}
              />
              <button
                type="button"
                disabled={busy || totpCode.length !== 6}
                className="workbench-button"
                onClick={async () => {
                  setBusy(true);
                  setMessage(null);
                  try {
                    await confirmTotpSetup(sessionToken, totpCode);
                    setTotpSetup(null);
                    setTotpCode("");
                    onChanged("totp");
                    setMessage(
                      zh
                        ? "身份验证器已启用。验证码允许约两分钟的提交延迟，且每个验证码只能使用一次。"
                        : "Authenticator enabled. Codes allow roughly two minutes of submission delay and can be used only once.",
                    );
                  } catch {
                    setMessage(
                      zh
                        ? "验证码无效、已使用或绑定已过期，请重新开始绑定。"
                        : "The code was invalid, already used, or enrollment expired. Start enrollment again.",
                    );
                    setTotpSetup(null);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {zh ? "验证并启用" : "Verify and enable"}
              </button>
            </div>
          </div>
        </div>
      )}
      {pinEnabled && (
        <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-5">
          <h3 className="m-0 text-base font-semibold text-slate-950">
            {zh ? "恢复密钥" : "Recovery key"}
          </h3>
          <p className="text-sm leading-6 text-slate-600">
            {zh
              ? "无法重新查看旧密钥。若需替换，请输入当前 PIN 生成新密钥；旧密钥随即失效。"
              : "The existing key cannot be viewed again. Enter your current PIN to generate a replacement; the old key stops working immediately."}
          </p>
          {!recoveryKey && (
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                aria-label={
                  zh
                    ? "用于更换恢复密钥的当前 PIN"
                    : "Current PIN for recovery key replacement"
                }
                type="password"
                minLength={6}
                maxLength={64}
                autoComplete="current-password"
                value={recoveryPin}
                onChange={(event) => setRecoveryPin(event.target.value)}
                className="min-w-0 flex-1 rounded-xl border border-slate-200 px-3.5 py-2.5"
              />
              <button
                type="button"
                disabled={busy || recoveryPin.length < 6}
                className="workbench-button"
                onClick={async () => {
                  setBusy(true);
                  setMessage(null);
                  try {
                    const result = await regenerateRecoveryKey(
                      sessionToken,
                      recoveryPin,
                    );
                    setRecoveryKey(result.recovery_key);
                    setRecoveryPin("");
                  } catch {
                    setMessage(
                      zh
                        ? "无法更新恢复密钥。"
                        : "Could not replace the recovery key.",
                    );
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {zh ? "生成新密钥" : "Generate new key"}
              </button>
            </div>
          )}
          {recoveryKey && (
            <div className="mt-3 rounded-xl border border-amber-300 bg-amber-50 p-4">
              <p className="mt-0 text-sm font-semibold text-amber-950">
                {zh
                  ? "请立即保存到安全位置；离开此页后无法再次查看。"
                  : "Save this in a secure place now; it cannot be viewed again after leaving."}
              </p>
              <code className="block break-all rounded-lg bg-slate-950 p-3 font-mono text-sm text-cyan-100 select-all">
                {recoveryKey}
              </code>
              <button
                type="button"
                className="workbench-button mt-3"
                onClick={() => setRecoveryKey(null)}
              >
                {zh ? "我已安全保存" : "I saved it securely"}
              </button>
            </div>
          )}
        </div>
      )}
      {message && <p className="mb-0 mt-3 text-sm text-slate-600">{message}</p>}
    </section>
  );
}
