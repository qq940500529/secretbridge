// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  KeyRound,
  Languages,
  ShieldAlert,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";

import { legalCopy, type LegalSection } from "./legal-copy";
import { setBrowserAuthMethod } from "../../api";
import type { Language } from "../../app/preferences";

export const ISSUE_URL =
  "https://github.com/qq940500529/secretbridge/issues/new?template=bug_report.md";
export const SECURITY_URL =
  "https://github.com/qq940500529/secretbridge/security/advisories/new";
export const LICENSING_URL =
  "https://github.com/qq940500529/secretbridge/blob/main/LICENSING.md";

interface LegalConsentProps {
  language: Language;
  canClose: boolean;
  requiresPinSetup: boolean;
  sessionToken: string | null;
  onLanguageChange: (language: Language) => void;
  onAccept: () => void;
  onClose: () => void;
  onInitialized: () => Promise<void>;
}

function Sections({ sections }: { sections: LegalSection[] }) {
  return sections.map((section) => (
    <section key={section.title} className="border-t border-slate-200 py-5">
      <h3 className="m-0 text-base font-semibold text-slate-900">
        {section.title}
      </h3>
      {section.paragraphs.map((paragraph) => (
        <p
          key={paragraph}
          className="mb-0 mt-3 text-sm leading-6 text-slate-600"
        >
          {paragraph}
        </p>
      ))}
    </section>
  ));
}

export function LegalConsent({
  language,
  canClose,
  requiresPinSetup,
  sessionToken,
  onLanguageChange,
  onAccept,
  onClose,
  onInitialized,
}: LegalConsentProps) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [step, setStep] = useState<"legal" | "pin">(
    canClose && requiresPinSetup && sessionToken ? "pin" : "legal",
  );
  const [pin, setPin] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [recoverySaved, setRecoverySaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const text = legalCopy[language];
  const zh = language === "zh-CN";
  const confirmationMismatch = confirmation.length > 0 && pin !== confirmation;

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, []);

  return (
    <div
      className="fixed inset-0 z-[100] grid place-items-center bg-slate-950/75 p-0 backdrop-blur-sm sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="legal-consent-title"
      aria-describedby="legal-consent-introduction"
    >
      <div
        className={`flex max-h-dvh w-full flex-col overflow-hidden bg-white shadow-2xl sm:max-h-[calc(100dvh-3rem)] sm:rounded-2xl ${
          step === "pin"
            ? "h-dvh max-w-2xl sm:h-[min(42rem,calc(100dvh-3rem))]"
            : "max-w-5xl"
        }`}
      >
        <header className="shrink-0 border-b border-slate-200 bg-gradient-to-r from-slate-950 to-cyan-950 px-5 py-5 text-white sm:px-8">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">
                <img
                  src="/secretbridge-logo.png"
                  alt=""
                  className="size-5 rounded-md"
                  aria-hidden="true"
                />
                {zh ? "秘桥 · SecretBridge Beta" : "SecretBridge Beta"}
              </div>
              <h1
                id="legal-consent-title"
                className="m-0 text-2xl font-bold tracking-tight sm:text-3xl"
              >
                {step === "legal"
                  ? text.title
                  : zh
                    ? "设置本机 PIN"
                    : "Set a local PIN"}
              </h1>
              <p
                id="legal-consent-introduction"
                className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-200"
              >
                {step === "legal"
                  ? text.introduction
                  : zh
                    ? "完成初始化后，PIN 用于本机登录和解锁加密诊断。恢复密钥仅显示一次。"
                    : "The PIN signs you in locally and unlocks encrypted diagnostics. Your recovery key is shown only once."}
              </p>
            </div>
            {canClose &&
              (step === "legal" || (!sessionToken && !recoveryKey)) && (
                <button
                  type="button"
                  onClick={onClose}
                  className="grid size-10 shrink-0 place-items-center rounded-lg border border-white/20 text-slate-200 hover:bg-white/10 hover:text-white"
                  aria-label={text.close}
                >
                  <X className="size-5" aria-hidden="true" />
                </button>
              )}
          </div>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-2 text-sm font-medium text-slate-200">
              <Languages className="size-4" aria-hidden="true" />
              {text.languageLabel}
            </span>
            <div className="inline-flex rounded-lg border border-white/20 bg-white/5 p-1">
              {(["zh-CN", "en"] as const).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => onLanguageChange(option)}
                  className={`rounded-md px-3 py-1.5 text-sm font-semibold transition ${
                    language === option
                      ? "bg-white text-slate-950"
                      : "text-slate-200 hover:bg-white/10"
                  }`}
                  aria-pressed={language === option}
                >
                  {option === "zh-CN" ? "简体中文" : "English"}
                </button>
              ))}
            </div>
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-6 sm:px-8">
          {step === "legal" ? (
            <>
              <div className="mb-6 flex gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-amber-950">
                <ShieldAlert
                  className="mt-0.5 size-5 shrink-0"
                  aria-hidden="true"
                />
                <p className="m-0 text-sm font-medium leading-6">
                  {text.prerelease}
                </p>
              </div>

              <article>
                <h2 className="mb-2 mt-0 text-xl font-bold text-slate-950">
                  {text.licenseHeading}
                </h2>
                <Sections sections={text.licenseSections} />
              </article>
              <article className="mt-7">
                <h2 className="mb-2 mt-0 text-xl font-bold text-slate-950">
                  {text.disclaimerHeading}
                </h2>
                <Sections sections={text.disclaimerSections} />
              </article>

              <div className="mt-7 rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex flex-wrap gap-x-5 gap-y-3 text-sm font-semibold">
                  <a
                    href={LICENSING_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-cyan-800 hover:text-cyan-950"
                  >
                    {text.sourceLicense}
                    <ExternalLink className="size-3.5" aria-hidden="true" />
                  </a>
                  <a
                    href={ISSUE_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-cyan-800 hover:text-cyan-950"
                  >
                    {text.feedback}
                    <ExternalLink className="size-3.5" aria-hidden="true" />
                  </a>
                  <a
                    href={SECURITY_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 text-cyan-800 hover:text-cyan-950"
                  >
                    {text.security}
                    <ExternalLink className="size-3.5" aria-hidden="true" />
                  </a>
                </div>
                <p className="mb-0 mt-3 text-xs leading-5 text-slate-500">
                  {text.privacyNote}
                </p>
              </div>
            </>
          ) : (
            <div className="mx-auto max-w-xl py-1">
              <div className="mb-5 flex items-center gap-3 text-sm font-semibold text-cyan-800">
                <span className="grid size-10 place-items-center rounded-xl bg-cyan-50">
                  <KeyRound className="size-5" />
                </span>
                {zh ? "首次运行 · 身份保护" : "First run · Identity protection"}
              </div>
              {!recoveryKey ? (
                <form
                  className="space-y-4"
                  onSubmit={async (event) => {
                    event.preventDefault();
                    if (
                      !sessionToken ||
                      pin.length < 6 ||
                      pin.length > 64 ||
                      pin !== confirmation
                    )
                      return;
                    setBusy(true);
                    setError(false);
                    try {
                      const result = await setBrowserAuthMethod(
                        sessionToken,
                        "pin",
                        pin,
                      );
                      if (!result?.recovery_key)
                        throw new Error("missing_recovery_key");
                      setRecoveryKey(result.recovery_key);
                      setPin("");
                      setConfirmation("");
                    } catch {
                      setError(true);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <div className="rounded-xl border border-cyan-200 bg-cyan-50/70 px-5 py-4">
                    <h2 className="m-0 text-lg font-bold text-slate-950">
                      {zh ? "创建 PIN" : "Create your PIN"}
                    </h2>
                    <p className="mb-0 mt-2 text-sm leading-6 text-slate-600">
                      {zh
                        ? "至少 6 位，最多 64 位；可以使用数字、字母和符号。较长的口令更能抵御设备数据被复制后的离线猜测。"
                        : "Use 6–64 characters: digits, letters and symbols are allowed. A longer passphrase better resists offline guessing if device data is copied."}
                    </p>
                  </div>
                  <label className="block text-sm font-semibold text-slate-800">
                    {zh ? "PIN / 口令" : "PIN / passphrase"}
                    <input
                      type="password"
                      autoComplete="new-password"
                      minLength={6}
                      maxLength={64}
                      required
                      value={pin}
                      onChange={(event) => {
                        setPin(event.target.value);
                        setError(false);
                      }}
                      className="mt-2 w-full rounded-xl border border-slate-300 px-4 py-3 focus:border-cyan-600 focus:outline-none focus:ring-2 focus:ring-cyan-100"
                    />
                  </label>
                  <label className="block text-sm font-semibold text-slate-800">
                    {zh ? "再次输入 PIN" : "Confirm PIN"}
                    <input
                      type="password"
                      autoComplete="new-password"
                      minLength={6}
                      maxLength={64}
                      required
                      value={confirmation}
                      aria-invalid={confirmationMismatch}
                      aria-describedby="pin-confirmation-feedback"
                      onChange={(event) => {
                        setConfirmation(event.target.value);
                        setError(false);
                      }}
                      className="mt-2 w-full rounded-xl border border-slate-300 px-4 py-3 focus:border-cyan-600 focus:outline-none focus:ring-2 focus:ring-cyan-100"
                    />
                  </label>
                  <div
                    id="pin-confirmation-feedback"
                    aria-live="polite"
                    className="min-h-6 text-sm leading-6 text-rose-700"
                  >
                    {confirmationMismatch
                      ? zh
                        ? "两次输入不一致，请核对后重试。"
                        : "The PINs do not match. Please check and try again."
                      : error
                        ? zh
                          ? "设置失败，请检查本机服务后重试。"
                          : "Setup failed. Check the local service and try again."
                        : null}
                  </div>
                  <button
                    type="submit"
                    disabled={
                      busy ||
                      !sessionToken ||
                      pin.length < 6 ||
                      pin !== confirmation
                    }
                    className="workbench-primary inline-flex items-center gap-2"
                  >
                    {busy
                      ? zh
                        ? "正在设置…"
                        : "Setting up…"
                      : zh
                        ? "设置 PIN 并生成恢复密钥"
                        : "Set PIN and create recovery key"}
                    {!busy && <ArrowRight className="size-4" />}
                  </button>
                </form>
              ) : (
                <div className="space-y-5">
                  <div className="rounded-2xl border border-amber-300 bg-amber-50 p-5">
                    <h2 className="m-0 text-lg font-bold text-amber-950">
                      {zh ? "立即保存恢复密钥" : "Save your recovery key now"}
                    </h2>
                    <p className="mb-0 mt-2 text-sm leading-6 text-amber-900">
                      {zh
                        ? "它只显示这一次。请存入可信密码管理器或离线安全位置；不要发给 AI，也不要保存在普通聊天或截图中。遗失 PIN 时可用它重置，重置后会生成新的恢复密钥。"
                        : "This key is shown only once. Keep it in a trusted password manager or secure offline place; never send it to an AI or ordinary chat. It resets a lost PIN and is rotated after use."}
                    </p>
                  </div>
                  <code
                    aria-label={zh ? "恢复密钥" : "Recovery key"}
                    className="block break-all rounded-2xl border border-slate-200 bg-slate-950 p-5 font-mono text-base leading-7 tracking-widest text-cyan-100 select-all"
                  >
                    {recoveryKey}
                  </code>
                  <label className="flex items-start gap-3 text-sm leading-6 text-slate-700">
                    <input
                      type="checkbox"
                      checked={recoverySaved}
                      onChange={(event) =>
                        setRecoverySaved(event.target.checked)
                      }
                      className="mt-1 size-4 accent-cyan-700"
                    />
                    {zh
                      ? "我已将恢复密钥保存到安全位置，并理解关闭后无法再次查看。"
                      : "I saved the recovery key securely and understand it cannot be viewed again."}
                  </label>
                  <button
                    type="button"
                    disabled={!recoverySaved || busy}
                    className="workbench-primary inline-flex items-center gap-2"
                    onClick={async () => {
                      setBusy(true);
                      await onInitialized();
                      setBusy(false);
                    }}
                  >
                    <CheckCircle2 className="size-4" />
                    {zh ? "完成初始化" : "Finish setup"}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {step === "legal" && (
          <footer className="border-t border-slate-200 bg-white px-5 py-4 sm:px-8">
            {!canClose && (
              <label className="mb-4 flex cursor-pointer items-start gap-3 text-sm leading-6 text-slate-700">
                <input
                  autoFocus
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(event) => setAcknowledged(event.target.checked)}
                  className="mt-1 size-4 shrink-0 accent-cyan-700"
                />
                <span>{text.acknowledgement}</span>
              </label>
            )}
            <div className="flex justify-end gap-3">
              {canClose ? (
                <button
                  type="button"
                  className="workbench-primary"
                  onClick={onClose}
                >
                  {text.close}
                </button>
              ) : (
                <button
                  type="button"
                  className="workbench-primary"
                  disabled={!acknowledged}
                  onClick={() => {
                    onAccept();
                    if (requiresPinSetup && sessionToken) setStep("pin");
                    else onClose();
                  }}
                >
                  {text.accept}
                </button>
              )}
            </div>
          </footer>
        )}
      </div>
    </div>
  );
}
