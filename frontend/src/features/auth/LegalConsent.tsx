// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ExternalLink, Languages, Scale, ShieldAlert, X } from "lucide-react";
import { useEffect, useState } from "react";

import { legalCopy, type LegalSection } from "./legal-copy";
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
  onLanguageChange: (language: Language) => void;
  onAccept: () => void;
  onClose: () => void;
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
  onLanguageChange,
  onAccept,
  onClose,
}: LegalConsentProps) {
  const [acknowledged, setAcknowledged] = useState(false);
  const text = legalCopy[language];

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
      <div className="flex max-h-dvh w-full max-w-5xl flex-col overflow-hidden bg-white shadow-2xl sm:max-h-[calc(100dvh-3rem)] sm:rounded-2xl">
        <header className="border-b border-slate-200 bg-gradient-to-r from-slate-950 to-cyan-950 px-5 py-5 text-white sm:px-8">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">
                <Scale className="size-4" aria-hidden="true" />
                SecretBridge Beta
              </div>
              <h1
                id="legal-consent-title"
                className="m-0 text-2xl font-bold tracking-tight sm:text-3xl"
              >
                {text.title}
              </h1>
              <p
                id="legal-consent-introduction"
                className="mb-0 mt-3 max-w-3xl text-sm leading-6 text-slate-200"
              >
                {text.introduction}
              </p>
            </div>
            {canClose && (
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

        <div className="overflow-y-auto px-5 py-6 sm:px-8">
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
        </div>

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
                onClick={onAccept}
              >
                {text.accept}
              </button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}
