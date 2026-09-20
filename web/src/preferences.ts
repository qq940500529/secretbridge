// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export type Language = "zh-CN" | "en";

export const LEGAL_CONSENT_VERSION = "2026-09-beta-1";

const LANGUAGE_KEY = "secretbridge.language.v1";
const LEGAL_CONSENT_KEY = "secretbridge.legal-consent.v1";

type PreferenceStorage = Pick<Storage, "getItem" | "setItem">;

function availableStorage(): PreferenceStorage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

export function systemLanguage(browserLanguage: string): Language {
  return browserLanguage.toLowerCase().startsWith("zh") ? "zh-CN" : "en";
}

export function initialLanguage(
  storage: PreferenceStorage | undefined = availableStorage(),
  browserLanguage = navigator.language,
): Language {
  try {
    const stored = storage?.getItem(LANGUAGE_KEY);
    if (stored === "zh-CN" || stored === "en") return stored;
  } catch {
    // Browser privacy settings can disable storage. System language remains usable.
  }
  return systemLanguage(browserLanguage);
}

export function storeLanguage(
  language: Language,
  storage: PreferenceStorage | undefined = availableStorage(),
): void {
  try {
    storage?.setItem(LANGUAGE_KEY, language);
  } catch {
    // A language switch must still work for this page when storage is disabled.
  }
}

export function hasCurrentLegalConsent(
  storage: PreferenceStorage | undefined = availableStorage(),
): boolean {
  try {
    return storage?.getItem(LEGAL_CONSENT_KEY) === LEGAL_CONSENT_VERSION;
  } catch {
    return false;
  }
}

export function storeLegalConsent(
  storage: PreferenceStorage | undefined = availableStorage(),
): void {
  try {
    storage?.setItem(LEGAL_CONSENT_KEY, LEGAL_CONSENT_VERSION);
  } catch {
    // Consent stays valid for the current page even when persistence is unavailable.
  }
}
