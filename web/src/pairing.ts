// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export function readPairingToken(hash: string): string | null {
  if (!hash.startsWith("#")) {
    return null;
  }

  const token = new URLSearchParams(hash.slice(1)).get("pair")?.trim();
  return token || null;
}

export function urlWithoutFragment(
  pathname: string,
  search: string,
): string {
  return `${pathname}${search}`;
}

export function consumePairingToken(): string | null {
  const token = readPairingToken(window.location.hash);
  if (token) {
    window.history.replaceState(
      null,
      "",
      urlWithoutFragment(window.location.pathname, window.location.search),
    );
  }
  return token;
}
