// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

export function parseTerminalEnvironment(
  source: string,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of source.split(/\r?\n/)) {
    if (!rawLine.trim()) continue;
    const separator = rawLine.indexOf("=");
    const name = separator < 0 ? "" : rawLine.slice(0, separator).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new Error("invalid environment variable");
    }
    result[name] = rawLine.slice(separator + 1);
  }
  return result;
}
