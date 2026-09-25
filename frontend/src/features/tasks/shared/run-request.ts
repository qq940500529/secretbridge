// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Retain uncertain submissions until the server acknowledges their outcome. */
export class RunRequestKeys {
  private readonly pending = new Map<string, string>();

  constructor(
    private readonly generate: () => string = () => crypto.randomUUID(),
  ) {}

  forApproval(id: string): string {
    const existing = this.pending.get(id);
    if (existing) return existing;
    const key = this.generate();
    this.pending.set(id, key);
    return key;
  }

  acknowledge(id: string): void {
    this.pending.delete(id);
  }
}
