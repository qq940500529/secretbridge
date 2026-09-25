// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ServiceStatus } from "./models";
import { readJson } from "./transport";

export async function stopBroker(token: string): Promise<void> {
  const response = await fetch("/api/v1/runtime/stop", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (response.status !== 202) throw new Error("broker_stop_failed");
}

export async function getStatus(): Promise<ServiceStatus> {
  return readJson<ServiceStatus>(
    await fetch("/api/v1/status", {
      cache: "no-store",
      credentials: "omit",
    }),
  );
}
