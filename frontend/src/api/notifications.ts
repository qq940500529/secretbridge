// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ApprovalNotificationChannel } from "./models";
import { readJson, sessionHeaders, sessionJsonHeaders } from "./transport";

export async function getApprovalNotificationSettings(
  token: string,
): Promise<{ channel: ApprovalNotificationChannel }> {
  return readJson(
    await fetch("/api/v1/notification-settings", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(token),
    }),
  );
}

export async function setApprovalNotificationSettings(
  token: string,
  channel: ApprovalNotificationChannel,
): Promise<{ channel: ApprovalNotificationChannel }> {
  return readJson(
    await fetch("/api/v1/notification-settings", {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(token),
      body: JSON.stringify({ channel }),
    }),
  );
}

export async function setBrokerLanguage(
  sessionToken: string,
  language: "en" | "zh-CN",
): Promise<void> {
  await readJson(
    await fetch("/api/v1/preferences/language", {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify({ language }),
    }),
  );
}
