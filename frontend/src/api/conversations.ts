// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ConversationApprovalPolicy, AiConversation } from "./models";
import { readJson, sessionHeaders, sessionJsonHeaders } from "./transport";

export async function listAiConversations(
  sessionToken: string,
): Promise<{ items: AiConversation[] }> {
  return readJson(
    await fetch("/api/v1/ai-conversations", {
      cache: "no-store",
      credentials: "omit",
      headers: sessionHeaders(sessionToken),
    }),
  );
}

export async function setAiConversationPolicy(
  sessionToken: string,
  id: string,
  request: {
    expected_version: number;
    approval_policy: ConversationApprovalPolicy;
    risk_acknowledgement?: string;
  },
): Promise<AiConversation> {
  return readJson(
    await fetch(`/api/v1/ai-conversations/${encodeURIComponent(id)}/policy`, {
      method: "PUT",
      cache: "no-store",
      credentials: "omit",
      headers: sessionJsonHeaders(sessionToken),
      body: JSON.stringify(request),
    }),
  );
}
