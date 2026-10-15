// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  getActionTemplate,
  type ActionTemplate,
  type Approval,
  type ApprovalOperation,
} from "../../../api/index";

type Language = "zh-CN" | "en";

export const operationLabels: Record<
  Language,
  Record<ApprovalOperation, string>
> = {
  "zh-CN": {
    inspect_metadata: "查看非秘密元数据",
    synthetic_health_check: "合成健康检查",
    postgres_connection_check: "PostgreSQL 只读连接检查",
    command_execution: "凭据任务",
  },
  en: {
    inspect_metadata: "Inspect non-secret metadata",
    synthetic_health_check: "Synthetic health check",
    postgres_connection_check: "PostgreSQL read-only connection check",
    command_execution: "Credential task",
  },
};

export function operationDisplayName(
  item: { action_template_id: string | null; operation: ApprovalOperation },
  templates: ReadonlyMap<string, ActionTemplate>,
  language: Language,
): string {
  if (!item.action_template_id)
    return operationLabels[language][item.operation];
  const template = templates.get(item.action_template_id);
  if (!template)
    return language === "zh-CN"
      ? "已移除的操作模板"
      : "Removed operation template";
  if (!template.one_time) return template.name;
  if (template.command?.ssh)
    return language === "zh-CN" ? "一次性 SSH 命令" : "One-time SSH command";
  return language === "zh-CN"
    ? `一次性操作 · ${operationLabels[language][item.operation]}`
    : `One-time operation · ${operationLabels[language][item.operation]}`;
}

// Drafts are deliberately absent from the saved-template catalog. Resolve only
// referenced active approvals, retaining saved entries and tolerating deletion.
export async function includeApprovalDrafts(
  sessionToken: string,
  approvals: Approval[],
  saved: ActionTemplate[],
): Promise<ActionTemplate[]> {
  const known = new Set(saved.map((template) => template.id));
  const missing = [
    ...new Set(
      approvals
        .filter((item) => item.state === "pending" || item.state === "approved")
        .map((item) => item.action_template_id)
        .filter((id): id is string => !!id && !known.has(id)),
    ),
  ];
  const fetched = await Promise.allSettled(
    missing.map((id) => getActionTemplate(sessionToken, id)),
  );
  return [
    ...saved,
    ...fetched
      .filter(
        (result): result is PromiseFulfilledResult<ActionTemplate> =>
          result.status === "fulfilled",
      )
      .map((result) => result.value),
  ];
}
