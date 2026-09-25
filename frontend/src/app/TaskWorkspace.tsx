// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { ActionTemplatesView } from "../features/tasks/templates/ActionTemplatesView";
import { ApprovalView } from "../features/tasks/approvals/ApprovalView";
import { OperationsView } from "../features/tasks/runs/OperationsView";

export function TaskWorkspace({
  language,
  sessionToken,
  templateId,
  targetId,
  section,
  onRequestTemplate,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
  templateId?: string;
  targetId?: string;
  section: "templates" | "approvals" | "runs";
  onRequestTemplate: (id: string) => void;
}) {
  return (
    <>
      {section === "templates" ? (
        <ActionTemplatesView
          language={language}
          sessionToken={sessionToken}
          initialTargetId={targetId}
          onRequest={onRequestTemplate}
        />
      ) : section === "approvals" ? (
        <ApprovalView
          language={language}
          sessionToken={sessionToken}
          initialTemplateId={templateId}
        />
      ) : (
        <OperationsView
          language={language}
          sessionToken={sessionToken}
          initialTemplateId={templateId}
        />
      )}
    </>
  );
}
