// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { ActionTemplatesView } from "./ActionTemplatesView";
import { ApprovalView } from "./ApprovalView";
import { OperationsView } from "./OperationsView";
import { AuditView } from "./AuditView";
import { AiConversationsView } from "./AiConversationsView";
import { SectionTabs } from "./Workbench";

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

export function HistoryWorkspace({
  language,
  sessionToken,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
}) {
  const [section, setSection] = useState<"runs" | "events" | "conversations">(
    "runs",
  );
  return (
    <>
      <SectionTabs
        selected={section}
        onSelect={setSection}
        items={[
          {
            id: "runs",
            label: language === "zh-CN" ? "执行历史" : "Run history",
          },
          { id: "events", label: language === "zh-CN" ? "事件记录" : "Events" },
          {
            id: "conversations",
            label: language === "zh-CN" ? "AI 会话" : "AI conversations",
          },
        ]}
      />
      {section === "runs" ? (
        <OperationsView
          language={language}
          sessionToken={sessionToken}
          historyOnly
        />
      ) : section === "events" ? (
        <AuditView language={language} sessionToken={sessionToken} />
      ) : (
        <AiConversationsView language={language} sessionToken={sessionToken} />
      )}
    </>
  );
}
