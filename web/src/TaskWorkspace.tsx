// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";
import { ActionTemplatesView } from "./ActionTemplatesView";
import { ApprovalView } from "./ApprovalView";
import { OperationsView } from "./OperationsView";
import { AuditView } from "./AuditView";
import { SectionTabs } from "./Workbench";

export function TaskWorkspace({
  language,
  sessionToken,
  templateId,
  targetId,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
  templateId?: string;
  targetId?: string;
}) {
  const [section, setSection] = useState<"templates" | "approvals" | "runs">(
    templateId ? "approvals" : "templates",
  );
  const [requested, setRequested] = useState<string | undefined>(templateId);
  const zh = language === "zh-CN";
  return (
    <>
      <SectionTabs
        selected={section}
        onSelect={setSection}
        items={[
          { id: "templates", label: zh ? "任务模板" : "Templates" },
          { id: "approvals", label: zh ? "授权确认" : "Authorization" },
          { id: "runs", label: zh ? "执行与结果" : "Execution & results" },
        ]}
      />
      {section === "templates" ? (
        <ActionTemplatesView
          language={language}
          sessionToken={sessionToken}
          initialTargetId={targetId}
          onRequest={(id) => {
            setRequested(id);
            setSection("approvals");
          }}
        />
      ) : section === "approvals" ? (
        <ApprovalView
          language={language}
          sessionToken={sessionToken}
          initialTemplateId={requested ?? templateId}
        />
      ) : (
        <OperationsView
          language={language}
          sessionToken={sessionToken}
          initialTemplateId={requested ?? templateId}
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
  const [section, setSection] = useState<"runs" | "events">("runs");
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
        ]}
      />
      {section === "runs" ? (
        <OperationsView
          language={language}
          sessionToken={sessionToken}
          historyOnly
        />
      ) : (
        <AuditView language={language} sessionToken={sessionToken} />
      )}
    </>
  );
}
