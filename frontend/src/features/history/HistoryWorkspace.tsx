// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from "react";
import { AiConversationsView } from "../tasks/approvals/AiConversationsView";
import { SectionTabs } from "../../shared/ui/SectionTabs";
import { AuditView } from "./AuditView";
import { RunHistoryView } from "./RunHistoryView";

export function HistoryWorkspace({
  language,
  sessionToken,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
}) {
  const [section, setSection] = useState<"logs" | "runs" | "conversations">(
    "logs",
  );
  const [requestedRunId, setRequestedRunId] = useState<string | null>(null);
  return (
    <>
      <SectionTabs
        selected={section}
        onSelect={setSection}
        items={[
          { id: "logs", label: language === "zh-CN" ? "安全日志" : "Safe log" },
          {
            id: "runs",
            label: language === "zh-CN" ? "运行与终端" : "Runs & terminals",
          },
          {
            id: "conversations",
            label: language === "zh-CN" ? "AI 会话" : "AI conversations",
          },
        ]}
      />
      {section === "logs" ? (
        <AuditView
          language={language}
          sessionToken={sessionToken}
          onShowRun={(id) => {
            setRequestedRunId(id);
            setSection("runs");
          }}
        />
      ) : section === "runs" ? (
        <RunHistoryView
          language={language}
          sessionToken={sessionToken}
          requestedRunId={requestedRunId}
        />
      ) : (
        <AiConversationsView language={language} sessionToken={sessionToken} />
      )}
    </>
  );
}
