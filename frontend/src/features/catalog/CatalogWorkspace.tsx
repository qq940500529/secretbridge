// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from "react";
import { SectionTabs } from "../../shared/ui/SectionTabs";
import { CredentialReferencesView } from "./credentials/CredentialReferencesView";
import { TargetsView } from "./targets/TargetsView";

export function CatalogWorkspace({
  language,
  sessionToken,
  onTask,
}: {
  language: "zh-CN" | "en";
  sessionToken: string;
  onTask: (targetId: string, templateId?: string) => void;
}) {
  const [section, setSection] = useState<"connections" | "credentials">(
    "connections",
  );
  return (
    <>
      <SectionTabs
        selected={section}
        onSelect={setSection}
        items={[
          {
            id: "connections",
            label: language === "zh-CN" ? "连接" : "Connections",
          },
          {
            id: "credentials",
            label: language === "zh-CN" ? "凭据" : "Credentials",
          },
        ]}
      />
      {section === "connections" ? (
        <TargetsView
          language={language}
          sessionToken={sessionToken}
          onTask={onTask}
          onCredentials={() => setSection("credentials")}
        />
      ) : (
        <CredentialReferencesView
          language={language}
          sessionToken={sessionToken}
        />
      )}
    </>
  );
}
