// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const sourceDirectory = dirname(fileURLToPath(import.meta.url));
const renderedViews = [
  "App.tsx",
  "../features/tasks/templates/ActionTemplatesView.tsx",
  "../features/tasks/approvals/ApprovalView.tsx",
  "../features/history/AuditView.tsx",
  "../features/catalog/CatalogView.tsx",
  "../features/tasks/runs/OperationsView.tsx",
  "../features/terminal/TerminalView.tsx",
  "../features/tasks/templates/editors/CommandEditor.tsx",
  "../features/tasks/shared/CommandReview.tsx",
  "../features/tasks/runs/RunOutputView.tsx",
  "../features/tasks/templates/ParameterEditor.tsx",
  "../features/tasks/approvals/ParameterFields.tsx",
  "../features/tasks/templates/editors/HttpEditor.tsx",
  "../features/tasks/templates/editors/SshEditor.tsx",
  "../features/tasks/templates/editors/TelnetEditor.tsx",
  "../features/catalog/credentials/CredentialSecretInput.tsx",
  "../shared/ui/EditorDialog.tsx",
  "../shared/ui/MasterDetail.tsx",
  "../shared/ui/SectionTabs.tsx",
  "../features/history/HistoryWorkspace.tsx",
  "TaskWorkspace.tsx",
  "../features/catalog/targets/ConnectionRelations.tsx",
  "../features/settings/DataMaintenanceView.tsx",
  "../features/auth/LegalConsent.tsx",
  "../features/auth/legal-copy.ts",
  "../features/settings/SettingsView.tsx",
];

describe("operator-facing copy", () => {
  it.each(renderedViews)("keeps development metadata out of %s", (fileName) => {
    const source = readFileSync(join(sourceDirectory, fileName), "utf8");

    expect(source).not.toMatch(/M\d+\s*·/u);
    expect(source).not.toContain("text.eyebrow");
    expect(source).not.toContain("release_stage");
  });
});
