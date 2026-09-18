// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const sourceDirectory = dirname(fileURLToPath(import.meta.url));
const renderedViews = [
  "App.tsx",
  "ActionTemplatesView.tsx",
  "ApprovalView.tsx",
  "AuditView.tsx",
  "CatalogView.tsx",
  "OperationsView.tsx",
  "TerminalView.tsx",
  "CommandEditor.tsx",
  "CommandReview.tsx",
  "RunOutputView.tsx",
  "ParameterEditor.tsx",
  "ParameterFields.tsx",
  "HttpEditor.tsx",
  "SshEditor.tsx",
  "CredentialSecretInput.tsx",
];

describe("operator-facing copy", () => {
  it.each(renderedViews)("keeps development metadata out of %s", (fileName) => {
    const source = readFileSync(join(sourceDirectory, fileName), "utf8");

    expect(source).not.toMatch(/M\d+\s*·/u);
    expect(source).not.toContain("text.eyebrow");
    expect(source).not.toContain("release_stage");
  });
});
