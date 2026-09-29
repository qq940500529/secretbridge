// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Approval } from "../../../api";

export interface ApprovalNoteDraft {
  approvalId: string;
  version: number;
  value: string;
}

export function noteForApproval(
  draft: ApprovalNoteDraft | null,
  approval: Pick<Approval, "id" | "version"> | undefined,
): string {
  return draft?.approvalId === approval?.id &&
    draft?.version === approval?.version
    ? (draft?.value ?? "")
    : "";
}
