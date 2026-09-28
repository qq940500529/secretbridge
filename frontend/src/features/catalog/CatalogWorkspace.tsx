// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { ResourcesView } from "./ResourcesView";
export function CatalogWorkspace(props: {
  language: "zh-CN" | "en";
  sessionToken: string;
  onTask: (targetId: string, templateId?: string) => void;
}) {
  return <ResourcesView {...props} />;
}
