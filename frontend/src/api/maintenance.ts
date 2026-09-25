// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import type {
  ConfigurationBundle,
  ImportReport,
  BackupReport,
  Diagnostics,
  DiagnosticExport,
} from "./models";
import {
  requireOk,
  readJson,
  sessionHeaders,
  sessionJsonHeaders,
} from "./transport";

async function maintenanceJson<T>(
  token: string,
  path: string,
  payload?: unknown,
): Promise<T> {
  return readJson<T>(
    await fetch(`/api/v1/maintenance/${path}`, {
      method: payload === undefined ? "GET" : "POST",
      credentials: "omit",
      cache: "no-store",
      headers:
        payload === undefined
          ? sessionHeaders(token)
          : sessionJsonHeaders(token),
      body: payload === undefined ? undefined : JSON.stringify(payload),
    }),
  );
}

export const exportConfiguration = (token: string) =>
  maintenanceJson<ConfigurationBundle>(token, "configuration");

export const previewConfiguration = (
  token: string,
  bundle: ConfigurationBundle,
) => maintenanceJson<ImportReport>(token, "configuration/preview", bundle);

export const importConfiguration = (
  token: string,
  bundle: ConfigurationBundle,
  digest: string,
) =>
  maintenanceJson<ImportReport>(token, "configuration/import", {
    bundle,
    expected_digest: digest,
  });

export const getDiagnostics = (token: string) =>
  maintenanceJson<Diagnostics>(token, "diagnostics");

export const unlockDiagnostics = (
  token: string,
  pin: string,
  includeCommands: boolean,
  includeEvents: boolean,
) =>
  maintenanceJson<DiagnosticExport>(token, "diagnostics/export", {
    pin,
    include_commands: includeCommands,
    include_events: includeEvents,
  });

export async function downloadBackup(token: string): Promise<Blob> {
  const response = await fetch("/api/v1/maintenance/backup", {
    credentials: "omit",
    cache: "no-store",
    headers: sessionHeaders(token),
  });
  await requireOk(response);
  return response.blob();
}

export async function previewBackup(
  token: string,
  file: Blob,
): Promise<BackupReport> {
  return readJson<BackupReport>(
    await fetch("/api/v1/maintenance/backup/preview", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        ...sessionHeaders(token),
        "Content-Type": "application/octet-stream",
      },
      body: file,
    }),
  );
}
