// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  AuthorizationMode,
  ParameterDefinition,
  ParameterValue,
} from "./api";

export function nextParameterName(names: string[]): string {
  let index = 1;
  while (names.includes(`param_${index}`)) index++;
  return `param_${index}`;
}

export function setParameterValue(
  values: Record<string, ParameterValue>,
  name: string,
  value: ParameterValue | undefined,
): Record<string, ParameterValue> {
  if (value !== undefined) return { ...values, [name]: value };
  const next = { ...values };
  delete next[name];
  return next;
}

export function parseParameter(
  kind: ParameterDefinition["kind"],
  text: string,
): ParameterValue {
  if (kind === "string") return text;
  if (kind === "boolean") {
    if (text === "true") return true;
    if (text === "false") return false;
    throw new Error("Expected true or false");
  }
  if (!/^-?\d+$/.test(text) || !Number.isSafeInteger(Number(text)))
    throw new Error("Expected a safe integer");
  return Number(text);
}

export function authorizationLabel(
  mode: AuthorizationMode,
  zh: boolean,
): string {
  return {
    every_run: zh ? "每次确认" : "Confirm every run",
    once: zh ? "仅当前一次" : "This run only",
    time_window: zh
      ? "有效期内允许（相同参数）"
      : "Allow until expiry (same parameters)",
  }[mode];
}

export function retryGuidance(
  status: string | null,
  zh: boolean,
): string | null {
  if (
    !status ||
    ["command_ok", "synthetic_ok", "postgres_connection_ok"].includes(status)
  )
    return null;
  if (status === "credential_unavailable")
    return zh
      ? "请检查凭据配置，再重新申请授权。"
      : "Check credential configuration and request new authorization.";
  if (status === "authorization_revoked")
    return zh
      ? "请按当前模板重新申请授权。"
      : "Request authorization for the current template.";
  if (status === "command_cleanup_failed")
    return zh
      ? "请先检查临时文件清理和本机权限，不要直接重试。"
      : "Check temporary-file cleanup and local permissions before retrying.";
  return zh
    ? "请检查输出并确认上次操作是否已产生效果；需要重试时使用新幂等键，避免重复业务操作。"
    : "Inspect output and check whether the previous operation already took effect. Use a new idempotency key only when a retry is intended.";
}
