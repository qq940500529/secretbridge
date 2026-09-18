// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CredentialKind } from "./api";
import { useEffect, useRef } from "react";

export async function readPrivateKeyFile(
  file: Pick<File, "size" | "text">,
): Promise<string> {
  if (file.size === 0 || file.size > 8192) throw new Error("invalid_key_file");
  const text = await file.text();
  if (
    !text ||
    text.includes("\0") ||
    new TextEncoder().encode(text).length > 8192
  )
    throw new Error("invalid_key_file");
  return text;
}

export function CredentialSecretInput({
  id,
  kind,
  value,
  onChange,
  onError,
  placeholder,
  className,
  zh,
  disabled = false,
}: {
  id: string;
  kind: CredentialKind;
  value: string;
  onChange: (value: string) => void;
  onError: () => void;
  placeholder: string;
  className: string;
  zh: boolean;
  disabled?: boolean;
}) {
  const readSequence = useRef(0);
  useEffect(
    () => () => {
      readSequence.current++;
    },
    [id, kind],
  );
  if (kind !== "ssh_key")
    return (
      <input
        id={id}
        disabled={disabled}
        type="password"
        autoComplete="new-password"
        maxLength={8192}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className={className}
      />
    );
  return (
    <div className="min-w-0 flex-1">
      <input
        id={id}
        disabled={disabled}
        type="file"
        className={className}
        onChange={(event) => {
          const sequence = ++readSequence.current;
          const file = event.currentTarget.files?.[0];
          event.currentTarget.value = "";
          onChange("");
          if (file)
            void readPrivateKeyFile(file)
              .then((text) => {
                if (sequence === readSequence.current) onChange(text);
              })
              .catch(() => {
                if (sequence === readSequence.current) onError();
              });
        }}
      />
      <p className="mt-1 text-xs leading-5 text-slate-500">
        {value
          ? zh
            ? "私钥已载入，点击保存后清空页面。"
            : "Key loaded; save it to clear the page buffer."
          : zh
            ? "选择本机私钥文件（最多 8 KiB）；内容仅发送到本机代理，不在页面展示。加密私钥的口令使用另一个凭据引用。"
            : "Choose a local private-key file (up to 8 KiB). Its content goes only to the local broker and is not displayed. Store encrypted-key passphrases in a separate credential reference."}
      </p>
    </div>
  );
}
