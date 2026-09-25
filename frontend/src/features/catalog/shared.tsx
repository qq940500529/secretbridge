// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  CircleAlert,
  KeyRound,
  LoaderCircle,
  Plus,
  ServerCog,
  Trash2,
  X,
} from "lucide-react";
import { type FormEvent, type MouseEvent, type ReactNode } from "react";
import { EditorDialog } from "../../shared/ui/EditorDialog";
import { MasterDetail } from "../../shared/ui/MasterDetail";
import {
  type ConfigurationStorage,
  type CredentialKind,
  type TargetEnvironment,
  type TargetKind,
} from "../../api/index";

export type Language = "zh-CN" | "en";

export const sharedCopy = {
  "zh-CN": {
    memoryTitle: "当前配置只保存在服务内存中",
    memoryBody:
      "元数据会在服务重启后清空；密码和令牌仍由操作系统凭据库管理。请优先使用持久化服务配置。",
    persistentTitle: "配置已保存到本机数据库",
    persistentBody:
      "SQLite 只保存非秘密元数据和配置状态；密码与令牌写入操作系统凭据库，不提供读取或导出接口。",
    loading: "正在读取本机配置…",
    loadError: "配置读取失败，请确认本地服务仍在线且页面会话有效。",
    saveError: "保存失败，请检查字段或重新配对页面会话。",
    versionConflict:
      "这条记录已被其他页面修改，列表已重新载入。请基于最新版本再次编辑。",
    deleteError: "删除失败。该记录可能仍被引用，或页面会话已经失效。",
    resourceInUse: "该凭据引用仍被目标使用。请先解除关联或删除相应目标。",
    delete: "删除",
    saving: "保存中…",
    add: "添加",
    save: "保存修改",
    edit: "编辑",
    cancel: "取消编辑",
    confirmDelete: "确定删除这条配置吗？",
    version: "版本",
    empty: "还没有记录",
  },
  en: {
    memoryTitle: "Configuration is currently memory-only",
    memoryBody:
      "Metadata is cleared on service restart; passwords and tokens still use the operating-system credential store. Prefer persistent service configuration.",
    persistentTitle: "Configuration is saved in a local database",
    persistentBody:
      "SQLite stores only non-secret metadata and configuration state. Passwords and tokens go to the operating-system credential store and have no read or export API.",
    loading: "Loading local configuration…",
    loadError:
      "Could not load configuration. Check the local service and page session.",
    saveError: "Could not save. Check the fields or pair this page again.",
    versionConflict:
      "Another page changed this record. The list has been reloaded; edit the latest version before saving again.",
    deleteError:
      "Could not delete. The record may still be referenced, or the page session may have expired.",
    resourceInUse:
      "This credential reference is still used by a target. Unlink it or delete the target first.",
    delete: "Delete",
    saving: "Saving…",
    add: "Add",
    save: "Save changes",
    edit: "Edit",
    cancel: "Cancel editing",
    confirmDelete: "Delete this configuration record?",
    version: "Version",
    empty: "No records yet",
  },
} as const;

export const credentialKindLabels: Record<
  Language,
  Record<CredentialKind, string>
> = {
  "zh-CN": { password: "密码", api_token: "API 令牌", ssh_key: "SSH 密钥" },
  en: { password: "Password", api_token: "API token", ssh_key: "SSH key" },
};

export const targetKindLabels: Record<Language, Record<TargetKind, string>> = {
  "zh-CN": {
    database: "数据库",
    http_service: "HTTP 服务",
    ssh_host: "SSH 主机",
    telnet_host: "Telnet 旧设备",
  },
  en: {
    database: "Database",
    http_service: "HTTP service",
    ssh_host: "SSH host",
    telnet_host: "Legacy Telnet device",
  },
};

export const environmentLabels: Record<
  Language,
  Record<TargetEnvironment, string>
> = {
  "zh-CN": { development: "开发", test: "测试", production: "生产" },
  en: { development: "Development", test: "Test", production: "Production" },
};

export const inputClass =
  "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";

export function CatalogPage({
  title,
  subtitle,
  language,
  storage,
  error,
  children,
}: {
  title: string;
  subtitle: string;
  language: Language;
  storage: ConfigurationStorage | null;
  error: string | null;
  children: ReactNode;
}) {
  const common = sharedCopy[language];
  return (
    <>
      <div className="mb-6">
        <h1 className="m-0 text-3xl font-bold tracking-tight text-slate-950">
          {title}
        </h1>
        <p className="mb-0 mt-3 max-w-3xl text-base leading-7 text-slate-600">
          {subtitle}
        </p>
      </div>
      {storage === "memory_only" && (
        <div className="mb-6 flex items-start gap-3 border-l-4 border-amber-400 bg-amber-50 px-4 py-3 text-amber-950">
          <CircleAlert className="mt-0.5 size-5 shrink-0 text-amber-700" />
          <div>
            <p className="m-0 text-sm font-semibold">{common.memoryTitle}</p>
            <p className="mb-0 mt-1 text-sm leading-6 text-amber-900/75">
              {common.memoryBody}
            </p>
          </div>
        </div>
      )}
      {error && (
        <div
          role="alert"
          className="mb-6 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800"
        >
          {error}
        </div>
      )}
      <div className="space-y-5">{children}</div>
    </>
  );
}

export function CatalogForm({
  title,
  open,
  onOpen,
  onClose,
  onSubmit,
  busy,
  submitLabel,
  busyLabel,
  onCancel,
  cancelLabel,
  children,
  error,
  returnFocusTarget,
}: {
  title: string;
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
  onSubmit: (event: FormEvent) => void;
  busy: boolean;
  submitLabel: string;
  busyLabel: string;
  onCancel?: () => void;
  cancelLabel: string;
  children: ReactNode;
  error: string | null;
  returnFocusTarget?: HTMLElement | null;
}) {
  return (
    <EditorDialog
      title={title}
      open={open}
      onOpen={onOpen}
      onClose={onClose}
      busy={busy}
      returnFocusTarget={returnFocusTarget}
    >
      {error && (
        <p role="alert" className="px-5 text-sm text-rose-700">
          {error}
        </p>
      )}
      <form onSubmit={onSubmit} className="max-w-4xl p-5">
        <div className="grid gap-4 md:grid-cols-2">{children}</div>
        <div className="mt-5 flex justify-end gap-2">
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              disabled={busy}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 px-4 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60"
            >
              <X className="size-4" />
              {cancelLabel}
            </button>
          )}
          <button
            type="submit"
            disabled={busy}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-cyan-700 px-5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-60"
          >
            {busy ? (
              <LoaderCircle className="size-4 animate-spin" />
            ) : (
              <Plus className="size-4" />
            )}
            {busy ? busyLabel : submitLabel}
          </button>
        </div>
      </form>
    </EditorDialog>
  );
}

export function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label
        htmlFor={htmlFor}
        className="mb-1.5 block text-sm font-medium text-slate-700"
      >
        {label}
      </label>
      {children}
    </div>
  );
}

export function CatalogList({
  title,
  icon,
  loading,
  loadingLabel,
  emptyLabel,
  children,
  items,
  language,
}: {
  title: string;
  icon: "credential" | "target";
  loading: boolean;
  loadingLabel: string;
  emptyLabel: string;
  children: ReactNode;
  items: Array<{ id: string; name: string; detail?: string }>;
  language: Language;
}) {
  const isEmpty = Array.isArray(children) && children.length === 0;
  return (
    <section aria-busy={loading}>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="m-0 inline-flex items-center gap-2 text-base font-semibold text-slate-950">
          {icon === "target" ? (
            <ServerCog className="size-4 text-slate-500" />
          ) : (
            <KeyRound className="size-4 text-slate-500" />
          )}
          {title}
        </h2>
        {!loading && !isEmpty && (
          <span className="text-xs tabular-nums text-slate-500">
            {Array.isArray(children) ? children.length : ""}
          </span>
        )}
      </div>
      {loading ? (
        <div className="flex min-h-40 items-center justify-center gap-2 rounded-2xl border border-slate-200 bg-white text-sm text-slate-500">
          <LoaderCircle className="size-4 animate-spin" />
          {loadingLabel}
        </div>
      ) : isEmpty ? (
        <div className="grid min-h-40 place-items-center rounded-2xl border border-dashed border-slate-300 bg-white/60 text-sm text-slate-500">
          {emptyLabel}
        </div>
      ) : (
        <MasterDetail items={items} language={language}>
          {children}
        </MasterDetail>
      )}
    </section>
  );
}

export function DeleteButton({
  label,
  onClick,
}: {
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex size-9 shrink-0 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700"
      aria-label={label}
      title={label}
    >
      <Trash2 className="size-4" />
    </button>
  );
}

export function IconButton({
  label,
  onClick,
  children,
}: {
  label: string;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex size-9 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700"
      aria-label={label}
      title={label}
    >
      {children}
    </button>
  );
}
