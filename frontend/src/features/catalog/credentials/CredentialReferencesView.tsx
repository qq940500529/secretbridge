// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Eraser, Pencil, ShieldCheck } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { CredentialSecretInput } from "./CredentialSecretInput";
import {
  createCredentialReference,
  clearCredentialSecret,
  deleteCredentialReference,
  listCredentialReferences,
  SecretBridgeApiError,
  setCredentialSecret,
  updateCredentialReference,
  type ConfigurationStorage,
  type CredentialKind,
  type CredentialReference,
} from "../../../api/index";

import {
  CatalogPage,
  CatalogForm,
  Field,
  CatalogList,
  DeleteButton,
  IconButton,
  inputClass,
  sharedCopy,
  credentialKindLabels,
  type Language,
} from "../shared";

export function CredentialReferencesView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const common = sharedCopy[language];
  const text =
    language === "zh-CN"
      ? {
          title: "凭据",
          subtitle:
            "名称、类型和用途保存在本机配置库；密码、API 令牌与 SSH 私钥单独写入操作系统凭据库，页面与 API 都不会回读秘密值。",
          formTitle: "添加凭据引用",
          name: "引用名称",
          namePlaceholder: "例如：测试库只读账号",
          kind: "凭据类型",
          address: "地址（可选）",
          addressPlaceholder: "计算机名、域名、网址、SMB/FTP 地址或 IP",
          username: "账号（可选）",
          usernamePlaceholder: "用于登录的账号或用户名，不要填写密码",
          purpose: "用途说明（可选）",
          purposePlaceholder: "说明允许用于什么，不要填写任何秘密",
          listTitle: "已登记的引用",
          states: { not_configured: "未配置", available: "已安全保存" },
          secret: "输入新秘密值",
          secretPlaceholder: "保存后立即从页面清空",
          setSecret: "保存到系统凭据库",
          clearSecret: "清除秘密",
          confirmClear: "确定从操作系统凭据库清除这个秘密值吗？",
          secretError:
            "系统凭据库操作失败。请检查系统凭据服务、字段内容或页面会话。",
        }
      : {
          title: "Credentials",
          subtitle:
            "Names, types, and purposes stay in local configuration. Passwords, API tokens and SSH private keys are written separately to the OS credential store and are never returned by the page or API.",
          formTitle: "Add credential reference",
          name: "Reference name",
          namePlaceholder: "Example: test database read-only account",
          kind: "Credential type",
          address: "Address (optional)",
          addressPlaceholder:
            "Computer name, domain, URL, SMB/FTP address, or IP",
          username: "Account (optional)",
          usernamePlaceholder:
            "Login account or username; never enter a password",
          purpose: "Purpose (optional)",
          purposePlaceholder: "Describe the allowed use; never enter a secret",
          listTitle: "Registered references",
          states: {
            not_configured: "Not configured",
            available: "Stored securely",
          },
          secret: "Enter a new secret",
          secretPlaceholder: "Cleared from the page after save",
          setSecret: "Save to OS credential store",
          clearSecret: "Clear secret",
          confirmClear:
            "Remove this secret from the operating-system credential store?",
          secretError:
            "The OS credential-store operation failed. Check the system credential service, field value, or page session.",
        };
  const [items, setItems] = useState<CredentialReference[]>([]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("password");
  const [address, setAddress] = useState("");
  const [username, setUsername] = useState("");
  const [purpose, setPurpose] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingVersion, setEditingVersion] = useState<number | null>(null);
  const [storage, setStorage] = useState<ConfigurationStorage | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const editorReturnFocus = useRef<HTMLElement | null>(null);
  const [secretDrafts, setSecretDrafts] = useState<Record<string, string>>({});
  const [secretBusyId, setSecretBusyId] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    listCredentialReferences(sessionToken)
      .then((response) => {
        if (active) {
          setItems(response.items);
          setStorage(response.storage);
        }
      })
      .catch(() => {
        if (active) setError(common.loadError);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [common.loadError, sessionToken]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const request = {
        name,
        kind,
        ...(address.trim() ? { address } : {}),
        ...(username.trim() ? { username } : {}),
        ...(purpose.trim() ? { purpose } : {}),
      };
      if (editingId) {
        const item = await updateCredentialReference(sessionToken, editingId, {
          ...request,
          expected_version: editingVersion ?? 0,
        });
        setItems((current) =>
          current.map((currentItem) =>
            currentItem.id === item.id ? item : currentItem,
          ),
        );
      } else {
        const item = await createCredentialReference(sessionToken, request);
        setItems((current) => [...current, item]);
      }
      resetForm();
    } catch (error) {
      if (
        error instanceof SecretBridgeApiError &&
        error.code === "version_conflict"
      ) {
        try {
          const response = await listCredentialReferences(sessionToken);
          setItems(response.items);
          setStorage(response.storage);
          resetForm();
        } catch {
          // Keep the conflict message; a later navigation can retry the list request.
        }
        setError(common.versionConflict);
      } else {
        setError(common.saveError);
      }
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    if (!window.confirm(common.confirmDelete)) return;
    setError(null);
    try {
      await deleteCredentialReference(sessionToken, id);
      setItems((current) => current.filter((item) => item.id !== id));
      if (editingId === id) resetForm();
    } catch (error) {
      setError(
        error instanceof SecretBridgeApiError &&
          error.code === "resource_in_use"
          ? common.resourceInUse
          : common.deleteError,
      );
    }
  }

  async function saveSecret(item: CredentialReference) {
    const secret = secretDrafts[item.id] ?? "";
    if (!secret) return;
    setSecretBusyId(item.id);
    setError(null);
    try {
      const updated = await setCredentialSecret(
        sessionToken,
        item.id,
        secret,
        item.version,
      );
      setItems((current) =>
        current.map((entry) => (entry.id === item.id ? updated : entry)),
      );
      setSecretDrafts((current) => ({ ...current, [item.id]: "" }));
    } catch (error) {
      if (
        error instanceof SecretBridgeApiError &&
        error.code === "version_conflict"
      ) {
        try {
          const response = await listCredentialReferences(sessionToken);
          setItems(response.items);
        } catch {
          /* Preserve the conflict and draft if reloading also fails. */
        }
        setError(common.versionConflict);
      } else {
        setError(text.secretError);
      }
    } finally {
      setSecretBusyId(null);
    }
  }

  async function clearSecret(item: CredentialReference) {
    if (!window.confirm(text.confirmClear)) return;
    setSecretBusyId(item.id);
    setError(null);
    try {
      const updated = await clearCredentialSecret(
        sessionToken,
        item.id,
        item.version,
      );
      setItems((current) =>
        current.map((entry) => (entry.id === item.id ? updated : entry)),
      );
      setSecretDrafts((current) => ({ ...current, [item.id]: "" }));
    } catch (error) {
      setError(
        error instanceof SecretBridgeApiError &&
          error.code === "version_conflict"
          ? common.versionConflict
          : text.secretError,
      );
    } finally {
      setSecretBusyId(null);
    }
  }

  function beginEdit(item: CredentialReference, trigger: HTMLElement) {
    editorReturnFocus.current = trigger;
    setEditorOpen(true);
    setEditingId(item.id);
    setEditingVersion(item.version);
    setName(item.name);
    setKind(item.kind);
    setAddress(item.address ?? "");
    setUsername(item.username ?? "");
    setPurpose(item.purpose ?? "");
    setError(null);
  }

  function resetForm() {
    setEditorOpen(false);
    setEditingId(null);
    setEditingVersion(null);
    setName("");
    setKind("password");
    setAddress("");
    setUsername("");
    setPurpose("");
  }

  return (
    <CatalogPage
      title={text.title}
      subtitle={text.subtitle}
      language={language}
      storage={storage}
      error={error}
    >
      <CatalogForm
        title={editingId ? common.edit : text.formTitle}
        open={editorOpen}
        onOpen={() => {
          editorReturnFocus.current = null;
          setError(null);
          setEditorOpen(true);
        }}
        returnFocusTarget={editorReturnFocus.current}
        onClose={resetForm}
        error={error}
        onSubmit={submit}
        busy={busy}
        submitLabel={editingId ? common.save : common.add}
        busyLabel={common.saving}
        onCancel={editingId ? resetForm : undefined}
        cancelLabel={common.cancel}
      >
        <Field label={text.name} htmlFor="credential-name">
          <input
            id="credential-name"
            required
            maxLength={80}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={text.namePlaceholder}
            className={inputClass}
          />
        </Field>
        <Field label={text.kind} htmlFor="credential-kind">
          <select
            id="credential-kind"
            value={kind}
            onChange={(event) => setKind(event.target.value as CredentialKind)}
            className={inputClass}
          >
            {Object.entries(credentialKindLabels[language]).map(
              ([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ),
            )}
          </select>
        </Field>
        <Field label={text.address} htmlFor="credential-address">
          <input
            id="credential-address"
            maxLength={2048}
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder={text.addressPlaceholder}
            className={inputClass}
          />
        </Field>
        <Field label={text.username} htmlFor="credential-username">
          <input
            id="credential-username"
            maxLength={256}
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder={text.usernamePlaceholder}
            className={inputClass}
          />
        </Field>
        <Field label={text.purpose} htmlFor="credential-purpose">
          <textarea
            id="credential-purpose"
            maxLength={240}
            rows={3}
            value={purpose}
            onChange={(event) => setPurpose(event.target.value)}
            placeholder={text.purposePlaceholder}
            className={inputClass}
          />
        </Field>
      </CatalogForm>

      <CatalogList
        title={text.listTitle}
        icon="credential"
        language={language}
        items={items.map((item) => ({
          id: item.id,
          name: item.name,
          detail: `${credentialKindLabels[language][item.kind]} · ${text.states[item.secret_state]}`,
        }))}
        loading={loading}
        loadingLabel={common.loading}
        emptyLabel={common.empty}
      >
        {items.map((item) => (
          <article key={item.id} className="p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-cyan-50 px-2.5 py-1 text-xs font-semibold text-cyan-700">
                    {credentialKindLabels[language][item.kind]}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium ${item.secret_state === "available" ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-600"}`}
                  >
                    <ShieldCheck className="size-3.5" />
                    {text.states[item.secret_state]}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">
                    {common.version} {item.version}
                  </span>
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">
                  {item.name}
                </h2>
                {item.purpose && (
                  <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">
                    {item.purpose}
                  </p>
                )}
                {(item.username || item.address) && (
                  <p className="mb-0 mt-2 break-all text-xs font-medium text-slate-500">
                    {[item.username, item.address].filter(Boolean).join(" @ ")}
                  </p>
                )}
              </div>
              <div className="flex shrink-0 gap-2">
                <IconButton
                  label={common.edit}
                  onClick={(event) => beginEdit(item, event.currentTarget)}
                >
                  <Pencil className="size-4" />
                </IconButton>
                <DeleteButton
                  label={common.delete}
                  onClick={() => void remove(item.id)}
                />
              </div>
            </div>
            <div className="mt-4 border-t border-slate-100 pt-4">
              <label
                htmlFor={`secret-${item.id}`}
                className="mb-1.5 block text-xs font-semibold text-slate-600"
              >
                {text.secret}
              </label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <CredentialSecretInput
                  id={`secret-${item.id}`}
                  kind={item.kind}
                  value={secretDrafts[item.id] ?? ""}
                  onChange={(value) =>
                    setSecretDrafts((current) => ({
                      ...current,
                      [item.id]: value,
                    }))
                  }
                  onError={() => setError(text.secretError)}
                  placeholder={text.secretPlaceholder}
                  className={inputClass}
                  zh={language === "zh-CN"}
                  disabled={secretBusyId === item.id}
                />
                <button
                  type="button"
                  disabled={
                    secretBusyId === item.id || !(secretDrafts[item.id] ?? "")
                  }
                  onClick={() => void saveSecret(item)}
                  className="shrink-0 rounded-xl bg-cyan-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50"
                >
                  {text.setSecret}
                </button>
                {item.secret_state === "available" && (
                  <button
                    type="button"
                    disabled={secretBusyId === item.id}
                    onClick={() => void clearSecret(item)}
                    className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-rose-200 px-3 py-2.5 text-sm font-semibold text-rose-700 hover:bg-rose-50 disabled:opacity-50"
                  >
                    <Eraser className="size-4" />
                    {text.clearSecret}
                  </button>
                )}
              </div>
            </div>
          </article>
        ))}
      </CatalogList>
    </CatalogPage>
  );
}
