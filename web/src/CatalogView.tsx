// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  CircleAlert,
  Eraser,
  KeyRound,
  LoaderCircle,
  Pencil,
  Plus,
  ServerCog,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";

import {
  createCredentialReference,
  clearCredentialSecret,
  createTarget,
  deleteCredentialReference,
  deleteTarget,
  listCredentialReferences,
  listTargets,
  SecretBridgeApiError,
  setCredentialSecret,
  updateCredentialReference,
  updateTarget,
  type ConfigurationStorage,
  type CredentialKind,
  type CredentialReference,
  type Target,
  type TargetEnvironment,
  type TargetKind,
} from "./api";

type Language = "zh-CN" | "en";

const sharedCopy = {
  "zh-CN": {
    memoryTitle: "当前配置只保存在服务内存中",
    memoryBody: "元数据会在服务重启后清空；密码和令牌仍由操作系统凭据库管理。请优先使用持久化服务配置。",
    persistentTitle: "配置已保存到本机数据库",
    persistentBody: "SQLite 只保存非秘密元数据和配置状态；密码与令牌写入操作系统凭据库，不提供读取或导出接口。",
    loading: "正在读取本机配置…",
    loadError: "配置读取失败，请确认本地服务仍在线且页面会话有效。",
    saveError: "保存失败，请检查字段或重新配对页面会话。",
    versionConflict: "这条记录已被其他页面修改，列表已重新载入。请基于最新版本再次编辑。",
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
    memoryBody: "Metadata is cleared on service restart; passwords and tokens still use the operating-system credential store. Prefer persistent service configuration.",
    persistentTitle: "Configuration is saved in a local database",
    persistentBody: "SQLite stores only non-secret metadata and configuration state. Passwords and tokens go to the operating-system credential store and have no read or export API.",
    loading: "Loading local configuration…",
    loadError: "Could not load configuration. Check the local service and page session.",
    saveError: "Could not save. Check the fields or pair this page again.",
    versionConflict: "Another page changed this record. The list has been reloaded; edit the latest version before saving again.",
    deleteError: "Could not delete. The record may still be referenced, or the page session may have expired.",
    resourceInUse: "This credential reference is still used by a target. Unlink it or delete the target first.",
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

const credentialKindLabels: Record<Language, Record<CredentialKind, string>> = {
  "zh-CN": { password: "密码", api_token: "API 令牌", ssh_key: "SSH 密钥" },
  en: { password: "Password", api_token: "API token", ssh_key: "SSH key" },
};

const targetKindLabels: Record<Language, Record<TargetKind, string>> = {
  "zh-CN": { database: "数据库", http_service: "HTTP 服务", ssh_host: "SSH 主机" },
  en: { database: "Database", http_service: "HTTP service", ssh_host: "SSH host" },
};

const environmentLabels: Record<Language, Record<TargetEnvironment, string>> = {
  "zh-CN": { development: "开发", test: "测试", production: "生产" },
  en: { development: "Development", test: "Test", production: "Production" },
};

export function CredentialReferencesView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const common = sharedCopy[language];
  const text = language === "zh-CN"
    ? {
        eyebrow: "M1 · 凭据引用",
        title: "建立凭据用途清单",
        subtitle: "名称、类型和用途保存在本机配置库；密码与 API 令牌单独写入操作系统凭据库，页面与 API 都不会回读秘密值。",
        formTitle: "添加凭据引用",
        name: "引用名称",
        namePlaceholder: "例如：测试库只读账号",
        kind: "凭据类型",
        purpose: "用途说明（可选）",
        purposePlaceholder: "说明允许用于什么，不要填写任何秘密",
        listTitle: "已登记的引用",
        states: { not_configured: "未配置", available: "已安全保存" },
        secret: "输入新秘密值",
        secretPlaceholder: "保存后立即从页面清空",
        setSecret: "保存到系统凭据库",
        clearSecret: "清除秘密",
        confirmClear: "确定从操作系统凭据库清除这个秘密值吗？",
        secretError: "系统凭据库操作失败。请检查系统凭据服务、字段内容或页面会话。",
        sshPending: "SSH 私钥写入将在专用文件型凭据适配器中提供。",
      }
    : {
        eyebrow: "M1 · Credential references",
        title: "Build a credential-purpose catalog",
        subtitle: "Names, types, and purposes stay in local configuration. Passwords and API tokens are written separately to the OS credential store and are never returned by the page or API.",
        formTitle: "Add credential reference",
        name: "Reference name",
        namePlaceholder: "Example: test database read-only account",
        kind: "Credential type",
        purpose: "Purpose (optional)",
        purposePlaceholder: "Describe the allowed use; never enter a secret",
        listTitle: "Registered references",
        states: { not_configured: "Not configured", available: "Stored securely" },
        secret: "Enter a new secret",
        secretPlaceholder: "Cleared from the page after save",
        setSecret: "Save to OS credential store",
        clearSecret: "Clear secret",
        confirmClear: "Remove this secret from the operating-system credential store?",
        secretError: "The OS credential-store operation failed. Check the system credential service, field value, or page session.",
        sshPending: "SSH private keys will use a dedicated file-credential adapter in a later increment.",
      };
  const [items, setItems] = useState<CredentialReference[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("password");
  const [purpose, setPurpose] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingVersion, setEditingVersion] = useState<number | null>(null);
  const [storage, setStorage] = useState<ConfigurationStorage>("memory_only");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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
      .catch(() => { if (active) setError(common.loadError); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [common.loadError, sessionToken]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const request = {
        name,
        kind,
        ...(purpose.trim() ? { purpose } : {}),
      };
      if (editingId) {
        const item = await updateCredentialReference(
          sessionToken,
          editingId,
          { ...request, expected_version: editingVersion ?? 0 },
        );
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
      if (error instanceof SecretBridgeApiError && error.code === "version_conflict") {
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
        error instanceof SecretBridgeApiError && error.code === "resource_in_use"
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
      const updated = await setCredentialSecret(sessionToken, item.id, secret, item.version);
      setItems((current) => current.map((entry) => entry.id === item.id ? updated : entry));
      setSecretDrafts((current) => ({ ...current, [item.id]: "" }));
    } catch (error) {
      if (error instanceof SecretBridgeApiError && error.code === "version_conflict") {
        const response = await listCredentialReferences(sessionToken);
        setItems(response.items);
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
      const updated = await clearCredentialSecret(sessionToken, item.id, item.version);
      setItems((current) => current.map((entry) => entry.id === item.id ? updated : entry));
      setSecretDrafts((current) => ({ ...current, [item.id]: "" }));
    } catch (error) {
      setError(error instanceof SecretBridgeApiError && error.code === "version_conflict" ? common.versionConflict : text.secretError);
    } finally {
      setSecretBusyId(null);
    }
  }

  function beginEdit(item: CredentialReference) {
    setEditingId(item.id);
    setEditingVersion(item.version);
    setName(item.name);
    setKind(item.kind);
    setPurpose(item.purpose ?? "");
    setError(null);
  }

  function resetForm() {
    setEditingId(null);
    setEditingVersion(null);
    setName("");
    setKind("password");
    setPurpose("");
  }

  return (
    <CatalogPage
      eyebrow={text.eyebrow}
      title={text.title}
      subtitle={text.subtitle}
      language={language}
      storage={storage}
      error={error}
    >
      <CatalogForm
        title={editingId ? common.edit : text.formTitle}
        onSubmit={submit}
        busy={busy}
        submitLabel={editingId ? common.save : common.add}
        busyLabel={common.saving}
        onCancel={editingId ? resetForm : undefined}
        cancelLabel={common.cancel}
      >
        <Field label={text.name} htmlFor="credential-name">
          <input id="credential-name" required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder={text.namePlaceholder} className={inputClass} />
        </Field>
        <Field label={text.kind} htmlFor="credential-kind">
          <select id="credential-kind" value={kind} onChange={(event) => setKind(event.target.value as CredentialKind)} className={inputClass}>
            {Object.entries(credentialKindLabels[language]).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </Field>
        <Field label={text.purpose} htmlFor="credential-purpose">
          <textarea id="credential-purpose" maxLength={240} rows={3} value={purpose} onChange={(event) => setPurpose(event.target.value)} placeholder={text.purposePlaceholder} className={inputClass} />
        </Field>
      </CatalogForm>

      <CatalogList
        title={text.listTitle}
        icon="credential"
        loading={loading}
        loadingLabel={common.loading}
        emptyLabel={common.empty}
      >
        {items.map((item) => (
          <article key={item.id} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-cyan-50 px-2.5 py-1 text-xs font-semibold text-cyan-700">{credentialKindLabels[language][item.kind]}</span>
                  <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium ${item.secret_state === "available" ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-600"}`}><ShieldCheck className="size-3.5" />{text.states[item.secret_state]}</span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-500">
                    {common.version} {item.version}
                  </span>
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">{item.name}</h2>
                {item.purpose && <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">{item.purpose}</p>}
              </div>
              <div className="flex shrink-0 gap-2">
                <IconButton label={common.edit} onClick={() => beginEdit(item)}>
                  <Pencil className="size-4" />
                </IconButton>
                <DeleteButton label={common.delete} onClick={() => void remove(item.id)} />
              </div>
            </div>
            {item.kind === "ssh_key" ? (
              <p className="mb-0 mt-4 rounded-xl bg-amber-50 p-3 text-xs leading-5 text-amber-800">{text.sshPending}</p>
            ) : (
              <div className="mt-4 border-t border-slate-100 pt-4">
                <label htmlFor={`secret-${item.id}`} className="mb-1.5 block text-xs font-semibold text-slate-600">{text.secret}</label>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input id={`secret-${item.id}`} type="password" autoComplete="new-password" maxLength={8192} value={secretDrafts[item.id] ?? ""} onChange={(event) => setSecretDrafts((current) => ({ ...current, [item.id]: event.target.value }))} placeholder={text.secretPlaceholder} className={inputClass} />
                  <button type="button" disabled={secretBusyId === item.id || !(secretDrafts[item.id] ?? "")} onClick={() => void saveSecret(item)} className="shrink-0 rounded-xl bg-cyan-700 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-800 disabled:opacity-50">{text.setSecret}</button>
                  {item.secret_state === "available" && <button type="button" disabled={secretBusyId === item.id} onClick={() => void clearSecret(item)} className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-xl border border-rose-200 px-3 py-2.5 text-sm font-semibold text-rose-700 hover:bg-rose-50 disabled:opacity-50"><Eraser className="size-4" />{text.clearSecret}</button>}
                </div>
              </div>
            )}
          </article>
        ))}
      </CatalogList>
    </CatalogPage>
  );
}

export function TargetsView({
  language,
  sessionToken,
}: {
  language: Language;
  sessionToken: string;
}) {
  const common = sharedCopy[language];
  const text = language === "zh-CN"
    ? {
        eyebrow: "M1 · 连接目标",
        title: "定义逻辑目标与凭据关系",
        subtitle: "数据库目标可登记 PostgreSQL 主机、端口、库名和账号；密码来自关联的系统凭据库。当前不会绕过审批主动连接业务系统。",
        formTitle: "添加逻辑目标",
        name: "目标名称",
        namePlaceholder: "例如：测试报表数据库",
        kind: "目标类型",
        environment: "环境",
        description: "用途说明（可选）",
        descriptionPlaceholder: "说明业务用途，不要填写地址或秘密",
        credential: "关联凭据引用（可选）",
        none: "暂不关联",
        listTitle: "已登记的逻辑目标",
        noCredential: "未关联凭据",
        postgresHost: "PostgreSQL 主机",
        postgresPort: "端口",
        postgresDatabase: "数据库名",
        postgresUsername: "登录账号",
        postgresTls: "TLS 校验",
        verifyFull: "强制加密并验证证书与主机名",
      }
    : {
        eyebrow: "M1 · Targets",
        title: "Define logical targets and credential relationships",
        subtitle: "Database targets can record a PostgreSQL host, port, database, and user; passwords come from the linked OS credential entry. No business connection bypasses approval.",
        formTitle: "Add logical target",
        name: "Target name",
        namePlaceholder: "Example: test reporting database",
        kind: "Target type",
        environment: "Environment",
        description: "Purpose (optional)",
        descriptionPlaceholder: "Describe the business use; do not enter an address or secret",
        credential: "Credential reference (optional)",
        none: "No reference",
        listTitle: "Registered logical targets",
        noCredential: "No credential reference",
        postgresHost: "PostgreSQL host",
        postgresPort: "Port",
        postgresDatabase: "Database",
        postgresUsername: "Login user",
        postgresTls: "TLS verification",
        verifyFull: "Require encryption and verify certificate + hostname",
      };
  const [items, setItems] = useState<Target[]>([]);
  const [credentials, setCredentials] = useState<CredentialReference[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TargetKind>("database");
  const [environment, setEnvironment] = useState<TargetEnvironment>("test");
  const [description, setDescription] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [postgresHost, setPostgresHost] = useState("");
  const [postgresPort, setPostgresPort] = useState("5432");
  const [postgresDatabase, setPostgresDatabase] = useState("");
  const [postgresUsername, setPostgresUsername] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingVersion, setEditingVersion] = useState<number | null>(null);
  const [storage, setStorage] = useState<ConfigurationStorage>("memory_only");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const credentialNames = useMemo(
    () => new Map(credentials.map((item) => [item.id, item.name])),
    [credentials],
  );

  useEffect(() => {
    let active = true;
    Promise.all([
      listTargets(sessionToken),
      listCredentialReferences(sessionToken),
    ])
      .then(([targets, references]) => {
        if (active) {
          setItems(targets.items);
          setCredentials(references.items);
          setStorage(targets.storage);
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
        environment,
        ...(description.trim() ? { description } : {}),
        ...(credentialId ? { credential_reference_id: credentialId } : {}),
        ...(kind === "database" ? {
          postgres: {
            host: postgresHost,
            port: Number(postgresPort),
            database: postgresDatabase,
            username: postgresUsername,
            tls_mode: "verify_full" as const,
          },
        } : {}),
      };
      if (editingId) {
        const item = await updateTarget(sessionToken, editingId, {
          ...request,
          expected_version: editingVersion ?? 0,
        });
        setItems((current) =>
          current.map((currentItem) =>
            currentItem.id === item.id ? item : currentItem,
          ),
        );
      } else {
        const item = await createTarget(sessionToken, request);
        setItems((current) => [...current, item]);
      }
      resetForm();
    } catch (error) {
      if (error instanceof SecretBridgeApiError && error.code === "version_conflict") {
        try {
          const [targets, references] = await Promise.all([
            listTargets(sessionToken),
            listCredentialReferences(sessionToken),
          ]);
          setItems(targets.items);
          setCredentials(references.items);
          setStorage(targets.storage);
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
      await deleteTarget(sessionToken, id);
      setItems((current) => current.filter((item) => item.id !== id));
      if (editingId === id) resetForm();
    } catch {
      setError(common.deleteError);
    }
  }

  function beginEdit(item: Target) {
    setEditingId(item.id);
    setEditingVersion(item.version);
    setName(item.name);
    setKind(item.kind);
    setEnvironment(item.environment);
    setDescription(item.description ?? "");
    setCredentialId(item.credential_reference_id ?? "");
    setPostgresHost(item.postgres?.host ?? "");
    setPostgresPort(String(item.postgres?.port ?? 5432));
    setPostgresDatabase(item.postgres?.database ?? "");
    setPostgresUsername(item.postgres?.username ?? "");
    setError(null);
  }

  function resetForm() {
    setEditingId(null);
    setEditingVersion(null);
    setName("");
    setKind("database");
    setEnvironment("test");
    setDescription("");
    setCredentialId("");
    setPostgresHost("");
    setPostgresPort("5432");
    setPostgresDatabase("");
    setPostgresUsername("");
  }

  return (
    <CatalogPage
      eyebrow={text.eyebrow}
      title={text.title}
      subtitle={text.subtitle}
      language={language}
      storage={storage}
      error={error}
    >
      <CatalogForm
        title={editingId ? common.edit : text.formTitle}
        onSubmit={submit}
        busy={busy}
        submitLabel={editingId ? common.save : common.add}
        busyLabel={common.saving}
        onCancel={editingId ? resetForm : undefined}
        cancelLabel={common.cancel}
      >
        <Field label={text.name} htmlFor="target-name">
          <input
            id="target-name"
            required
            maxLength={80}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={text.namePlaceholder}
            className={inputClass}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={text.kind} htmlFor="target-kind">
            <select
              id="target-kind"
              value={kind}
              onChange={(event) => setKind(event.target.value as TargetKind)}
              className={inputClass}
            >
              {Object.entries(targetKindLabels[language]).map(
                ([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ),
              )}
            </select>
          </Field>
          <Field label={text.environment} htmlFor="target-environment">
            <select
              id="target-environment"
              value={environment}
              onChange={(event) =>
                setEnvironment(event.target.value as TargetEnvironment)
              }
              className={inputClass}
            >
              {Object.entries(environmentLabels[language]).map(
                ([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ),
              )}
            </select>
          </Field>
        </div>
        <Field label={text.credential} htmlFor="target-credential">
          <select
            id="target-credential"
            value={credentialId}
            onChange={(event) => setCredentialId(event.target.value)}
            className={inputClass}
          >
            <option value="">{text.none}</option>
            {credentials.map((item) => (
              <option key={item.id} value={item.id}>{item.name}</option>
            ))}
          </select>
        </Field>
        {kind === "database" && (
          <div className="space-y-4 rounded-2xl border border-cyan-100 bg-cyan-50/50 p-4">
            <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
              <Field label={text.postgresHost} htmlFor="target-postgres-host">
                <input id="target-postgres-host" required maxLength={253} value={postgresHost} onChange={(event) => setPostgresHost(event.target.value)} placeholder="db.example.internal" className={inputClass} />
              </Field>
              <Field label={text.postgresPort} htmlFor="target-postgres-port">
                <input id="target-postgres-port" required type="number" min={1} max={65535} value={postgresPort} onChange={(event) => setPostgresPort(event.target.value)} className={inputClass} />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={text.postgresDatabase} htmlFor="target-postgres-database">
                <input id="target-postgres-database" required maxLength={63} value={postgresDatabase} onChange={(event) => setPostgresDatabase(event.target.value)} className={inputClass} />
              </Field>
              <Field label={text.postgresUsername} htmlFor="target-postgres-username">
                <input id="target-postgres-username" required maxLength={63} autoComplete="username" value={postgresUsername} onChange={(event) => setPostgresUsername(event.target.value)} className={inputClass} />
              </Field>
            </div>
            <Field label={text.postgresTls} htmlFor="target-postgres-tls">
              <select id="target-postgres-tls" value="verify_full" disabled className={inputClass}><option value="verify_full">{text.verifyFull}</option></select>
            </Field>
          </div>
        )}
        <Field label={text.description} htmlFor="target-description">
          <textarea
            id="target-description"
            maxLength={240}
            rows={3}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder={text.descriptionPlaceholder}
            className={inputClass}
          />
        </Field>
      </CatalogForm>

      <CatalogList
        title={text.listTitle}
        icon="target"
        loading={loading}
        loadingLabel={common.loading}
        emptyLabel={common.empty}
      >
        {items.map((item) => (
          <article key={item.id} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">
                    {targetKindLabels[language][item.kind]}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
                    {environmentLabels[language][item.environment]}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-500">
                    {common.version} {item.version}
                  </span>
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">{item.name}</h2>
                {item.description && <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">{item.description}</p>}
                <p className="mb-0 mt-3 flex items-center gap-2 text-xs font-medium text-slate-500">
                  <KeyRound className="size-3.5" />
                  {item.credential_reference_id
                    ? (credentialNames.get(item.credential_reference_id) ?? text.noCredential)
                    : text.noCredential}
                </p>
                {item.postgres && <p className="mb-0 mt-2 break-all text-xs font-medium text-slate-500">{item.postgres.username}@{item.postgres.host}:{item.postgres.port}/{item.postgres.database} · TLS verify-full</p>}
              </div>
              <div className="flex shrink-0 gap-2">
                <IconButton label={common.edit} onClick={() => beginEdit(item)}>
                  <Pencil className="size-4" />
                </IconButton>
                <DeleteButton label={common.delete} onClick={() => void remove(item.id)} />
              </div>
            </div>
          </article>
        ))}
      </CatalogList>
    </CatalogPage>
  );
}

const inputClass =
  "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100";

function CatalogPage({
  eyebrow,
  title,
  subtitle,
  language,
  storage,
  error,
  children,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  language: Language;
  storage: ConfigurationStorage;
  error: string | null;
  children: ReactNode;
}) {
  const common = sharedCopy[language];
  const persistent = storage === "sqlite";
  return (
    <>
      <div className="mb-6">
        <p className="m-0 text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">{eyebrow}</p>
        <h1 className="mb-0 mt-2 text-3xl font-bold tracking-tight text-slate-950">{title}</h1>
        <p className="mb-0 mt-3 max-w-3xl text-base leading-7 text-slate-600">{subtitle}</p>
      </div>
      <div className="mb-6 flex items-start gap-3 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-amber-950">
        <CircleAlert className="mt-0.5 size-5 shrink-0 text-amber-700" />
        <div>
          <p className="m-0 text-sm font-semibold">
            {persistent ? common.persistentTitle : common.memoryTitle}
          </p>
          <p className="mb-0 mt-1 text-sm leading-6 text-amber-900/75">
            {persistent ? common.persistentBody : common.memoryBody}
          </p>
        </div>
      </div>
      {error && (
        <div role="alert" className="mb-6 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
          {error}
        </div>
      )}
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(280px,0.72fr)_minmax(0,1.28fr)]">{children}</div>
    </>
  );
}

function CatalogForm({ title, onSubmit, busy, submitLabel, busyLabel, onCancel, cancelLabel, children }: { title: string; onSubmit: (event: FormEvent) => void; busy: boolean; submitLabel: string; busyLabel: string; onCancel?: () => void; cancelLabel: string; children: ReactNode }) {
  return (
    <form onSubmit={onSubmit} className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="mb-5 flex items-center gap-3">
        <div className="grid size-10 place-items-center rounded-xl bg-cyan-50 text-cyan-700"><Plus className="size-5" /></div>
        <h2 className="m-0 text-base font-semibold text-slate-950">{title}</h2>
      </div>
      <div className="space-y-4">{children}</div>
      <button type="submit" disabled={busy} className="mt-5 inline-flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-slate-950 px-4 text-sm font-semibold text-white transition hover:bg-cyan-800 disabled:cursor-not-allowed disabled:opacity-60">
        {busy ? <LoaderCircle className="size-4 animate-spin" /> : <Plus className="size-4" />}
        {busy ? busyLabel : submitLabel}
      </button>
      {onCancel && (
        <button type="button" onClick={onCancel} disabled={busy} className="mt-2 inline-flex h-10 w-full items-center justify-center gap-2 rounded-xl text-sm font-semibold text-slate-600 transition hover:bg-slate-100 disabled:opacity-60">
          <X className="size-4" />
          {cancelLabel}
        </button>
      )}
    </form>
  );
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: ReactNode }) {
  return <div><label htmlFor={htmlFor} className="mb-1.5 block text-sm font-medium text-slate-700">{label}</label>{children}</div>;
}

function CatalogList({ title, icon, loading, loadingLabel, emptyLabel, children }: { title: string; icon: "credential" | "target"; loading: boolean; loadingLabel: string; emptyLabel: string; children: ReactNode }) {
  const isEmpty = Array.isArray(children) && children.length === 0;
  return (
    <section aria-busy={loading}>
      <div className="mb-4 flex items-center gap-3">
        <div className="grid size-10 place-items-center rounded-xl bg-indigo-50 text-indigo-700">
          {icon === "target" ? <ServerCog className="size-5" /> : <KeyRound className="size-5" />}
        </div>
        <h2 className="m-0 text-base font-semibold text-slate-950">{title}</h2>
      </div>
      {loading ? (
        <div className="flex min-h-40 items-center justify-center gap-2 rounded-2xl border border-slate-200 bg-white text-sm text-slate-500"><LoaderCircle className="size-4 animate-spin" />{loadingLabel}</div>
      ) : isEmpty ? (
        <div className="grid min-h-40 place-items-center rounded-2xl border border-dashed border-slate-300 bg-white/60 text-sm text-slate-500">{emptyLabel}</div>
      ) : (
        <div className="space-y-4">{children}</div>
      )}
    </section>
  );
}

function DeleteButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className="inline-flex size-9 shrink-0 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700" aria-label={label} title={label}>
      <Trash2 className="size-4" />
    </button>
  );
}

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="inline-flex size-9 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition hover:border-cyan-200 hover:bg-cyan-50 hover:text-cyan-700" aria-label={label} title={label}>
      {children}
    </button>
  );
}
