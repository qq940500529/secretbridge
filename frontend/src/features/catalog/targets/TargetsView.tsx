// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { KeyRound, Pencil } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { ConnectionRelations } from "./ConnectionRelations";
import {
  createTarget,
  deleteTarget,
  listCredentialReferences,
  listTargets,
  SecretBridgeApiError,
  updateTarget,
  type ConfigurationStorage,
  type CredentialReference,
  type Target,
  type TargetEnvironment,
  type TargetKind,
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
  targetKindLabels,
  environmentLabels,
  type Language,
} from "../shared";

export function TargetsView({
  language,
  sessionToken,
  onTask,
}: {
  language: Language;
  sessionToken: string;
  onTask?: (targetId: string, templateId?: string) => void;
}) {
  const common = sharedCopy[language];
  const text =
    language === "zh-CN"
      ? {
          title: "连接",
          subtitle:
            "按业务用途组织凭据、任务与执行记录。各任务分别配置真实连接地址；可选 PostgreSQL 字段仅供内置连接检查，不会覆盖任务连接器。",
          formTitle: "新建连接",
          name: "连接名称",
          namePlaceholder: "例如：测试报表数据库",
          kind: "连接类型",
          environment: "环境",
          address: "地址（可选）",
          addressPlaceholder: "计算机名、域名、网址、SMB/FTP 地址或 IP",
          username: "账号（可选）",
          usernamePlaceholder: "连接使用的账号或用户名",
          description: "用途说明（可选）",
          descriptionPlaceholder: "说明业务用途，不要填写地址或秘密",
          credential: "关联凭据引用（可选）",
          none: "暂不关联",
          listTitle: "已保存连接",
          noCredential: "未关联凭据",
          postgresHost: "PostgreSQL 主机",
          postgresPort: "端口",
          postgresDatabase: "数据库名",
          postgresUsername: "登录账号",
          postgresTls: "TLS 校验",
          verifyFull: "强制加密并验证证书与主机名",
          telnetWarning:
            "Telnet 会以明文传输账号、密码和命令。仅在无法升级的隔离旧设备上显式启用，并优先迁移到 SSH。",
          allowTelnet: "我确认允许此连接使用不加密的 Telnet",
        }
      : {
          title: "Connections",
          subtitle:
            "Organize credentials, tasks and results by purpose. Tasks configure their own endpoints; optional PostgreSQL fields apply only to the built-in check, not task connectors.",
          formTitle: "New connection",
          name: "Connection name",
          namePlaceholder: "Example: test reporting database",
          kind: "Connection type",
          environment: "Environment",
          address: "Address (optional)",
          addressPlaceholder:
            "Computer name, domain, URL, SMB/FTP address, or IP",
          username: "Account (optional)",
          usernamePlaceholder: "Account or username used by this connection",
          description: "Purpose (optional)",
          descriptionPlaceholder:
            "Describe the business use; do not enter an address or secret",
          credential: "Credential reference (optional)",
          none: "No reference",
          listTitle: "Saved connections",
          noCredential: "No credential reference",
          postgresHost: "PostgreSQL host",
          postgresPort: "Port",
          postgresDatabase: "Database",
          postgresUsername: "Login user",
          postgresTls: "TLS verification",
          verifyFull: "Require encryption and verify certificate + hostname",
          telnetWarning:
            "Telnet sends accounts, passwords, and commands in plaintext. Enable it only for an isolated legacy device that cannot be upgraded, and migrate to SSH.",
          allowTelnet:
            "I explicitly allow unencrypted Telnet for this connection",
        };
  const [items, setItems] = useState<Target[]>([]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [credentials, setCredentials] = useState<CredentialReference[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TargetKind>("database");
  const [environment, setEnvironment] = useState<TargetEnvironment>("test");
  const [description, setDescription] = useState("");
  const [address, setAddress] = useState("");
  const [username, setUsername] = useState("");
  const [allowInsecureProtocol, setAllowInsecureProtocol] = useState(false);
  const [credentialId, setCredentialId] = useState("");
  const [postgresHost, setPostgresHost] = useState("");
  const [postgresPort, setPostgresPort] = useState("5432");
  const [postgresDatabase, setPostgresDatabase] = useState("");
  const [postgresUsername, setPostgresUsername] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingVersion, setEditingVersion] = useState<number | null>(null);
  const [storage, setStorage] = useState<ConfigurationStorage | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const editorReturnFocus = useRef<HTMLElement | null>(null);
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
        ...(address.trim() ? { address } : {}),
        ...(username.trim() ? { username } : {}),
        ...(kind === "telnet_host"
          ? { allow_insecure_protocol: allowInsecureProtocol }
          : {}),
        ...(description.trim() ? { description } : {}),
        ...(credentialId ? { credential_reference_id: credentialId } : {}),
        ...(kind === "database" && postgresHost.trim()
          ? {
              postgres: {
                host: postgresHost,
                port: Number(postgresPort),
                database: postgresDatabase,
                username: postgresUsername,
                tls_mode: "verify_full" as const,
              },
            }
          : {}),
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
      if (
        error instanceof SecretBridgeApiError &&
        error.code === "version_conflict"
      ) {
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

  function beginEdit(item: Target, trigger: HTMLElement) {
    editorReturnFocus.current = trigger;
    setEditorOpen(true);
    setEditingId(item.id);
    setEditingVersion(item.version);
    setName(item.name);
    setKind(item.kind);
    setEnvironment(item.environment);
    setDescription(item.description ?? "");
    setAddress(item.address ?? "");
    setUsername(item.username ?? "");
    setAllowInsecureProtocol(item.allow_insecure_protocol);
    setCredentialId(item.credential_reference_id ?? "");
    setPostgresHost(item.postgres?.host ?? "");
    setPostgresPort(String(item.postgres?.port ?? 5432));
    setPostgresDatabase(item.postgres?.database ?? "");
    setPostgresUsername(item.postgres?.username ?? "");
    setError(null);
  }

  function resetForm() {
    setEditorOpen(false);
    setEditingId(null);
    setEditingVersion(null);
    setName("");
    setKind("database");
    setEnvironment("test");
    setDescription("");
    setAddress("");
    setUsername("");
    setAllowInsecureProtocol(false);
    setCredentialId("");
    setPostgresHost("");
    setPostgresPort("5432");
    setPostgresDatabase("");
    setPostgresUsername("");
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
                  <option key={value} value={value}>
                    {label}
                  </option>
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
                  <option key={value} value={value}>
                    {label}
                  </option>
                ),
              )}
            </select>
          </Field>
        </div>
        <Field label={text.address} htmlFor="target-address">
          <input
            id="target-address"
            maxLength={2048}
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder={text.addressPlaceholder}
            className={inputClass}
          />
        </Field>
        <Field label={text.username} htmlFor="target-username">
          <input
            id="target-username"
            maxLength={256}
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder={text.usernamePlaceholder}
            className={inputClass}
          />
        </Field>
        <Field label={text.credential} htmlFor="target-credential">
          <select
            id="target-credential"
            value={credentialId}
            onChange={(event) => setCredentialId(event.target.value)}
            className={inputClass}
          >
            <option value="">{text.none}</option>
            {credentials.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </Field>
        {kind === "telnet_host" && (
          <div className="rounded-2xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950">
            <p className="mt-0 leading-6">{text.telnetWarning}</p>
            <label className="flex items-start gap-3 font-semibold">
              <input
                type="checkbox"
                checked={allowInsecureProtocol}
                onChange={(event) =>
                  setAllowInsecureProtocol(event.target.checked)
                }
                className="mt-1"
              />
              <span>{text.allowTelnet}</span>
            </label>
          </div>
        )}
        {kind === "database" && (
          <div className="space-y-4 rounded-2xl border border-cyan-100 bg-cyan-50/50 p-4">
            <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
              <Field label={text.postgresHost} htmlFor="target-postgres-host">
                <input
                  id="target-postgres-host"
                  maxLength={253}
                  value={postgresHost}
                  onChange={(event) => setPostgresHost(event.target.value)}
                  placeholder="db.example.internal"
                  className={inputClass}
                />
              </Field>
              <Field label={text.postgresPort} htmlFor="target-postgres-port">
                <input
                  id="target-postgres-port"
                  required
                  type="number"
                  min={1}
                  max={65535}
                  value={postgresPort}
                  onChange={(event) => setPostgresPort(event.target.value)}
                  className={inputClass}
                />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label={text.postgresDatabase}
                htmlFor="target-postgres-database"
              >
                <input
                  id="target-postgres-database"
                  required={Boolean(postgresHost.trim())}
                  maxLength={63}
                  value={postgresDatabase}
                  onChange={(event) => setPostgresDatabase(event.target.value)}
                  className={inputClass}
                />
              </Field>
              <Field
                label={text.postgresUsername}
                htmlFor="target-postgres-username"
              >
                <input
                  id="target-postgres-username"
                  required={Boolean(postgresHost.trim())}
                  maxLength={63}
                  autoComplete="username"
                  value={postgresUsername}
                  onChange={(event) => setPostgresUsername(event.target.value)}
                  className={inputClass}
                />
              </Field>
            </div>
            <Field label={text.postgresTls} htmlFor="target-postgres-tls">
              <select
                id="target-postgres-tls"
                value="verify_full"
                disabled
                className={inputClass}
              >
                <option value="verify_full">{text.verifyFull}</option>
              </select>
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
        language={language}
        items={items.map((item) => ({
          id: item.id,
          name: item.name,
          detail: `${targetKindLabels[language][item.kind]} · ${environmentLabels[language][item.environment]}`,
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
                  <span className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-700">
                    {targetKindLabels[language][item.kind]}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
                    {environmentLabels[language][item.environment]}
                  </span>
                  {item.kind === "telnet_host" && (
                    <span className="rounded-full bg-amber-100 px-2.5 py-1 text-xs font-semibold text-amber-900">
                      {item.allow_insecure_protocol
                        ? language === "zh-CN"
                          ? "已允许明文协议"
                          : "Plaintext explicitly allowed"
                        : language === "zh-CN"
                          ? "默认禁用"
                          : "Disabled by default"}
                    </span>
                  )}
                  <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">
                    {common.version} {item.version}
                  </span>
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">
                  {item.name}
                </h2>
                {item.description && (
                  <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">
                    {item.description}
                  </p>
                )}
                <p className="mb-0 mt-3 flex items-center gap-2 text-xs font-medium text-slate-500">
                  <KeyRound className="size-3.5" />
                  {item.credential_reference_id
                    ? (credentialNames.get(item.credential_reference_id) ??
                      text.noCredential)
                    : text.noCredential}
                </p>
                {(item.username || item.address) && (
                  <p className="mb-0 mt-2 break-all text-xs font-medium text-slate-500">
                    {[item.username, item.address].filter(Boolean).join(" @ ")}
                  </p>
                )}
                {item.postgres && (
                  <p className="mb-0 mt-2 break-all text-xs font-medium text-slate-500">
                    {item.postgres.username}@{item.postgres.host}:
                    {item.postgres.port}/{item.postgres.database} · TLS
                    verify-full
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
            <ConnectionRelations
              targetId={item.id}
              credentials={credentials}
              language={language}
              sessionToken={sessionToken}
              onTask={onTask}
            />
          </article>
        ))}
      </CatalogList>
    </CatalogPage>
  );
}
