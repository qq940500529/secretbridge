// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Pencil, PlugZap, ShieldCheck } from "lucide-react";
import {
  listResources,
  saveResource,
  setResourceSecret,
  clearResourceSecret,
  removeResource,
  testResource,
  type Resource,
  type ResourceRequest,
  type ConnectionOptions,
  type ConfigurationStorage,
  type ConnectionTestResult,
} from "../../api";
import {
  CatalogPage,
  CatalogForm,
  CatalogList,
  Field,
  DeleteButton,
  IconButton,
  inputClass,
  sharedCopy,
  credentialKindLabels,
  environmentLabels,
  targetKindLabels,
  type Language,
} from "./shared";
import { CredentialSecretInput } from "./credentials/CredentialSecretInput";
import { ConnectionRelations } from "./targets/ConnectionRelations";

const blank = (): ResourceRequest => ({
  name: "",
  kind: "generic",
  environment: "test",
  address: "",
  username: "",
  description: "",
  authentication_kind: "password",
  labels: [],
  connection: { protocol: "none" },
});
const missingLabels: Record<string, [string, string]> = {
  address: ["地址", "address"],
  database: ["数据库名", "database"],
  username: ["账号", "account"],
  host_key_sha256: ["SSH 主机指纹", "SSH host fingerprint"],
  header_name: ["API Key 请求头名称", "API Key header name"],
};
const testCodes: Record<string, [string, string]> = {
  configuration_incomplete: [
    "请先补充连接配置",
    "Complete connection settings first",
  ],
  connection_ok: ["连接与认证检查通过", "Connection and authentication passed"],
  authentication_not_configured: [
    "请先保存秘密值",
    "Save authentication first",
  ],
  credential_unavailable: [
    "系统凭据库不可用",
    "OS credential store unavailable",
  ],
  authentication_failed: [
    "认证失败，请检查账号和秘密值",
    "Authentication failed; check account and secret",
  ],
  host_key_rejected: [
    "SSH 主机密钥不匹配，请独立核对",
    "SSH host key mismatch; verify independently",
  ],
  timed_out: ["连接超时", "Connection timed out"],
  test_not_configured: ["此资源未配置协议测试", "No protocol test configured"],
  connection_failed: [
    "连接失败，请检查网络、地址及 TLS 配置",
    "Connection failed; check network, address and TLS",
  ],
  http_status_rejected: [
    "服务未接受 HEAD 检查；不自动发送其他请求",
    "Service rejected HEAD; no other request was sent",
  ],
};

export function ResourcesView({
  language,
  sessionToken,
  onTask,
}: {
  language: Language;
  sessionToken: string;
  onTask: (targetId: string, templateId?: string) => void;
}) {
  const zh = language === "zh-CN";
  const common = sharedCopy[language];
  const [items, setItems] = useState<Resource[]>([]);
  const [storage, setStorage] = useState<ConfigurationStorage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Resource | null>(null);
  const [form, setForm] = useState<ResourceRequest>(blank);
  const [secret, setSecret] = useState("");
  const [labels, setLabels] = useState("");
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ConnectionTestResult>>(
    {},
  );
  async function reload() {
    const result = await listResources(sessionToken);
    setItems(result.items);
    setStorage(result.storage);
    return result;
  }
  useEffect(() => {
    let active = true;
    listResources(sessionToken)
      .then((result) => {
        if (active) {
          setItems(result.items);
          setStorage(result.storage);
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
  }, [sessionToken, common.loadError]);
  const change = (value: Partial<ResourceRequest>) =>
    setForm((current) => ({ ...current, ...value }));
  function close() {
    setOpen(false);
    setEditing(null);
    setSecret("");
    setForm(blank());
    setLabels("");
  }
  function edit(resource: Resource) {
    setEditing(resource);
    setForm({
      name: resource.name,
      kind: resource.kind,
      environment: resource.environment,
      address: resource.address ?? "",
      username: resource.username ?? "",
      description: resource.description ?? "",
      authentication_kind: resource.authentication.kind,
      connection: resource.connection,
      labels: resource.labels,
      expected_version: resource.version,
    });
    setLabels(resource.labels.join(", "));
    setSecret("");
    setError(null);
    setOpen(true);
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    let savedId = editing?.id;
    try {
      let saved = await saveResource(
        sessionToken,
        {
          ...form,
          labels: labels
            .split(/[,，]/)
            .map((value) => value.trim())
            .filter(Boolean),
        },
        editing?.id,
      );
      // A failed native write leaves one visible unconfigured aggregate, not a duplicate on retry.
      savedId = saved.id;
      setEditing(saved);
      change({ expected_version: saved.version });
      if (secret) {
        const candidate = secret;
        setSecret("");
        saved = await setResourceSecret(sessionToken, saved, candidate);
      }
      await reload();
      close();
    } catch {
      setSecret("");
      const refreshed = await reload().catch(() => undefined);
      const current = refreshed?.items.find((item) => item.id === savedId);
      if (current) {
        setEditing(current);
        change({ expected_version: current.version });
      }
      setError(
        zh
          ? "未完成保存。资源可能已建立，秘密值已清空；请检查后重试。"
          : "Save was incomplete. The resource may exist; the secret buffer was cleared. Review and retry.",
      );
    } finally {
      setBusy(false);
    }
  }
  function selectKind(kind: ResourceRequest["kind"]) {
    const value: ConnectionOptions["protocol"] =
      kind === "database"
        ? "database"
        : kind === "ssh_host"
          ? "ssh"
          : kind === "http_service"
            ? "http"
            : kind === "telnet_host"
              ? "telnet"
              : "none";
    const connection: ConnectionOptions =
      value === "database"
        ? {
            protocol: value,
            engine: "postgres",
            port: 5432,
            database: "",
            tls_mode: "verify_full",
            ca_certificate: null,
          }
        : value === "ssh"
          ? { protocol: value, port: 22, host_key_sha256: "" }
          : value === "http"
            ? { protocol: value, authentication: "bearer", header_name: null }
            : value === "telnet"
              ? { protocol: value, allow_plaintext: false }
              : { protocol: "none" };
    const incompatible =
      kind === "database"
        ? form.authentication_kind !== "password"
        : kind === "ssh_host"
          ? form.authentication_kind === "api_token"
          : kind === "http_service"
            ? form.authentication_kind === "ssh_key"
            : false;
    if (incompatible && editing?.authentication.secret_state === "available") {
      setError(
        zh
          ? "请先清除当前秘密，再更改为此资源类型。"
          : "Clear the current secret before selecting this resource type.",
      );
      return;
    }
    if (incompatible) setSecret("");
    change({
      kind,
      connection,
      authentication_kind: incompatible ? "password" : form.authentication_kind,
    });
  }
  const connection = form.connection;
  return (
    <CatalogPage
      title={zh ? "资源" : "Resources"}
      subtitle={
        zh
          ? "地址、账号和认证统一维护。用环境与用途标签组织资源，任务按需组合使用；秘密值只写入本机凭据库。"
          : "Manage addresses, accounts and authentication together. Organize resources with environment and purpose labels; tasks compose them as needed. Secrets remain write-only in the OS store."
      }
      language={language}
      storage={storage}
      error={open ? null : error}
    >
      <CatalogForm
        title={
          editing
            ? zh
              ? "编辑资源"
              : "Edit resource"
            : zh
              ? "新建资源"
              : "New resource"
        }
        open={open}
        onOpen={() => {
          close();
          setOpen(true);
          setError(null);
        }}
        onClose={close}
        error={error}
        onSubmit={submit}
        busy={busy}
        submitLabel={editing ? common.save : common.add}
        busyLabel={common.saving}
        cancelLabel={common.cancel}
      >
        <ResourceFormSection
          title={zh ? "基本信息" : "Basic information"}
          hint={
            zh
              ? "带 * 为必填项；其余配置可稍后补充。"
              : "Fields marked * are required; other settings can be completed later."
          }
        >
          <div className="sm:col-span-2">
            <Field
              label={zh ? "资源名称 *" : "Resource name *"}
              htmlFor="resource-name"
            >
              <input
                id="resource-name"
                required
                maxLength={80}
                className={inputClass}
                value={form.name}
                onChange={(e) => change({ name: e.target.value })}
              />
            </Field>
          </div>
          <div className="grid gap-4 sm:col-span-2 sm:grid-cols-2">
            <Field label={zh ? "类型" : "Type"} htmlFor="resource-kind">
              <select
                id="resource-kind"
                className={inputClass}
                value={form.kind}
                onChange={(e) =>
                  selectKind(e.target.value as ResourceRequest["kind"])
                }
              >
                {Object.entries(targetKindLabels[language]).map(
                  ([key, value]) => (
                    <option key={key} value={key}>
                      {value}
                    </option>
                  ),
                )}
              </select>
            </Field>
            <Field
              label={zh ? "环境" : "Environment"}
              htmlFor="resource-environment"
            >
              <select
                id="resource-environment"
                className={inputClass}
                value={form.environment}
                onChange={(e) =>
                  change({
                    environment: e.target
                      .value as ResourceRequest["environment"],
                  })
                }
              >
                {Object.entries(environmentLabels[language]).map(
                  ([key, value]) => (
                    <option key={key} value={key}>
                      {value}
                    </option>
                  ),
                )}
              </select>
            </Field>
          </div>
        </ResourceFormSection>
        <ResourceFormSection
          title={zh ? "连接参数" : "Connection settings"}
          hint={
            zh
              ? "地址只填写一次。数据库及协议细节按实际需要补充。"
              : "Enter the address once. Add database and protocol details as needed."
          }
        >
          {connection.protocol === "database" && (
            <Field
              label={zh ? "数据库引擎" : "Database engine"}
              htmlFor="resource-engine"
            >
              <select
                id="resource-engine"
                className={inputClass}
                value={connection.engine}
                onChange={(e) =>
                  change({
                    connection: {
                      ...connection,
                      engine: e.target.value as "postgres" | "mysql",
                      port: e.target.value === "mysql" ? 3306 : 5432,
                    },
                  })
                }
              >
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL</option>
              </select>
            </Field>
          )}
          <div
            className={
              connection.protocol === "database" ||
              connection.protocol === "ssh"
                ? ""
                : "sm:col-span-2"
            }
          >
            <Field
              label={zh ? "主机或地址" : "Host or address"}
              htmlFor="resource-address"
            >
              <input
                id="resource-address"
                className={inputClass}
                maxLength={2048}
                value={form.address ?? ""}
                onChange={(e) => change({ address: e.target.value })}
              />
            </Field>
          </div>
          {(connection.protocol === "database" ||
            connection.protocol === "ssh") && (
            <Field label={zh ? "端口" : "Port"} htmlFor="resource-port">
              <input
                id="resource-port"
                type="number"
                min={1}
                max={65535}
                className={inputClass}
                value={connection.port}
                onChange={(e) =>
                  change({
                    connection: {
                      ...connection,
                      port: e.target.value
                        ? Number(e.target.value)
                        : connection.protocol === "ssh"
                          ? 22
                          : connection.engine === "mysql"
                            ? 3306
                            : 5432,
                    },
                  })
                }
              />
            </Field>
          )}
          {connection.protocol === "database" && (
            <Field
              label={zh ? "数据库名" : "Database"}
              htmlFor="resource-database"
            >
              <input
                id="resource-database"
                className={inputClass}
                value={connection.database}
                onChange={(e) =>
                  change({
                    connection: { ...connection, database: e.target.value },
                  })
                }
              />
            </Field>
          )}{" "}
          {connection.protocol === "database" && (
            <>
              <Field
                label={zh ? "传输加密" : "Transport encryption"}
                htmlFor="resource-tls"
              >
                <select
                  id="resource-tls"
                  className={inputClass}
                  value={connection.tls_mode}
                  onChange={(e) =>
                    change({
                      connection: {
                        ...connection,
                        tls_mode: e.target.value as "verify_full" | "disabled",
                        ca_certificate: null,
                      },
                    })
                  }
                >
                  <option value="verify_full">
                    {zh
                      ? "TLS：验证证书与主机名"
                      : "TLS: verify certificate and hostname"}
                  </option>
                  <option value="disabled">
                    {zh ? "不使用 TLS" : "No TLS"}
                  </option>
                </select>
              </Field>
              {connection.tls_mode === "disabled" ? (
                <p
                  role="note"
                  className="border-l-4 border-amber-400 bg-amber-50 p-3 text-sm text-amber-950"
                >
                  {zh
                    ? "账号、密码和数据将明文传输。仅在你信任的网络中使用；不会自动切换或放宽 TLS 验证。"
                    : "Accounts, passwords and data travel unencrypted. Use only on a network you trust; TLS verification is never downgraded automatically."}
                </p>
              ) : (
                <Field
                  label={
                    zh ? "自定义 CA 路径（可选）" : "Custom CA path (optional)"
                  }
                  htmlFor="resource-ca"
                >
                  <input
                    id="resource-ca"
                    className={inputClass}
                    value={connection.ca_certificate ?? ""}
                    onChange={(e) =>
                      change({
                        connection: {
                          ...connection,
                          ca_certificate: e.target.value || null,
                        },
                      })
                    }
                  />
                </Field>
              )}
            </>
          )}{" "}
          {connection.protocol === "ssh" && (
            <Field
              label={
                zh
                  ? "已核验的 SSH 主机指纹（SHA256）"
                  : "Verified SSH host fingerprint (SHA256)"
              }
              htmlFor="resource-host-key"
            >
              <input
                id="resource-host-key"
                className={inputClass}
                value={connection.host_key_sha256}
                onChange={(e) =>
                  change({
                    connection: {
                      ...connection,
                      host_key_sha256: e.target.value,
                    },
                  })
                }
              />
            </Field>
          )}
          {connection.protocol === "telnet" && (
            <label className="flex gap-3 border-l-4 border-amber-400 bg-amber-50 p-3 text-sm text-amber-950">
              <input
                type="checkbox"
                checked={connection.allow_plaintext}
                onChange={(e) =>
                  change({
                    connection: {
                      ...connection,
                      allow_plaintext: e.target.checked,
                    },
                  })
                }
              />
              {zh
                ? "允许此 Telnet 资源使用明文协议（密码和数据不加密）"
                : "Allow plaintext for this Telnet resource (passwords and data are unencrypted)"}
            </label>
          )}
        </ResourceFormSection>
        <ResourceFormSection
          title={zh ? "身份认证" : "Authentication"}
          hint={
            zh
              ? "秘密仅写入本机凭据库，保存后清空；也可先保存资源再配置。"
              : "Secrets are write-only and cleared after saving; authentication can also be added later."
          }
        >
          <Field
            label={zh ? "账号（可选）" : "Account (optional)"}
            htmlFor="resource-username"
          >
            <input
              id="resource-username"
              className={inputClass}
              maxLength={256}
              value={form.username ?? ""}
              onChange={(e) => change({ username: e.target.value })}
            />
          </Field>
          <Field
            label={zh ? "认证类型" : "Authentication"}
            htmlFor="resource-authentication"
          >
            <select
              id="resource-authentication"
              className={inputClass}
              disabled={editing?.authentication.secret_state === "available"}
              value={form.authentication_kind}
              onChange={(e) => {
                change({
                  authentication_kind: e.target
                    .value as ResourceRequest["authentication_kind"],
                });
                setSecret("");
              }}
            >
              {Object.entries(credentialKindLabels[language]).map(
                ([key, value]) =>
                  (connection.protocol === "database"
                    ? key === "password"
                    : connection.protocol === "ssh"
                      ? key !== "api_token"
                      : connection.protocol === "http"
                        ? key !== "ssh_key"
                        : true) && (
                    <option key={key} value={key}>
                      {value}
                    </option>
                  ),
              )}
            </select>
          </Field>
          {editing?.authentication.secret_state === "available" && (
            <p className="sm:col-span-2 text-xs text-slate-500">
              {zh
                ? "清除当前秘密后才能更改认证类型。"
                : "Clear the current secret before changing its authentication type."}
            </p>
          )}
          {connection.protocol === "http" && (
            <Field
              label={zh ? "HTTP 认证方式" : "HTTP authentication"}
              htmlFor="resource-http-auth"
            >
              <select
                id="resource-http-auth"
                className={inputClass}
                value={connection.authentication}
                onChange={(e) =>
                  change({
                    connection: {
                      ...connection,
                      authentication: e.target.value as
                        "none" | "bearer" | "basic" | "api_key",
                      header_name:
                        e.target.value === "api_key" ? "X-API-Key" : null,
                    },
                  })
                }
              >
                <option value="none">{zh ? "无认证" : "None"}</option>
                <option value="bearer">Bearer</option>
                <option value="basic">Basic</option>
                <option value="api_key">API Key</option>
              </select>
            </Field>
          )}
          {connection.protocol === "http" &&
            connection.authentication === "api_key" && (
              <Field
                label={zh ? "API Key 请求头名称" : "API Key header name"}
                htmlFor="resource-api-header"
              >
                <input
                  id="resource-api-header"
                  maxLength={128}
                  className={inputClass}
                  value={connection.header_name ?? ""}
                  onChange={(e) =>
                    change({
                      connection: {
                        ...connection,
                        header_name: e.target.value,
                      },
                    })
                  }
                />
              </Field>
            )}
          <div className="sm:col-span-2">
            <Field
              label={
                editing
                  ? zh
                    ? "替换秘密值（留空不更改）"
                    : "Replace secret (leave empty to keep)"
                  : zh
                    ? "秘密值（可稍后配置）"
                    : "Secret (can be configured later)"
              }
              htmlFor="resource-secret"
            >
              <CredentialSecretInput
                id="resource-secret"
                kind={form.authentication_kind}
                value={secret}
                onChange={setSecret}
                onError={() => setError(common.saveError)}
                placeholder={
                  zh
                    ? "保存后立即清空，不可读回"
                    : "Cleared after saving; never read back"
                }
                className={inputClass}
                zh={zh}
              />
            </Field>
          </div>
        </ResourceFormSection>
        <ResourceFormSection
          title={zh ? "用途与说明" : "Purpose and description"}
          hint={
            zh
              ? "可选信息，方便检索和区分资源用途。"
              : "Optional metadata for finding resources and understanding their purpose."
          }
        >
          <Field
            label={
              zh
                ? "用途标签（逗号分隔，可选）"
                : "Purpose labels (comma separated, optional)"
            }
            htmlFor="resource-labels"
          >
            <input
              id="resource-labels"
              className={inputClass}
              value={labels}
              onChange={(e) => setLabels(e.target.value)}
              placeholder={
                zh
                  ? "如：报表、开发工具、个人服务"
                  : "Reporting, development, personal services"
              }
            />
          </Field>
          <div className="sm:col-span-2">
            <Field
              label={zh ? "说明（可选）" : "Description (optional)"}
              htmlFor="resource-description"
            >
              <textarea
                id="resource-description"
                maxLength={240}
                className={inputClass}
                value={form.description ?? ""}
                onChange={(e) => change({ description: e.target.value })}
              />
            </Field>
          </div>
        </ResourceFormSection>
      </CatalogForm>
      <CatalogList
        title={zh ? "已保存资源" : "Saved resources"}
        icon="target"
        loading={loading}
        loadingLabel={common.loading}
        emptyLabel={
          zh
            ? "创建一个资源即可配置认证和连接，无需分别登记。"
            : "Create a resource to configure authentication and connection together."
        }
        items={items.map((item) => ({
          id: item.id,
          name: item.name,
          detail: `${targetKindLabels[language][item.kind]} · ${environmentLabels[language][item.environment]} · ${item.labels.join(" · ")}`,
        }))}
        language={language}
      >
        {items.map((item) => (
          <article key={item.id} className="p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex flex-wrap gap-2 text-xs text-slate-600">
                  <span>{targetKindLabels[language][item.kind]}</span>
                  <span>· {environmentLabels[language][item.environment]}</span>
                  {item.labels.map((label) => (
                    <span
                      key={label}
                      className="rounded bg-slate-100 px-2 py-0.5"
                    >
                      {label}
                    </span>
                  ))}
                </div>
                <h2 className="mt-3 mb-1 text-xl font-semibold">{item.name}</h2>
                <p className="m-0 text-sm text-slate-500">
                  {item.username ? `${item.username} @ ` : ""}
                  {item.address ||
                    (zh ? "未设置地址" : "No address configured")}
                </p>
              </div>
              <div className="flex gap-2">
                <IconButton label={common.edit} onClick={() => edit(item)}>
                  <Pencil className="size-4" />
                </IconButton>
                <DeleteButton
                  label={common.delete}
                  onClick={async () => {
                    if (!window.confirm(common.confirmDelete)) return;
                    try {
                      await removeResource(sessionToken, item.id);
                      await reload();
                    } catch {
                      setError(common.deleteError);
                    }
                  }}
                />
              </div>
            </div>
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-y border-slate-100 py-4">
              <span className="inline-flex items-center gap-2 text-sm">
                <ShieldCheck className="size-4 text-cyan-700" />
                {
                  credentialKindLabels[language][item.authentication.kind]
                } ·{" "}
                {item.authentication.secret_state === "available"
                  ? zh
                    ? "已安全保存"
                    : "Securely saved"
                  : zh
                    ? "待配置"
                    : "Not configured"}
              </span>
              <div className="flex gap-2">
                <button className="workbench-button" onClick={() => edit(item)}>
                  {zh ? "更换认证" : "Change authentication"}
                </button>
                {item.authentication.secret_state === "available" && (
                  <button
                    className="workbench-button text-rose-700"
                    onClick={async () => {
                      if (
                        !window.confirm(
                          zh
                            ? "清除秘密值后相关任务将无法认证，是否继续？"
                            : "Clear the secret? Related tasks will no longer authenticate.",
                        )
                      )
                        return;
                      try {
                        await clearResourceSecret(sessionToken, item);
                        await reload();
                      } catch {
                        setError(common.saveError);
                      }
                    }}
                  >
                    {zh ? "清除秘密" : "Clear secret"}
                  </button>
                )}
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <span className="text-sm text-slate-500">
                {item.connection.protocol === "database"
                  ? `${item.connection.engine} · ${item.connection.database} · ${item.connection.port} · TLS ${item.connection.tls_mode}`
                  : item.connection.protocol.toUpperCase()}
              </span>
              <button
                className="workbench-button"
                disabled={
                  testing !== null ||
                  item.connection.protocol === "none" ||
                  item.connection.protocol === "telnet"
                }
                onClick={async () => {
                  setTesting(item.id);
                  try {
                    const result = await testResource(sessionToken, item);
                    setResults((current) => ({
                      ...current,
                      [item.id]: result,
                    }));
                  } catch {
                    setError(
                      zh
                        ? "测试未完成，请检查会话和资源版本。"
                        : "Test not completed; check session and resource version.",
                    );
                  } finally {
                    setTesting(null);
                  }
                }}
              >
                <PlugZap className="mr-2 size-4" />
                {testing === item.id
                  ? zh
                    ? "测试中…"
                    : "Testing…"
                  : zh
                    ? "测试连接"
                    : "Test connection"}
              </button>
            </div>
            {results[item.id] && (
              <p
                role="status"
                className={`mt-3 border-l-4 p-3 text-sm ${results[item.id].success ? "border-emerald-400 bg-emerald-50 text-emerald-800" : "border-amber-400 bg-amber-50 text-amber-900"}`}
              >
                {testCodes[results[item.id].code]?.[zh ? 0 : 1] ??
                  results[item.id].code}{" "}
                {(results[item.id].missing_fields ?? [])
                  .map((field) => missingLabels[field]?.[zh ? 0 : 1] ?? field)
                  .join("、")}{" "}
                · {results[item.id].duration_ms} ms ·{" "}
                {new Intl.DateTimeFormat(language, {
                  timeStyle: "medium",
                }).format(results[item.id].tested_at_unix_ms)}
              </p>
            )}
            {item.description && (
              <p className="text-sm text-slate-600">{item.description}</p>
            )}
            <ConnectionRelations
              targetId={item.id}
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

function ResourceFormSection({
  title,
  hint,
  children,
}: {
  title: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <section className="min-w-0 border-t border-slate-200 pt-5 first:border-0 first:pt-0 md:col-span-2">
      <h3 className="m-0 text-sm font-semibold text-slate-950">{title}</h3>
      <p className="mb-4 mt-1 text-xs leading-5 text-slate-500">{hint}</p>
      <div className="grid min-w-0 gap-4 sm:grid-cols-2">{children}</div>
    </section>
  );
}
