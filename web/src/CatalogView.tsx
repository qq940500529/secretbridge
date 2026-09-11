// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  CircleAlert,
  KeyRound,
  LoaderCircle,
  Plus,
  ServerCog,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useMemo, useState } from "react";

import {
  createCredentialReference,
  createTarget,
  deleteCredentialReference,
  deleteTarget,
  listCredentialReferences,
  listTargets,
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
    memoryBody: "服务重启后自动清空。本阶段只验证配置关系，不接收真实密码、令牌、私钥或业务地址。",
    loading: "正在读取本机配置…",
    loadError: "配置读取失败，请确认本地服务仍在线且页面会话有效。",
    saveError: "保存失败，请检查字段或重新配对页面会话。",
    deleteError: "删除失败。该记录可能仍被引用，或页面会话已经失效。",
    delete: "删除",
    saving: "保存中…",
    add: "添加",
    empty: "还没有记录",
  },
  en: {
    memoryTitle: "Configuration is currently memory-only",
    memoryBody: "Everything is cleared on service restart. This phase validates relationships only and accepts no real passwords, tokens, private keys, or business addresses.",
    loading: "Loading local configuration…",
    loadError: "Could not load configuration. Check the local service and page session.",
    saveError: "Could not save. Check the fields or pair this page again.",
    deleteError: "Could not delete. The record may still be referenced, or the page session may have expired.",
    delete: "Delete",
    saving: "Saving…",
    add: "Add",
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
        subtitle: "这里只登记凭据的名称、类型和用途。秘密值将在通过安全门槛后由本机安全存储单独管理。",
        formTitle: "添加凭据引用",
        name: "引用名称",
        namePlaceholder: "例如：测试库只读账号",
        kind: "凭据类型",
        purpose: "用途说明（可选）",
        purposePlaceholder: "说明允许用于什么，不要填写任何秘密",
        listTitle: "已登记的引用",
        state: "未配置秘密",
      }
    : {
        eyebrow: "M1 · Credential references",
        title: "Build a credential-purpose catalog",
        subtitle: "Only names, types, and intended uses are recorded here. Secret values will be handled separately by native secure storage after the security gates pass.",
        formTitle: "Add credential reference",
        name: "Reference name",
        namePlaceholder: "Example: test database read-only account",
        kind: "Credential type",
        purpose: "Purpose (optional)",
        purposePlaceholder: "Describe the allowed use; never enter a secret",
        listTitle: "Registered references",
        state: "Secret not configured",
      };
  const [items, setItems] = useState<CredentialReference[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<CredentialKind>("password");
  const [purpose, setPurpose] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    listCredentialReferences(sessionToken)
      .then((records) => { if (active) setItems(records); })
      .catch(() => { if (active) setError(common.loadError); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [common.loadError, sessionToken]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const item = await createCredentialReference(sessionToken, {
        name,
        kind,
        ...(purpose.trim() ? { purpose } : {}),
      });
      setItems((current) => [...current, item]);
      setName("");
      setPurpose("");
    } catch {
      setError(common.saveError);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await deleteCredentialReference(sessionToken, id);
      setItems((current) => current.filter((item) => item.id !== id));
    } catch {
      setError(common.deleteError);
    }
  }

  return (
    <CatalogPage
      eyebrow={text.eyebrow}
      title={text.title}
      subtitle={text.subtitle}
      language={language}
      error={error}
    >
      <CatalogForm
        title={text.formTitle}
        onSubmit={submit}
        busy={busy}
        submitLabel={common.add}
        busyLabel={common.saving}
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
                  <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600"><ShieldCheck className="size-3.5" />{text.state}</span>
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">{item.name}</h2>
                {item.purpose && <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">{item.purpose}</p>}
              </div>
              <DeleteButton label={common.delete} onClick={() => void remove(item.id)} />
            </div>
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
        subtitle: "当前只登记逻辑目标，不接收主机名、端口、连接串或网络地址，也不会尝试连接业务系统。",
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
      }
    : {
        eyebrow: "M1 · Targets",
        title: "Define logical targets and credential relationships",
        subtitle: "This alpha records logical targets only. It accepts no hostnames, ports, connection strings, or network addresses and makes no business-system connections.",
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
      };
  const [items, setItems] = useState<Target[]>([]);
  const [credentials, setCredentials] = useState<CredentialReference[]>([]);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<TargetKind>("database");
  const [environment, setEnvironment] = useState<TargetEnvironment>("test");
  const [description, setDescription] = useState("");
  const [credentialId, setCredentialId] = useState("");
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
          setItems(targets);
          setCredentials(references);
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
      const item = await createTarget(sessionToken, {
        name,
        kind,
        environment,
        ...(description.trim() ? { description } : {}),
        ...(credentialId ? { credential_reference_id: credentialId } : {}),
      });
      setItems((current) => [...current, item]);
      setName("");
      setDescription("");
    } catch {
      setError(common.saveError);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await deleteTarget(sessionToken, id);
      setItems((current) => current.filter((item) => item.id !== id));
    } catch {
      setError(common.deleteError);
    }
  }

  return (
    <CatalogPage
      eyebrow={text.eyebrow}
      title={text.title}
      subtitle={text.subtitle}
      language={language}
      error={error}
    >
      <CatalogForm
        title={text.formTitle}
        onSubmit={submit}
        busy={busy}
        submitLabel={common.add}
        busyLabel={common.saving}
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
                </div>
                <h2 className="m-0 break-words text-base font-semibold text-slate-950">{item.name}</h2>
                {item.description && <p className="mb-0 mt-2 break-words text-sm leading-6 text-slate-600">{item.description}</p>}
                <p className="mb-0 mt-3 flex items-center gap-2 text-xs font-medium text-slate-500">
                  <KeyRound className="size-3.5" />
                  {item.credential_reference_id
                    ? (credentialNames.get(item.credential_reference_id) ?? text.noCredential)
                    : text.noCredential}
                </p>
              </div>
              <DeleteButton label={common.delete} onClick={() => void remove(item.id)} />
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
  error,
  children,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  language: Language;
  error: string | null;
  children: ReactNode;
}) {
  const common = sharedCopy[language];
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
          <p className="m-0 text-sm font-semibold">{common.memoryTitle}</p>
          <p className="mb-0 mt-1 text-sm leading-6 text-amber-900/75">{common.memoryBody}</p>
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

function CatalogForm({ title, onSubmit, busy, submitLabel, busyLabel, children }: { title: string; onSubmit: (event: FormEvent) => void; busy: boolean; submitLabel: string; busyLabel: string; children: ReactNode }) {
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
