// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import type {
  CommandConfig,
  CredentialReference,
  HttpConfig,
  HttpField,
  HttpValueSource,
} from "./api";

export const emptyHttp: HttpConfig = {
  method: "GET",
  url: "",
  headers: [],
  query: [],
  body: [],
  response_fields: [],
  accepted_statuses: [],
};
export function nextFieldName(names: string[], prefix: string): string {
  let i = 1;
  while (names.includes(`${prefix}_${i}`)) i++;
  return `${prefix}_${i}`;
}
export function parseStatuses(text: string): number[] | null {
  if (!text.trim()) return [];
  const parts = text.trim().split(/[\s,]+/);
  return parts.length <= 32 && parts.every((p) => /^[2-5][0-9]{2}$/.test(p))
    ? [...new Set(parts.map(Number))]
    : null;
}

export function HttpEditor({
  value,
  onChange,
  config,
  onConfigChange,
  credentials,
  zh,
}: {
  value: HttpConfig;
  onChange: (v: HttpConfig) => void;
  config: CommandConfig;
  onConfigChange: (c: CommandConfig) => void;
  credentials: CredentialReference[];
  zh: boolean;
}) {
  const [statuses, setStatuses] = useState(value.accepted_statuses.join(", "));
  useEffect(
    () => setStatuses(value.accepted_statuses.join(", ")),
    [value.accepted_statuses],
  );
  const editSlot = (
    i: number,
    change: Partial<CommandConfig["slots"][number]>,
  ) =>
    onConfigChange({
      ...config,
      slots: config.slots.map((s, j) => (i === j ? { ...s, ...change } : s)),
    });
  return (
    <>
      <div className="grid gap-4 sm:grid-cols-[8rem_1fr]">
        <label className="text-sm font-semibold">
          {zh ? "请求方法" : "Method"}
          <select
            value={value.method}
            onChange={(e) =>
              onChange({
                ...value,
                method: e.target.value,
                body: ["GET", "HEAD"].includes(e.target.value)
                  ? []
                  : value.body,
              })
            }
            className={input}
          >
            {["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
        </label>
        <label className="text-sm font-semibold">
          {zh
            ? "固定请求地址（不含查询串、账户或密码）"
            : "Fixed URL (no query, user or password)"}
          <input
            type="url"
            required
            maxLength={2048}
            value={value.url}
            placeholder="https://api.example.com/v1/status"
            onChange={(e) => onChange({ ...value, url: e.target.value })}
            className={input}
          />
        </label>
      </div>
      {value.url.trim().toLowerCase().startsWith("http:") && (
        <p className="border-l-4 border-amber-400 px-3 text-sm text-amber-900">
          {zh
            ? "HTTP 不加密传输，凭据可能被网络上的其他人读取。除可信本机测试外，请使用 HTTPS。"
            : "HTTP sends credentials without transport encryption. Prefer HTTPS except for trusted local tests."}
        </p>
      )}
      <section className="space-y-2 border-t border-slate-200 pt-4">
        <h3 className="text-sm font-semibold">
          {zh ? "认证凭据插槽" : "Authentication slots"}
        </h3>
        {config.slots.map((s, i) => (
          <div
            key={i}
            className="grid items-end gap-2 sm:grid-cols-[1fr_2fr_auto]"
          >
            <label className="text-xs">
              {zh ? "插槽名" : "Slot name"}
              <input
                required
                pattern="[A-Za-z_][A-Za-z_0-9]*"
                maxLength={64}
                value={s.name}
                onChange={(e) => editSlot(i, { name: e.target.value })}
                className={input}
              />
            </label>
            <label className="text-xs">
              {zh ? "凭据引用" : "Credential"}
              <select
                required
                value={s.credential_id}
                onChange={(e) => editSlot(i, { credential_id: e.target.value })}
                className={input}
              >
                <option value="">
                  {zh ? "选择凭据" : "Choose credential"}
                </option>
                {credentials.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                    {c.secret_state !== "available"
                      ? zh
                        ? "（未配置）"
                        : " (not configured)"
                      : ""}
                  </option>
                ))}
              </select>
            </label>
            <Remove
              zh={zh}
              onClick={() =>
                onConfigChange({
                  ...config,
                  slots: config.slots.filter((_, j) => i !== j),
                })
              }
            />
          </div>
        ))}
        <Add
          zh={zh}
          disabled={config.slots.length >= 8}
          onClick={() =>
            onConfigChange({
              ...config,
              slots: [
                ...config.slots,
                {
                  name: nextFieldName(
                    config.slots.map((s) => s.name),
                    "secret",
                  ),
                  credential_id: "",
                  injection: "protocol",
                  environment_variable: null,
                },
              ],
            })
          }
        />
      </section>
      <Fields
        title={
          zh ? "请求头（如 Authorization）" : "Headers (e.g. Authorization)"
        }
        fields={value.headers}
        onChange={(headers) => onChange({ ...value, headers })}
        config={config}
        secret
        zh={zh}
      />
      <Fields
        title={
          zh
            ? "查询参数（自动编码）"
            : "Query parameters (encoded automatically)"
        }
        fields={value.query}
        onChange={(query) => onChange({ ...value, query })}
        config={config}
        secret={false}
        zh={zh}
      />
      {!["GET", "HEAD"].includes(value.method) && (
        <Fields
          title={zh ? "JSON 请求体字段" : "JSON body fields"}
          fields={value.body}
          onChange={(body) => onChange({ ...value, body })}
          config={config}
          secret
          zh={zh}
        />
      )}
      <section className="space-y-2 border-t border-slate-200 pt-4">
        <h3 className="text-sm font-semibold">
          {zh
            ? "返回字段（留空只返回状态码）"
            : "Response fields (empty means status only)"}
        </h3>
        <p className="text-xs text-slate-600">
          {zh
            ? "用 JSON Pointer 选择字段，如 /data/version；响应最大 256 KiB。"
            : "Select fields using JSON Pointer, e.g. /data/version. Response limit: 256 KiB."}
        </p>
        {value.response_fields.map((f, i) => (
          <div
            key={i}
            className="grid items-end gap-2 sm:grid-cols-[1fr_2fr_auto]"
          >
            <label className="text-xs">
              {zh ? "输出名" : "Output name"}
              <input
                required
                maxLength={64}
                pattern="[A-Za-z_][A-Za-z_0-9]*"
                value={f.name}
                onChange={(e) =>
                  onChange({
                    ...value,
                    response_fields: value.response_fields.map((v, j) =>
                      i === j ? { ...v, name: e.target.value } : v,
                    ),
                  })
                }
                className={input}
              />
            </label>
            <label className="text-xs">
              JSON Pointer
              <input
                maxLength={512}
                pattern="/.*|"
                value={f.pointer}
                onChange={(e) =>
                  onChange({
                    ...value,
                    response_fields: value.response_fields.map((v, j) =>
                      i === j ? { ...v, pointer: e.target.value } : v,
                    ),
                  })
                }
                className={input}
              />
            </label>
            <Remove
              zh={zh}
              onClick={() =>
                onChange({
                  ...value,
                  response_fields: value.response_fields.filter(
                    (_, j) => i !== j,
                  ),
                })
              }
            />
          </div>
        ))}
        <Add
          zh={zh}
          disabled={value.response_fields.length >= 32}
          onClick={() =>
            onChange({
              ...value,
              response_fields: [
                ...value.response_fields,
                {
                  name: nextFieldName(
                    value.response_fields.map((f) => f.name),
                    "field",
                  ),
                  pointer: "/data",
                },
              ],
            })
          }
        />
      </section>
      <label className="block text-sm font-semibold">
        {zh
          ? "成功状态码（留空接受所有 2xx）"
          : "Accepted status codes (empty accepts all 2xx)"}
        <input
          value={statuses}
          placeholder="200, 201, 204"
          onChange={(e) => {
            const text = e.target.value;
            setStatuses(text);
            const parsed = parseStatuses(text);
            e.target.setCustomValidity(
              parsed
                ? ""
                : zh
                  ? "填写 200–599 状态码，以逗号或空格分隔，最多 32 个。"
                  : "Enter up to 32 codes from 200–599, separated by commas or spaces.",
            );
            if (parsed) onChange({ ...value, accepted_statuses: parsed });
          }}
          className={input}
        />
      </label>
      <p className="border-l-4 border-cyan-600 px-3 text-sm leading-6 text-slate-600">
        {zh
          ? "凭据只填充到请求头或 JSON 请求体，不放入 URL。不跟随重定向、不使用环境代理、不返回原始响应头。不要在固定文本里填写密码；改用凭据插槽。"
          : "Credentials go only into headers or JSON body, never URLs. Redirects and environment proxies are disabled; raw response headers are not returned. Use credential slots, not literal passwords."}
      </p>
    </>
  );
}

function Fields({
  title,
  fields,
  onChange,
  config,
  secret,
  zh,
}: {
  title: string;
  fields: HttpField[];
  onChange: (f: HttpField[]) => void;
  config: CommandConfig;
  secret: boolean;
  zh: boolean;
}) {
  const edit = (i: number, c: Partial<HttpField>) =>
    onChange(fields.map((f, j) => (i === j ? { ...f, ...c } : f)));
  return (
    <section className="space-y-2 border-t border-slate-200 pt-4">
      <h3 className="text-sm font-semibold">{title}</h3>
      {fields.map((f, i) => (
        <div
          key={i}
          className="grid items-end gap-2 sm:grid-cols-[1fr_8rem_2fr_auto]"
        >
          <label className="text-xs">
            {zh ? "字段名" : "Name"}
            <input
              required
              maxLength={128}
              value={f.name}
              onChange={(e) => edit(i, { name: e.target.value })}
              className={input}
            />
          </label>
          <label className="text-xs">
            {zh ? "来源" : "Source"}
            <select
              value={f.source.kind}
              onChange={(e) => {
                const kind = e.target.value as HttpValueSource["kind"];
                edit(i, {
                  source:
                    kind === "literal"
                      ? { kind, value: "" }
                      : kind === "parameter"
                        ? { kind, name: "" }
                        : { kind, name: "", prefix: "" },
                });
              }}
              className={input}
            >
              <option value="literal">{zh ? "固定文本" : "Literal"}</option>
              <option value="parameter">{zh ? "普通参数" : "Parameter"}</option>
              {secret && (
                <option value="credential">
                  {zh ? "凭据插槽" : "Credential slot"}
                </option>
              )}
            </select>
          </label>
          <div>
            {f.source.kind === "literal" ? (
              <label className="text-xs">
                {zh ? "文本" : "Text"}
                <input
                  maxLength={8192}
                  value={f.source.value}
                  onChange={(e) =>
                    edit(i, {
                      source: { kind: "literal", value: e.target.value },
                    })
                  }
                  className={input}
                />
              </label>
            ) : (
              <label className="text-xs">
                {f.source.kind === "parameter"
                  ? zh
                    ? "参数名（在下方定义）"
                    : "Parameter (defined below)"
                  : zh
                    ? "插槽名"
                    : "Slot name"}
                <select
                  required
                  value={f.source.name}
                  onChange={(e) =>
                    edit(i, {
                      source: {
                        ...f.source,
                        name: e.target.value,
                      } as HttpValueSource,
                    })
                  }
                  className={input}
                >
                  <option value="">{zh ? "请选择" : "Choose"}</option>
                  {(f.source.kind === "parameter"
                    ? (config.parameters ?? [])
                    : config.slots
                  ).map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {f.source.kind === "credential" && (
              <label className="mt-2 block text-xs">
                {zh
                  ? "前缀（可用 Bearer 加空格）"
                  : "Prefix (e.g. Bearer + space)"}
                <input
                  maxLength={128}
                  value={f.source.prefix}
                  onChange={(e) =>
                    edit(i, {
                      source: {
                        ...f.source,
                        prefix: e.target.value,
                      } as HttpValueSource,
                    })
                  }
                  className={input}
                />
              </label>
            )}
          </div>
          <Remove
            zh={zh}
            onClick={() => onChange(fields.filter((_, j) => i !== j))}
          />
        </div>
      ))}
      <Add
        zh={zh}
        disabled={fields.length >= 32}
        onClick={() =>
          onChange([
            ...fields,
            {
              name: nextFieldName(
                fields.map((f) => f.name),
                "field",
              ),
              source: { kind: "literal", value: "" },
            },
          ])
        }
      />
    </section>
  );
}
function Add({
  zh,
  disabled,
  onClick,
}: {
  zh: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="inline-flex items-center gap-2 py-2 text-sm font-semibold text-cyan-700 disabled:opacity-50"
    >
      <Plus className="size-4" />
      {zh ? "添加一行" : "Add row"}
    </button>
  );
}
function Remove({ zh, onClick }: { zh: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      aria-label={zh ? "移除行" : "Remove row"}
      onClick={onClick}
      className="rounded-lg p-3 text-slate-500 hover:bg-rose-50 hover:text-rose-700"
    >
      <Trash2 className="size-4" />
    </button>
  );
}
const input =
  "mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";
