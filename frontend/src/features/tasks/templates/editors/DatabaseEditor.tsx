// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  CommandConfig,
  CredentialReference,
  DatabaseConfig,
} from "../../../../api/index";

export const emptyDatabase: DatabaseConfig = {
  engine: "postgres",
  operation: "check",
  host: "",
  port: 5432,
  database: "",
  username: "",
  password_slot: "database_password",
  tls_mode: "verify_full",
  ca_certificate: null,
  query: "",
  columns: [],
  max_rows: 100,
};
const input =
  "mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal";
export function DatabaseEditor({
  config,
  onChange,
  credentials,
  zh,
}: {
  config: CommandConfig;
  onChange: (value: CommandConfig) => void;
  credentials: CredentialReference[];
  zh: boolean;
}) {
  const value = config.database!;
  const update = (change: Partial<DatabaseConfig>) =>
    onChange({ ...config, database: { ...value, ...change } });
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="text-sm font-semibold">
          {zh ? "数据库类型" : "Database engine"}
          <select
            className={input}
            value={value.engine}
            onChange={(e) =>
              update({
                engine: e.target.value as DatabaseConfig["engine"],
                port: e.target.value === "mysql" ? 3306 : 5432,
              })
            }
          >
            <option value="postgres">PostgreSQL</option>
            <option value="mysql">MySQL</option>
          </select>
        </label>
        <label className="text-sm font-semibold">
          {zh ? "数据库操作" : "Database operation"}
          <select
            className={input}
            value={value.operation}
            onChange={(e) =>
              onChange({
                ...config,
                parameters: [],
                database: {
                  ...value,
                  operation: e.target.value as DatabaseConfig["operation"],
                  query: "",
                  columns: [],
                },
              })
            }
          >
            <option value="check">
              {zh ? "连接检查" : "Connection check"}
            </option>
            <option value="version">
              {zh ? "版本查询" : "Server version"}
            </option>
            <option value="query">
              {zh ? "只读查询模板" : "Read-only query template"}
            </option>
          </select>
        </label>
        {(
          [
            ["host", zh ? "数据库主机" : "Database host"],
            ["database", zh ? "数据库名称" : "Database name"],
            ["username", zh ? "数据库用户名" : "Database username"],
          ] as const
        ).map(([key, label]) => (
          <label key={key} className="text-sm font-semibold">
            {label}
            <input
              className={input}
              value={value[key]}
              required
              onChange={(e) => update({ [key]: e.target.value })}
            />
          </label>
        ))}
        <label className="text-sm font-semibold">
          {zh ? "数据库端口" : "Database port"}
          <input
            type="number"
            min={1}
            max={65535}
            required
            className={input}
            value={value.port}
            onChange={(e) => update({ port: Number(e.target.value) })}
          />
        </label>
        <label className="text-sm font-semibold">
          {zh ? "数据库密码引用" : "Database password reference"}
          <select
            required
            className={input}
            value={config.slots[0]?.credential_id ?? ""}
            onChange={(e) =>
              onChange({
                ...config,
                slots: e.target.value
                  ? [
                      {
                        name: value.password_slot,
                        credential_id: e.target.value,
                        injection: "protocol",
                        environment_variable: null,
                      },
                    ]
                  : [],
              })
            }
          >
            <option value="">
              {zh ? "选择已保存的密码" : "Select a saved password"}
            </option>
            {credentials
              .filter((c) => c.kind === "password")
              .map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
          </select>
        </label>
        <label className="text-sm font-semibold">
          {zh ? "传输加密" : "Transport encryption"}
          <select
            className={input}
            value={value.tls_mode}
            onChange={(e) =>
              update({
                tls_mode: e.target.value as DatabaseConfig["tls_mode"],
                ca_certificate: null,
              })
            }
          >
            <option value="verify_full">
              {zh
                ? "TLS：验证证书与主机名"
                : "TLS: verify certificate and hostname"}
            </option>
            <option value="loopback_plaintext">
              {zh
                ? "仅数值回环地址：不加密"
                : "Numeric loopback only: plaintext"}
            </option>
          </select>
        </label>
      </div>
      {value.tls_mode === "verify_full" ? (
        <label className="block text-sm font-semibold">
          {zh
            ? "私有 CA 证书路径（可选）"
            : "Private CA certificate path (optional)"}
          <input
            className={input}
            value={value.ca_certificate ?? ""}
            onChange={(e) => update({ ca_certificate: e.target.value || null })}
          />
        </label>
      ) : (
        <p className="text-xs text-amber-800">
          {zh
            ? "仅允许 127.0.0.1 或 ::1 等数值回环地址；不要用此选项连接业务远端。"
            : "Only numeric loopback addresses, such as 127.0.0.1 or ::1, are allowed; never use this for remote services."}
        </p>
      )}
      {value.operation === "query" && (
        <>
          <label className="block text-sm font-semibold">
            {zh ? "只读 SQL" : "Read-only SQL"}
            <textarea
              rows={7}
              required
              className={`${input} font-mono`}
              value={value.query}
              onChange={(e) => update({ query: e.target.value })}
            />
          </label>
          <p className="text-xs text-slate-600">
            {zh
              ? "登记 SELECT 或 WITH 查询，不带末尾分号。普通参数写为 {{param:名称}}，不加引号；字段或表名不可作为参数。"
              : "Register a SELECT or WITH query without a trailing semicolon. Use unquoted {{param:name}} for bound values, never for identifiers."}
          </p>
          <label className="block text-sm font-semibold">
            {zh
              ? "允许返回的列（每行一项）"
              : "Allowed output columns (one per line)"}
            <textarea
              rows={3}
              required
              className={input}
              value={value.columns.join("\n")}
              onChange={(e) => update({ columns: e.target.value.split("\n") })}
            />
          </label>
        </>
      )}
      <label className="block text-sm font-semibold">
        {zh ? "结果行数上限" : "Result row limit"}
        <input
          type="number"
          min={1}
          max={1000}
          required
          className={input}
          value={value.max_rows}
          onChange={(e) => update({ max_rows: Number(e.target.value) })}
        />
      </label>
      <p className="text-xs text-slate-600">
        {zh
          ? "密码由原生驱动认证使用，不拼入 SQL。结果可能包含业务数据，请只登记确有需要的返回列，并使用只读数据库账户。"
          : "The native driver uses the password for authentication, never in SQL. Results may contain business data; select only necessary columns and use a read-only account."}
      </p>
    </div>
  );
}
