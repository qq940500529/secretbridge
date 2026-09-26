// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
export function parseDatabaseResult(text: string): {
  columns: string[];
  rows: (string | null)[][];
  truncated: boolean;
  cleanup_ok: boolean;
  validation_status?:
    | "verified"
    | "not_configured"
    | "expected_rows_missing"
    | "incomplete_output";
  expected_min_rows?: number | null;
} | null {
  try {
    const value = JSON.parse(text);
    if (
      value.kind !== "database" ||
      !Array.isArray(value.columns) ||
      !value.columns.every((c: unknown) => typeof c === "string") ||
      !Array.isArray(value.rows) ||
      !value.rows.every(
        (r: unknown) =>
          Array.isArray(r) &&
          r.length === value.columns.length &&
          r.every((c: unknown) => c === null || typeof c === "string"),
      )
    )
      return null;
    return value;
  } catch {
    return null;
  }
}
export function DatabaseResultView({
  result,
  zh,
}: {
  result: NonNullable<ReturnType<typeof parseDatabaseResult>>;
  zh: boolean;
}) {
  return (
    <div className="space-y-3">
      {result.validation_status && (
        <p
          role="status"
          className={`rounded-lg px-3 py-2 text-sm ${result.validation_status === "verified" ? "bg-emerald-50 text-emerald-800" : "bg-amber-50 text-amber-900"}`}
        >
          {result.validation_status === "verified"
            ? zh
              ? "结果已按预设条件验证。"
              : "Result meets the configured expectation."
            : result.validation_status === "expected_rows_missing"
              ? zh
                ? `结果未达预期：至少需要 ${result.expected_min_rows ?? 1} 行。`
                : `Result below expectation: at least ${result.expected_min_rows ?? 1} row(s) required.`
              : result.validation_status === "incomplete_output"
                ? zh
                  ? "输出被截断，无法确认是否满足预期。"
                  : "Output was truncated; the expectation cannot be confirmed."
                : zh
                  ? "进程已完成，但未配置业务行数校验。"
                  : "Process completed; no business row-count validation was configured."}
        </p>
      )}
      <p className="text-xs text-slate-600">
        {zh
          ? `返回 ${result.rows.length} 行。数值以文本显示以保留精度。`
          : `${result.rows.length} rows returned. Numeric values are displayed as text to preserve precision.`}
      </p>
      {result.truncated && (
        <p role="status" className="text-sm text-amber-800">
          {zh
            ? "结果达到行数或大小上限，未返回全部数据；请缩小查询范围后再运行。"
            : "The row or size limit was reached. Narrow the query and run again."}
        </p>
      )}
      {!result.cleanup_ok && (
        <p role="status" className="text-sm text-amber-800">
          {zh
            ? "连接清理超时，请核查数据库端会话。"
            : "Connection cleanup timed out; check the database session."}
        </p>
      )}
      <div className="max-h-96 overflow-auto border border-slate-200">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">
            {zh ? "数据库查询结果" : "Database query results"}
          </caption>
          <thead className="sticky top-0 bg-slate-100">
            <tr>
              {result.columns.map((c, i) => (
                <th
                  key={i}
                  scope="col"
                  className="whitespace-nowrap border-b border-slate-200 px-3 py-2 font-semibold"
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {result.rows.map((r, i) => (
              <tr key={i} className="even:bg-slate-50">
                {r.map((c, j) => (
                  <td
                    key={j}
                    className="min-w-28 max-w-xl whitespace-pre-wrap break-words border-b border-slate-100 px-3 py-2 align-top"
                  >
                    {c === null ? (
                      <span className="italic text-slate-400">NULL</span>
                    ) : (
                      c
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!result.rows.length && (
        <p className="text-sm text-slate-600">
          {zh
            ? "查询成功，没有匹配的数据。"
            : "Query succeeded with no matching rows."}
        </p>
      )}
    </div>
  );
}
