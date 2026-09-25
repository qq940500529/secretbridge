// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ParameterDefinition, ParameterValue } from "../../../api/index";
import { parseParameter, setParameterValue } from "../shared/parameters";

export function ParameterFields({
  definitions,
  values,
  onChange,
  zh,
}: {
  definitions: ParameterDefinition[];
  values: Record<string, ParameterValue>;
  onChange: (values: Record<string, ParameterValue>) => void;
  zh: boolean;
}) {
  if (!definitions.length) return null;
  return (
    <fieldset className="mt-5 grid gap-4 border-t border-slate-200 pt-4 sm:grid-cols-2">
      <legend className="px-1 text-sm font-semibold">
        {zh
          ? "本次任务参数（审批后固定）"
          : "Task parameters (frozen after request)"}
      </legend>
      {definitions.map((p) => {
        const value = Object.hasOwn(values, p.name)
          ? values[p.name]
          : p.default;
        const change = (text: string) => {
          if (
            p.kind === "string" &&
            Array.from(text).length > (p.max_length ?? 2048)
          )
            throw new Error("Maximum length exceeded");
          onChange(
            setParameterValue(
              values,
              p.name,
              text === "" ? undefined : parseParameter(p.kind, text),
            ),
          );
        };
        const options = p.choices.length
          ? p.choices
          : p.kind === "boolean"
            ? [true, false]
            : [];
        return (
          <label key={p.name} className="text-sm font-semibold">
            {p.label}
            {p.required ? " *" : ""}
            {options.length ? (
              <select
                required={p.required}
                value={
                  value === null || value === undefined
                    ? ""
                    : JSON.stringify(value)
                }
                onChange={(e) => {
                  onChange(
                    setParameterValue(
                      values,
                      p.name,
                      e.target.value === ""
                        ? undefined
                        : (JSON.parse(e.target.value) as ParameterValue),
                    ),
                  );
                }}
                className={input}
              >
                <option value="">
                  {zh ? "使用默认值／留空" : "Default / unset"}
                </option>
                {options.map((v) => (
                  <option key={JSON.stringify(v)} value={JSON.stringify(v)}>
                    {String(v)}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type={p.kind === "integer" ? "number" : "text"}
                step={p.kind === "integer" ? 1 : undefined}
                required={p.required}
                maxLength={(p.max_length ?? 2048) * 2}
                value={
                  value === null || value === undefined ? "" : String(value)
                }
                onChange={(e) => {
                  try {
                    change(e.target.value);
                    e.target.setCustomValidity("");
                  } catch {
                    e.target.setCustomValidity(
                      zh
                        ? "输入不符合参数类型或长度要求"
                        : "Check the parameter type and length",
                    );
                  }
                }}
                className={input}
              />
            )}
          </label>
        );
      })}
      <p className="text-xs font-normal text-slate-500 sm:col-span-2">
        {zh
          ? "只填非秘密数据；这些值会保存并向任务调用者返回。"
          : "Non-secret data only. These values are stored and returned to task callers."}
      </p>
    </fieldset>
  );
}
const input =
  "mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";
