// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { Plus, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type ChangeEvent } from "react";
import type { ParameterDefinition } from "./api";
import { parseParameter, nextParameterName } from "./parameters";

export function ParameterEditor({
  value,
  onChange,
  zh,
}: {
  value: ParameterDefinition[];
  onChange: (value: ParameterDefinition[]) => void;
  zh: boolean;
}) {
  const update = (index: number, change: Partial<ParameterDefinition>) =>
    onChange(value.map((p, i) => (i === index ? { ...p, ...change } : p)));
  return (
    <section className="space-y-3 border-t border-slate-200 pt-4">
      <h3 className="text-sm font-semibold">
        {zh ? "普通参数" : "Ordinary parameters"}
      </h3>
      <p className="text-sm text-slate-600">
        {zh
          ? "使用完整的 {{param:参数名}}，每个值作为一个独立参数，不拼接 Shell。这里不要填写密码或密钥。"
          : "Use an entire {{param:name}} argument. Each value stays one argv entry. Never enter passwords or keys here."}
      </p>
      {value.map((p, index) => (
        <fieldset
          key={`${index}-${p.kind}`}
          className="grid gap-3 border-b border-slate-200 pb-4 sm:grid-cols-3"
        >
          <label className="text-xs">
            {zh ? "参数名" : "Name"}
            <input
              required
              pattern="[A-Za-z_][A-Za-z_0-9]*"
              maxLength={64}
              value={p.name}
              onChange={(e) => update(index, { name: e.target.value })}
              className={input}
            />
          </label>
          <label className="text-xs">
            {zh ? "显示名称" : "Label"}
            <input
              required
              maxLength={80}
              value={p.label}
              onChange={(e) => update(index, { label: e.target.value })}
              className={input}
            />
          </label>
          <label className="text-xs">
            {zh ? "类型" : "Type"}
            <select
              value={p.kind}
              onChange={(e) =>
                update(index, {
                  kind: e.target.value as ParameterDefinition["kind"],
                  default: null,
                  choices: [],
                  max_length: null,
                })
              }
              className={input}
            >
              {["string", "integer", "boolean"].map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs">
            {zh ? "默认值（空白表示未设置）" : "Default (blank = unset)"}
            <TypedInput
              identity={p.name}
              value={p.default === null ? "" : String(p.default)}
              zh={zh}
              onValue={(text) =>
                update(index, {
                  default: text === "" ? null : parseParameter(p.kind, text),
                })
              }
            />
          </label>
          <label className="text-xs">
            {zh
              ? "允许值（每行一个，空白不限）"
              : "Allowed values (one per line; blank = any)"}
            <TypedInput
              identity={p.name}
              multiline
              value={p.choices.map(String).join("\n")}
              zh={zh}
              onValue={(text) =>
                update(index, {
                  choices:
                    text === ""
                      ? []
                      : text.split("\n").map((s) => parseParameter(p.kind, s)),
                })
              }
            />
          </label>
          <div className="space-y-2">
            {p.kind === "string" && (
              <label className="text-xs">
                {zh ? "最大字符数" : "Maximum characters"}
                <input
                  type="number"
                  min={1}
                  max={2048}
                  value={p.max_length ?? ""}
                  onChange={(e) =>
                    update(index, {
                      max_length:
                        e.target.value === "" ? null : Number(e.target.value),
                    })
                  }
                  className={input}
                />
              </label>
            )}
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={p.required}
                onChange={(e) => update(index, { required: e.target.checked })}
              />
              {zh ? "必填" : "Required"}
            </label>
            <button
              type="button"
              aria-label={zh ? "删除参数" : "Remove parameter"}
              onClick={() => onChange(value.filter((_, i) => i !== index))}
              className="p-2 text-slate-500 hover:text-rose-700"
            >
              <Trash2 className="size-4" />
            </button>
          </div>
        </fieldset>
      ))}
      <button
        type="button"
        disabled={value.length >= 16}
        onClick={() =>
          onChange([
            ...value,
            {
              name: nextParameterName(value.map((p) => p.name)),
              label: zh ? "新参数" : "New parameter",
              kind: "string",
              required: true,
              default: null,
              choices: [],
              max_length: 256,
            },
          ])
        }
        className="inline-flex items-center gap-2 text-sm font-semibold text-cyan-700 disabled:opacity-50"
      >
        <Plus className="size-4" />
        {zh ? "添加普通参数" : "Add parameter"}
      </button>
    </section>
  );
}
const input =
  "mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal outline-none focus:border-cyan-600";

function TypedInput({
  identity,
  value,
  onValue,
  zh,
  multiline = false,
}: {
  identity: string;
  value: string;
  onValue: (value: string) => void;
  zh: boolean;
  multiline?: boolean;
}) {
  const [draft, setDraft] = useState(value);
  const element = useRef<HTMLInputElement | HTMLTextAreaElement | null>(null);
  useEffect(() => {
    setDraft(value);
    element.current?.setCustomValidity("");
  }, [identity, value]);
  const change = (
    event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    setDraft(event.target.value);
    try {
      onValue(event.target.value);
      event.target.setCustomValidity("");
    } catch {
      event.target.setCustomValidity(
        zh ? "请输入符合类型的值" : "Enter a value of the selected type",
      );
    }
  };
  return multiline ? (
    <textarea
      ref={(node) => {
        element.current = node;
      }}
      rows={2}
      value={draft}
      onChange={change}
      className={input}
    />
  ) : (
    <input
      ref={(node) => {
        element.current = node;
      }}
      value={draft}
      onChange={change}
      className={input}
    />
  );
}
