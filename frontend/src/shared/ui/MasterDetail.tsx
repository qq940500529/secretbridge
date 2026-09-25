// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { Children, type ReactNode, useId, useState } from "react";

export function MasterDetail({
  items,
  children,
  language,
  selectedId,
  onSelect,
}: {
  items: Array<{ id: string; name: string; detail?: string }>;
  children: ReactNode;
  language: "zh-CN" | "en";
  selectedId?: string;
  onSelect?: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [selection, setSelection] = useState("");
  const rows = Children.toArray(children);
  const visible = items.filter((item) =>
    `${item.name} ${item.detail ?? ""}`
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );
  const selected =
    visible.find((item) => item.id === (selectedId ?? selection)) ?? visible[0];
  const paneId = useId();
  return (
    <div className="enterprise-surface workbench-master-detail">
      <aside
        className="workbench-master"
        aria-label={language === "zh-CN" ? "记录列表" : "Records"}
      >
        <div className="border-b border-slate-200 p-3">
          <input
            type="search"
            aria-label={language === "zh-CN" ? "搜索记录" : "Search records"}
            placeholder={
              language === "zh-CN" ? "搜索名称或类型…" : "Search name or type…"
            }
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className="workbench-search"
          />
        </div>
        <div className="workbench-records">
          {visible.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={selected?.id === item.id ? "true" : undefined}
              aria-controls={paneId}
              onClick={() => {
                setSelection(item.id);
                onSelect?.(item.id);
              }}
              className="workbench-record"
            >
              <span className="block break-words font-semibold">
                {item.name}
              </span>
              {item.detail && (
                <span className="mt-1 block break-words text-xs text-slate-500">
                  {item.detail}
                </span>
              )}
            </button>
          ))}
          {visible.length === 0 && (
            <p role="status" className="px-4 text-sm text-slate-500">
              {language === "zh-CN" ? "没有匹配记录" : "No matching records"}
            </p>
          )}
        </div>
      </aside>
      <section
        id={paneId}
        aria-label={language === "zh-CN" ? "记录详情" : "Record details"}
        className="min-w-0 break-words"
      >
        {selected && rows[items.findIndex((item) => item.id === selected.id)]}
      </section>
    </div>
  );
}
