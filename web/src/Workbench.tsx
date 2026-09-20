// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  Children,
  type ReactNode,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import { Plus, X } from "lucide-react";

export function EditorDialog({
  title,
  open,
  onOpen,
  onClose,
  busy = false,
  triggerIcon,
  returnFocusTarget,
  children,
}: {
  title: string;
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
  busy?: boolean;
  triggerIcon?: ReactNode;
  returnFocusTarget?: HTMLElement | null;
  children: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const heading = useId();
  useEffect(() => {
    const element = dialog.current;
    if (open && element && !element.open) {
      // WebKit does not consistently focus buttons activated with a pointer,
      // so document.activeElement is not a reliable return target here.
      returnFocus.current = returnFocusTarget ?? trigger.current;
      element.showModal();
    }
    if (!open && element?.open) {
      const target = returnFocus.current?.isConnected
        ? returnFocus.current
        : trigger.current;
      element.close();
      requestAnimationFrame(() => target?.focus());
    }
  }, [open, returnFocusTarget]);
  return (
    <>
      <button
        ref={trigger}
        type="button"
        className="workbench-primary"
        onClick={() => {
          returnFocus.current = trigger.current;
          onOpen();
        }}
      >
        {triggerIcon ?? <Plus className="size-4" />}
        {title}
      </button>
      <dialog
        ref={dialog}
        aria-labelledby={heading}
        data-presentation="side-drawer"
        className="workbench-dialog"
        onCancel={(event) => {
          event.preventDefault();
          if (!busy) onClose();
        }}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            if (!busy) onClose();
          }
        }}
      >
        <header className="sticky top-0 z-10 flex items-center justify-between gap-4 border-b border-slate-200 bg-white px-5 py-4">
          <h2 id={heading} className="m-0 text-lg font-semibold">
            {title}
          </h2>
          <button
            type="button"
            aria-label={
              /[\u3400-\u9fff]/u.test(title) ? "关闭编辑器" : "Close editor"
            }
            disabled={busy}
            onClick={onClose}
            className="workbench-button"
          >
            <X className="size-4" />
          </button>
        </header>
        {open && children}
      </dialog>
    </>
  );
}

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

export function SectionTabs<T extends string>({
  items,
  selected,
  onSelect,
}: {
  items: Array<{ id: T; label: string }>;
  selected: T;
  onSelect: (id: T) => void;
}) {
  return (
    <nav
      className="workbench-tabs"
      aria-label={
        items.some((item) => /[\u3400-\u9fff]/u.test(item.label))
          ? "工作区分区"
          : "Workspace sections"
      }
    >
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          aria-current={item.id === selected ? "page" : undefined}
          onClick={() => onSelect(item.id)}
        >
          {item.label}
        </button>
      ))}
    </nav>
  );
}
