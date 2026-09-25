// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

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
