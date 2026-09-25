// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type ReactNode, useEffect, useId, useRef } from "react";
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
