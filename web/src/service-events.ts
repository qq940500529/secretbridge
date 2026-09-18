// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef } from "react";

/** Invalidation only: resource values continue to come from authenticated HTTP APIs. */
export function subscribeServiceChanges(token: string, onChange: () => void): () => void {
  let stopped = false;
  let socket: WebSocket | null = null;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let refresh: ReturnType<typeof setTimeout> | undefined;
  let delay = 500;
  let ready = false;

  const notify = () => {
    if (refresh !== undefined || stopped) return;
    refresh = setTimeout(() => {
      refresh = undefined;
      if (!stopped) onChange();
    }, 50);
  };
  const connect = () => {
    if (stopped) return;
    const url = new URL("/api/v1/events", window.location.href);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const current = new WebSocket(url.toString());
    socket = current;
    ready = false;
    current.onopen = () => {
      if (!stopped && socket === current) {
        current.send(JSON.stringify({ type: "authenticate", token }));
      }
    };
    current.onmessage = (event) => {
      if (stopped || socket !== current || typeof event.data !== "string") return;
      try {
        const message = JSON.parse(event.data) as { type?: string };
        if (message.type === "ready") {
          ready = true;
          delay = 500;
          notify(); // Reconcile changes missed while disconnected.
        } else if (message.type === "changed" && ready) {
          notify();
        }
      } catch { /* Ignore malformed or unrelated notifications. */ }
    };
    current.onerror = () => current.close();
    current.onclose = () => {
      if (stopped || socket !== current) return;
      ready = false;
      retry = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 10000);
    };
  };

  // Slow fallback also reconciles time-based approval expiry and unavailable WebSockets.
  const fallback = setInterval(notify, 15000);
  connect();
  return () => {
    stopped = true;
    clearInterval(fallback);
    clearTimeout(retry);
    clearTimeout(refresh);
    socket?.close();
  };
}

export function useServiceChanges(token: string, onChange: () => void): void {
  const callback = useRef(onChange);
  callback.current = onChange;
  useEffect(() => subscribeServiceChanges(token, () => callback.current()), [token]);
}
