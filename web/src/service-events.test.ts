// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { subscribeServiceChanges } from "./service-events";

class FakeSocket {
  static instances: FakeSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  send = vi.fn();
  close = vi.fn(() => this.onclose?.());
  constructor(public url: string) { FakeSocket.instances.push(this); }
  message(type: string) { this.onmessage?.({ data: JSON.stringify({ type }) }); }
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeSocket.instances = [];
  vi.stubGlobal("window", { location: { href: "http://127.0.0.1:8787/" } });
  vi.stubGlobal("WebSocket", FakeSocket);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe("live service changes", () => {
  it("authenticates in the first frame, never in the URL, and coalesces invalidations", () => {
    const changed = vi.fn();
    const stop = subscribeServiceChanges("test-session", changed);
    const socket = FakeSocket.instances[0];
    expect(socket.url).toBe("ws://127.0.0.1:8787/api/v1/events");
    socket.onopen?.();
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: "authenticate", token: "test-session" }));
    socket.message("changed");
    vi.advanceTimersByTime(100);
    expect(changed).not.toHaveBeenCalled();
    socket.message("ready");
    socket.message("changed");
    socket.message("changed");
    vi.advanceTimersByTime(50);
    expect(changed).toHaveBeenCalledTimes(1);
    stop();
    vi.advanceTimersByTime(60000);
    expect(FakeSocket.instances).toHaveLength(1);
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it("reconnects, reconciles missed state and retains a slow fallback", () => {
    const changed = vi.fn();
    const stop = subscribeServiceChanges("test-session", changed);
    FakeSocket.instances[0].message("ready");
    vi.advanceTimersByTime(50);
    FakeSocket.instances[0].onclose?.();
    vi.advanceTimersByTime(500);
    expect(FakeSocket.instances).toHaveLength(2);
    FakeSocket.instances[1].message("ready");
    vi.advanceTimersByTime(50);
    expect(changed).toHaveBeenCalledTimes(2);
    vi.advanceTimersByTime(15000);
    expect(changed).toHaveBeenCalledTimes(3);
    stop();
  });

  it("ignores late frames and malformed notifications after disposal", () => {
    const changed = vi.fn();
    const stop = subscribeServiceChanges("test-session", changed);
    const socket = FakeSocket.instances[0];
    socket.onmessage?.({ data: "not JSON" });
    socket.message("ready");
    stop();
    socket.message("changed");
    vi.advanceTimersByTime(10000);
    expect(changed).not.toHaveBeenCalled();
  });
});
