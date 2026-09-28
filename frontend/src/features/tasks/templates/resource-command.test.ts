// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import type { Resource } from "../../../api";
import { commandFromResource } from "./resource-command";

const base: Resource = {
  id: "synthetic-resource",
  name: "Test resource",
  kind: "generic",
  environment: "test",
  address: "https://example.com/api",
  username: "sample",
  description: null,
  version: 3,
  created_at_unix_ms: 1,
  updated_at_unix_ms: 2,
  labels: [],
  authentication: {
    kind: "password",
    secret_state: "available",
    secret_version: 2,
  },
  connection: { protocol: "none" },
};
describe("resource task snapshots", () => {
  it("preserves explicitly disabled database TLS without mutating the resource", () => {
    const resource: Resource = {
      ...base,
      kind: "database",
      address: "localhost",
      connection: {
        protocol: "database",
        engine: "postgres",
        port: 5432,
        database: "sample",
        tls_mode: "disabled",
        ca_certificate: null,
      },
    };
    const before = JSON.stringify(resource);
    const snapshot = commandFromResource(resource);
    expect(snapshot.database?.tls_mode).toBe("disabled");
    expect(snapshot.database?.host).toBe("localhost");
    expect(snapshot.slots[0].credential_id).toBe(resource.id);
    expect(JSON.stringify(resource)).toBe(before);
  });
  it.each(["none", "bearer", "basic", "api_key"] as const)(
    "builds %s HTTP authentication without secret literals",
    (authentication) => {
      const resource: Resource = {
        ...base,
        kind: "http_service",
        connection: {
          protocol: "http",
          authentication,
          header_name: "X-Access-Key",
        },
      };
      const snapshot = commandFromResource(resource);
      expect(snapshot.http?.url).toBe(base.address);
      expect(snapshot.slots).toHaveLength(authentication === "none" ? 0 : 1);
      const header = snapshot.http?.headers[0];
      if (authentication === "basic")
        expect(header?.source).toEqual({
          kind: "basic_credential",
          name: "authentication",
          username: "sample",
        });
      if (authentication === "api_key")
        expect(header?.name).toBe("X-Access-Key");
      if (authentication === "bearer")
        expect(header?.source).toEqual({
          kind: "credential",
          name: "authentication",
          prefix: "Bearer ",
        });
    },
  );
});
