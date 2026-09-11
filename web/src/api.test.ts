// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  listCredentialReferences,
  updateCredentialReference,
} from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("configuration API client", () => {
  it("preserves the storage mode returned by the catalog", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [], storage: "sqlite" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    const result = await listCredentialReferences("synthetic-session-token");

    expect(result).toEqual({ items: [], storage: "sqlite" });
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/credential-references",
      expect.objectContaining({ credentials: "omit" }),
    );
  });

  it("updates metadata with PUT without introducing a secret field", async () => {
    const response = {
      id: "synthetic-id",
      name: "Updated reference",
      kind: "api_token",
      purpose: "Test-only metadata",
      secret_state: "not_configured",
      created_at_unix_ms: 1,
      updated_at_unix_ms: 2,
      version: 2,
    };
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await updateCredentialReference(
      "synthetic-session-token",
      "synthetic-id",
      {
        name: "Updated reference",
        kind: "api_token",
        purpose: "Test-only metadata",
        expected_version: 1,
      },
    );

    const [, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(request.method).toBe("PUT");
    expect(JSON.parse(request.body as string)).toEqual({
      name: "Updated reference",
      kind: "api_token",
      purpose: "Test-only metadata",
      expected_version: 1,
    });
    expect(request.body).not.toContain("secret");
  });

  it("preserves safe API error codes for conflict handling", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ code: "version_conflict" }), {
          status: 409,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    await expect(
      updateCredentialReference(
        "synthetic-session-token",
        "synthetic-id",
        {
          name: "Stale update",
          kind: "password",
          expected_version: 1,
        },
      ),
    ).rejects.toMatchObject({ status: 409, code: "version_conflict" });
  });
});
