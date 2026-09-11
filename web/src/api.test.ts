// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createApproval,
  createActionTemplate,
  decideApproval,
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

  it("creates a bounded synthetic approval without an execution payload", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "approval-id" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await createApproval("synthetic-session-token", {
      action_template_id: "template-id",
      reason: "Review metadata summary",
      expires_in_seconds: 300,
    });

    const [path, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/approvals");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body as string)).toEqual({
      action_template_id: "template-id",
      reason: "Review metadata summary",
      expires_in_seconds: 300,
    });
    expect(request.body).not.toContain("command");
    expect(request.body).not.toContain("secret");
  });

  it("creates a fixed action template without command or endpoint fields", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "template-id" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await createActionTemplate("synthetic-session-token", {
      target_id: "target-id",
      name: "Synthetic metadata inspection",
      operation: "inspect_metadata",
      result_scope: "metadata_summary",
      timeout_seconds: 15,
    });

    const [path, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/action-templates");
    const body = JSON.parse(request.body as string);
    expect(body).toEqual({
      target_id: "target-id",
      name: "Synthetic metadata inspection",
      operation: "inspect_metadata",
      result_scope: "metadata_summary",
      timeout_seconds: 15,
    });
    expect(body).not.toHaveProperty("command");
    expect(body).not.toHaveProperty("endpoint");
  });

  it("sends optimistic versions with approval decisions", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "approval-id", state: "revoked" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await decideApproval(
      "synthetic-session-token",
      "approval-id",
      "revoke",
      { expected_version: 2, note: "No longer needed" },
    );

    const [path, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/approvals/approval-id/revoke");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body as string)).toEqual({
      expected_version: 2,
      note: "No longer needed",
    });
  });
});
