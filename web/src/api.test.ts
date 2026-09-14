// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cancelSyntheticRun,
  createApproval,
  createActionTemplate,
  createSyntheticRun,
  decideApproval,
  evaluateActionTemplate,
  listCredentialReferences,
  setCredentialSecret,
  clearCredentialSecret,
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

  it("uses dedicated write-only secret mutations with optimistic versions", async () => {
    const fetch = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(JSON.stringify({ id: "credential-id", secret_state: "available", version: 2 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ));
    vi.stubGlobal("fetch", fetch);

    await setCredentialSecret("session-token", "credential-id", "test-secret", 1);
    await clearCredentialSecret("session-token", "credential-id", 2);

    expect(fetch.mock.calls[0]?.[0]).toBe("/api/v1/credential-references/credential-id/secret");
    expect(fetch.mock.calls[0]?.[1]).toEqual(expect.objectContaining({
      method: "PUT",
      body: JSON.stringify({ secret: "test-secret", expected_version: 1 }),
    }));
    expect(fetch.mock.calls[1]?.[1]).toEqual(expect.objectContaining({
      method: "DELETE",
      body: JSON.stringify({ expected_version: 2 }),
    }));
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

  it("reads an explainable synthetic policy evaluation without mutation", async () => {
    const evaluation = {
      policy_version: "synthetic-policy-v1",
      decision: "eligible_for_approval",
      reason_codes: ["fixed_synthetic_scope"],
      requirements: ["explicit_approval", "synthetic_only"],
      action_template_id: "template-id",
      action_template_version: 2,
      target_id: "target-id",
      target_version: 3,
      target_environment: "test",
      operation: "inspect_metadata",
      result_scope: "metadata_summary",
      timeout_seconds: 15,
      execution_mode: "synthetic_simulation",
    };
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(evaluation), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(
      evaluateActionTemplate("synthetic-session-token", "template-id"),
    ).resolves.toEqual(evaluation);
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/action-templates/template-id/policy-evaluation",
      expect.objectContaining({ cache: "no-store", credentials: "omit" }),
    );
    const [, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(request.method).toBeUndefined();
    expect(request.body).toBeUndefined();
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

  it("submits synthetic runs with an explicit idempotency key", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ run: { id: "run-id" }, replayed: false, execution_mode: "synthetic_simulation" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await createSyntheticRun(
      "synthetic-session-token",
      "approval-id",
      "request-123",
    );

    const [path, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/runs");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body as string)).toEqual({
      approval_id: "approval-id",
      idempotency_key: "request-123",
    });
    expect(request.body).not.toContain("command");
    expect(request.body).not.toContain("argument");
  });

  it("cancels a run with optimistic version protection", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "run-id", state: "cancelled", version: 3 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await cancelSyntheticRun("synthetic-session-token", "run-id", 2);

    const [path, request] = fetch.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/runs/run-id/cancel");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body as string)).toEqual({ expected_version: 2 });
  });
});
