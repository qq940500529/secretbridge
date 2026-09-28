// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
import type { CommandConfig, Resource } from "../../../api";
import { emptyCommand } from "./editors/CommandEditor";
import { emptyDatabase } from "./editors/DatabaseEditor";
import { emptyHttp } from "./editors/HttpEditor";
import { emptySsh } from "./editors/SshEditor";

/** Copy canonical metadata into a reviewable, immutable task snapshot. */
export function commandFromResource(resource: Resource): CommandConfig {
  const config: CommandConfig = { ...emptyCommand, slots: [] };
  const options = resource.connection;
  const slot = {
    name: "authentication",
    credential_id: resource.id,
    injection: "protocol" as const,
    environment_variable: null,
  };
  if (options.protocol === "database")
    return {
      ...config,
      slots: [slot],
      database: {
        ...emptyDatabase,
        engine: options.engine,
        host: resource.address ?? "",
        username: resource.username ?? "",
        port: options.port,
        database: options.database,
        tls_mode: options.tls_mode,
        ca_certificate: options.ca_certificate,
        password_slot: slot.name,
      },
    };
  if (options.protocol === "ssh")
    return {
      ...config,
      slots: [slot],
      ssh: {
        ...emptySsh,
        host: resource.address ?? "",
        username: resource.username ?? "",
        port: options.port,
        host_key_sha256: options.host_key_sha256,
        authentication:
          resource.authentication.kind === "ssh_key"
            ? { kind: "private_key", slot: slot.name, passphrase_slot: null }
            : { kind: "password", slot: slot.name },
      },
    };
  if (options.protocol === "http")
    return {
      ...config,
      http: {
        ...emptyHttp,
        url: resource.address ?? "",
        headers:
          options.authentication === "bearer"
            ? [
                {
                  name: "Authorization",
                  source: {
                    kind: "credential",
                    name: slot.name,
                    prefix: "Bearer ",
                  },
                },
              ]
            : options.authentication === "basic"
              ? [
                  {
                    name: "Authorization",
                    source: {
                      kind: "basic_credential",
                      name: slot.name,
                      username: resource.username ?? "",
                    },
                  },
                ]
              : options.authentication === "api_key"
                ? [
                    {
                      name: options.header_name ?? "X-API-Key",
                      source: {
                        kind: "credential",
                        name: slot.name,
                        prefix: "",
                      },
                    },
                  ]
                : [],
      },
      slots: options.authentication !== "none" ? [slot] : [],
    };
  return config;
}
