// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Copyable, client-specific local MCP registration. No client files are modified.

use super::Result;
use serde_json::{Value, json};
use std::path::Path;

pub(super) const CLIENTS: &[&str] = &[
    "generic",
    "codex",
    "claude-code",
    "cursor",
    "copilot-cli",
    "opencode",
    "workbuddy",
    "deepseek-harness",
];

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .filter(|value| path.is_absolute() && !value.chars().any(char::is_control))
        .ok_or("client_config_path_invalid")
}

fn pretty(value: &Value) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|_| "client_config_render_failed")
}

fn shell_quote(value: &str) -> String {
    if cfg!(windows) {
        // PowerShell single-quoted literals do not interpolate variables.
        format!("'{}'", value.replace('\'', "''"))
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

pub(super) fn render(client: &str, binary: &Path, data: &Path) -> Result<String> {
    if !CLIENTS.contains(&client) {
        return Err("client_unknown");
    }
    let binary = path_text(binary)?;
    let data = path_text(data)?;
    let env = json!({"SECRETBRIDGE_DATA_DIR": data});
    let basic = json!({"command": binary, "args": ["--mcp-stdio"], "env": env});
    match client {
        "codex" => Ok(format!(
            "[mcp_servers.secretbridge]\ncommand = {}\nargs = [\"--mcp-stdio\"]\n\n[mcp_servers.secretbridge.env]\nSECRETBRIDGE_DATA_DIR = {}\n",
            serde_json::to_string(binary).map_err(|_| "client_config_render_failed")?,
            serde_json::to_string(data).map_err(|_| "client_config_render_failed")?
        )),
        "claude-code" => Ok(format!(
            "claude mcp add --scope user --transport stdio --env {} secretbridge -- {} --mcp-stdio\n",
            shell_quote(&format!("SECRETBRIDGE_DATA_DIR={data}")),
            shell_quote(binary)
        )),
        "generic" | "cursor" | "workbuddy" => {
            pretty(&json!({"mcpServers": {"secretbridge": basic}}))
        }
        "copilot-cli" => pretty(&json!({"mcpServers": {"secretbridge": {
            "type": "local", "command": binary, "args": ["--mcp-stdio"], "env": env,
            "tools": ["*"]
        }}})),
        "opencode" => pretty(&json!({
            "$schema": "https://opencode.ai/config.json",
            "mcp": {"servers": {"secretbridge": {
                "type": "local", "command": [binary, "--mcp-stdio"],
                "environment": env
            }}}
        })),
        "deepseek-harness" => Ok(format!(
            "- id: mcp-secretbridge\n  name: '@deepseek-ai/dsh-mcp-client'\n  config:\n    serverName: secretbridge\n    transport: stdio\n    command: {}\n    args: ['--mcp-stdio']\n    env:\n      SECRETBRIDGE_DATA_DIR: {}\n",
            serde_json::to_string(binary).map_err(|_| "client_config_render_failed")?,
            serde_json::to_string(data).map_err(|_| "client_config_render_failed")?
        )),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn paths() -> (&'static Path, &'static Path) {
        if cfg!(windows) {
            (
                Path::new("C:\\SecretBridge\\app.exe"),
                Path::new("C:\\SecretBridge\\data"),
            )
        } else {
            (
                Path::new("/opt/secretbridge/bin/secretbridge"),
                Path::new("/tmp/secretbridge-test"),
            )
        }
    }

    #[test]
    fn every_client_uses_the_same_local_bridge_and_data_directory() {
        let (binary, data) = paths();
        for client in CLIENTS {
            let rendered = render(client, binary, data).unwrap();
            assert!(rendered.contains("--mcp-stdio"), "{client}");
            let expected_path = if *client == "claude-code" {
                binary.to_str().unwrap().to_owned()
            } else {
                serde_json::to_string(binary.to_str().unwrap()).unwrap()[1..]
                    .trim_end_matches('"')
                    .to_owned()
            };
            assert!(rendered.contains(&expected_path), "{client}");
            assert!(rendered.contains("SECRETBRIDGE_DATA_DIR"), "{client}");
            assert!(!rendered.contains("token"), "{client}");
            assert!(!rendered.contains("password"), "{client}");
            if ["generic", "cursor", "workbuddy", "copilot-cli", "opencode"].contains(client) {
                let parsed: Value = serde_json::from_str(&rendered).unwrap();
                let server = if *client == "opencode" {
                    &parsed["mcp"]["servers"]["secretbridge"]
                } else {
                    &parsed["mcpServers"]["secretbridge"]
                };
                assert_eq!(
                    server["command"],
                    if *client == "opencode" {
                        json!([binary, "--mcp-stdio"])
                    } else {
                        json!(binary)
                    }
                );
            }
        }
    }

    #[test]
    fn invalid_client_or_relative_path_is_rejected() {
        let (binary, data) = paths();
        assert_eq!(render("unknown", binary, data), Err("client_unknown"));
        assert_eq!(
            render("cursor", Path::new("relative"), data),
            Err("client_config_path_invalid")
        );
    }

    #[test]
    fn generic_configuration_is_a_portable_stdio_example() {
        let (binary, data) = paths();
        let value: Value = serde_json::from_str(&render("generic", binary, data).unwrap()).unwrap();
        assert_eq!(
            value["mcpServers"]["secretbridge"],
            json!({
                "command": binary.to_str().unwrap(),
                "args": ["--mcp-stdio"],
                "env": {"SECRETBRIDGE_DATA_DIR": data.to_str().unwrap()}
            })
        );
    }

    #[test]
    fn quotes_paths_with_spaces_without_shell_interpolation() {
        let (binary, data) = if cfg!(windows) {
            (
                Path::new("C:\\Program Files\\Bridge's app.exe"),
                Path::new("C:\\Data & test"),
            )
        } else {
            (
                Path::new("/opt/Bridge's app"),
                Path::new("/tmp/data & test"),
            )
        };
        let command = render("claude-code", binary, data).unwrap();
        if cfg!(windows) {
            assert!(command.contains("'C:\\Program Files\\Bridge''s app.exe'"));
            assert!(command.contains("'SECRETBRIDGE_DATA_DIR=C:\\Data & test'"));
        } else {
            assert!(command.contains("'/opt/Bridge'\\''s app'"));
            assert!(command.contains("'SECRETBRIDGE_DATA_DIR=/tmp/data & test'"));
        }
        assert!(command.contains("--scope user"));
        let json = render("workbuddy", binary, data).unwrap();
        assert!(serde_json::from_str::<Value>(&json).is_ok());
    }
}
