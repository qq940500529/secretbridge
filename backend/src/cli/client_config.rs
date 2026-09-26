// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Copyable, client-specific local MCP registration. No client files are modified.

use super::Result;
use serde_json::{Value, json};
use std::{fs, path::Path};
use uuid::Uuid;

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

/// Export the signed release's preassembled plugin. Never modify an existing
/// directory: its ownership and locally edited contents are unknown.
pub(super) fn export_codex_plugin(
    binary: &Path,
    destination: &Path,
    launcher: &(String, Vec<String>),
) -> Result<()> {
    path_text(binary)?;
    if !destination.is_absolute() || destination.file_name().is_none() || destination.exists() {
        return Err("plugin_destination_invalid");
    }
    let parent = destination.parent().ok_or("plugin_destination_invalid")?;
    if !parent.is_dir() {
        return Err("plugin_destination_invalid");
    }
    let source = binary
        .parent()
        .and_then(Path::parent)
        .ok_or("plugin_bundle_unavailable")?
        .join("plugins/secretbridge");
    if !source.join(".codex-plugin/plugin.json").is_file() {
        return Err("plugin_bundle_unavailable");
    }
    let staging = parent.join(format!(".secretbridge-plugin-{}", Uuid::new_v4()));
    fs::create_dir(&staging).map_err(|_| "plugin_export_failed")?;
    let result = (|| {
        let plugin = staging.join("plugins/secretbridge");
        fs::create_dir_all(&plugin).map_err(|_| "plugin_export_failed")?;
        copy_plugin_tree(&source, &plugin)?;
        let config = json!({"mcpServers":{"secretbridge":{
            "command":launcher.0,"args":launcher.1
        }}});
        fs::write(
            plugin.join(".mcp.json"),
            serde_json::to_vec_pretty(&config).map_err(|_| "plugin_export_failed")?,
        )
        .map_err(|_| "plugin_export_failed")?;
        let marketplace = json!({
            "name":"secretbridge-local",
            "interface":{"displayName":"SecretBridge"},
            "plugins":[{
                "name":"secretbridge",
                "source":{"source":"local","path":"./plugins/secretbridge"},
                "policy":{"installation":"AVAILABLE","authentication":"ON_INSTALL"},
                "category":"Productivity"
            }]
        });
        fs::write(
            staging.join("marketplace.json"),
            serde_json::to_vec_pretty(&marketplace).map_err(|_| "plugin_export_failed")?,
        )
        .map_err(|_| "plugin_export_failed")?;
        fs::rename(&staging, destination).map_err(|_| "plugin_export_failed")
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn copy_plugin_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source).map_err(|_| "plugin_bundle_unavailable")? {
        let entry = entry.map_err(|_| "plugin_bundle_unavailable")?;
        let kind = entry.file_type().map_err(|_| "plugin_bundle_unavailable")?;
        if kind.is_symlink() {
            return Err("plugin_bundle_invalid");
        }
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target).map_err(|_| "plugin_export_failed")?;
            copy_plugin_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target).map_err(|_| "plugin_export_failed")?;
        } else {
            return Err("plugin_bundle_invalid");
        }
    }
    Ok(())
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

    #[test]
    fn prebuilt_codex_plugin_export_personalizes_binary_without_overwriting() {
        let root =
            std::env::temp_dir().join(format!("secretbridge-plugin-test-{}", Uuid::new_v4()));
        let bundle = root.join("release/plugins/secretbridge");
        fs::create_dir_all(bundle.join(".codex-plugin")).unwrap();
        fs::write(
            bundle.join(".codex-plugin/plugin.json"),
            r#"{"name":"secretbridge"}"#,
        )
        .unwrap();
        fs::write(bundle.join(".mcp.json"), "{}").unwrap();
        let binary = root.join("release/bin/secretbridge");
        let destination = root.join("codex-plugin");
        let launcher = (
            "stable-launcher".to_owned(),
            vec!["--mcp-active".to_owned()],
        );
        export_codex_plugin(&binary, &destination, &launcher).unwrap();
        let value: Value = serde_json::from_slice(
            &fs::read(destination.join("plugins/secretbridge/.mcp.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            value["mcpServers"]["secretbridge"]["command"],
            "stable-launcher"
        );
        assert_eq!(
            value["mcpServers"]["secretbridge"]["args"],
            json!(["--mcp-active"])
        );
        assert_eq!(
            export_codex_plugin(&binary, &destination, &launcher),
            Err("plugin_destination_invalid")
        );
        assert!(
            destination
                .join("plugins/secretbridge/.codex-plugin/plugin.json")
                .is_file()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(
                &fs::read(destination.join("marketplace.json")).unwrap()
            )
            .unwrap()["name"],
            "secretbridge-local"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
