// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{Result, installation::Installation, private_file};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartupFile {
    pub path: PathBuf,
    pub sha256: String,
}
fn name(installation: &Installation) -> String {
    format!("com.shulianchuangyuan.secretbridge.{}", installation.id)
}
fn path_text(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or("startup_path_invalid")?;
    if text.chars().any(char::is_control) {
        return Err("startup_path_invalid");
    }
    Ok(text.into())
}
fn allowed_paths(installation: &Installation) -> Result<Vec<PathBuf>> {
    let name = name(installation);
    #[cfg(windows)]
    {
        let base = env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or("startup_unavailable")?;
        Ok(vec![
            base.join("Microsoft/Windows/Start Menu/Programs/Startup")
                .join(format!("{name}.lnk")),
            super::installation::root()?.join(format!("{name}.ps1")),
        ])
    }
    #[cfg(target_os = "macos")]
    {
        let base = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("startup_unavailable")?;
        Ok(vec![
            base.join("Library/LaunchAgents")
                .join(format!("{name}.plist")),
        ])
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|path| PathBuf::from(path).join(".config")))
            .ok_or("startup_unavailable")?;
        if !base.is_absolute() {
            return Err("startup_path_invalid");
        }
        Ok(vec![base.join("autostart").join(format!("{name}.desktop"))])
    }
}
fn digest(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "startup_file_changed")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
        return Err("startup_file_changed");
    }
    let bytes = fs::read(path).map_err(|_| "startup_file_changed")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub(super) struct Snapshot(Vec<(PathBuf, Option<Vec<u8>>)>);
impl Snapshot {
    pub(super) fn capture(installation: &Installation) -> Result<Self> {
        let paths = allowed_paths(installation)?;
        let mut saved = Vec::new();
        for path in paths {
            if !path.is_absolute() {
                return Err("startup_path_invalid");
            }
            let bytes = if path.try_exists().map_err(|_| "startup_file_changed")? {
                let hash = digest(&path)?;
                if !installation
                    .startup_files
                    .iter()
                    .any(|file| file.path == path && file.sha256 == hash)
                {
                    return Err("startup_file_changed");
                }
                Some(fs::read(&path).map_err(|_| "startup_file_changed")?)
            } else {
                None
            };
            saved.push((path, bytes));
        }
        if installation
            .startup_files
            .iter()
            .any(|file| !saved.iter().any(|(path, _)| *path == file.path))
        {
            return Err("startup_path_invalid");
        }
        Ok(Self(saved))
    }
    pub(super) fn restore(&self) -> Result<()> {
        for (path, bytes) in &self.0 {
            if let Some(bytes) = bytes {
                write_descriptor(path, bytes)?;
            } else if path.exists() {
                fs::remove_file(path).map_err(|_| "startup_restore_failed")?;
            }
        }
        Ok(())
    }
}
fn write_descriptor(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    private_file(&temporary, bytes).map_err(|_| "startup_write_failed")?;
    fs::rename(&temporary, path).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        "startup_write_failed"
    })
}
pub(super) fn disable(installation: &Installation) -> Result<()> {
    let snapshot = Snapshot::capture(installation)?;
    let result = disable_inner(installation);
    if result.is_err() {
        snapshot.restore()?;
    }
    result
}
fn disable_inner(installation: &Installation) -> Result<()> {
    let allowed = allowed_paths(installation)?;
    for file in &installation.startup_files {
        if !allowed.contains(&file.path) {
            return Err("startup_path_invalid");
        }
        if file.path.exists() {
            if digest(&file.path)? != file.sha256 {
                return Err("startup_file_changed");
            }
            fs::remove_file(&file.path).map_err(|_| "startup_write_failed")?;
        }
    }
    Ok(())
}
pub(super) fn enable(root: &Path, installation: &Installation) -> Result<Vec<StartupFile>> {
    let snapshot = Snapshot::capture(installation)?;
    let result = enable_inner(root, installation);
    if result.is_err() {
        snapshot.restore()?;
    }
    result
}
fn enable_inner(root: &Path, installation: &Installation) -> Result<Vec<StartupFile>> {
    let active = installation.active.as_ref().ok_or("not_installed")?;
    let binary = root.join("releases").join(active).join(if cfg!(windows) {
        "bin/secretbridge-server.exe"
    } else {
        "bin/secretbridge-server"
    });
    let paths = allowed_paths(installation)?;
    for path in &paths {
        if path.exists()
            && !installation
                .startup_files
                .iter()
                .any(|file| file.path == *path && digest(path).ok().as_ref() == Some(&file.sha256))
        {
            return Err("startup_file_changed");
        }
    }
    let contents = render(&binary, root, installation)?;
    for path in &paths {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| "startup_write_failed")?;
        }
    }
    let descriptor = if cfg!(windows) {
        paths[1].clone()
    } else {
        paths[0].clone()
    };
    write_descriptor(&descriptor, contents.as_bytes())?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let shortcut = ps_quote(&path_text(&paths[0])?);
        let script = ps_quote(&path_text(&descriptor)?);
        let shell = env::var_os("SystemRoot")
            .map(PathBuf::from)
            .ok_or("startup_unavailable")?
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let code = format!(
            "$ErrorActionPreference='Stop'; $s=(New-Object -ComObject WScript.Shell).CreateShortcut({shortcut}); $s.TargetPath=$PSHOME+'\\powershell.exe'; $s.Arguments='-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File '+[char]34+{script}+[char]34; $s.WindowStyle=7; $s.Description='SecretBridge background startup'; $s.Save()"
        );
        let result = std::process::Command::new(shell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &code,
            ])
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|_| "startup_write_failed")?;
        if !result.status.success() {
            return Err("startup_write_failed");
        }
    }
    paths
        .into_iter()
        .map(|path| {
            Ok(StartupFile {
                sha256: digest(&path)?,
                path,
            })
        })
        .collect()
}
#[cfg(windows)]
fn ps_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}
#[cfg(target_os = "macos")]
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_quote(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\\\\\")
            .replace('"', "\\\\\"")
            .replace('`', "\\\\`")
            .replace('$', "\\\\$")
            .replace('%', "%%")
    )
}
fn render(binary: &Path, root: &Path, installation: &Installation) -> Result<String> {
    let binary = path_text(binary)?;
    let root = path_text(root)?;
    let data = path_text(&installation.data_directory)?;
    #[cfg(windows)]
    {
        Ok(format!(
            "# SecretBridge generated user-login startup\n$ErrorActionPreference='Stop'\n$env:SECRETBRIDGE_DATA_DIR={}\n$env:SECRETBRIDGE_INSTALL_DIR={}\n$env:SECRETBRIDGE_BIND={}\nStart-Process -FilePath {} -ArgumentList @('start','--no-open') -WindowStyle Hidden\n",
            ps_quote(&data),
            ps_quote(&root),
            ps_quote(&installation.bind),
            ps_quote(&binary)
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array><string>{}</string><string>start</string><string>--no-open</string></array><key>EnvironmentVariables</key><dict><key>SECRETBRIDGE_DATA_DIR</key><string>{}</string><key>SECRETBRIDGE_INSTALL_DIR</key><string>{}</string><key>SECRETBRIDGE_BIND</key><string>{}</string></dict><key>RunAtLoad</key><true/><key>AbandonProcessGroup</key><true/></dict></plist>\n",
            xml(&name(installation)),
            xml(&binary),
            xml(&data),
            xml(&root),
            xml(&installation.bind)
        ))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(format!(
            "[Desktop Entry]\nType=Application\nName=SecretBridge\nComment=SecretBridge background startup\nExec=/usr/bin/env {} {} {} {} start --no-open\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            desktop_quote(&format!("SECRETBRIDGE_DATA_DIR={data}")),
            desktop_quote(&format!("SECRETBRIDGE_INSTALL_DIR={root}")),
            desktop_quote(&format!("SECRETBRIDGE_BIND={}", installation.bind)),
            desktop_quote(&binary)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_snapshot_restores_binary_files_and_removes_only_new_descriptors() {
        let root = std::env::temp_dir().join(format!(
            "secretbridge-startup-snapshot-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let existing = root.join("owned.lnk");
        let newly_created = root.join("owned.ps1");
        let unknown = root.join("user-note.txt");
        fs::write(&existing, b"\0original\xff").unwrap();
        fs::write(&unknown, b"keep").unwrap();
        let snapshot = Snapshot(vec![
            (existing.clone(), Some(b"\0original\xff".to_vec())),
            (newly_created.clone(), None),
        ]);
        fs::write(&existing, b"replacement").unwrap();
        fs::write(&newly_created, b"new").unwrap();
        snapshot.restore().unwrap();
        assert_eq!(fs::read(&existing).unwrap(), b"\0original\xff");
        assert!(!newly_created.exists());
        assert_eq!(fs::read(&unknown).unwrap(), b"keep");
        fs::remove_file(existing).unwrap();
        fs::remove_file(unknown).unwrap();
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn startup_descriptor_quotes_paths_and_never_requests_a_password() {
        let installation = Installation {
            format_version: 1,
            id: uuid::Uuid::new_v4(),
            active: Some("release-0123456789abcdef".into()),
            previous: None,
            data_directory: PathBuf::from("/tmp/a & b's $data"),
            bind: "127.0.0.1:8787".into(),
            startup_files: Vec::new(),
        };
        let descriptor = render(
            Path::new("/tmp/new folder/app"),
            Path::new("/tmp/install & space"),
            &installation,
        )
        .unwrap();
        assert!(descriptor.contains("--no-open"));
        assert!(descriptor.contains("SECRETBRIDGE_DATA_DIR"));
        assert!(!descriptor.contains("password"));
        #[cfg(windows)]
        assert!(descriptor.contains("b''s"));
        #[cfg(target_os = "macos")]
        assert!(descriptor.contains("&amp;"));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(descriptor.contains("\\\\$data"));
    }
}
