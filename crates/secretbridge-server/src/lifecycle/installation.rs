// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{Result, launch, private_file, startup, stop};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub format_version: u32,
    pub id: Uuid,
    pub active: Option<String>,
    pub previous: Option<String>,
    pub data_directory: PathBuf,
    pub bind: String,
    pub startup_files: Vec<startup::StartupFile>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub format: String,
    pub format_version: u32,
    pub version: String,
    pub platform: String,
    pub architecture: String,
    pub schema_version: i64,
    pub files: Vec<PackageFile>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
pub(super) fn root() -> Result<PathBuf> {
    let root = env::var_os("SECRETBRIDGE_INSTALL_DIR").map_or_else(
        || super::super::data_directory().map(|data| data.join("application")),
        |value| Ok(PathBuf::from(value)),
    )?;
    if !root.is_absolute()
        || root.file_name().is_none()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || root == super::super::data_directory()?
    {
        return Err("install_directory_invalid");
    }
    Ok(root)
}
fn read_json<T: for<'a> Deserialize<'a>>(path: &Path, limit: u64) -> Result<T> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "installation_invalid")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err("installation_invalid");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "installation_invalid")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "installation_invalid")?;
    if bytes.len() as u64 > limit {
        return Err("installation_invalid");
    }
    serde_json::from_slice(&bytes).map_err(|_| "installation_invalid")
}
fn release_id(value: &str) -> bool {
    value.len() == 24
        && value.starts_with("release-")
        && value[8..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn load() -> Result<Option<Installation>> {
    let root = root()?;
    if !root.exists() {
        return Ok(None);
    }
    if fs::symlink_metadata(&root)
        .map_err(|_| "installation_invalid")?
        .file_type()
        .is_symlink()
    {
        return Err("installation_invalid");
    }
    let installation: Installation = read_json(&root.join("installation.json"), 65536)?;
    if installation.format_version != 1
        || installation.id.is_nil()
        || installation
            .active
            .iter()
            .chain(installation.previous.iter())
            .any(|id| !release_id(id))
        || installation.data_directory != super::super::data_directory()?
        || super::super::require_loopback(
            installation
                .bind
                .parse()
                .map_err(|_| "installation_invalid")?,
        )
        .is_err()
    {
        return Err("installation_invalid");
    }
    Ok(Some(installation))
}
fn save(root: &Path, installation: &Installation) -> Result<()> {
    let path = root.join(format!("installation-{}.tmp", Uuid::new_v4()));
    private_file(
        &path,
        &serde_json::to_vec_pretty(installation).map_err(|_| "installation_invalid")?,
    )
    .map_err(|_| "installation_write_failed")?;
    fs::rename(&path, root.join("installation.json")).map_err(|_| {
        let _ = fs::remove_file(&path);
        "installation_write_failed"
    })
}
struct InstallLock {
    file: fs::File,
}
impl InstallLock {
    fn acquire(root: &Path) -> Result<Self> {
        let path = root.join("installer.lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|_| "installer_busy")?;
        file.try_lock().map_err(|_| "installer_busy")?;
        file.set_len(0).map_err(|_| "installer_busy")?;
        file.write_all(b"SecretBridge installation in progress\n")
            .map_err(|_| "installer_busy")?;
        file.sync_all().map_err(|_| "installer_busy")?;
        Ok(Self { file })
    }
}
impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
fn binary_name() -> &'static str {
    if cfg!(windows) {
        "bin/secretbridge-server.exe"
    } else {
        "bin/secretbridge-server"
    }
}
fn safe_path(root: &Path, value: &str) -> Result<PathBuf> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains(':')
        || value.contains('\0')
        || Path::new(value)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("package_path_invalid");
    }
    let mut path = root.to_path_buf();
    for part in Path::new(value).components() {
        path.push(part.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.file_type().is_symlink()
        {
            return Err("package_path_invalid");
        }
    }
    Ok(path)
}
fn manifest(root: &Path, check_files: bool) -> Result<Manifest> {
    let manifest: Manifest = read_json(&root.join("secretbridge-package.json"), 2 * 1024 * 1024)?;
    if manifest.format != "secretbridge-package"
        || manifest.format_version != 1
        || manifest.version.len() > 80
        || manifest.version.is_empty()
        || !manifest
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        || manifest.platform != env::consts::OS
        || manifest.architecture != env::consts::ARCH
        || manifest.schema_version != secretbridge_core::SCHEMA_VERSION
        || manifest.files.len() > 8192
    {
        return Err("package_incompatible");
    }
    let mut seen = HashSet::new();
    let mut bytes = 0_u64;
    for file in &manifest.files {
        if !seen.insert(file.path.clone())
            || !(file.path.starts_with("web/")
                || [
                    binary_name(),
                    "LICENSE",
                    "LICENSING.md",
                    "COPYRIGHT.md",
                    "THIRD_PARTY_NOTICES.md",
                    "COMMERCIAL_LICENSE.md",
                    "README.md",
                    "SOURCE.json",
                    "SOURCE.tar.gz",
                    "SBOM.cdx.json",
                    "THIRD_PARTY_LICENSES.txt",
                ]
                .contains(&file.path.as_str()))
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("package_invalid");
        }
        bytes = bytes.checked_add(file.bytes).ok_or("package_too_large")?;
        if bytes > 536_870_912 {
            return Err("package_too_large");
        }
        let path = safe_path(root, &file.path)?;
        if check_files {
            let metadata = fs::metadata(&path).map_err(|_| "package_file_missing")?;
            if !metadata.is_file() || metadata.len() != file.bytes {
                return Err("package_invalid");
            }
            if checksum(&path)? != file.sha256 {
                return Err("package_checksum_mismatch");
            }
        }
    }
    for required in [
        binary_name(),
        "web/index.html",
        "web/secretbridge-build.json",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "COPYRIGHT.md",
        "SOURCE.json",
        "SOURCE.tar.gz",
        "SBOM.cdx.json",
        "THIRD_PARTY_LICENSES.txt",
    ] {
        if !seen.contains(required) {
            return Err("package_file_missing");
        }
    }
    if check_files {
        validate_sbom(root, &manifest)?;
    }
    Ok(manifest)
}

fn validate_sbom(root: &Path, manifest: &Manifest) -> Result<()> {
    let sbom: serde_json::Value = read_json(&root.join("SBOM.cdx.json"), 16 * 1024 * 1024)?;
    let component = sbom
        .pointer("/metadata/component")
        .and_then(serde_json::Value::as_object)
        .ok_or("package_sbom_invalid")?;
    if sbom.get("bomFormat").and_then(serde_json::Value::as_str) != Some("CycloneDX")
        || sbom.get("specVersion").and_then(serde_json::Value::as_str) != Some("1.6")
        || sbom.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || component.get("name").and_then(serde_json::Value::as_str) != Some("SecretBridge")
        || component.get("version").and_then(serde_json::Value::as_str)
            != Some(manifest.version.as_str())
        || !sbom
            .get("components")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| !items.is_empty() && items.len() <= 8192)
    {
        return Err("package_sbom_invalid");
    }
    let properties = sbom
        .pointer("/metadata/properties")
        .and_then(serde_json::Value::as_array)
        .ok_or("package_sbom_invalid")?;
    for (name, expected) in [
        ("secretbridge:platform", manifest.platform.as_str()),
        ("secretbridge:architecture", manifest.architecture.as_str()),
    ] {
        if !properties.iter().any(|property| {
            property.get("name").and_then(serde_json::Value::as_str) == Some(name)
                && property.get("value").and_then(serde_json::Value::as_str) == Some(expected)
        }) {
            return Err("package_sbom_invalid");
        }
    }
    Ok(())
}
fn checksum(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|_| "package_file_missing")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer).map_err(|_| "package_invalid")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}
pub(super) fn active_paths() -> Result<Option<(PathBuf, PathBuf)>> {
    let Some(installation) = load()? else {
        return Ok(None);
    };
    let Some(active) = installation.active else {
        return Ok(None);
    };
    let release = safe_path(&root()?, &format!("releases/{active}"))?;
    manifest(&release, true)?;
    Ok(Some((release.join(binary_name()), release.join("web"))))
}
pub(super) fn summary() -> Result<serde_json::Value> {
    let Some(installation) = load()? else {
        return Ok(serde_json::Value::Null);
    };
    Ok(
        serde_json::json!({"active_release":installation.active,"previous_release":installation.previous,"autostart":!installation.startup_files.is_empty(),"data_retained_on_uninstall":true}),
    )
}

pub(super) fn verify(package: &Path) -> Result<serde_json::Value> {
    let package = fs::canonicalize(package).map_err(|_| "package_unavailable")?;
    let verified = manifest(&package, true)?;
    super::validate_web_build_for(&package.join("web"), &verified.version)?;
    let bytes = verified.files.iter().map(|file| file.bytes).sum::<u64>();
    Ok(serde_json::json!({
        "valid": true,
        "version": verified.version,
        "platform": verified.platform,
        "architecture": verified.architecture,
        "schema_version": verified.schema_version,
        "files": verified.files.len(),
        "bytes": bytes,
        "sbom": "CycloneDX 1.6",
        "executable_digest_verified": true,
        "executable_version_check": "activation"
    }))
}

pub(super) async fn install(package: &Path) -> Result<()> {
    let package = fs::canonicalize(package).map_err(|_| "package_unavailable")?;
    let verified = manifest(&package, true)?;
    let root = root()?;
    let old = if root.exists() {
        load()?.ok_or("installation_invalid")?
    } else {
        super::super::create_private_data_directory(&root)
            .map_err(|_| "installation_write_failed")?;
        let installation = Installation {
            format_version: 1,
            id: Uuid::new_v4(),
            active: None,
            previous: None,
            data_directory: super::super::data_directory()?,
            bind: env::var("SECRETBRIDGE_BIND")
                .unwrap_or_else(|_| super::super::DEFAULT_ADDRESS.into()),
            startup_files: Vec::new(),
        };
        super::super::require_loopback(
            installation
                .bind
                .parse()
                .map_err(|_| "installation_invalid")?,
        )?;
        save(&root, &installation)?;
        installation
    };
    let _lock = InstallLock::acquire(&root)?;
    let id = format!(
        "release-{}",
        &checksum(&package.join("secretbridge-package.json"))?[..16]
    );
    let releases = safe_path(&root, "releases")?;
    fs::create_dir_all(&releases).map_err(|_| "installation_write_failed")?;
    let release = safe_path(&root, &format!("releases/{id}"))?;
    if !release.exists() {
        stage_release(&package, &releases, &release, &verified)?;
    }
    manifest(&release, true)?;
    if old.active.as_ref() == Some(&id) {
        let status = super::start(false).await?;
        if status.version != verified.version {
            return Err("installed_version_mismatch");
        }
        println!(
            "{}",
            serde_json::json!({"installed":true,"version":verified.version,"binary":release.join(binary_name()),"replayed":true})
        );
        return Ok(());
    }
    let mut pending = old.clone();
    pending.previous = old.active.clone();
    pending.active = Some(id);
    activate(&root, &old, &mut pending, &release, &verified).await?;
    println!(
        "{}",
        serde_json::json!({"installed":true,"version":verified.version,"binary":release.join(binary_name()),"data_retained":true})
    );
    Ok(())
}
fn stage_release(
    package: &Path,
    releases: &Path,
    release: &Path,
    verified: &Manifest,
) -> Result<()> {
    let staging = releases.join(format!("pending-{}", Uuid::new_v4()));
    fs::create_dir(&staging).map_err(|_| "installation_write_failed")?;
    let result = (|| {
        fs::copy(
            package.join("secretbridge-package.json"),
            staging.join("secretbridge-package.json"),
        )
        .map_err(|_| "installation_write_failed")?;
        for file in &verified.files {
            let destination = safe_path(&staging, &file.path)?;
            fs::create_dir_all(destination.parent().ok_or("package_path_invalid")?)
                .map_err(|_| "installation_write_failed")?;
            fs::copy(safe_path(package, &file.path)?, destination)
                .map_err(|_| "installation_write_failed")?;
        }
        manifest(&staging, true)?;
        fs::rename(&staging, release).map_err(|_| "installation_write_failed")
    })();
    if result.is_err() {
        remove_release_files(&staging, verified)?;
    }
    result
}
async fn activate(
    root: &Path,
    old: &Installation,
    pending: &mut Installation,
    release: &Path,
    verified: &Manifest,
) -> Result<()> {
    let snapshot = if old.startup_files.is_empty() {
        None
    } else {
        Some(startup::Snapshot::capture(old)?)
    };
    stop().await?;
    let activation = async {
        let status = launch(&release.join(binary_name()), &release.join("web")).await?;
        if status.version != verified.version || status.schema_version != verified.schema_version {
            return Err("installed_version_mismatch");
        }
        if !old.startup_files.is_empty() {
            pending.startup_files = startup::enable(root, pending)?;
        }
        save(root, pending)?;
        Ok(())
    }
    .await;
    if activation.is_err() {
        stop().await.map_err(|_| "installation_recovery_failed")?;
        if let Some(snapshot) = snapshot {
            snapshot.restore()?;
        }
        save(root, old)?;
        if let Some(active) = &old.active {
            let prior = safe_path(root, &format!("releases/{active}"))?;
            launch(&prior.join(binary_name()), &prior.join("web"))
                .await
                .map_err(|_| "installation_recovery_failed")?;
        }
        return Err("installation_activation_failed");
    }
    Ok(())
}
pub(super) async fn rollback() -> Result<()> {
    let root = root()?;
    let _lock = InstallLock::acquire(&root)?;
    let old = load()?.ok_or("not_installed")?;
    let prior = old.previous.as_ref().ok_or("no_previous_release")?;
    let release = safe_path(&root, &format!("releases/{prior}"))?;
    let verified = manifest(&release, true)?;
    let mut pending = old.clone();
    std::mem::swap(&mut pending.active, &mut pending.previous);
    activate(&root, &old, &mut pending, &release, &verified).await?;
    println!(
        "{}",
        serde_json::json!({"rolled_back":true,"version":verified.version,"binary":release.join(binary_name()),"data_retained":true})
    );
    Ok(())
}
pub(super) fn autostart(enabled: bool) -> Result<()> {
    let root = root()?;
    let _lock = InstallLock::acquire(&root)?;
    let mut installation = load()?.ok_or("not_installed")?;
    let snapshot = startup::Snapshot::capture(&installation)?;
    if enabled {
        installation.startup_files = startup::enable(&root, &installation)?;
    } else {
        startup::disable(&installation)?;
        installation.startup_files.clear();
    }
    if let Err(error) = save(&root, &installation) {
        snapshot.restore()?;
        return Err(error);
    }
    println!(
        "{}",
        serde_json::json!({"autostart":enabled,"effective":"next_login"})
    );
    Ok(())
}
pub(super) async fn uninstall(remove_configuration: bool) -> Result<()> {
    let root = root()?;
    let lock = InstallLock::acquire(&root)?;
    let installation = load()?.ok_or("not_installed")?;
    stop().await?;
    startup::disable(&installation)?;
    if remove_configuration {
        remove_catalog(&installation.data_directory).await?;
    }
    let releases = safe_path(&root, "releases")?;
    if releases.is_dir() {
        for entry in fs::read_dir(&releases).map_err(|_| "uninstall_failed")? {
            let entry = entry.map_err(|_| "uninstall_failed")?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(release_id) {
                continue;
            }
            let release = safe_path(&root, &format!("releases/{}", name.to_string_lossy()))?;
            if let Ok(manifest) = manifest(&release, false) {
                remove_release_files_with_retry(&release, &manifest).await?;
            }
        }
    }
    let _ = fs::remove_dir(releases);
    fs::remove_file(root.join("installation.json")).map_err(|_| "uninstall_failed")?;
    drop(lock);
    let _ = fs::remove_file(root.join("installer.lock"));
    let _ = fs::remove_dir(&root);
    println!(
        "{}",
        serde_json::json!({"uninstalled":true,"data_retained":!remove_configuration,"system_credentials_retained":true,"unknown_files_retained":root.exists()})
    );
    Ok(())
}
async fn remove_catalog(data: &Path) -> Result<()> {
    // Only delete documented catalog files, never arbitrary data or vault entries.
    let mut paths = Vec::new();
    for entry in fs::read_dir(data).map_err(|_| "configuration_remove_failed")? {
        let entry = entry.map_err(|_| "configuration_remove_failed")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let migration_backup = name
            .strip_prefix("secretbridge.pre-migration-v")
            .and_then(|rest| rest.strip_suffix(".sqlite3"))
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(version, id)| {
                !version.is_empty()
                    && version.bytes().all(|byte| byte.is_ascii_digit())
                    && Uuid::parse_str(id).is_ok()
            });
        if [
            "secretbridge.sqlite3",
            "secretbridge.sqlite3-wal",
            "secretbridge.sqlite3-shm",
        ]
        .contains(&name)
            || migration_backup
        {
            let path = safe_path(data, name)?;
            if !fs::symlink_metadata(&path)
                .map_err(|_| "configuration_remove_failed")?
                .is_file()
            {
                return Err("configuration_remove_failed");
            }
            paths.push(path);
        }
    }
    for path in paths {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while path.exists() {
            if fs::remove_file(&path).is_ok() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("configuration_remove_failed");
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    Ok(())
}

fn remove_release_files(release: &Path, manifest: &Manifest) -> Result<()> {
    for file in &manifest.files {
        let path = safe_path(release, &file.path)?;
        if path.is_file() {
            fs::remove_file(&path).map_err(|_| "uninstall_file_in_use")?;
        }
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == release {
                break;
            }
            let _ = fs::remove_dir(directory);
            parent = directory.parent();
        }
    }
    let _ = fs::remove_file(release.join("secretbridge-package.json"));
    let _ = fs::remove_dir(release);
    Ok(())
}

async fn remove_release_files_with_retry(release: &Path, manifest: &Manifest) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match remove_release_files(release, manifest) {
            Ok(()) => return Ok(()),
            Err("uninstall_file_in_use") if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_paths_reject_traversal_absolute_and_platform_escapes() {
        let root = std::env::temp_dir();
        for value in [
            "../outside",
            "/outside",
            "web/../../outside",
            "web\\outside",
            "web:stream",
            "",
        ] {
            assert!(safe_path(&root, value).is_err(), "{value}");
        }
        assert_eq!(
            safe_path(&root, "web/assets/app.js").unwrap(),
            root.join("web/assets/app.js")
        );
        assert!(release_id("release-0123456789abcdef"));
        assert!(!release_id("release-../outside"));
    }

    #[test]
    fn stale_install_lock_file_is_reusable_but_live_lock_is_rejected() {
        let root = std::env::temp_dir().join(format!("secretbridge-lock-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("installer.lock"), b"stale synthetic marker").unwrap();

        let first = InstallLock::acquire(&root).expect("acquire stale lock file");
        assert!(matches!(InstallLock::acquire(&root), Err("installer_busy")));
        drop(first);
        drop(InstallLock::acquire(&root).expect("reacquire released lock"));

        fs::remove_file(root.join("installer.lock")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn sbom_must_match_package_version_and_target() {
        let root = std::env::temp_dir().join(format!("secretbridge-sbom-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let manifest = Manifest {
            format: "secretbridge-package".into(),
            format_version: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            platform: env::consts::OS.into(),
            architecture: env::consts::ARCH.into(),
            schema_version: secretbridge_core::SCHEMA_VERSION,
            files: Vec::new(),
        };
        let mut sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {"name": "SecretBridge", "version": manifest.version.clone()},
                "properties": [
                    {"name": "secretbridge:platform", "value": manifest.platform.clone()},
                    {"name": "secretbridge:architecture", "value": manifest.architecture.clone()}
                ]
            },
            "components": [{"type": "library", "name": "fixture", "version": "1"}]
        });
        fs::write(
            root.join("SBOM.cdx.json"),
            serde_json::to_vec(&sbom).unwrap(),
        )
        .unwrap();
        assert!(validate_sbom(&root, &manifest).is_ok());
        sbom["metadata"]["component"]["version"] = serde_json::json!("wrong");
        fs::write(
            root.join("SBOM.cdx.json"),
            serde_json::to_vec(&sbom).unwrap(),
        )
        .unwrap();
        assert_eq!(validate_sbom(&root, &manifest), Err("package_sbom_invalid"));
        fs::remove_file(root.join("SBOM.cdx.json")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn configuration_removal_preserves_unrecognised_files_and_names() {
        let data = std::env::temp_dir().join(format!("secretbridge-removal-{}", Uuid::new_v4()));
        fs::create_dir(&data).unwrap();
        let backup = format!("secretbridge.pre-migration-v15-{}.sqlite3", Uuid::new_v4());
        for name in [
            "secretbridge.sqlite3",
            "secretbridge.sqlite3-wal",
            backup.as_str(),
            "user-note.txt",
            "secretbridge.pre-migration-v15-user.sqlite3",
        ] {
            fs::write(data.join(name), b"synthetic").unwrap();
        }
        remove_catalog(&data).await.unwrap();
        assert!(!data.join("secretbridge.sqlite3").exists());
        assert!(!data.join(backup).exists());
        assert!(data.join("user-note.txt").exists());
        assert!(
            data.join("secretbridge.pre-migration-v15-user.sqlite3")
                .exists()
        );
        fs::remove_file(data.join("user-note.txt")).unwrap();
        fs::remove_file(data.join("secretbridge.pre-migration-v15-user.sqlite3")).unwrap();
        fs::remove_dir(data).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn release_removal_waits_for_a_transient_windows_file_lock() {
        use std::os::windows::fs::OpenOptionsExt;

        let release = std::env::temp_dir().join(format!("secretbridge-release-{}", Uuid::new_v4()));
        fs::create_dir(&release).unwrap();
        let binary = release.join("secretbridge.exe");
        fs::write(&binary, b"synthetic").unwrap();
        let manifest = Manifest {
            format: "secretbridge-package".into(),
            format_version: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            platform: env::consts::OS.into(),
            architecture: env::consts::ARCH.into(),
            schema_version: secretbridge_core::SCHEMA_VERSION,
            files: vec![PackageFile {
                path: "secretbridge.exe".into(),
                bytes: 9,
                sha256: "synthetic".into(),
            }],
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let binary_for_thread = binary.clone();
        let handle = std::thread::spawn(move || {
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(binary_for_thread)
                .unwrap();
            ready_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(file);
        });
        ready_rx.recv().unwrap();

        remove_release_files_with_retry(&release, &manifest)
            .await
            .unwrap();
        handle.join().unwrap();
        assert!(!release.exists());
    }
}
