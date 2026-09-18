// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

pub use crate::catalog::maintenance::BackupReport;
use crate::catalog::{
    Catalog,
    maintenance::{MAX_BACKUP_BYTES, copy_database, inspect_backup},
};
use std::{fs, io::Read, path::Path};

fn read_backup(path: &Path) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "backup_unreadable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 268_435_456 {
        return Err("backup_invalid");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "backup_unreadable")?
        .take(268_435_457)
        .read_to_end(&mut bytes)
        .map_err(|_| "backup_unreadable")?;
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err("backup_invalid");
    }
    Ok(bytes)
}

/// Checks a SQLite backup without modifying the running broker or credential store.
///
/// # Errors
/// Returns a fixed error code for an unreadable, invalid, or unsupported backup.
pub fn inspect_configuration_backup(path: &Path) -> Result<BackupReport, &'static str> {
    inspect_backup(&read_backup(path)?)
        .map(|(report, _)| report)
        .map_err(|_| "backup_invalid")
}

/// Restores configuration into a new, absolute data directory. Existing directories are never overwritten.
/// Credentials must be entered again and outstanding authorizations are revoked.
///
/// # Errors
/// Returns a fixed error code if validation, destination creation, or restoration fails.
pub fn restore_configuration_backup(
    path: &Path,
    directory: &Path,
) -> Result<BackupReport, &'static str> {
    let (report, catalog) = inspect_backup(&read_backup(path)?).map_err(|_| "backup_invalid")?;
    if !directory.is_absolute() || directory.file_name().is_none() || directory.exists() {
        return Err("restore_requires_new_directory");
    }
    catalog
        .recover_interrupted_runs()
        .map_err(|_| "restore_failed")?;
    let unfinished: bool = catalog
        .lock()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM synthetic_runs WHERE state IN ('queued','running'))",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "restore_failed")?;
    if unfinished {
        return Err("restore_failed");
    }
    catalog.lock().execute_batch("BEGIN IMMEDIATE;
        UPDATE credential_references SET secret_configured=0, secret_updated_at_unix_ms=NULL, version=version+1;
        UPDATE approvals SET state='revoked', version=version+1 WHERE state IN ('pending','approved');
        COMMIT;").map_err(|_| "restore_failed")?;
    fs::create_dir(directory).map_err(|_| "restore_requires_new_directory")?;
    let database_path = directory.join("secretbridge.sqlite3");
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "restore_failed")?;
        }
        let mut destination =
            rusqlite::Connection::open(&database_path).map_err(|_| "restore_failed")?;
        copy_database(&catalog.lock(), &mut destination).map_err(|_| "restore_failed")?;
        destination.close().map_err(|_| "restore_failed")?;
        fs::OpenOptions::new()
            .write(true)
            .open(&database_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| "restore_failed")?;
        Ok(report)
    })();
    if result.is_err() {
        // Only files created by this operation in its newly created directory are removed.
        for name in [
            "secretbridge.sqlite3",
            "secretbridge.sqlite3-wal",
            "secretbridge.sqlite3-shm",
            "secretbridge.sqlite3-journal",
        ] {
            let _ = fs::remove_file(directory.join(name));
        }
        let _ = fs::remove_dir(directory);
    }
    result
}

pub(crate) fn open_with_migration_backup(
    path: &Path,
) -> Result<Catalog, crate::catalog::CatalogOpenError> {
    use crate::catalog::{CatalogOpenError, SCHEMA_VERSION};
    let connection = rusqlite::Connection::open(path)?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version <= 0 || version >= SCHEMA_VERSION {
        return Catalog::initialize(connection);
    }
    let rollback_path = path.with_file_name(format!(
        "secretbridge.pre-migration-v{version}-{}.sqlite3",
        uuid::Uuid::new_v4()
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&rollback_path)
        .map_err(|_| CatalogOpenError::Recovery)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| CatalogOpenError::Recovery)?;
    }
    let mut rollback = rusqlite::Connection::open(&rollback_path)?;
    copy_database(&connection, &mut rollback).map_err(|_| CatalogOpenError::Recovery)?;
    rollback.pragma_update(None, "journal_mode", "DELETE")?;
    file.sync_all().map_err(|_| CatalogOpenError::Recovery)?;
    match Catalog::initialize(connection) {
        Ok(catalog) => Ok(catalog),
        Err(error) => {
            let mut live = rusqlite::Connection::open(path)?;
            copy_database(&rollback, &mut live).map_err(|_| CatalogOpenError::Recovery)?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upgrade_retains_consistent_pre_migration_backup() {
        let directory =
            std::env::temp_dir().join(format!("secretbridge-migration-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secretbridge.sqlite3");
        let catalog = Catalog::open(&path).unwrap();
        catalog
            .lock()
            .execute_batch("DROP TABLE configuration_imports; PRAGMA user_version=14;")
            .unwrap();
        drop(catalog);
        let upgraded = Catalog::open(&path).unwrap();
        assert_eq!(
            upgraded
                .lock()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15
        );
        let backup = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .find(|item| {
                item.file_name()
                    .to_string_lossy()
                    .starts_with("secretbridge.pre-migration-v14-")
            })
            .unwrap()
            .path();
        assert_eq!(
            inspect_configuration_backup(&backup)
                .unwrap()
                .schema_version,
            14
        );
        drop(upgraded);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn failed_schema_migration_rolls_database_back_to_original_version() {
        let directory = std::env::temp_dir().join(format!(
            "secretbridge-migration-failure-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secretbridge.sqlite3");
        let catalog = Catalog::open(&path).unwrap();
        // A name collision causes migration 15 to fail after beginning its transaction.
        catalog
            .lock()
            .execute_batch("PRAGMA user_version=14;")
            .unwrap();
        drop(catalog);
        assert!(Catalog::open(&path).is_err());
        let raw = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            raw.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            raw.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        drop(raw);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn malformed_backup_never_creates_a_restore_destination() {
        let directory = std::env::temp_dir().join(format!(
            "secretbridge-invalid-backup-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("invalid.sqlite3");
        fs::write(&path, b"invalid fixture").unwrap();
        let destination = directory.join("restore");
        assert!(restore_configuration_backup(&path, &destination).is_err());
        assert!(!destination.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
