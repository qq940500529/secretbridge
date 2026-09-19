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
    if version == 0 || version == SCHEMA_VERSION {
        return Catalog::initialize(connection);
    }
    Err(CatalogOpenError::UnsupportedSchema(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unpublished_legacy_schema_is_rejected_without_mutation() {
        let directory =
            std::env::temp_dir().join(format!("secretbridge-migration-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secretbridge.sqlite3");
        let catalog = Catalog::open(&path).unwrap();
        catalog.lock().pragma_update(None, "user_version", 15).unwrap();
        drop(catalog);
        assert!(matches!(
            Catalog::open(&path),
            Err(crate::catalog::CatalogOpenError::UnsupportedSchema(15))
        ));
        let raw = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            raw.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15
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
