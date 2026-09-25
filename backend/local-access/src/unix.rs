// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn private_metadata(path: &Path) -> io::Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(metadata)
}

/// Restrict a broker data directory to its owner.
pub fn protect_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    is_private_path(path).and_then(|private| {
        if private {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    })
}

/// Create a private connection document without replacing an existing path.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

/// Check that a directory or file is owner-only and not a symbolic link.
pub fn is_private_path(path: &Path) -> io::Result<bool> {
    let metadata = private_metadata(path)?;
    Ok(metadata.is_dir() || metadata.is_file())
}

/// Check a private connection file and its owner-only parent directory.
pub fn is_private_connection_path(path: &Path) -> io::Result<bool> {
    let file = private_metadata(path)?;
    if !file.is_file() {
        return Ok(false);
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let directory = private_metadata(parent)?;
    Ok(directory.is_dir() && directory.uid() == file.uid())
}

/// Restrict a bound Unix socket to its owner.
pub fn protect_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
