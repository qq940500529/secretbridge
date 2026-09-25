// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OS access controls for the broker's private data and local IPC endpoints.
//! Protocol tokens and authorization remain in the broker, not this crate.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{
    create_private_file, is_private_connection_path, is_private_path, protect_directory,
    protect_socket,
};
#[cfg(windows)]
pub use windows::{
    create_private_file, create_private_named_pipe, is_private_connection_path, is_private_path,
    protect_directory,
};
