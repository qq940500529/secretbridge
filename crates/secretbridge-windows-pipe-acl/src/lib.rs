// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows FFI is confined to this small crate. The broker remains unsafe-free.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr::{self, NonNull},
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct LocalAllocation(NonNull<c_void>);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Every instance owns one allocation returned by a Windows API that requires LocalFree.
        unsafe { LocalFree(self.0.as_ptr()) };
    }
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken returned this owned handle.
        unsafe { CloseHandle(self.0) };
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = ptr::null_mut();
    // SAFETY: The output pointer is valid and GetCurrentProcess returns a pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = TokenHandle(token);
    let mut bytes = 0u32;
    // SAFETY: This sizing call supplies no output buffer and writes only the required length.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut bytes) };
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > 65_536 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The aligned allocation is at least `bytes` long; the token handle remains open.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: A successful TokenUser query begins with a fully initialized TOKEN_USER.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = ptr::null_mut();
    // SAFETY: The SID pointer refers into the still-live token information buffer.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_text = LocalAllocation(
        NonNull::new(sid_text.cast())
            .ok_or(io::Error::other("Windows returned a null SID string"))?,
    );
    let wide = sid_text.0.as_ptr().cast::<u16>();
    let mut length = 0usize;
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated UTF-16 allocation.
    while unsafe { *wide.add(length) } != 0 {
        length += 1;
        if length > 256 {
            return Err(io::Error::other("Windows returned an invalid SID string"));
        }
    }
    // SAFETY: The loop found the terminator within the owned allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length) })
        .map_err(|_| io::Error::other("Windows returned an invalid SID string"))
}

fn private_descriptor() -> io::Result<LocalAllocation> {
    let sid = current_user_sid()?;
    // A protected DACL with only the current user and LocalSystem excludes Everyone,
    // Anonymous and unrelated local accounts. The bearer token remains mandatory.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})\0")
        .encode_utf16()
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and the output pointer is valid.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    NonNull::new(descriptor)
        .map(LocalAllocation)
        .ok_or(io::Error::other(
            "Windows returned a null security descriptor",
        ))
}

fn path_wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.is_empty() || wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows path",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn sid_from_string(value: &str) -> io::Result<LocalAllocation> {
    let wide: Vec<u16> = format!("{value}\0").encode_utf16().collect();
    let mut sid = ptr::null_mut();
    // SAFETY: The string is NUL-terminated and Windows writes one allocated SID pointer.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    NonNull::new(sid)
        .map(LocalAllocation)
        .ok_or(io::Error::other("Windows returned a null SID"))
}

fn has_private_dacl(descriptor: *mut c_void) -> io::Result<bool> {
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: The caller owns a live Windows security descriptor and output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Ok(false);
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    // SAFETY: The descriptor and output pointers are live and valid.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || acl.is_null() {
        return Ok(false);
    }
    // SAFETY: Windows returned an ACL pointer inside the live descriptor.
    if unsafe { (*acl).AceCount } != 2 {
        return Ok(false);
    }
    let user_sid = sid_from_string(&current_user_sid()?)?;
    let system_sid = sid_from_string("S-1-5-18")?;
    let mut user_found = false;
    let mut system_found = false;
    for index in 0..2 {
        let mut raw_ace = ptr::null_mut();
        // SAFETY: The ACL contains two ACEs and Windows writes a pointer into raw_ace.
        if unsafe { GetAce(acl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The ACE pointer belongs to the live ACL and begins with the common header.
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != 0 {
            return Ok(false);
        }
        let sid: *mut c_void = (&raw const ace.SidStart).cast_mut().cast();
        // SAFETY: SidStart is the SID stored within this standard access-allowed ACE.
        user_found |= unsafe { EqualSid(sid, user_sid.0.as_ptr()) } != 0;
        // SAFETY: Both pointers refer to live Windows SIDs.
        system_found |= unsafe { EqualSid(sid, system_sid.0.as_ptr()) } != 0;
    }
    Ok(user_found && system_found)
}

/// Applies the protected current-user DACL to an existing data directory.
///
/// # Errors
/// Returns an error when Windows cannot replace and verify its DACL.
pub fn protect_directory(path: &Path) -> io::Result<()> {
    let descriptor = private_descriptor()?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl: *mut ACL = ptr::null_mut();
    // SAFETY: The owned descriptor and output pointers remain live for the call.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0.as_ptr(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(io::Error::other("Windows could not prepare a private DACL"));
    }
    let wide = path_wide(path)?;
    // SAFETY: The path and ACL remain live for this synchronous security update.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if !is_private_path(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "data directory DACL is not private",
        ));
    }
    Ok(())
}

/// Checks the on-disk object DACL before consuming a bridge connection document.
///
/// # Errors
/// Returns an error when the descriptor cannot be queried.
pub fn is_private_path(path: &Path) -> io::Result<bool> {
    let wide = path_wide(path)?;
    let mut raw = ptr::null_mut();
    // SAFETY: The path is NUL-terminated and Windows writes one allocated descriptor pointer.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut raw,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalAllocation(NonNull::new(raw).ok_or(io::Error::other(
        "Windows returned a null security descriptor",
    ))?);
    has_private_dacl(descriptor.0.as_ptr())
}

/// Atomically creates a bridge document with a protected current-user DACL.
///
/// # Errors
/// Returns an error if the path exists or Windows cannot enforce the DACL.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let descriptor = private_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.as_ptr(),
        bInheritHandle: 0,
    };
    let wide = path_wide(path)?;
    // SAFETY: The path and attributes remain live during CreateFileW; no handle inheritance is allowed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_NONE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a fresh owned handle, transferred to File exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Creates a local named pipe with a protected current-user-only DACL.
///
/// # Errors
/// Fails closed if the current SID, descriptor or pipe cannot be created.
pub fn create_private_named_pipe(
    options: &ServerOptions,
    name: &str,
) -> io::Result<NamedPipeServer> {
    let descriptor = private_descriptor()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` and its descriptor remain alive for this synchronous CreateNamedPipe call.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::io::AsRawHandle,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::Security::{
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
        DACL_SECURITY_INFORMATION,
    };

    #[tokio::test]
    async fn native_pipe_dacl_excludes_everyone_and_anonymous() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            r"\\.\pipe\secretbridge-acl-test-{}-{unique}",
            std::process::id()
        );
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(true)
            .reject_remote_clients(true);
        let pipe = create_private_named_pipe(&options, &name).unwrap();
        let mut raw = ptr::null_mut();
        // SAFETY: The live pipe handle and output pointer are valid for this synchronous query.
        let status = unsafe {
            GetSecurityInfo(
                pipe.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut raw,
            )
        };
        assert_eq!(status, 0, "Windows could not read the pipe DACL");
        let descriptor = LocalAllocation(NonNull::new(raw).unwrap());
        assert!(has_private_dacl(descriptor.0.as_ptr()).unwrap());
    }

    #[test]
    fn native_directory_and_file_dacls_are_private() {
        use std::io::Write;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "secretbridge-acl-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        protect_directory(&directory).unwrap();
        assert!(is_private_path(&directory).unwrap());
        let path = directory.join("mcp-bridge.json");
        let mut file = create_private_file(&path).unwrap();
        file.write_all(b"synthetic test only").unwrap();
        drop(file);
        assert!(is_private_path(&path).unwrap());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
