// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows FFI is confined to this small crate. The broker remains unsafe-free.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    ptr::{self, NonNull},
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    },
    Security::{GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser},
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
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
        },
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
        let mut text = ptr::null_mut();
        let mut length = 0u32;
        // SAFETY: Windows owns the queried descriptor and allocates the string returned here.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0.as_ptr(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            )
        };
        assert_ne!(converted, 0, "Windows could not format the pipe DACL");
        let text = LocalAllocation(NonNull::new(text.cast()).unwrap());
        // SAFETY: Windows reported the UTF-16 string length for this live allocation.
        let sddl = String::from_utf16(unsafe {
            std::slice::from_raw_parts(text.0.as_ptr().cast::<u16>(), length as usize)
        })
        .unwrap();
        let sddl = sddl.trim_end_matches('\0');
        assert!(sddl.starts_with("D:P"), "pipe DACL must be protected");
        assert!(
            sddl.contains(&current_user_sid().unwrap()),
            "owner ACE missing"
        );
        assert!(sddl.contains(";;;SY)"), "LocalSystem ACE missing");
        assert!(!sddl.contains(";;;WD)"), "Everyone must not read the pipe");
        assert!(!sddl.contains(";;;AN)"), "Anonymous must not read the pipe");
        assert_eq!(sddl.matches("(A;").count(), 2, "unexpected pipe ACE");
    }
}
