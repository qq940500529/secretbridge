// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use super::{
    BACKLOG_LIMIT, MAX_ENVIRONMENT_VARIABLES, OutputBuffer, TerminalError, TerminalShell,
    resolve_name, resolve_working_directory, system_capabilities, validate_environment,
    validate_size,
};

#[test]
fn terminal_size_has_safe_bounds() {
    assert_eq!(validate_size(24, 80), Ok(()));
    assert_eq!(validate_size(1, 80), Err(TerminalError::InvalidSize));
    assert_eq!(validate_size(24, 501), Err(TerminalError::InvalidSize));
}

#[test]
fn session_name_and_working_directory_are_validated() {
    assert_eq!(
        resolve_name(Some("  Build shell  "), TerminalShell::Bash, 1),
        Ok("Build shell".to_owned())
    );
    assert_eq!(
        resolve_name(Some("\n"), TerminalShell::Bash, 1),
        Err(TerminalError::InvalidName)
    );
    assert!(resolve_working_directory(None).is_ok());
    assert_eq!(
        resolve_working_directory(Some("relative/path")),
        Err(TerminalError::InvalidWorkingDirectory)
    );
}

#[test]
fn ordinary_environment_is_bounded_and_portable() {
    let valid = BTreeMap::from([
        ("LANG".to_owned(), "zh_CN.UTF-8".to_owned()),
        ("BUILD_NUMBER_2".to_owned(), "42".to_owned()),
    ]);
    assert_eq!(validate_environment(&valid), Ok(()));
    assert_eq!(
        validate_environment(&BTreeMap::from([(
            "INVALID-NAME".to_owned(),
            "value".to_owned()
        )])),
        Err(TerminalError::InvalidEnvironment)
    );
    let too_many = (0..=MAX_ENVIRONMENT_VARIABLES)
        .map(|index| (format!("VAR_{index}"), String::new()))
        .collect();
    assert_eq!(
        validate_environment(&too_many),
        Err(TerminalError::InvalidEnvironment)
    );
}

#[test]
fn current_platform_exposes_an_installed_default_shell() {
    let capabilities = system_capabilities();
    assert!(!capabilities.shells.is_empty());
    assert_eq!(
        capabilities.default_shell,
        capabilities.shells.first().map(|item| item.shell)
    );
    #[cfg(windows)]
    assert!(
        capabilities
            .shells
            .iter()
            .any(|item| item.shell == TerminalShell::Cmd)
    );
}

#[test]
fn backlog_retains_only_the_newest_bytes() {
    let mut output = OutputBuffer::new();
    output.append(&vec![1; BACKLOG_LIMIT]);
    output.append(&[2, 3]);
    let replay = output.snapshot(Some(0));
    assert_eq!(replay.output.len(), BACKLOG_LIMIT);
    assert_eq!(replay.output[BACKLOG_LIMIT - 2], 2);
    assert_eq!(replay.output[BACKLOG_LIMIT - 1], 3);
    assert_eq!(replay.replay_from, 2);
    assert_eq!(replay.next_cursor, (BACKLOG_LIMIT + 2) as u64);
    assert!(replay.truncated);
}

#[test]
fn valid_cursor_replays_only_missing_output() {
    let mut output = OutputBuffer::new();
    output.append(b"first second");
    let replay = output.snapshot(Some(6));
    assert_eq!(replay.replay_from, 6);
    assert_eq!(replay.output, b"second");
    assert!(!replay.truncated);
}

#[test]
fn oversized_chunk_preserves_cursor_and_only_retains_the_tail() {
    let mut output = OutputBuffer::new();
    let chunk = (0..BACKLOG_LIMIT + 17)
        .map(|index| u8::try_from(index % 251).expect("bounded byte"))
        .collect::<Vec<_>>();
    output.append(&chunk);
    let replay = output.snapshot(Some(0));
    assert_eq!(replay.replay_from, 17);
    assert_eq!(replay.next_cursor, (BACKLOG_LIMIT + 17) as u64);
    assert_eq!(replay.output, chunk[17..]);
    assert!(replay.truncated);
}

#[test]
fn future_cursor_is_reported_as_truncated() {
    let mut output = OutputBuffer::new();
    output.append(b"available");
    let replay = output.snapshot(Some(100));
    assert_eq!(replay.replay_from, 0);
    assert_eq!(replay.output, b"available");
    assert!(replay.truncated);
}
