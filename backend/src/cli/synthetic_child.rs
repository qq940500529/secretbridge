// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    io::{self, BufRead, Write},
    time::Duration,
};

const MAX_SYNTHETIC_FLOOD_BYTES: usize = 2 * 1024 * 1024;
const MAX_SYNTHETIC_WAIT_MILLIS: usize = 30_000;

pub(crate) fn run_synthetic_terminal() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    writeln!(stdout, "SecretBridge synthetic terminal")?;
    writeln!(
        stdout,
        "No system shell, credentials, files, or network targets are available."
    )?;
    writeln!(stdout, "Type 'help' to list the safe built-in commands.\r")?;
    write!(stdout, "secretbridge> ")?;
    stdout.flush()?;

    for line in stdin.lock().lines() {
        let line = line?;
        match line.trim() {
            "help" => writeln!(
                stdout,
                "help             show this message\r\nstatus           show the isolated mode\r\nflood <bytes>    emit bounded synthetic output\r\nwait <ms>        pause for cancellation testing\r\nclear            clear the screen\r\nexit             close this synthetic terminal"
            )?,
            "status" => writeln!(
                stdout,
                "mode=synthetic_only credentials=disabled shell=disabled"
            )?,
            "clear" => write!(stdout, "\x1b[2J\x1b[H")?,
            "exit" => {
                writeln!(stdout, "Synthetic terminal closed.")?;
                stdout.flush()?;
                break;
            }
            "" => {}
            input if command_name(input) == "flood" => {
                if let Some(bytes) = bounded_argument(input, "flood", MAX_SYNTHETIC_FLOOD_BYTES) {
                    write_synthetic_flood(&mut stdout, bytes)?;
                } else {
                    writeln!(
                        stdout,
                        "usage: flood <bytes>, where bytes is 1..={MAX_SYNTHETIC_FLOOD_BYTES}"
                    )?;
                }
            }
            input if command_name(input) == "wait" => {
                if let Some(milliseconds) =
                    bounded_argument(input, "wait", MAX_SYNTHETIC_WAIT_MILLIS)
                {
                    writeln!(stdout, "wait begin milliseconds={milliseconds}")?;
                    stdout.flush()?;
                    std::thread::sleep(Duration::from_millis(milliseconds as u64));
                    writeln!(stdout, "wait complete milliseconds={milliseconds}")?;
                } else {
                    writeln!(
                        stdout,
                        "usage: wait <milliseconds>, where milliseconds is 1..={MAX_SYNTHETIC_WAIT_MILLIS}"
                    )?;
                }
            }
            input => writeln!(stdout, "echo: {input}")?,
        }
        write!(stdout, "secretbridge> ")?;
        stdout.flush()?;
    }
    Ok(())
}

fn command_name(input: &str) -> &str {
    input.split_whitespace().next().unwrap_or_default()
}

pub(crate) fn bounded_argument(input: &str, command: &str, maximum: usize) -> Option<usize> {
    let mut parts = input.split_whitespace();
    if parts.next()? != command {
        return None;
    }
    let value = parts.next()?.parse::<usize>().ok()?;
    (value > 0 && value <= maximum && parts.next().is_none()).then_some(value)
}

fn write_synthetic_flood(stdout: &mut impl Write, bytes: usize) -> io::Result<()> {
    writeln!(stdout, "flood begin bytes={bytes}")?;
    let chunk = [b'x'; 8 * 1024];
    let mut remaining = bytes;
    while remaining > 0 {
        let count = remaining.min(chunk.len());
        stdout.write_all(&chunk[..count])?;
        remaining -= count;
    }
    writeln!(stdout, "\r\nflood complete bytes={bytes}")
}
