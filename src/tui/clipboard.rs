use std::io::{self, Write};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

pub fn copy(text: &str) -> Result<&'static str> {
    if try_native_clipboard(text) {
        return Ok("system clipboard");
    }
    copy_via_osc52(text)?;
    Ok("terminal clipboard")
}

fn try_native_clipboard(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    let commands: &[(&str, &[&str])] = &[("pbcopy", &[])];
    #[cfg(target_os = "linux")]
    let commands: &[(&str, &[&str])] = &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])];
    #[cfg(target_os = "windows")]
    let commands: &[(&str, &[&str])] = &[("clip", &[])];
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let commands: &[(&str, &[&str])] = &[];

    commands.iter().any(|(program, args)| {
        let Ok(mut child) = Command::new(program)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.wait();
            return false;
        };
        if stdin.write_all(text.as_bytes()).is_err() {
            drop(stdin);
            let _ = child.wait();
            return false;
        }
        drop(stdin);
        child.wait().is_ok_and(|status| status.success())
    })
}

fn copy_via_osc52(text: &str) -> Result<()> {
    let encoded = base64_encode(text.as_bytes());
    let mut stdout = io::stdout().lock();
    write!(stdout, "\x1b]52;c;{encoded}\x07")
        .and_then(|_| stdout.flush())
        .map_err(|error| anyhow!("could not write to terminal clipboard: {error}"))
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    #[test]
    fn encodes_osc52_payloads_as_base64() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"1.2.3.4"), "MS4yLjMuNA==");
        assert_eq!(base64_encode("2001:db8::1".as_bytes()), "MjAwMTpkYjg6OjE=");
    }
}
