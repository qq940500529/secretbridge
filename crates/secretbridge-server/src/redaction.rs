// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use zeroize::Zeroizing;

/// Filters bytes before decoding or persistence; unfinished secret prefixes stay private.
pub struct Redactor {
    patterns: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
pub struct Utf8Decoder {
    pending: Vec<u8>,
}
impl Utf8Decoder {
    pub fn feed(&mut self, bytes: &[u8], final_chunk: bool) -> String {
        self.pending.extend_from_slice(bytes);
        let mut output = String::new();
        let mut offset = 0;
        while offset < self.pending.len() {
            match std::str::from_utf8(&self.pending[offset..]) {
                Ok(text) => {
                    output.push_str(text);
                    offset = self.pending.len();
                }
                Err(error) => {
                    output.push_str(
                        std::str::from_utf8(&self.pending[offset..offset + error.valid_up_to()])
                            .expect("validated prefix"),
                    );
                    offset += error.valid_up_to();
                    if let Some(length) = error.error_len() {
                        output.push('\u{fffd}');
                        offset += length;
                    } else if final_chunk {
                        output.push('\u{fffd}');
                        offset = self.pending.len();
                    } else {
                        break;
                    }
                }
            }
        }
        self.pending.drain(..offset);
        output
    }
}

impl Redactor {
    pub fn new(secrets: &[Zeroizing<String>]) -> Self {
        let mut redactor = Self {
            patterns: Vec::new(),
            pending: Zeroizing::new(Vec::new()),
        };
        redactor.extend(secrets);
        redactor
    }

    /// Adds secrets before they can reach a long-lived stream. Existing pending bytes remain
    /// private and are reconsidered against the expanded pattern set.
    pub fn extend(&mut self, secrets: &[Zeroizing<String>]) {
        for secret in secrets {
            if secret.is_empty() {
                continue;
            }
            self.patterns.push(Zeroizing::new(secret.as_bytes().to_vec()));
            self.patterns.push(Zeroizing::new(
                secret.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ));
            self.patterns.push(Zeroizing::new(
                secret.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            ));
            let escaped = Zeroizing::new(
                serde_json::to_string(secret.as_str()).expect("string serialization"),
            );
            self.patterns.push(Zeroizing::new(
                escaped.as_bytes()[1..escaped.len() - 1].to_vec(),
            ));
            // Percent encoding preserves the case of unescaped characters.
            let mut encoded = Zeroizing::new(String::new());
            let mut encoded_lower = Zeroizing::new(String::new());
            for byte in secret.bytes() {
                use std::fmt::Write as _;
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    encoded.push(char::from(byte));
                    encoded_lower.push(char::from(byte));
                } else {
                    write!(encoded, "%{byte:02X}").expect("string formatting");
                    write!(encoded_lower, "%{byte:02x}").expect("string formatting");
                }
            }
            self.patterns
                .push(Zeroizing::new(encoded.as_bytes().to_vec()));
            self.patterns
                .push(Zeroizing::new(encoded_lower.as_bytes().to_vec()));
        }
        self.patterns
            .sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        self.patterns.dedup();
    }

    pub fn feed(&mut self, bytes: &[u8], final_chunk: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < self.pending.len() {
            let remaining = &self.pending[offset..];
            // A longer, incomplete match takes precedence over a shorter complete secret.
            if !final_chunk
                && self
                    .patterns
                    .iter()
                    .any(|p| p.len() > remaining.len() && p.starts_with(remaining))
            {
                break;
            }
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|p| remaining.starts_with(p.as_slice()))
            {
                output.extend_from_slice(b"[REDACTED]");
                offset += pattern.len();
            } else if final_chunk && self.patterns.iter().any(|p| p.starts_with(remaining)) {
                // Even an unfinished echo at EOF must not expose a prefix of a secret.
                output.extend_from_slice(b"[REDACTED]");
                offset = self.pending.len();
            } else {
                output.push(self.pending[offset]);
                offset += 1;
            }
        }
        let tail = Zeroizing::new(self.pending[offset..].to_vec());
        self.pending.clear();
        self.pending.extend_from_slice(&tail);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_split_and_encoding_is_filtered_before_decoding() {
        let secrets = vec![Zeroizing::new("密码 a&\"Z".to_owned())];
        let prototype = Redactor::new(&secrets);
        for pattern in &prototype.patterns {
            for split in 0..=pattern.len() {
                let mut redactor = Redactor::new(&secrets);
                let mut result = redactor.feed(&pattern[..split], false);
                result.extend(redactor.feed(&pattern[split..], true));
                assert_eq!(result, b"[REDACTED]");
            }
        }
    }

    #[test]
    fn overlapping_secrets_and_incomplete_echo_do_not_leak() {
        let mut redactor = Redactor::new(&[
            Zeroizing::new("abc".into()),
            Zeroizing::new("abcdef".into()),
        ]);
        assert!(redactor.feed(b"abc", false).is_empty());
        assert_eq!(redactor.feed(b"def!", false), b"[REDACTED]!");
        assert!(redactor.feed(b"ab", false).is_empty());
        assert_eq!(redactor.feed(b"", true), b"[REDACTED]");
    }

    #[test]
    fn long_lived_stream_accepts_new_secrets_without_releasing_pending_bytes() {
        let mut redactor = Redactor::new(&[]);
        assert_eq!(redactor.feed(b"ordinary\n", false), b"ordinary\n");
        redactor.extend(&[Zeroizing::new("later-secret".into())]);
        assert!(redactor.feed(b"later-", false).is_empty());
        assert_eq!(redactor.feed(b"secret\n", false), b"[REDACTED]\n");
        assert_eq!(redactor.feed(b"still ordinary", true), b"still ordinary");
    }

    #[test]
    fn utf8_decoder_preserves_chinese_split_at_every_byte() {
        let text = "程序输出：宝宝，完成啦！";
        for split in 0..=text.len() {
            let mut decoder = Utf8Decoder::default();
            let mut result = decoder.feed(&text.as_bytes()[..split], false);
            result.push_str(&decoder.feed(&text.as_bytes()[split..], true));
            assert_eq!(result, text);
        }
    }
}
