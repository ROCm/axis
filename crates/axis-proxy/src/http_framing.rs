// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP/1.1 message framing rules shared by the request inspectors.
//!
//! Every place that reads a body length must accept exactly the same values,
//! or one parser can see a different message than another. Keep that rule here.

/// Parse a `Content-Length` field value.
///
/// Optional surrounding spaces and tabs are allowed. The rest must be one or
/// more ASCII digits that fit in a `u64`: no sign, no list such as `4, 4`, and
/// no empty value (RFC 9110 section 8.6).
pub(crate) fn parse_content_length(value: &[u8]) -> Option<u64> {
    let value = trim_optional_whitespace(value);
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// Trim only the optional whitespace HTTP defines: space and horizontal tab.
fn trim_optional_whitespace(value: &[u8]) -> &[u8] {
    let is_blank = |byte: &u8| matches!(byte, b' ' | b'\t');
    let start = value
        .iter()
        .position(|byte| !is_blank(byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_blank(byte))
        .map_or(start, |last| last + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_accepts_only_plain_digits() {
        assert_eq!(parse_content_length(b"0"), Some(0));
        assert_eq!(parse_content_length(b"0004"), Some(4));
        assert_eq!(parse_content_length(b" \t12 \t"), Some(12));
        assert_eq!(
            parse_content_length(b"18446744073709551615"),
            Some(u64::MAX)
        );
    }

    #[test]
    fn content_length_rejects_everything_else() {
        for value in [
            b"".as_slice(),
            b"  ",
            b"+4",
            b"-1",
            b"4, 4",
            b"4 4",
            b"0x10",
            b"4\x0b",
            b"\xc2\xa04",
            b"18446744073709551616",
        ] {
            assert_eq!(
                parse_content_length(value),
                None,
                "{}",
                String::from_utf8_lossy(value)
            );
        }
    }
}
