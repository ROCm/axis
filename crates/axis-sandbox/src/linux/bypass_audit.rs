// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Linux firewall bypass audit parsing.
//!
//! Enforcement is the namespace firewall's `REJECT` rule. This module only
//! turns matching kernel `LOG` records into structured AXIS audit events, so a
//! malformed or unreadable log source must never make direct egress permissive.

use axis_core::audit::{AuditLog, NetworkBypassDetails};
use axis_core::types::SandboxId;
use jiff::Timestamp;
use std::collections::HashMap;
use std::io::{self, BufRead};

pub const BYPASS_LOG_MARKER: &str = "AXIS-BYPASS:";
pub const BYPASS_LOG_TOKEN_LEN: usize = 16;
pub const IPTABLES_LOG_PREFIX_LIMIT: usize = 29;
const POLICY_CONTEXT: &str = "iptables OUTPUT LOG+REJECT";
const MAX_LOG_FIELD_LEN: usize = 128;

/// One parsed firewall bypass record correlated to a known sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassLogRecord {
    pub sandbox_id: SandboxId,
    pub token: String,
    pub details: NetworkBypassDetails,
}

/// A sandbox-correlated token short enough for iptables' log-prefix limit.
pub fn bypass_log_token(sandbox_id: SandboxId) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in sandbox_id.0.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The exact iptables LOG prefix used for direct egress attempts.
pub fn bypass_log_prefix(sandbox_id: SandboxId) -> String {
    let prefix = format!("{BYPASS_LOG_MARKER}{} ", bypass_log_token(sandbox_id));
    debug_assert!(prefix.len() <= IPTABLES_LOG_PREFIX_LIMIT);
    prefix
}

pub fn token_map_for_sandbox(sandbox_id: SandboxId) -> HashMap<String, SandboxId> {
    let mut tokens = HashMap::new();
    tokens.insert(bypass_log_token(sandbox_id), sandbox_id);
    tokens
}

pub fn parse_bypass_log_line(
    line: &str,
    active_tokens: &HashMap<String, SandboxId>,
) -> Option<BypassLogRecord> {
    let message = bypass_log_message(line)?;
    let token_start = BYPASS_LOG_MARKER.len();
    let token_end = token_start + BYPASS_LOG_TOKEN_LEN;
    let token = message.get(token_start..token_end)?;
    if !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if !message
        .get(token_end..)
        .and_then(|tail| tail.chars().next())
        .is_some_and(char::is_whitespace)
    {
        return None;
    }

    let sandbox_id = *active_tokens.get(token)?;
    let fields = parse_log_fields(&message[token_end..])?;
    let destination = required_field(&fields, "DST")?;
    let protocol = required_field(&fields, "PROTO")?.to_ascii_uppercase();
    let source_port = optional_port(&fields, "SPT")?;
    let destination_port = optional_port(&fields, "DPT")?;

    Some(BypassLogRecord {
        sandbox_id,
        token: token.to_string(),
        details: NetworkBypassDetails {
            observed_at: Timestamp::now(),
            source: optional_field(&fields, "SRC"),
            destination,
            protocol,
            source_port,
            destination_port,
            input_interface: optional_field(&fields, "IN"),
            output_interface: optional_field(&fields, "OUT"),
            policy_context: POLICY_CONTEXT.into(),
        },
    })
}

fn bypass_log_message(line: &str) -> Option<&str> {
    if line.starts_with(BYPASS_LOG_MARKER) {
        return Some(line);
    }

    let (header, message) = line.split_once(';')?;
    if valid_kmsg_header(header) && message.starts_with(BYPASS_LOG_MARKER) {
        Some(message)
    } else {
        None
    }
}

fn valid_kmsg_header(header: &str) -> bool {
    let mut parts = header.split(',');
    let Some(priority) = parts.next().and_then(|part| part.parse::<u16>().ok()) else {
        return false;
    };
    if priority > 15 {
        return false;
    }
    if parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .is_none()
    {
        return false;
    }
    if parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .is_none()
    {
        return false;
    }
    let Some(flags) = parts.next() else {
        return false;
    };
    !flags.is_empty() && parts.next().is_none()
}

/// Parse all immediately available bypass events from a bounded reader.
pub fn collect_available_bypass_events<R: BufRead>(
    reader: &mut R,
    active_tokens: &HashMap<String, SandboxId>,
    audit_log: &AuditLog,
) -> io::Result<Vec<BypassLogRecord>> {
    let mut records = Vec::new();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(record) = parse_bypass_log_line(&line, active_tokens) {
                    audit_log.network_bypass_detected(record.sandbox_id, record.details.clone());
                    records.push(record);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }

    Ok(records)
}

#[cfg(target_os = "linux")]
pub fn open_kernel_log_source() -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/kmsg")
}

#[cfg(target_os = "linux")]
pub fn collect_available_kernel_bypass_events(
    active_tokens: &HashMap<String, SandboxId>,
    audit_log: &AuditLog,
) -> io::Result<Vec<BypassLogRecord>> {
    let file = open_kernel_log_source()?;
    let mut reader = std::io::BufReader::new(file);
    collect_available_bypass_events(&mut reader, active_tokens, audit_log)
}

fn parse_log_fields(text: &str) -> Option<HashMap<&str, &str>> {
    let mut fields = HashMap::new();
    for field in text.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        if fields.insert(key, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

fn required_field(fields: &HashMap<&str, &str>, key: &str) -> Option<String> {
    optional_field(fields, key)
}

fn optional_field(fields: &HashMap<&str, &str>, key: &str) -> Option<String> {
    let value = *fields.get(key)?;
    if value.is_empty()
        || value.len() > MAX_LOG_FIELD_LEN
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    Some(value.to_string())
}

fn optional_port(fields: &HashMap<&str, &str>, key: &str) -> Option<Option<u16>> {
    let Some(value) = fields.get(key).copied() else {
        return Some(None);
    };
    if value.is_empty() {
        return Some(None);
    }
    value.parse::<u16>().ok().map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axis_core::audit::{AuditEvent, AuditSink, EventCategory, Severity};
    use std::sync::{Arc, Mutex};

    struct CapturingSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for CapturingSink {
        fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn bypass_prefix_fits_iptables_limit_and_is_sandbox_specific() {
        let first: SandboxId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let second: SandboxId = "00000000-0000-4000-8000-000000000002".parse().unwrap();

        let first_prefix = bypass_log_prefix(first);
        let second_prefix = bypass_log_prefix(second);

        assert_ne!(first_prefix, second_prefix);
        assert!(first_prefix.starts_with(BYPASS_LOG_MARKER));
        assert_eq!(bypass_log_token(first).len(), BYPASS_LOG_TOKEN_LEN);
        assert!(
            bypass_log_token(first)
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert!(first_prefix.len() <= IPTABLES_LOG_PREFIX_LIMIT);
        assert!(first_prefix.ends_with(' '));
    }

    #[test]
    fn parses_kernel_iptables_log_for_known_token() {
        let sandbox_id: SandboxId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let tokens = token_map_for_sandbox(sandbox_id);
        let line = format!(
            "4,99,123456,-;{}IN= OUT=axs000000000 SRC=10.9.0.2 DST=203.0.113.7 LEN=60 PROTO=TCP SPT=43100 DPT=443",
            bypass_log_prefix(sandbox_id)
        );

        let record = parse_bypass_log_line(&line, &tokens).unwrap();

        assert_eq!(record.sandbox_id, sandbox_id);
        assert_eq!(record.token, bypass_log_token(sandbox_id));
        assert_eq!(record.details.source.as_deref(), Some("10.9.0.2"));
        assert_eq!(record.details.destination, "203.0.113.7");
        assert_eq!(record.details.protocol, "TCP");
        assert_eq!(record.details.source_port, Some(43100));
        assert_eq!(record.details.destination_port, Some(443));
        assert_eq!(record.details.input_interface, None);
        assert_eq!(
            record.details.output_interface.as_deref(),
            Some("axs000000000")
        );
        assert_eq!(record.details.policy_context, POLICY_CONTEXT);
    }

    #[test]
    fn ignores_unknown_tokens_and_unrelated_logs() {
        let sandbox_id: SandboxId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let tokens = token_map_for_sandbox(sandbox_id);
        let embedded_marker = format!(
            "7,42,1000,-;driver message mentions {}OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=443",
            bypass_log_prefix(sandbox_id)
        );
        let malformed_kmsg_header = format!(
            "driver;{}OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=443",
            bypass_log_prefix(sandbox_id)
        );

        assert!(parse_bypass_log_line("kernel: unrelated", &tokens).is_none());
        assert!(parse_bypass_log_line(&embedded_marker, &tokens).is_none());
        assert!(parse_bypass_log_line(&malformed_kmsg_header, &tokens).is_none());
        assert!(
            parse_bypass_log_line(
                "AXIS-BYPASS:ffffffffffffffff OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=443",
                &tokens,
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_malformed_log_records() {
        let sandbox_id: SandboxId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let tokens = token_map_for_sandbox(sandbox_id);
        let prefix = bypass_log_prefix(sandbox_id);

        for line in [
            format!("{prefix}OUT=eth0 DST=203.0.113.7 DPT=443"),
            format!("{prefix}OUT=eth0 PROTO=TCP DPT=443"),
            format!("{prefix}OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=not-a-port"),
            format!("{prefix}OUT=eth0 DST=203.0.113.7 DST=198.51.100.9 PROTO=TCP DPT=443"),
            "AXIS-BYPASS:nothex000000000 OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=443".to_string(),
            format!(
                "{}{}OUT=eth0 DST=203.0.113.7 PROTO=TCP DPT=443",
                BYPASS_LOG_MARKER,
                bypass_log_token(sandbox_id)
            ),
        ] {
            assert!(parse_bypass_log_line(&line, &tokens).is_none(), "{line}");
        }
    }

    #[test]
    fn collect_available_events_emits_audit_and_skips_bad_lines() {
        let sandbox_id: SandboxId = "00000000-0000-4000-8000-000000000001".parse().unwrap();
        let tokens = token_map_for_sandbox(sandbox_id);
        let good = format!(
            "{}OUT=axs SRC=10.0.0.2 DST=198.51.100.10 PROTO=UDP SPT=52000 DPT=53\n",
            bypass_log_prefix(sandbox_id)
        );
        let input = format!(
            "unrelated\n{}OUT=axs DST=198.51.100.11 PROTO=TCP DPT=not-a-port\n{good}",
            bypass_log_prefix(sandbox_id)
        );
        let mut reader = std::io::Cursor::new(input);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut audit_log = AuditLog::new();
        audit_log.add_sink(Box::new(CapturingSink {
            events: events.clone(),
        }));

        let records = collect_available_bypass_events(&mut reader, &tokens, &audit_log).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].details.protocol, "UDP");
        assert_eq!(records[0].details.destination_port, Some(53));

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].category, EventCategory::SecurityFinding));
        assert!(matches!(events[0].severity, Severity::High));
        assert_eq!(events[0].sandbox_id, Some(sandbox_id));
        assert_eq!(events[0].details["destination"], "198.51.100.10");
    }
}
