// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! OCSF-structured audit event emitter.
//!
//! Events follow the Open Cybersecurity Schema Framework for structured
//! security telemetry. Each event is self-contained and can be emitted
//! to file, syslog, or a structured log sink.

use crate::types::{PolicyDecision, SandboxId};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// OCSF activity categories used by AXIS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    SandboxLifecycle,
    NetworkActivity,
    PolicyDecision,
    InferenceActivity,
    SecurityFinding,
}

/// Severity levels for audit events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A structured OCSF audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: Timestamp,
    pub category: EventCategory,
    pub severity: Severity,
    pub sandbox_id: Option<SandboxId>,
    pub message: String,
    pub details: serde_json::Value,
}

/// Structured details for a kernel-rejected network bypass attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkBypassDetails {
    #[serde(serialize_with = "serialize_timestamp")]
    pub observed_at: Timestamp,
    pub source: Option<String>,
    pub destination: String,
    pub protocol: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
    pub policy_context: String,
}

/// Writes RFC 3339 in UTC with nine fractional digits, so timestamps keep a
/// fixed width and sort correctly as text.
fn serialize_timestamp<S: serde::Serializer>(
    timestamp: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{timestamp:.9}"))
}

impl AuditEvent {
    pub fn new(
        category: EventCategory,
        severity: Severity,
        sandbox_id: Option<SandboxId>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Timestamp::now(),
            category,
            severity,
            sandbox_id,
            message: message.into(),
            details: serde_json::Value::Null,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Emits audit events to configured sinks.
pub struct AuditLog {
    sinks: Vec<Box<dyn AuditSink>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    pub fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            if let Err(e) = sink.write(event) {
                tracing::error!("audit sink error: {e}");
            }
        }
    }

    // Convenience constructors for common events.

    pub fn sandbox_created(&self, sandbox_id: SandboxId, policy_name: &str) {
        self.emit(&AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(sandbox_id),
            format!("sandbox created with policy '{policy_name}'"),
        ));
    }

    pub fn sandbox_destroyed(&self, sandbox_id: SandboxId) {
        self.emit(&AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(sandbox_id),
            "sandbox destroyed",
        ));
    }

    pub fn network_decision(
        &self,
        sandbox_id: SandboxId,
        host: &str,
        port: u16,
        decision: &PolicyDecision,
    ) {
        let severity = if decision.allowed {
            Severity::Info
        } else {
            Severity::Medium
        };
        let action = if decision.allowed {
            "allowed"
        } else {
            "denied"
        };
        self.emit(
            &AuditEvent::new(
                EventCategory::NetworkActivity,
                severity,
                Some(sandbox_id),
                format!("network connection to {host}:{port} {action}"),
            )
            .with_details(serde_json::to_value(decision).unwrap_or_default()),
        );
    }

    pub fn network_bypass_detected(&self, sandbox_id: SandboxId, details: NetworkBypassDetails) {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            timestamp: details.observed_at,
            category: EventCategory::SecurityFinding,
            severity: Severity::High,
            sandbox_id: Some(sandbox_id),
            message: format!(
                "network bypass attempt to {} rejected by firewall",
                details.destination
            ),
            details: serde_json::to_value(details).unwrap_or_default(),
        };
        self.emit(&event);
    }

    pub fn credential_leak_detected(&self, sandbox_id: SandboxId, pattern: &str) {
        self.emit(&AuditEvent::new(
            EventCategory::SecurityFinding,
            Severity::High,
            Some(sandbox_id),
            format!("credential leak detected: {pattern}"),
        ));
    }

    pub fn inference_budget_denied(&self, sandbox_id: SandboxId, reason: &str) {
        self.emit(&AuditEvent::new(
            EventCategory::InferenceActivity,
            Severity::Medium,
            Some(sandbox_id),
            format!("inference token budget denied request: {reason}"),
        ));
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for audit event output sinks.
pub trait AuditSink: Send + Sync {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>>;
}

/// Writes audit events as JSON lines to a tracing span.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(event)?;
        tracing::info!(target: "axis::audit", "{json}");
        Ok(())
    }
}

/// Broadcasts audit events to a tokio broadcast channel.
/// Used by the gateway to stream events to WebSocket clients.
pub struct BroadcastSink {
    tx: tokio::sync::broadcast::Sender<AuditEvent>,
}

impl BroadcastSink {
    pub fn new(tx: tokio::sync::broadcast::Sender<AuditEvent>) -> Self {
        Self { tx }
    }
}

impl AuditSink for BroadcastSink {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        // Ignore send errors (no subscribers is not an error).
        let _ = self.tx.send(event.clone());
        Ok(())
    }
}

/// Writes audit events as JSON lines to a file.
pub struct FileSink {
    path: std::path::PathBuf,
}

impl FileSink {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl AuditSink for FileSink {
    fn write(&self, event: &AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(event)?;
        writeln!(file, "{json}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn create_and_serialize_event() {
        let event = AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            Some(SandboxId::new()),
            "test event",
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("test event"));
        assert!(json.contains("sandbox_lifecycle"));
    }

    #[test]
    fn timestamp_serializes_as_fixed_width_rfc3339_utc() {
        let mut event = AuditEvent::new(
            EventCategory::SandboxLifecycle,
            Severity::Info,
            None,
            "test event",
        );
        for (nanos, expected) in [
            (0, "2026-11-18T11:06:40.000000000Z"),
            (120_000_000, "2026-11-18T11:06:40.120000000Z"),
            (123_456_789, "2026-11-18T11:06:40.123456789Z"),
        ] {
            event.timestamp = Timestamp::new(1_795_000_000, nanos).unwrap();
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(json["timestamp"], expected);
            let parsed: AuditEvent = serde_json::from_value(json).unwrap();
            assert_eq!(parsed.timestamp, event.timestamp);
        }

        // Existing audit logs drop the fraction, or shorten it to 3 or 6
        // digits, when it ends in zeros.
        for (old, nanos) in [
            ("2026-11-18T11:06:40Z", 0),
            ("2026-11-18T11:06:40.120Z", 120_000_000),
            ("2026-11-18T11:06:40.123456Z", 123_456_000),
        ] {
            let mut json = serde_json::to_value(&event).unwrap();
            json["timestamp"] = old.into();
            let parsed: AuditEvent = serde_json::from_value(json).unwrap();
            assert_eq!(
                parsed.timestamp,
                Timestamp::new(1_795_000_000, nanos).unwrap()
            );
        }
    }

    #[test]
    fn audit_log_with_tracing_sink() {
        let mut log = AuditLog::new();
        log.add_sink(Box::new(TracingSink));
        log.sandbox_created(SandboxId::new(), "test-policy");
        // No panic = success (tracing subscriber not installed in test, that's fine)
    }

    #[test]
    fn network_bypass_detected_emits_structured_security_finding() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut log = AuditLog::new();
        log.add_sink(Box::new(CapturingSink {
            events: events.clone(),
        }));
        let sandbox_id =
            SandboxId(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap());
        let observed_at = Timestamp::new(1_795_000_000, 120_000_000).unwrap();

        log.network_bypass_detected(
            sandbox_id,
            NetworkBypassDetails {
                observed_at,
                source: Some("10.0.0.2".into()),
                destination: "203.0.113.7".into(),
                protocol: "TCP".into(),
                source_port: Some(43100),
                destination_port: Some(443),
                input_interface: None,
                output_interface: Some("axs000000000000".into()),
                policy_context: "iptables OUTPUT LOG+REJECT".into(),
            },
        );

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(matches!(event.category, EventCategory::SecurityFinding));
        assert!(matches!(event.severity, Severity::High));
        assert_eq!(event.sandbox_id, Some(sandbox_id));
        assert_eq!(event.timestamp, observed_at);
        assert_eq!(
            event.details["observed_at"],
            "2026-11-18T11:06:40.120000000Z"
        );
        assert!(event.message.contains("203.0.113.7"));
        assert_eq!(event.details["destination"], "203.0.113.7");
        assert_eq!(event.details["destination_port"], 443);
        assert_eq!(
            event.details["policy_context"],
            "iptables OUTPUT LOG+REJECT"
        );
    }
}
