// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! VRAM allocation tracking and quota accounting.
//!
//! Intended design: the worker tracks cumulative hipMalloc allocations per
//! sandbox and rejects allocations that would exceed the policy limit, and
//! hipFree decreases the tracked usage, all server-side.
//!
//! Not enforced yet: nothing records allocations against this tracker, so
//! `gpu.vram_limit_mb` is rejected by policy validation when the GPU is
//! enabled.

use axis_core::types::SandboxId;
use std::collections::HashMap;

/// Tracks VRAM allocations for a single sandbox.
struct VramState {
    limit_bytes: u64,
    used_bytes: u64,
    /// Track individual allocations by device pointer for accurate Free accounting.
    allocations: HashMap<u64, u64>, // device_ptr → size
}

/// Result of a VRAM allocation check.
#[derive(Debug)]
pub enum VramCheck {
    Allowed,
    Denied {
        requested: u64,
        used: u64,
        limit: u64,
    },
}

/// VRAM quota tracker across sandboxes.
pub struct VramTracker {
    sandboxes: HashMap<SandboxId, VramState>,
}

impl VramTracker {
    pub fn new() -> Self {
        Self {
            sandboxes: HashMap::new(),
        }
    }

    /// Register a sandbox with a VRAM limit.
    pub fn register(&mut self, sandbox_id: SandboxId, limit_mb: u64) {
        self.sandboxes.insert(
            sandbox_id,
            VramState {
                limit_bytes: limit_mb * 1024 * 1024,
                used_bytes: 0,
                allocations: HashMap::new(),
            },
        );
        tracing::info!("vram quota: sandbox {sandbox_id} registered with {limit_mb}MB limit");
    }

    /// Remove a sandbox's quota tracker.
    pub fn unregister(&mut self, sandbox_id: &SandboxId) {
        if let Some(state) = self.sandboxes.remove(sandbox_id)
            && state.used_bytes > 0
        {
            tracing::warn!(
                "vram quota: sandbox {sandbox_id} unregistered with {}MB still allocated",
                state.used_bytes / (1024 * 1024),
            );
        }
    }

    /// Check if an allocation is within the quota.
    pub fn check_alloc(&self, sandbox_id: &SandboxId, size_bytes: u64) -> VramCheck {
        let Some(state) = self.sandboxes.get(sandbox_id) else {
            return VramCheck::Allowed; // No quota = unlimited.
        };

        if state.used_bytes + size_bytes > state.limit_bytes {
            VramCheck::Denied {
                requested: size_bytes,
                used: state.used_bytes,
                limit: state.limit_bytes,
            }
        } else {
            VramCheck::Allowed
        }
    }

    /// Record a successful allocation.
    pub fn record_alloc(&mut self, sandbox_id: &SandboxId, device_ptr: u64, size_bytes: u64) {
        if let Some(state) = self.sandboxes.get_mut(sandbox_id) {
            state.used_bytes += size_bytes;
            state.allocations.insert(device_ptr, size_bytes);
        }
    }

    /// Record a free, reducing the quota usage.
    pub fn record_free(&mut self, sandbox_id: &SandboxId, device_ptr: u64) {
        if let Some(state) = self.sandboxes.get_mut(sandbox_id)
            && let Some(size) = state.allocations.remove(&device_ptr)
        {
            state.used_bytes = state.used_bytes.saturating_sub(size);
        }
    }

    /// Get current VRAM usage for a sandbox.
    pub fn usage(&self, sandbox_id: &SandboxId) -> Option<(u64, u64)> {
        self.sandboxes
            .get(sandbox_id)
            .map(|s| (s.used_bytes, s.limit_bytes))
    }
}

impl Default for VramTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_within_limit() {
        let mut tracker = VramTracker::new();
        let id = SandboxId::new();
        tracker.register(id, 1024); // 1GB limit

        let mb100 = 100 * 1024 * 1024;
        assert!(matches!(
            tracker.check_alloc(&id, mb100),
            VramCheck::Allowed
        ));

        tracker.record_alloc(&id, 0xDEAD0000, mb100);
        let (used, limit) = tracker.usage(&id).unwrap();
        assert_eq!(used, mb100);
        assert_eq!(limit, 1024 * 1024 * 1024);
    }

    #[test]
    fn alloc_exceeds_limit() {
        let mut tracker = VramTracker::new();
        let id = SandboxId::new();
        tracker.register(id, 100); // 100MB limit

        let mb90 = 90 * 1024 * 1024;
        let mb20 = 20 * 1024 * 1024;
        tracker.record_alloc(&id, 0x1000, mb90);

        assert!(matches!(
            tracker.check_alloc(&id, mb20),
            VramCheck::Denied { .. }
        ));
    }

    #[test]
    fn free_reduces_usage() {
        let mut tracker = VramTracker::new();
        let id = SandboxId::new();
        tracker.register(id, 100);

        let mb50 = 50 * 1024 * 1024;
        tracker.record_alloc(&id, 0x1000, mb50);
        tracker.record_alloc(&id, 0x2000, mb50);

        let (used, _) = tracker.usage(&id).unwrap();
        assert_eq!(used, 2 * mb50);

        tracker.record_free(&id, 0x1000);
        let (used, _) = tracker.usage(&id).unwrap();
        assert_eq!(used, mb50);
    }

    #[test]
    fn no_quota_means_unlimited() {
        let tracker = VramTracker::new();
        let id = SandboxId::new();
        // Not registered = unlimited.
        assert!(matches!(
            tracker.check_alloc(&id, u64::MAX),
            VramCheck::Allowed
        ));
    }
}
