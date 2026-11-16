// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HIP API filtering — per-sandbox allow/deny lists by API category.
//!
//! Not enforced yet: the filter is not passed to the worker, so HIP calls are
//! not filtered (including the default IPC/context denials), and
//! `gpu.allowed_apis` / `gpu.denied_apis` are rejected by policy validation
//! when the GPU is enabled.

use crate::protocol::ApiCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// GPU access policy from the sandbox YAML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuPolicy {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub device: u32,

    #[serde(default = "default_transport")]
    pub transport: GpuTransport,

    #[serde(default)]
    pub vram_limit_mb: Option<u64>,

    #[serde(default)]
    pub compute_timeout_sec: Option<u64>,

    #[serde(default)]
    pub allowed_apis: Vec<ApiCategory>,

    #[serde(default)]
    pub denied_apis: Vec<ApiCategory>,
}

fn default_transport() -> GpuTransport {
    GpuTransport::Tcp
}

/// Worker transport. Only TCP is implemented; see the crate docs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuTransport {
    Uds,
    #[default]
    Tcp,
}

/// API filter that checks whether an opcode category is permitted.
pub struct ApiFilter {
    allowed: HashSet<ApiCategory>,
    denied: HashSet<ApiCategory>,
}

/// Default allowed categories (everything except IPC, peer access, device reset).
const DEFAULT_ALLOWED: &[ApiCategory] = &[
    ApiCategory::Connection,
    ApiCategory::DeviceManagement,
    ApiCategory::MemoryAlloc,
    ApiCategory::MemoryTransfer,
    ApiCategory::MemorySet,
    ApiCategory::MemoryInfo,
    ApiCategory::MemoryPools,
    ApiCategory::HostMemory,
    ApiCategory::UnifiedMemory,
    ApiCategory::Streams,
    ApiCategory::Events,
    ApiCategory::Modules,
    ApiCategory::KernelLaunch,
    ApiCategory::FunctionAttrs,
    ApiCategory::Occupancy,
    ApiCategory::Graphs,
    ApiCategory::ErrorHandling,
    ApiCategory::RuntimeInfo,
];

/// Default denied categories (security-sensitive).
const DEFAULT_DENIED: &[ApiCategory] = &[
    ApiCategory::Ipc,     // cross-sandbox GPU memory sharing
    ApiCategory::Context, // deprecated, can interfere with other sandboxes
];

impl ApiFilter {
    /// Create a filter from a GPU policy.
    pub fn from_policy(policy: &GpuPolicy) -> Self {
        let allowed: HashSet<ApiCategory> = if policy.allowed_apis.is_empty() {
            DEFAULT_ALLOWED.iter().copied().collect()
        } else {
            policy.allowed_apis.iter().copied().collect()
        };

        let mut denied: HashSet<ApiCategory> = DEFAULT_DENIED.iter().copied().collect();
        for cat in &policy.denied_apis {
            denied.insert(*cat);
        }

        Self { allowed, denied }
    }

    /// Check if an API category is permitted.
    pub fn is_allowed(&self, category: ApiCategory) -> bool {
        if self.denied.contains(&category) {
            return false;
        }
        self.allowed.contains(&category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_allows_malloc() {
        let policy = GpuPolicy {
            enabled: true,
            ..Default::default()
        };
        let filter = ApiFilter::from_policy(&policy);
        assert!(filter.is_allowed(ApiCategory::MemoryAlloc));
        assert!(filter.is_allowed(ApiCategory::KernelLaunch));
        assert!(filter.is_allowed(ApiCategory::Streams));
    }

    #[test]
    fn default_filter_denies_ipc() {
        let policy = GpuPolicy {
            enabled: true,
            ..Default::default()
        };
        let filter = ApiFilter::from_policy(&policy);
        assert!(!filter.is_allowed(ApiCategory::Ipc));
        assert!(!filter.is_allowed(ApiCategory::Context));
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let policy = GpuPolicy {
            enabled: true,
            denied_apis: vec![ApiCategory::KernelLaunch],
            ..Default::default()
        };
        let filter = ApiFilter::from_policy(&policy);
        assert!(!filter.is_allowed(ApiCategory::KernelLaunch));
        assert!(filter.is_allowed(ApiCategory::MemoryAlloc)); // still allowed
    }

    #[test]
    fn explicit_allow_list() {
        let policy = GpuPolicy {
            enabled: true,
            allowed_apis: vec![ApiCategory::MemoryAlloc, ApiCategory::MemoryTransfer],
            ..Default::default()
        };
        let filter = ApiFilter::from_policy(&policy);
        assert!(filter.is_allowed(ApiCategory::MemoryAlloc));
        assert!(filter.is_allowed(ApiCategory::MemoryTransfer));
        assert!(!filter.is_allowed(ApiCategory::KernelLaunch)); // not in explicit list
    }
}
