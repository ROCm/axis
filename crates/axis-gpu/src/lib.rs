// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS GPU — HIP Remote para-virtual GPU isolation.
//!
//! Provides sandboxed GPU access by proxying HIP API calls from the sandbox
//! to a per-sandbox worker process that holds the real GPU context.
//!
//! For any policy that passes validation, the worker is passed only
//! `-d <device>` and `-p <port>`, and the client is pointed at 127.0.0.1. The
//! API filter, VRAM quota tracker, compute-timeout handling, and Unix-socket
//! endpoint in this crate are not wired to the worker yet, so they enforce
//! nothing; policy validation in `axis-core` rejects the policy fields that
//! would request them.

pub mod api_filter;
pub mod protocol;
pub mod transport;
pub mod vram_quota;
pub mod worker_mgr;
