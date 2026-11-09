// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Core — policy model, OPA engine, audit events, and shared types.

pub mod audit;
pub mod backend_defaults;
pub mod backend_evidence;
pub mod bench;
pub mod capability;
pub mod capability_map;
pub mod connect_attribution;
pub mod container_backend;
pub mod daemon_auth;
pub mod mxc_config;
pub mod opa;
pub mod policy;
pub mod process_backend;
pub mod sandbox_env;
pub mod types;
pub mod vm_backend;
