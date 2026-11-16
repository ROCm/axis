// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows isolation components.
//!
//! Process-containment launches are intentionally routed through the MXC
//! adapter. The modules below provide supporting Windows primitives and do not
//! form an implicit host-process fallback.

pub mod acl;
pub mod appcontainer;
pub mod etw;
pub mod job_object;
pub(crate) mod mxc;
pub mod restricted;
