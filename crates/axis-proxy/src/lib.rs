// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Proxy — HTTP proxy with policy enforcement: CONNECT tunnels and
//! forwarded absolute-form `http://` requests.

mod http_framing;
pub mod identity;
pub mod l7;
pub mod proxy;
pub mod secrets;
