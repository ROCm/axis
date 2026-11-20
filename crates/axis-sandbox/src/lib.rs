// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AXIS Sandbox — OS-specific process isolation.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(all(test, not(target_os = "macos")))]
#[path = "macos/profile.rs"]
mod macos_profile_tests;

#[cfg(target_os = "windows")]
pub mod windows;

pub mod workspace;

mod sandbox;
pub use sandbox::{Sandbox, SandboxConfig, SandboxError, StartupTrace};

#[cfg(test)]
pub(crate) mod test_support {
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    pub(crate) fn with_home<T>(home: &Path, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        struct EnvGuard {
            home: Option<OsString>,
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                // SAFETY: tests that mutate HOME must use this helper, which serializes
                // access with ENV_LOCK and restores the previous value before releasing it.
                unsafe {
                    match &self.home {
                        Some(value) => std::env::set_var("HOME", value),
                        None => std::env::remove_var("HOME"),
                    }
                }
            }
        }

        let previous = std::env::var_os("HOME");
        // SAFETY: guarded by ENV_LOCK; see EnvGuard::drop for the paired restore.
        unsafe {
            std::env::set_var("HOME", home);
        }
        let _env_guard = EnvGuard { home: previous };

        f()
    }
}
