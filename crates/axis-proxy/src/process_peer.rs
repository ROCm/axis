// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Peer authentication for a proxy that listens on host loopback.
//!
//! Rootless MXC strict proxy reaches the proxy through slirp4netns, so the
//! client is a host loopback socket rather than a per-sandbox veth address.
//! A connection is accepted only when its client socket is held by the
//! sandbox executor or one of its descendants. Linux only; fails closed.
//! Each check reads `/proc/net/tcp` and every `/proc/<pid>/stat`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ROOT_WAIT: Duration = Duration::from_secs(5);
const MAX_ANCESTRY_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy)]
struct Root {
    pid: u32,
    start_time: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SandboxProcessPeer {
    root: Arc<Mutex<Option<Root>>>,
}

impl SandboxProcessPeer {
    /// Register the sandbox executor once it has started.
    pub fn set_root(&self, pid: u32) {
        let start_time = process_stat(Path::new("/proc"), pid).map(|(_, start)| start);
        *self.root.lock().unwrap() = Some(Root { pid, start_time });
    }

    pub fn verify(&self, peer: SocketAddr, proxy: SocketAddr) -> Result<(), String> {
        // The sandbox can connect before the launcher has registered it.
        let deadline = Instant::now() + ROOT_WAIT;
        let root = loop {
            if let Some(root) = *self.root.lock().unwrap() {
                break root;
            }
            if Instant::now() >= deadline {
                return Err("no sandbox process is registered".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        verify_in(Path::new("/proc"), root, peer, proxy)
    }
}

fn verify_in(
    proc_root: &Path,
    root: Root,
    peer: SocketAddr,
    proxy: SocketAddr,
) -> Result<(), String> {
    let inode = socket_inode(proc_root, peer, proxy)
        .ok_or_else(|| format!("no client socket found for {peer}"))?;
    let link = format!("socket:[{inode}]");

    let processes: HashMap<u32, (u32, u64)> = std::fs::read_dir(proc_root)
        .map_err(|e| format!("cannot read {}: {e}", proc_root.display()))?
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .filter_map(|pid| Some((pid, process_stat(proc_root, pid)?)))
        .collect();

    // Start times are compared again after the scan so a recycled PID cannot
    // stand in for the executor or for the process holding the socket.
    let unchanged =
        |pid: u32, start: u64| process_stat(proc_root, pid).is_some_and(|(_, now)| now == start);
    let holder = processes.iter().find(|(pid, _)| {
        descends_from(&processes, **pid, root.pid) && holds_socket(proc_root, **pid, &link)
    });
    match (holder, root.start_time) {
        (Some((pid, (_, start))), Some(root_start))
            if unchanged(*pid, *start) && unchanged(root.pid, root_start) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "client socket for {peer} is not held by sandbox process {}",
            root.pid
        )),
    }
}

/// Inode of the established socket `peer -> proxy` in this network namespace.
fn socket_inode(proc_root: &Path, peer: SocketAddr, proxy: SocketAddr) -> Option<u64> {
    let (peer, proxy) = (proc_net_addr(peer)?, proc_net_addr(proxy)?);
    let table = std::fs::read_to_string(proc_root.join("net/tcp")).ok()?;
    table
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.len() > 9 && fields[1] == peer && fields[2] == proxy)
        .and_then(|fields| fields[9].parse().ok())
        .filter(|inode| *inode != 0)
}

fn proc_net_addr(addr: SocketAddr) -> Option<String> {
    let IpAddr::V4(ip) = addr.ip() else {
        return None;
    };
    Some(format!(
        "{:08X}:{:04X}",
        u32::from_ne_bytes(ip.octets()),
        addr.port()
    ))
}

/// Parent PID and start time from `/proc/<pid>/stat`.
fn process_stat(proc_root: &Path, pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    // The command name may contain spaces and parentheses.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let parent = fields.nth(1)?.parse().ok()?;
    let start_time = fields.nth(17)?.parse().ok()?;
    Some((parent, start_time))
}

fn descends_from(processes: &HashMap<u32, (u32, u64)>, mut pid: u32, root: u32) -> bool {
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if pid == root {
            return true;
        }
        match processes.get(&pid) {
            Some((parent, _)) => pid = *parent,
            None => return false,
        }
    }
    false
}

fn holds_socket(proc_root: &Path, pid: u32, link: &str) -> bool {
    std::fs::read_dir(proc_root.join(pid.to_string()).join("fd"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|target| target.as_os_str() == link))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn add_process(proc_root: &Path, pid: u32, parent: u32, socket: Option<u64>) {
        let dir = proc_root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        let rest = "0 ".repeat(17);
        std::fs::write(
            dir.join("stat"),
            format!("{pid} (a b) c) S {parent} {rest}{}", 1000 + pid),
        )
        .unwrap();
        if let Some(inode) = socket {
            std::os::unix::fs::symlink(format!("socket:[{inode}]"), dir.join("fd/7")).unwrap();
        }
    }

    #[test]
    fn accepts_only_sockets_held_by_the_sandbox_process_tree() {
        let proc_dir = tempfile::tempdir().unwrap();
        let proc_root = proc_dir.path();
        let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let inside: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let outside: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::write(
            proc_root.join("net/tcp"),
            "header\n\
             0: 0100007F:9C40 0100007F:1F90 01 0 0 0 0 0 501\n\
             1: 0100007F:9C41 0100007F:1F90 01 0 0 0 0 0 502\n",
        )
        .unwrap();
        add_process(proc_root, 10, 1, None);
        add_process(proc_root, 11, 10, None);
        add_process(proc_root, 12, 11, Some(501));
        add_process(proc_root, 20, 1, Some(502));

        let root = Root {
            pid: 10,
            start_time: Some(1010),
        };
        assert_eq!(verify_in(proc_root, root, inside, proxy), Ok(()));
        assert!(verify_in(proc_root, root, outside, proxy).is_err());
        assert!(verify_in(proc_root, root, "127.0.0.1:40002".parse().unwrap(), proxy).is_err());

        // A different process now owns the executor's PID.
        let recycled = Root {
            pid: 10,
            start_time: Some(1),
        };
        assert!(verify_in(proc_root, recycled, inside, proxy).is_err());
        let unknown = Root {
            pid: 10,
            start_time: None,
        };
        assert!(verify_in(proc_root, unknown, inside, proxy).is_err());
    }
}
