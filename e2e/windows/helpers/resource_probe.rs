// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::convert::TryFrom;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::{self, Command};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.first().map(String::as_str) {
        Some("allocate") => allocate(&args[1..]),
        Some("spawn-allocate") => spawn_allocate(&args[1..]),
        Some("hold") => hold(&args[1..]),
        Some("spawn-hold") => spawn_hold(&args[1..]),
        Some("burn") => burn(&args[1..]),
        _ => Err("usage: resource-probe <allocate|spawn-allocate|hold|spawn-hold|burn> ...".into()),
    };
    if let Err(err) = result {
        eprintln!("resource probe: {err}");
        process::exit(2);
    }
}

fn parse_u64(value: Option<&String>, name: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}

fn allocate(args: &[String]) -> Result<(), String> {
    let megabytes = parse_u64(args.first(), "megabytes")?;
    let hold_ms = parse_u64(args.get(1), "hold_ms")?;
    let marker = args.get(2).map(PathBuf::from);
    let bytes = usize::try_from(
        megabytes
            .checked_mul(1024 * 1024)
            .ok_or("allocation size overflow")?,
    )
    .map_err(|_| "allocation does not fit usize")?;
    let mut allocation = Vec::<u8>::new();
    allocation
        .try_reserve_exact(bytes)
        .map_err(|err| format!("allocation failed: {err}"))?;
    allocation.resize(bytes, 0);
    for offset in (0..bytes).step_by(4096) {
        allocation[offset] = 0xA5;
    }
    black_box(&allocation);
    if let Some(marker) = marker {
        fs::write(marker, b"allocated").map_err(|err| err.to_string())?;
    }
    thread::sleep(Duration::from_millis(hold_ms));
    Ok(())
}

fn spawn_allocate(args: &[String]) -> Result<(), String> {
    let count = parse_u64(args.first(), "count")?;
    let megabytes = parse_u64(args.get(1), "megabytes")?;
    let hold_ms = parse_u64(args.get(2), "hold_ms")?;
    let marker_dir = PathBuf::from(args.get(3).ok_or("missing marker_dir")?);
    fs::create_dir_all(&marker_dir).map_err(|err| err.to_string())?;
    let exe = env::current_exe().map_err(|err| err.to_string())?;
    let mut children = Vec::new();
    for index in 0..count {
        let marker = marker_dir.join(format!("allocated-{index}.txt"));
        children.push(
            Command::new(&exe)
                .arg("allocate")
                .arg(megabytes.to_string())
                .arg(hold_ms.to_string())
                .arg(marker)
                .spawn()
                .map_err(|err| format!("spawn allocation child {index}: {err}"))?,
        );
    }
    for mut child in children {
        let status = child.wait().map_err(|err| err.to_string())?;
        if !status.success() {
            return Err(format!("allocation child exited with {status}"));
        }
    }
    Ok(())
}

fn hold(args: &[String]) -> Result<(), String> {
    let marker = PathBuf::from(args.first().ok_or("missing marker")?);
    let hold_ms = parse_u64(args.get(1), "hold_ms")?;
    fs::write(marker, b"started").map_err(|err| err.to_string())?;
    thread::sleep(Duration::from_millis(hold_ms));
    Ok(())
}

fn spawn_hold(args: &[String]) -> Result<(), String> {
    let count = parse_u64(args.first(), "count")?;
    let hold_ms = parse_u64(args.get(1), "hold_ms")?;
    let marker_dir = PathBuf::from(args.get(2).ok_or("missing marker_dir")?);
    fs::create_dir_all(&marker_dir).map_err(|err| err.to_string())?;
    let exe = env::current_exe().map_err(|err| err.to_string())?;
    let mut children = Vec::new();
    for index in 0..count {
        let marker = marker_dir.join(format!("started-{index}.txt"));
        children.push(
            Command::new(&exe)
                .arg("hold")
                .arg(marker)
                .arg(hold_ms.to_string())
                .spawn()
                .map_err(|err| format!("spawn hold child {index}: {err}"))?,
        );
    }
    for mut child in children {
        let status = child.wait().map_err(|err| err.to_string())?;
        if !status.success() {
            return Err(format!("hold child exited with {status}"));
        }
    }
    Ok(())
}

fn burn(args: &[String]) -> Result<(), String> {
    let iterations = parse_u64(args.first(), "iterations")?;
    let started = Instant::now();
    let mut value = 0x9E37_79B9_7F4A_7C15u64;
    for index in 0..iterations {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        value = value.wrapping_add(index);
        black_box(value);
    }
    println!("burn checksum={value} elapsed_ms={}", started.elapsed().as_millis());
    Ok(())
}
