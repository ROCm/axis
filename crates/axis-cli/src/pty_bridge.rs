// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

pub(crate) fn run(socket: PathBuf, command: Vec<String>) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("PTY bridge command must not be empty"))?;

    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("connect PTY bridge socket '{}'", socket.display()))?;
    let mut winsize_stream = UnixStream::connect(winsize_socket_path(&socket)).ok();
    let (rows, cols) = winsize_stream
        .as_mut()
        .and_then(|stream| read_winsize(stream).ok())
        .unwrap_or((24, 80));
    let pty = open_pty(rows, cols).context("open PTY")?;

    let slave_stdin = dup_file(&pty.slave).context("duplicate PTY slave for stdin")?;
    let slave_stdout = dup_file(&pty.slave).context("duplicate PTY slave for stdout")?;
    let slave_stderr = dup_file(&pty.slave).context("duplicate PTY slave for stderr")?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::from(slave_stdin))
        .stdout(Stdio::from(slave_stdout))
        .stderr(Stdio::from(slave_stderr))
        .spawn()
        .with_context(|| format!("spawn bridged command '{program}'"))?;

    drop(pty.slave);

    if let Some(mut winsize_stream) = winsize_stream {
        let master = dup_file(&pty.master).context("duplicate PTY master for resize")?;
        let child_pid = child.id();
        thread::spawn(move || apply_later_resizes(&mut winsize_stream, &master, child_pid));
    }

    let mut socket_to_pty = stream
        .try_clone()
        .context("clone PTY bridge socket for input")?;
    let mut pty_input = pty
        .master
        .try_clone()
        .context("clone PTY master for input")?;
    let input_thread = thread::spawn(move || {
        let _ = io::copy(&mut socket_to_pty, &mut pty_input);
    });

    copy_pty_output(pty.master, &mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = input_thread.join();

    let status = child.wait().context("wait for bridged command")?;
    Ok(status.code().unwrap_or(1))
}

struct PtyFiles {
    master: File,
    slave: File,
}

fn winsize_socket_path(stdio: &Path) -> PathBuf {
    stdio.with_file_name("winsize.sock")
}

fn read_winsize(stream: &mut UnixStream) -> io::Result<(u16, u16)> {
    let mut bytes = [0u8; 4];
    stream.read_exact(&mut bytes)?;
    let rows = u16::from_le_bytes([bytes[0], bytes[1]]);
    let cols = u16::from_le_bytes([bytes[2], bytes[3]]);
    Ok(nonzero_winsize(rows, cols))
}

fn nonzero_winsize(rows: u16, cols: u16) -> (u16, u16) {
    (
        if rows == 0 { 24 } else { rows },
        if cols == 0 { 80 } else { cols },
    )
}

fn apply_later_resizes(stream: &mut UnixStream, master: &File, child_pid: u32) {
    while let Ok((rows, cols)) = read_winsize(stream) {
        resize_pty(master, rows, cols, child_pid);
    }
}

fn resize_pty(master: &File, rows: u16, cols: u16, child_pid: u32) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) };
    if ret == 0 && child_pid > 0 {
        let pid = child_pid as i32;
        unsafe {
            libc::kill(pid, libc::SIGWINCH);
            // The TUI may be the leader of its own process group.
            libc::kill(-pid, libc::SIGWINCH);
        }
    }
}

fn open_pty(rows: u16, cols: u16) -> Result<PtyFiles> {
    let (rows, cols) = nonzero_winsize(rows, cols);
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    #[cfg(target_vendor = "apple")]
    let mut size = size;

    #[cfg(target_vendor = "apple")]
    let size_ptr: *mut libc::winsize = &mut size;
    #[cfg(not(target_vendor = "apple"))]
    let size_ptr: *const libc::winsize = &size;

    let mut master_fd = -1;
    let mut slave_fd = -1;
    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            size_ptr,
        )
    };
    if result < 0 {
        bail!("{}", io::Error::last_os_error());
    }

    set_close_on_exec(master_fd)?;
    set_close_on_exec(slave_fd)?;

    let master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    Ok(PtyFiles { master, slave })
}

fn dup_file(file: &File) -> io::Result<File> {
    file.try_clone()
}

fn set_close_on_exec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!("{}", io::Error::last_os_error());
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        bail!("{}", io::Error::last_os_error());
    }
    Ok(())
}

fn copy_pty_output(mut master: File, stream: &mut UnixStream) {
    let mut buf = [0u8; 8192];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}
