---
name: axis-e2e
description: Run AXIS on a real Linux host to verify a change end to end - gated real-runtime tests, MXC and native launches, an agent or TUI inside the sandbox, or main against a pull request in the same harness - and report the result. Use when a change touches launch, seccomp, Landlock, MXC, the proxy or policy translation and unit tests are not enough, or when reproducing a runtime issue. Not for the local checks in DEVELOPMENT.md, or for benchmark numbers (docs/runtime-performance-benchmarks.md).
---

# AXIS end to end on a real host

Read these first; they are the source of truth and this skill does not repeat them:

- [docs/security-test-tiers.md](../../../docs/security-test-tiers.md): gated tests, their environment variables, skip rules.
- [docs/linux-setup.md](../../../docs/linux-setup.md): what each backend and network mode needs from the host, and how `auto` picks a backend.
- [docs/runtime-performance-benchmarks.md](../../../docs/runtime-performance-benchmarks.md): numbers for launch-path and proxy changes.

## Scripts

`scripts/` has helpers for the steps below; each prints its usage with `-h`. Run them from an AXIS checkout and keep their output for the report.

- `preflight.sh --require mxc,strace,tty --out host.txt`: records the host and fails when a requirement is missing.
- `build.sh WORK base=origin/main pr=pr-123@origin/main`: builds each revision in its own worktree and target directory, with the `lxc-exec` its `ci.yml` pins, into `WORK/bin/NAME`. It checks the paths AXIS will accept and refuses identical binaries from different commits. `build.sh --clean WORK` removes everything it created.
- `run-tui.sh --axis WORK/bin/pr/axis --policy p.yaml --out runs/pr-1 --expect TEXT -- PROGRAM`: runs a terminal program in a PTY with a fresh home, types Ctrl-C, and writes `result.txt` (came up, exited, leftovers). A leftover is a process that names the run directory or PROGRAM and did not exist before the run; the script lists and stops it, and leaves your other processes alone. `--axis none` runs it without AXIS, which is how to pick `--expect`. `--strace` adds `denied.txt`.

Alternate the builds over several runs, for example `for i in 1 2 3; do for b in base pr; do run-tui.sh --axis WORK/bin/$b/axis --out runs/$b-$i ...; done; done`.

## Build what you test

- Build the helpers too: `cargo build --release --locked -p axis-cli -p axis-sandbox --bins`. Without `-p axis-sandbox --bins` there is no `axis-seccomp-launcher`, and MXC refuses to start.
- MXC needs `lxc-exec` built at the `MXC_REF` pinned in `.github/workflows/ci.yml`. Another revision fails with "Config schema version ... is newer than supported".
- When you compare builds (main against a pull request, or variants), give each source tree its own `CARGO_TARGET_DIR` and check that the binaries differ (`md5sum */axis`). Trees unpacked with `git archive` carry commit-time mtimes, so a shared target directory silently reuses the first build.

## Where the binaries live

AXIS looks for `axis-seccomp-launcher` and `lxc-exec` beside `axis`, then in its install directories, then in absolute `PATH` entries. It skips a candidate unless every path component is owned by root or the effective user, is not a symlink, and is not group- or world-writable. The error only says "no safe ... found", so check the components first (`namei -l`):

- Not under `/tmp`, and not in a directory created under `umask 002`: `chmod -R go-w` the bin directory.
- A root caller needs root-owned directories, for example a new directory under `/opt`, not a user's home.

## Choose the backend and network mode on purpose

- The bundled agent policies use `network.mode: proxy`, and `auto` runs strict proxy on the native backend. To test MXC, copy the policy and set `runtime.provider: mxc`; confirm the backend in the log or the process tree (`lxc-exec`, `bwrap`).
- MXC proxy needs unprivileged user and network namespaces; native proxy needs `CAP_NET_ADMIN` or the netns helper.
- MXC `block` mode denies every socket domain except `AF_UNIX`, so a program that serves on TCP loopback (agent TUIs often start a local server) fails there for that reason alone. Use `allow` for those and say which mode you tested.

## Running

- Give each run its own fake `HOME` and a short workspace path. Never point a test at a real `~/.config`, `~/.ssh` or agent state. The PTY bridge socket lives under the workspace and its path must stay under 108 bytes.
- Run with a clean environment (`env -i PATH=/usr/bin:/bin HOME=...`), as CI does. Extra tools on `PATH`, such as another `python3`, change results.
- `axis run` first tries axisd at `$XDG_RUNTIME_DIR/axis/axisd.sock` or `/tmp/axis-axisd.sock`, which on a shared host can be someone else's. Pass `--socket` with a path that does not exist to keep the run standalone.
- Interactive programs need a terminal: `script -qfec "<cmd>" /dev/null`, or tmux. Ctrl-C reaches the program only as the byte `0x03` through the PTY bridge, so type it (`printf '\003'` into the script's stdin, or `tmux send-keys C-c`); a signal sent to `script` is not what a user does. To stop a stuck run, send SIGTERM to `axis`, which tears the sandbox down.
- Do not wrap the command inside the sandbox with `timeout`: seccomp denies `timer_create`. Put `timeout` outside `axis run`.
- To see what seccomp denies: `strace -f -qq --status=failed -o trace.log axis run ...` and count `= -1 EPERM` by syscall. `prctl(PR_CAPBSET_DROP)` and `setsockopt(SO_*BUFFORCE)` failures come from Bubblewrap and MXC setup, not from the payload. Judge behavior only from runs without strace.
- To find which allowed syscall matters, add it to `process.blocked_syscalls` in a copy of the policy and rerun; no rebuild needed. A name AXIS does not know fails the launch.
- Run MXC as a non-root user. As root, Bubblewrap failed to set up its uid map on a host where the same non-root user could run it.

## Shared hosts

Work in a private directory (`chmod 700`), do not use sudo unless the person you work for agreed, do not touch other users' processes or sockets, and remove what you created, including stray clones and network namespaces.

## Report

| Item | Detail |
|---|---|
| Commits | Head SHA, the `main` it was tested on, and any local merge or patch |
| Host | Distribution, kernel, caller (root or not), backend, network mode |
| Commands | The exact commands, or the script that ran them |
| Results | Pass, fail and ignored counts; for a launch, what the program showed, over several alternating runs |
| Comparison | The same harness on `main`, when the claim is "fixed" or "no change" |
| Not run | Each skipped case and why. A skip is not a pass. |
