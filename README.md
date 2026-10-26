# Vlitz

A cross-platform dynamic debugger CLI built on [Frida](https://frida.re/), for reverse engineers who want an interactive shell to inspect, scan, hook and patch a running process.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/vlitz.svg?logo=rust&logoColor=white&color=dea584)](https://crates.io/crates/vlitz)
[![Rust](https://img.shields.io/badge/Rust-1.70+-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)

**Status:** Active — published on crates.io (v0.2.2). The interactive session commands below are implemented; automated tests cover only the store/data layer, and most verification has been manual against real processes.

## Features

- Attach to a process by name, PID, app identifier, or spawn an executable (`-f`)
- Connect to the local device, a USB device (`-U`), a remote frida-server (`-R` / `-H HOST`), or a device by ID (`-D`)
- `ps`, `kill`, `devices` subcommands for process and device management
- Interactive session after attaching, with:
  - **Enumeration** — `list modules|ranges|functions|variables` into a paged "Field" working set
  - **Stores** — `field` and `lib` working sets with paging, sorting, filtering, move/remove/save
  - **Navigation** — `select`, `deselect`, `add`, `sub`, `goto` to move an address cursor
  - **Memory** — `view`, `read`, `write` at an address or selection
  - **Scanning** — `scan bytes|string|value|next|changed|unchanged|snapshot|results|list|clear`, plus `thread list`
  - **Hooking** — `hook add|remove|list|enable|disable|clear`
  - **Disassembly / patching** — `disas`, `disas func`, `patch bytes|nop|restore`, `nop`
  - `debug exports`, `help`, `clear`, `exit`
- Shell completion scripts via `vlitz completions <shell>`

## How it works

`src/main.rs` parses the CLI (`src/core/cli.rs`, clap) and dispatches in `src/core/mod.rs`. `core/actions.rs` resolves the Frida device from the connection flags; `core/manager.rs`, `ps.rs` and `kill.rs` implement process listing and termination.

For `attach`, `src/gum/mod.rs` creates a Frida session, injects the embedded JavaScript agent `src/agent.js`, and hands control to `gum/session.rs`, which runs the read-eval loop. `gum/commander.rs` holds session state (navigator, `field` and `lib` stores) and dispatches to command groups in `gum/commands/` (`nav_cmds`, `store_cmds`, `memory_cmds`, `hook_cmds`, `disasm_cmds`, `scan_cmds`). Each command calls into the agent via Frida RPC; results flow back as JSON (`gum/handler.rs`) and are rendered as tables (`gum/store.rs`, `gum/vzdata.rs`, `util/format.rs`).

## Tech stack

- Language: Rust (edition 2021, MSRV 1.70)
- Instrumentation: `frida` / `frida-sys` 0.17 with the `auto-download` feature (downloads the matching Frida Gum devkit at build time)
- CLI: `clap` (derive) + `clap_complete`
- Terminal: `crossterm`, `ctrlc`
- Serialization: `serde`, `serde_json`
- CI: GitHub Actions — `ci.yml` (fmt, clippy, build, test), `release.yml` (cross-platform binaries on `v*` tags), `publish-crates.yml` (crates.io on `v*` tags)

## Getting started

### Requirements

- Rust 1.70 or later
- A C toolchain plus `pkg-config`, `clang` and `libclang-dev` (needed by `frida-sys` bindgen on Linux; see `.github/workflows/ci.yml`)
- A running `frida-server` on the target device for USB/remote use

### Install

From crates.io:

```bash
cargo install vlitz
```

From source:

```bash
git clone https://github.com/eunhhu/vlitz.git
cd vlitz
cargo build --release
# binary at target/release/vlitz
```

Prebuilt archives for Linux, macOS and Windows are attached to GitHub Releases by `release.yml`.

### Run

```bash
vlitz --help
vlitz devices                 # list Frida devices
vlitz ps                      # list local processes
vlitz ps -s pid chrome        # filter by name, sort by PID
vlitz -U ps                   # processes on a USB device
vlitz -H 192.168.0.10 ps      # processes on a remote frida-server

vlitz attach -n notepad.exe   # attach by name
vlitz attach -p 1234          # attach by PID
vlitz -U attach -N com.example.app   # attach by identifier on USB device
vlitz attach -f ./target_bin  # spawn and attach

vlitz kill -n notepad.exe

vlitz completions zsh > _vlitz   # bash, zsh, fish, powershell, elvish
```

Inside a session, type `help` or `help <command>` for usage.

Development:

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets
```

## Project structure

```
src/
├── main.rs            # entry point
├── agent.js           # Frida agent injected into the target (embedded at build time)
├── core/              # CLI parsing, device lookup, ps / kill / devices
│   ├── cli.rs
│   ├── actions.rs
│   ├── manager.rs
│   ├── process.rs
│   ├── ps.rs
│   ├── kill.rs
│   └── error.rs
├── gum/               # attach flow and the interactive session
│   ├── session.rs     # REPL loop
│   ├── commander.rs   # session state + command dispatch
│   ├── commands/      # nav, store, memory, hook, disasm, scan command groups
│   ├── store.rs       # paged Field/Lib stores
│   ├── vzdata.rs      # typed data items shown in stores
│   ├── navigator.rs   # address cursor
│   ├── filter.rs      # filter expression parsing
│   ├── handler.rs     # agent message handling
│   ├── list.rs, memory.rs
│   └── *_tests.rs     # unit tests
└── util/              # logger and table/format helpers
.github/workflows/     # ci.yml, release.yml, publish-crates.yml
plans/                 # design notes
```

## Configuration

Vlitz reads no environment variables itself; all options are CLI flags. `frida-sys` uses network access at build time to download the Frida devkit when the `auto-download` feature is enabled.

## License

MIT — see [LICENSE](LICENSE).

Vlitz is intended for legitimate security research, debugging and education. Use it only on software you are authorized to analyze.
