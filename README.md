# Vlitz

Vlitz is a dynamic debugger / runtime inspection CLI built on top of [Frida](https://frida.re/).

It connects to a local/USB/remote Frida device, attaches to (or spawns) a target process, injects an embedded Frida JavaScript agent (`src/agent.js`), and then provides an interactive REPL for memory inspection, hooking, scanning, and patching.

## Quick Start

```bash
# Build
cargo build

# List devices
./target/debug/vlitz devices

# List processes on local device
./target/debug/vlitz ps

# Attach by name (enters interactive session)
./target/debug/vlitz attach -n "target_app"
```

## Installation

### Prerequisites

- Rust (edition 2021; `cargo` available)
- A target environment supported by Frida (local OS / iOS / Android / etc.)

This project depends on the Rust `frida` crate with the `auto-download` feature enabled (`Cargo.toml`), so the Frida devkit is downloaded automatically during builds.

### From Source

```bash
git clone https://github.com/eunhhu/vlitz.git
cd vlitz
cargo build --release
```

Binary output:

- `target/release/vlitz`

## CLI Usage

Vlitz is implemented with `clap` (see `src/core/cli.rs`). Top-level commands are dispatched from `src/core/mod.rs`.

### Commands

- `vlitz devices` — enumerate all devices
- `vlitz ps [--sort name|pid] [FILTER]` — list processes (optionally filtered by substring)
- `vlitz attach <TARGET>` — attach to process by name (positional)
- `vlitz attach -n <NAME>` — attach to process by name
- `vlitz attach -p <PID>` — attach to process by PID
- `vlitz attach -N <IDENTIFIER>` — attach to process by “identifier” (currently treated the same as name)
- `vlitz attach -f <FILE>` — spawn an executable then attach
- `vlitz kill <TARGET>` / `vlitz kill -n <NAME>` / `vlitz kill -p <PID>` — kill process
- `vlitz completions <SHELL>` — print shell completions to stdout

### Connection Options

Connection flags are shared across `attach`, `ps`, and `kill` (`ConnectionArgs` in `src/core/cli.rs`).

- `-D, --device <ID>`: connect to device by ID
- `-U, --usb`: connect to USB device
- `-R, --remote`: connect to Frida “remote device”
- `-H, --host <HOST>`: currently only selects “remote device” mode; the host value is not used yet

Note: if no connection flag is provided, Vlitz uses the local device.

### Shell Completions

```bash
# bash
vlitz completions bash > vlitz.bash
source vlitz.bash

# zsh
vlitz completions zsh > _vlitz

# fish
vlitz completions fish > vlitz.fish
source vlitz.fish
```

There is also a hidden flag `--generate-completion <SHELL>` (see `src/core/cli.rs`), but `vlitz completions <SHELL>` is the intended interface.

## Interactive Session

After `vlitz attach ...`, Vlitz enters an interactive REPL implemented in `src/gum/session.rs` and driven by `src/gum/commander.rs`.

The prompt shows the current navigator selection (address/module/function/etc.). Use `help` inside the REPL for the authoritative command list.

### Concepts

- **Agent**: `src/agent.js` is injected into the target and exposes RPC exports used by Rust.
- **Field store**: a working set (temporary) populated by list/scan commands.
- **Lib store**: a saved set (persistent for the session) where you can store selected items.
- **Navigator**: the “current selection” used as the default target by some commands.

### Selectors

Many commands accept a selector:

- Index: `0`, `15`
- List: `1,2,5`
- Range: `0-10`
- All: `all`
- Store prefix: `field:0`, `lib:all`

Indices are **0-based** (matching the `[0]` / `[1]` indices printed in store listings).

If no store is specified, Vlitz defaults to searching `lib`. Numeric selectors can fall back to `field`.

### Command Overview

Core:

- `help [command]` (aliases: `h`, `?`)
- `debug exports` (alias: `dbg e`) — dump agent exports (debug)
- `exit` (aliases: `quit`, `q`)
- `clear` (alias: `cls`)

Navigation:

- `select <selector>`
- `deselect`
- `add <offset>` / `sub <offset>` (hex `0x...` or decimal)
- `goto <address>`

Stores:

- `field list|next|prev|sort|move|remove|clear|filter ...`
- `lib list|next|prev|sort|save|move|remove|clear|filter ...`

Memory enumeration and I/O:

- `list modules [filter]`
- `list ranges [protect] [filter]`
- `list functions [module_selector] [filter]`
- `list variables [module_selector] [filter]`
- `view [target_or_size] [size] [type]`
- `read <target> [type] [length]`
- `write <target> <value> [type]`

Hooking:

- `hook add <target> [options]` (options include: `-e` enter, `-l` leave, `-a` args, `-r` retval, `-b` backtrace)
- `hook list|remove|enable|disable|clear ...`

Disassembly / patching:

- `disas [target] [count]` (aliases: `dis`, `u`)
- `disas func [target]`
- `patch bytes <target> <bytes>`
- `patch nop <target> [count]`
- `patch restore <target>`
- `nop <target> [count]` (shortcut)

Scanning / threads:

- `scan bytes|string|value|next|changed|unchanged|snapshot|results|list|clear ...`
- `thread list|regs|stack|backtrace ...`

### Filter Expressions

`field filter <expr>` / `lib filter <expr>` supports:

- Logical ops: `&` (and), `|` (or)
- Operators: `=`, `!=`, `<`, `<=`, `>`, `>=`, `:`, `!:`
- Values can be quoted: `name:"lib"` or `name:'lib'`

Examples:

- `field filter name:"lib" & address>=0x1000`
- `lib filter name:objc | name:java`

## Project Structure

```text
src/
  main.rs                # entry point
  core/                   # clap CLI + device/process operations
    cli.rs                # CLI definition
    actions.rs            # connection resolution (local/usb/remote/device-id)
    manager.rs            # Frida context + DeviceManager lifetime management
    ps.rs                 # process listing
    kill.rs               # process kill
    process.rs            # process lookup helpers
  gum/                    # Frida session + interactive debugger features
    mod.rs                # attach + script injection
    session.rs            # REPL loop
    commander.rs          # REPL command dispatcher + implementation
    commands/             # command table builders
    memory.rs             # typed memory read/write helpers
    list.rs               # module/range/function/variable enumeration
    store.rs              # Field/Lib stores + selector parsing
    navigator.rs          # current selection/prompt state
    handler.rs            # Frida message/log formatting
    vzdata.rs             # core data model used by stores/navigator
  util/                   # formatting/logging helpers
  agent.js                # injected Frida JS agent (rpc.exports)
```

## Development

```bash
cargo fmt
cargo clippy
cargo test
```

## Security / Ethics

Vlitz is intended for legitimate debugging, security research, and education. Use it responsibly and follow applicable laws and authorization requirements.
