# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vlitz is a dynamic debugger CLI tool built in Rust that leverages Frida's dynamic instrumentation capabilities. It provides cross-platform debugging and analysis features for applications on Windows, macOS, Linux, iOS, and Android.

## Build and Development Commands

```bash
# Build commands
cargo build                    # Debug build
cargo build --release          # Release build

# Development commands
cargo test                     # Run tests
cargo fmt                      # Format code
cargo clippy                   # Run linter

# Run the tool
./target/debug/vlitz --help    # Show help
./target/release/vlitz ps      # List processes
```

## Architecture Overview

### Core Module Structure

- **`src/core/`**: Main application logic and CLI handling
  - `cli.rs`: Clap-based command line argument parsing with subcommands (attach, ps, kill, devices)
  - `actions.rs`: Device discovery and connection handling
  - `manager.rs`: Process and device management
  - `ps.rs`: Process listing functionality
  - `kill.rs`: Process termination capabilities

- **`src/gum/`**: Frida integration layer
  - `mod.rs`: Main attachment logic and session management
  - `session.rs`: Interactive session handling with the attached process
  - `handler.rs`: Message handling between Frida script and CLI
  - `commander.rs`, `filter.rs`, `list.rs`, `memory.rs`, `navigator.rs`: Interactive debugging features
  - `store.rs`, `vzdata.rs`: Data storage and management

- **`src/util/`**: Utility functions
  - `logger.rs`: Logging utilities

### Key Design Patterns

1. **Command Pattern**: Each CLI subcommand (attach, ps, kill, devices) has dedicated handling in `core/mod.rs:execute_cli()`

2. **Connection Management**: Connection options (USB, remote, device ID) are unified through `ConnectionArgs` and handled by `actions::get_device()`

3. **Process Targeting**: Multiple ways to target processes (PID, name, file spawn) unified through `TargetArgs` and `ProcessArgs`

4. **Frida Integration**: JavaScript agent (`agent.js`) is embedded and injected into target processes for dynamic instrumentation

5. **Session Management**: Once attached, the tool enters an interactive session mode managed by `gum/session.rs`

### Data Flow

1. CLI parsing → Device connection → Process targeting → Frida session creation → JavaScript agent injection → Interactive session
2. The embedded JavaScript agent (`src/agent.js`) handles runtime instrumentation and communicates back to the Rust CLI through Frida's messaging system

### Key Dependencies

- `frida`: Core dynamic instrumentation with auto-download feature
- `clap`: CLI parsing with derive macros and shell completion
- `crossterm`: Cross-platform terminal manipulation for interactive features
- `rustyline`: Interactive shell functionality
- `serde/serde_json`: Data serialization for Frida communication

### JavaScript Agent

The `src/agent.js` file contains the Frida script that gets injected into target processes. It provides filtering, memory access, and other dynamic analysis capabilities that are controlled from the CLI.