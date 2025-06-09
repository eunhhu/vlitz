# Vlitz

A strong dynamic debugger CLI tool based on [Frida](https://frida.re/)

## Overview

Vlitz is a powerful command-line interface tool that leverages Frida's dynamic instrumentation capabilities to provide advanced debugging and analysis features for applications across multiple platforms.

## Features

- **Dynamic Process Analysis**: Attach to running processes and analyze their behavior in real-time
- **Cross-Platform Support**: Works on Windows, macOS, Linux, iOS, and Android
- **Multiple Connection Methods**: Connect via USB, remote servers, or local devices
- **Process Management**: List, filter, and manage target processes
- **Interactive Shell**: Provides an interactive environment for dynamic analysis
- **Shell Completion**: Built-in shell completion support for improved productivity

## Installation

### Prerequisites

- Rust 1.70 or later
- Frida (automatically downloaded when using the `auto-download` feature)

### From Source

```bash
git clone https://github.com/your-username/vlitz.git
cd vlitz
cargo build --release
```

The binary will be available at `target/release/vlitz`

## Usage

### Basic Commands

```bash
# Show help
vlitz --help

# List processes
vlitz ps

# Attach to a process by name
vlitz attach -n "target_app"

# Attach to a process by PID
vlitz attach -p 1234

# Connect to USB device
vlitz -U ps

# Connect to remote Frida server
vlitz -H 192.168.1.100 ps
```

### Connection Options

- `-D, --device <ID>`: Connect to device with the given ID
- `-U, --usb`: Connect to USB device
- `-R, --remote`: Connect to remote frida-server
- `-H, --host <HOST>`: Connect to remote frida-server on HOST

### Process Selection

- `-p, --pid <PID>`: Target process by Process ID
- `-n, --name <NAME>`: Target process by name
- `-f, --file <FILE>`: Target process by spawning executable

### Shell Completion

Generate shell completion scripts:

```bash
# For Bash
vlitz --generate-completion bash > vlitz.bash
source vlitz.bash

# For Zsh
vlitz --generate-completion zsh > _vlitz
# Move to your zsh completions directory

# For Fish
vlitz --generate-completion fish > vlitz.fish
source vlitz.fish
```

## Examples

### Analyze a Running Application

```bash
# List all running processes
vlitz ps

# Attach to a specific application
vlitz attach -n "notepad.exe"

# Kill a process
vlitz kill -p 1234
```

### Remote Debugging

```bash
# Connect to a remote Android device
vlitz -U ps

# Attach to an Android app
vlitz -U attach -n "com.example.app"
```

## Project Structure

```
src/
├── core/           # Core functionality
│   ├── actions.rs  # Action handlers
│   ├── cli.rs      # CLI argument parsing
│   ├── kill.rs     # Process termination
│   ├── manager.rs  # Process management
│   └── ps.rs       # Process listing
├── gum/            # Frida Gum integration
│   ├── commander.rs # Command execution
│   ├── filter.rs   # Process filtering
│   ├── handler.rs  # Event handling
│   └── list.rs     # Process enumeration
├── util/           # Utility functions
└── main.rs         # Application entry point
```

## Dependencies

- **clap**: Command-line argument parsing with derive support
- **frida**: Frida bindings for Rust with auto-download capability
- **crossterm**: Cross-platform terminal manipulation
- **rustyline**: Readline implementation for interactive shells
- **serde/serde_json**: Serialization and JSON handling
- **regex**: Regular expression support
- **ctrlc**: Signal handling for graceful shutdown

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Check code formatting
cargo fmt

# Run clippy for linting
cargo clippy
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

[Add your license information here]

## Acknowledgments

- [Frida](https://frida.re/) - The dynamic instrumentation toolkit that powers this tool
- The Rust community for excellent crates and documentation

## Support

If you encounter any issues or have questions, please:

1. Check the [Issues](https://github.com/your-username/vlitz/issues) page
2. Create a new issue with detailed information about your problem
3. Include your operating system, Rust version, and steps to reproduce

---

**Note**: This tool is designed for legitimate security research, debugging, and educational purposes. Please use responsibly and in accordance with applicable laws and regulations.

