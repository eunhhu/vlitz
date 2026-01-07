# Vlitz Completion Plan: Native/Desktop Dynamic Debugger

## Executive Summary

This plan outlines the implementation roadmap to transform vlitz from a basic Frida REPL tool into a full-featured dynamic debugging platform focused on Native/Desktop environments. The priority features are **function hooking**, **disassembly**, and **memory scanning**.

---

## Current State Analysis

### Implemented Features
| Feature | Status | Location |
|---------|--------|----------|
| CLI with attach/ps/kill/devices | ✅ Complete | `src/core/cli.rs` |
| Interactive REPL session | ✅ Basic | `src/gum/session.rs` |
| Memory read/write operations | ✅ Complete | `src/gum/memory.rs` |
| Module enumeration | ✅ Complete | `src/gum/list.rs` |
| Function/Variable listing | ✅ Complete | `src/gum/list.rs` |
| Memory range listing | ✅ Complete | `src/gum/list.rs` |
| Navigator for address navigation | ✅ Complete | `src/gum/navigator.rs` |
| Field/Lib stores | ✅ Complete | `src/gum/store.rs` |
| Filtering and sorting | ✅ Complete | `src/gum/filter.rs` |
| Data types defined | ✅ Partial | `src/gum/vzdata.rs` |

### Missing Features (Priority Order)
1. **Function Hooking** - No Interceptor implementation
2. **Disassembly** - Only `Instruction.parse` stub in agent.js
3. **Memory Scanning** - No pattern/value search
4. **Code Patching** - No NOP/patch support
5. **Thread/Stack Operations** - Defined but not implemented
6. **Stalker Code Tracing** - Not implemented
7. **Rustyline Integration** - Dependency exists but not used

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         vlitz CLI                                │
│                    src/main.rs, src/core/                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Session Manager                             │
│                    src/gum/session.rs                            │
│              [Rustyline Editor + Command Parser]                 │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Commander                                 │
│                   src/gum/commander.rs                           │
│           [Command Registration + Execution Engine]              │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│   Navigator   │     │  Field Store  │     │   Lib Store   │
│   [Context]   │     │ [Working Set] │     │ [Saved Items] │
└───────────────┘     └───────────────┘     └───────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Frida Script Bridge                           │
│                      src/agent.js                                │
│    [RPC Exports: Memory, Hooks, Disasm, Scan, Stalker]          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Target Process                              │
│              [Injected Frida Gum Runtime]                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Core UX Improvements

### 1.1 Rustyline Integration

**File Changes:**
- `src/gum/session.rs` - Replace stdin reading with rustyline Editor
- New: `src/gum/completer.rs` - Custom completion handler

**Implementation:**

```rust
// src/gum/session.rs - Key changes
use rustyline::{Editor, Config, EditMode};
use rustyline::history::DefaultHistory;

pub struct VlitzCompleter {
    commands: Vec<String>,
    // Reference to commander for dynamic completions
}

impl Completer for VlitzCompleter {
    type Candidate = String;
    
    fn complete(&self, line: &str, pos: usize, ctx: &Context) 
        -> Result<(usize, Vec<String>), ReadlineError> {
        // Complete commands, subcommands, selectors, addresses
    }
}
```

**Features:**
- Command history with persistence (`~/.vlitz_history`)
- Tab completion for commands, subcommands, selectors
- Vim/Emacs mode selection
- Multi-line editing support

### 1.2 Command Completion Structure

```
Command Completion Tree:
├── help [command]
├── exit
├── list
│   ├── modules [filter]
│   ├── ranges [protect] [filter]
│   ├── functions [module] [filter]
│   ├── variables [module] [filter]
│   ├── threads
│   ├── imports [module] [filter]
│   └── exports [module] [filter]
├── hook
│   ├── add <target> [options]
│   ├── remove <id>
│   ├── list
│   ├── enable <id>
│   └── disable <id>
├── disas [target] [count]
├── scan
│   ├── bytes <pattern> [range]
│   ├── string <text> [range]
│   ├── value <type> <value> [range]
│   └── next [filter]
├── patch <target> <bytes>
├── nop <target> [count]
├── view [target] [size] [type]
├── read <target> [type] [length]
├── write <target> <value> [type]
├── select <selector>
├── deselect
├── add <offset>
├── sub <offset>
├── goto <address>
├── field [subcommand]
├── lib [subcommand]
├── thread
│   ├── list
│   ├── select <id>
│   ├── regs [id]
│   └── stack [id] [depth]
├── trace
│   ├── start <target>
│   ├── stop
│   └── dump
└── export <format> <file>
```

---

## Phase 2: Function Hooking System

### 2.1 Data Structure Design

**New VzData type in `src/gum/vzdata.rs`:**

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct VzHook {
    pub base: VzBase,
    pub id: String,           // Unique hook identifier
    pub target: u64,          // Target address
    pub target_name: Option<String>,  // Symbol name if available
    pub module: Option<String>,
    pub enabled: bool,
    pub on_enter: bool,       // Log on enter
    pub on_leave: bool,       // Log on leave
    pub log_args: bool,       // Log arguments
    pub log_retval: bool,     // Log return value
    pub modify_args: Option<Vec<String>>,   // Argument modifications
    pub modify_retval: Option<String>,      // Return value modification
}
```

### 2.2 Agent.js Hook Implementation

```javascript
// src/agent.js - Hook management additions

const activeHooks = new Map();  // id -> { listener, config }
let hookIdCounter = 0;

rpc.exports = {
    // ... existing exports ...
    
    // Hook management
    hook_attach: (address, config) => {
        const id = `hook_${hookIdCounter++}`;
        const target = ptr(address);
        
        const listener = Interceptor.attach(target, {
            onEnter: function(args) {
                if (config.on_enter) {
                    const argData = [];
                    for (let i = 0; i < (config.arg_count || 4); i++) {
                        argData.push(args[i].toString());
                    }
                    send({
                        type: 'hook_enter',
                        id: id,
                        address: address,
                        args: argData,
                        thread: this.threadId,
                        depth: this.depth
                    });
                }
                
                // Argument modification
                if (config.modify_args) {
                    config.modify_args.forEach((mod, idx) => {
                        if (mod !== null) {
                            args[idx] = ptr(mod);
                        }
                    });
                }
            },
            onLeave: function(retval) {
                if (config.on_leave) {
                    send({
                        type: 'hook_leave',
                        id: id,
                        address: address,
                        retval: retval.toString(),
                        thread: this.threadId
                    });
                }
                
                // Return value modification
                if (config.modify_retval !== undefined) {
                    retval.replace(ptr(config.modify_retval));
                }
            }
        });
        
        activeHooks.set(id, { listener, config, address });
        return { id, address };
    },
    
    hook_detach: (id) => {
        const hook = activeHooks.get(id);
        if (hook) {
            hook.listener.detach();
            activeHooks.delete(id);
            return true;
        }
        return false;
    },
    
    hook_list: () => {
        return Array.from(activeHooks.entries()).map(([id, h]) => ({
            id,
            address: h.address,
            enabled: true,
            config: h.config
        }));
    },
    
    hook_enable: (id) => {
        // Re-attach hook
    },
    
    hook_disable: (id) => {
        // Detach but keep config
    }
};
```

### 2.3 Rust Hook Commands

**New file: `src/gum/commands/hook_cmds.rs`**

```rust
// Hook command implementations
pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();
    
    let mut hook_subs: Vec<SubCommand> = Vec::new();
    
    hook_subs.push(SubCommand::new(
        "add",
        "Add a hook to target address or function",
        vec![
            CommandArg::required("target", "Address, selector, or function name"),
            CommandArg::optional("options", "Hook options: -e (enter) -l (leave) -a (args) -r (retval)"),
        ],
        |c, a| Commander::hook_add(c, a),
    ));
    
    hook_subs.push(SubCommand::new(
        "remove",
        "Remove a hook by ID",
        vec![CommandArg::required("id", "Hook ID to remove")],
        |c, a| Commander::hook_remove(c, a),
    ));
    
    hook_subs.push(SubCommand::new(
        "list",
        "List all active hooks",
        vec![],
        |c, a| Commander::hook_list(c, a),
    ).alias("ls"));
    
    // ... more subcommands
    
    cmds.push(Command::new(
        "hook",
        "Function hooking operations",
        vec!["hk"],
        vec![],
        hook_subs,
        None,
    ));
    
    cmds
}
```

### 2.4 Hook Message Handler

**Updates to `src/gum/handler.rs`:**

```rust
impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &str) {
        if let Ok(msg) = serde_json::from_str::<Value>(message) {
            if let Some(msg_type) = msg.get("type").and_then(|t| t.as_str()) {
                match msg_type {
                    "hook_enter" => {
                        let id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        let addr = msg.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                        let args = msg.get("args").and_then(|v| v.as_array());
                        println!("[HOOK ENTER] {} @ {} args: {:?}", id, addr, args);
                    }
                    "hook_leave" => {
                        let id = msg.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        let retval = msg.get("retval").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("[HOOK LEAVE] {} => {}", id, retval);
                    }
                    _ => {}
                }
            }
        }
    }
}
```

---

## Phase 3: Disassembly Support

### 3.1 Agent.js Disassembly Implementation

```javascript
// src/agent.js - Disassembly functions

rpc.exports = {
    // ... existing exports ...
    
    disassemble: (address, count = 10) => {
        const instructions = [];
        let current = ptr(address);
        
        for (let i = 0; i < count; i++) {
            try {
                const insn = Instruction.parse(current);
                if (!insn) break;
                
                instructions.push({
                    address: current.toString(),
                    size: insn.size,
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    bytes: Array.from(new Uint8Array(current.readByteArray(insn.size))),
                    groups: insn.groups || [],
                    regsRead: insn.regsRead || [],
                    regsWritten: insn.regsWritten || []
                });
                
                current = current.add(insn.size);
            } catch (e) {
                break;
            }
        }
        
        return instructions;
    },
    
    disassemble_function: (address) => {
        // Disassemble until RET or invalid instruction
        const instructions = [];
        let current = ptr(address);
        const maxInstructions = 1000;
        
        for (let i = 0; i < maxInstructions; i++) {
            try {
                const insn = Instruction.parse(current);
                if (!insn) break;
                
                instructions.push({
                    address: current.toString(),
                    size: insn.size,
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    bytes: Array.from(new Uint8Array(current.readByteArray(insn.size)))
                });
                
                // Check for return instructions (architecture-dependent)
                if (insn.mnemonic === 'ret' || insn.mnemonic === 'retq') {
                    break;
                }
                
                current = current.add(insn.size);
            } catch (e) {
                break;
            }
        }
        
        return instructions;
    }
};
```

### 3.2 Rust Disassembly Display

**New file: `src/gum/disasm.rs`**

```rust
use crossterm::style::Stylize;
use frida::Script;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub size: usize,
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
}

pub fn disassemble(
    script: &mut Script,
    address: u64,
    count: usize,
) -> Result<Vec<Instruction>, String> {
    let result = script
        .exports
        .call("disassemble", Some(json!([address, count])))
        .map_err(|e| e.to_string())?;
    
    let arr = result
        .ok_or("No data returned")?
        .as_array()
        .ok_or("Invalid array")?
        .clone();
    
    let mut instructions = Vec::new();
    for item in arr {
        let addr_str = item.get("address").and_then(|v| v.as_str()).unwrap_or("0");
        let address = crate::gum::vzdata::string_to_u64(addr_str);
        
        instructions.push(Instruction {
            address,
            size: item.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            mnemonic: item.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            op_str: item.get("opStr").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            bytes: item.get("bytes")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|b| b.as_u64().map(|n| n as u8)).collect())
                .unwrap_or_default(),
        });
    }
    
    Ok(instructions)
}

pub fn format_disassembly(instructions: &[Instruction]) -> String {
    let mut output = String::new();
    
    for insn in instructions {
        let bytes_hex = insn.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        let addr = format!("{:#018x}", insn.address).yellow();
        let bytes = format!("{:<24}", bytes_hex).dark_grey();
        let mnemonic = insn.mnemonic.clone().cyan();
        let operands = insn.op_str.clone();
        
        output.push_str(&format!("{}  {}  {} {}\n", addr, bytes, mnemonic, operands));
    }
    
    output
}
```

### 3.3 Disassembly Command

```rust
// In commander.rs
pub(crate) fn disas(&mut self, args: &[&str]) -> bool {
    let (address, count) = self.parse_disas_args(args);
    
    match disassemble(&mut self.script, address, count) {
        Ok(instructions) => {
            println!("{}", format_disassembly(&instructions));
        }
        Err(e) => {
            logger::error(&format!("Disassembly error: {}", e));
        }
    }
    true
}
```

---

## Phase 4: Memory Search and Scan

### 4.1 Agent.js Scan Implementation

```javascript
// src/agent.js - Memory scanning

let scanResults = [];  // Store current scan results

rpc.exports = {
    // ... existing exports ...
    
    scan_pattern: (pattern, ranges = null) => {
        scanResults = [];
        const targetRanges = ranges || Process.enumerateRanges('r--');
        
        for (const range of targetRanges) {
            try {
                const matches = Memory.scanSync(range.base, range.size, pattern);
                for (const match of matches) {
                    scanResults.push({
                        address: match.address.toString(),
                        size: match.size,
                        pattern: pattern
                    });
                }
            } catch (e) {
                // Skip inaccessible ranges
            }
        }
        
        return scanResults;
    },
    
    scan_value: (type, value, ranges = null) => {
        scanResults = [];
        const targetRanges = ranges || Process.enumerateRanges('r--');
        
        // Convert value to pattern based on type
        let pattern;
        switch (type) {
            case 'int32':
                const buf = Memory.alloc(4);
                buf.writeS32(parseInt(value));
                pattern = Array.from(new Uint8Array(buf.readByteArray(4)))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                break;
            case 'int64':
                const buf64 = Memory.alloc(8);
                buf64.writeS64(parseInt(value));
                pattern = Array.from(new Uint8Array(buf64.readByteArray(8)))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                break;
            case 'float':
                const bufF = Memory.alloc(4);
                bufF.writeFloat(parseFloat(value));
                pattern = Array.from(new Uint8Array(bufF.readByteArray(4)))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                break;
            case 'double':
                const bufD = Memory.alloc(8);
                bufD.writeDouble(parseFloat(value));
                pattern = Array.from(new Uint8Array(bufD.readByteArray(8)))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                break;
            case 'string':
                pattern = Array.from(new TextEncoder().encode(value))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(' ');
                break;
            default:
                return [];
        }
        
        return rpc.exports.scan_pattern(pattern, ranges);
    },
    
    scan_string: (text, ranges = null) => {
        return rpc.exports.scan_value('string', text, ranges);
    },
    
    scan_next: (type, value) => {
        // Refine previous results
        const newResults = [];
        
        for (const result of scanResults) {
            try {
                const addr = ptr(result.address);
                let currentValue;
                
                switch (type) {
                    case 'int32':
                        currentValue = addr.readS32();
                        if (currentValue === parseInt(value)) {
                            newResults.push(result);
                        }
                        break;
                    case 'float':
                        currentValue = addr.readFloat();
                        if (Math.abs(currentValue - parseFloat(value)) < 0.0001) {
                            newResults.push(result);
                        }
                        break;
                    // ... other types
                }
            } catch (e) {
                // Address no longer readable
            }
        }
        
        scanResults = newResults;
        return scanResults;
    },
    
    scan_changed: () => {
        // Find addresses where value changed
    },
    
    scan_unchanged: () => {
        // Find addresses where value is same
    },
    
    get_scan_results: () => scanResults,
    
    clear_scan: () => {
        scanResults = [];
        return true;
    }
};
```

### 4.2 Scan Commands

**New file: `src/gum/commands/scan_cmds.rs`**

```rust
pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();
    
    let mut scan_subs: Vec<SubCommand> = Vec::new();
    
    scan_subs.push(SubCommand::new(
        "bytes",
        "Scan for byte pattern (hex: 'AA BB ?? CC')",
        vec![
            CommandArg::required("pattern", "Byte pattern with ?? wildcards"),
            CommandArg::optional("range", "Memory range selector"),
        ],
        |c, a| Commander::scan_bytes(c, a),
    ));
    
    scan_subs.push(SubCommand::new(
        "string",
        "Scan for string value",
        vec![
            CommandArg::required("text", "String to search"),
            CommandArg::optional("range", "Memory range selector"),
        ],
        |c, a| Commander::scan_string(c, a),
    ));
    
    scan_subs.push(SubCommand::new(
        "value",
        "Scan for typed value",
        vec![
            CommandArg::required("type", "Value type (int32, float, etc.)"),
            CommandArg::required("value", "Value to search"),
            CommandArg::optional("range", "Memory range selector"),
        ],
        |c, a| Commander::scan_value(c, a),
    ));
    
    scan_subs.push(SubCommand::new(
        "next",
        "Refine scan with new value",
        vec![
            CommandArg::required("value", "New value to filter"),
        ],
        |c, a| Commander::scan_next(c, a),
    ));
    
    scan_subs.push(SubCommand::new(
        "results",
        "Show current scan results",
        vec![],
        |c, a| Commander::scan_results(c, a),
    ));
    
    scan_subs.push(SubCommand::new(
        "clear",
        "Clear scan results",
        vec![],
        |c, a| Commander::scan_clear(c, a),
    ));
    
    cmds.push(Command::new(
        "scan",
        "Memory scanning operations",
        vec!["s"],
        vec![],
        scan_subs,
        None,
    ));
    
    cmds
}
```

---

## Phase 5: Code Patching

### 5.1 Agent.js Patching

```javascript
rpc.exports = {
    // ... existing exports ...
    
    patch_bytes: (address, bytes) => {
        const target = ptr(address);
        const range = Process.findRangeByAddress(target);
        
        if (!range) {
            return { success: false, error: 'Address not in valid range' };
        }
        
        // Save original bytes
        const original = Array.from(new Uint8Array(target.readByteArray(bytes.length)));
        
        // Make writable if needed
        const wasWritable = range.protection.includes('w');
        if (!wasWritable) {
            Memory.protect(target, bytes.length, 'rwx');
        }
        
        // Write new bytes
        target.writeByteArray(bytes);
        
        // Restore protection
        if (!wasWritable) {
            Memory.protect(target, bytes.length, range.protection);
        }
        
        return { 
            success: true, 
            address: address,
            original: original,
            patched: bytes
        };
    },
    
    nop_instruction: (address, count = 1) => {
        const target = ptr(address);
        const arch = Process.arch;
        
        // Get NOP opcode for architecture
        let nopBytes;
        let nopSize;
        
        switch (arch) {
            case 'x64':
            case 'ia32':
                nopBytes = [0x90];  // Single-byte NOP
                nopSize = 1;
                break;
            case 'arm':
                nopBytes = [0x00, 0xf0, 0x20, 0xe3];  // NOP (ARM mode)
                nopSize = 4;
                break;
            case 'arm64':
                nopBytes = [0x1f, 0x20, 0x03, 0xd5];  // NOP
                nopSize = 4;
                break;
            default:
                return { success: false, error: 'Unsupported architecture' };
        }
        
        // Calculate total bytes to NOP
        let totalSize = 0;
        let current = target;
        
        for (let i = 0; i < count; i++) {
            const insn = Instruction.parse(current);
            if (!insn) break;
            totalSize += insn.size;
            current = current.add(insn.size);
        }
        
        // Generate NOP sled
        const nops = [];
        for (let i = 0; i < totalSize; i += nopSize) {
            nops.push(...nopBytes);
        }
        
        return rpc.exports.patch_bytes(address, nops.slice(0, totalSize));
    },
    
    restore_bytes: (address, original) => {
        return rpc.exports.patch_bytes(address, original);
    }
};
```

---

## Phase 6: Thread and Stack Operations

### 6.1 Agent.js Thread Functions

```javascript
rpc.exports = {
    // ... existing exports ...
    
    list_threads: () => {
        return Process.enumerateThreads().map(t => ({
            id: t.id,
            state: t.state,
            context: t.context ? {
                pc: t.context.pc.toString(),
                sp: t.context.sp.toString()
            } : null
        }));
    },
    
    get_thread_context: (threadId) => {
        const threads = Process.enumerateThreads();
        const thread = threads.find(t => t.id === threadId);
        
        if (!thread || !thread.context) {
            return null;
        }
        
        const ctx = thread.context;
        const regs = {};
        
        // Architecture-specific register extraction
        if (Process.arch === 'x64') {
            regs.rax = ctx.rax.toString();
            regs.rbx = ctx.rbx.toString();
            regs.rcx = ctx.rcx.toString();
            regs.rdx = ctx.rdx.toString();
            regs.rsi = ctx.rsi.toString();
            regs.rdi = ctx.rdi.toString();
            regs.rbp = ctx.rbp.toString();
            regs.rsp = ctx.rsp.toString();
            regs.r8 = ctx.r8.toString();
            regs.r9 = ctx.r9.toString();
            regs.r10 = ctx.r10.toString();
            regs.r11 = ctx.r11.toString();
            regs.r12 = ctx.r12.toString();
            regs.r13 = ctx.r13.toString();
            regs.r14 = ctx.r14.toString();
            regs.r15 = ctx.r15.toString();
            regs.rip = ctx.pc.toString();
        } else if (Process.arch === 'arm64') {
            for (let i = 0; i <= 28; i++) {
                regs[`x${i}`] = ctx[`x${i}`].toString();
            }
            regs.fp = ctx.fp.toString();
            regs.lr = ctx.lr.toString();
            regs.sp = ctx.sp.toString();
            regs.pc = ctx.pc.toString();
        }
        // ... other architectures
        
        return regs;
    },
    
    read_stack: (address, depth = 32) => {
        const stack = [];
        let current = ptr(address);
        const ptrSize = Process.pointerSize;
        
        for (let i = 0; i < depth; i++) {
            try {
                const value = current.readPointer();
                const module = Process.findModuleByAddress(value);
                
                stack.push({
                    offset: i * ptrSize,
                    address: current.toString(),
                    value: value.toString(),
                    module: module ? module.name : null
                });
                
                current = current.add(ptrSize);
            } catch (e) {
                break;
            }
        }
        
        return stack;
    },
    
    backtrace: (context = null) => {
        const bt = Thread.backtrace(context, Backtracer.ACCURATE);
        return bt.map(addr => {
            const module = Process.findModuleByAddress(addr);
            const symbol = DebugSymbol.fromAddress(addr);
            
            return {
                address: addr.toString(),
                module: module ? module.name : null,
                symbol: symbol ? symbol.name : null,
                offset: module ? addr.sub(module.base).toInt32() : null
            };
        });
    }
};
```

---

## Phase 7: Stalker Code Tracing

### 7.1 Agent.js Stalker Implementation

```javascript
let stalkerSession = null;
let stalkerEvents = [];

rpc.exports = {
    // ... existing exports ...
    
    stalker_start: (threadId, options = {}) => {
        if (stalkerSession) {
            return { success: false, error: 'Stalker already running' };
        }
        
        stalkerEvents = [];
        
        Stalker.follow(threadId, {
            events: {
                call: options.calls !== false,
                ret: options.rets === true,
                exec: options.exec === true,
                block: options.blocks === true
            },
            onReceive: function(events) {
                const parsed = Stalker.parse(events);
                for (const event of parsed) {
                    stalkerEvents.push(event);
                    
                    if (stalkerEvents.length > 10000) {
                        stalkerEvents.shift();  // Limit buffer
                    }
                }
            },
            onCallSummary: function(summary) {
                send({ type: 'stalker_summary', data: summary });
            }
        });
        
        stalkerSession = { threadId, options };
        return { success: true, threadId };
    },
    
    stalker_stop: () => {
        if (stalkerSession) {
            Stalker.unfollow(stalkerSession.threadId);
            Stalker.flush();
            stalkerSession = null;
            return { success: true };
        }
        return { success: false, error: 'No stalker session' };
    },
    
    stalker_events: (limit = 100) => {
        return stalkerEvents.slice(-limit);
    },
    
    stalker_clear: () => {
        stalkerEvents = [];
        return true;
    }
};
```

---

## Phase 8: File Structure

### New Files to Create

```
src/
├── gum/
│   ├── commands/
│   │   ├── mod.rs           (update)
│   │   ├── hook_cmds.rs     (new)
│   │   ├── scan_cmds.rs     (new)
│   │   ├── disasm_cmds.rs   (new)
│   │   ├── thread_cmds.rs   (new)
│   │   ├── patch_cmds.rs    (new)
│   │   └── trace_cmds.rs    (new)
│   ├── disasm.rs            (new)
│   ├── hook.rs              (new)
│   ├── scan.rs              (new)
│   ├── thread.rs            (new)
│   ├── patch.rs             (new)
│   ├── trace.rs             (new)
│   ├── completer.rs         (new)
│   └── ...
```

### Updated Files

- `src/agent.js` - Add all new RPC exports
- `src/gum/session.rs` - Rustyline integration
- `src/gum/commander.rs` - New command handlers
- `src/gum/vzdata.rs` - New VzHook, VzInstruction types
- `src/gum/handler.rs` - Hook message handling
- `Cargo.toml` - Potentially add new dependencies

---

## Complete Command Reference

### Core Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `help [cmd]` | `h` | Show help |
| `exit` | `q`, `quit` | Exit session |
| `select <sel>` | - | Select data into navigator |
| `deselect` | - | Clear navigator |
| `add <offset>` | - | Add offset to navigator |
| `sub <offset>` | - | Subtract offset |
| `goto <addr>` | - | Jump to address |

### Listing Commands
| Command | Description |
|---------|-------------|
| `list modules [filter]` | List process modules |
| `list ranges [prot] [filter]` | List memory ranges |
| `list functions [mod] [filter]` | List module functions |
| `list variables [mod] [filter]` | List module variables |
| `list threads` | List process threads |
| `list imports [mod] [filter]` | List module imports |
| `list exports [mod] [filter]` | List module exports |

### Memory Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `view [target] [size] [type]` | `v` | View memory hex dump |
| `read <target> [type] [len]` | `r` | Read typed value |
| `write <target> <val> [type]` | `w` | Write typed value |

### Hooking Commands
| Command | Description |
|---------|-------------|
| `hook add <target> [opts]` | Add function hook |
| `hook remove <id>` | Remove hook |
| `hook list` | List active hooks |
| `hook enable <id>` | Enable hook |
| `hook disable <id>` | Disable hook |

### Disassembly Commands
| Command | Alias | Description |
|---------|-------|-------------|
| `disas [target] [count]` | `d` | Disassemble instructions |
| `disas func [target]` | - | Disassemble function |

### Scanning Commands
| Command | Description |
|---------|-------------|
| `scan bytes <pattern>` | Scan for byte pattern |
| `scan string <text>` | Scan for string |
| `scan value <type> <val>` | Scan for typed value |
| `scan next <val>` | Refine scan |
| `scan results` | Show results |
| `scan clear` | Clear results |

### Patching Commands
| Command | Description |
|---------|-------------|
| `patch <target> <bytes>` | Patch bytes at address |
| `nop <target> [count]` | NOP instructions |

### Thread Commands
| Command | Description |
|---------|-------------|
| `thread list` | List threads |
| `thread regs [id]` | Show registers |
| `thread stack [id] [depth]` | Dump stack |
| `thread bt [id]` | Show backtrace |

### Tracing Commands
| Command | Description |
|---------|-------------|
| `trace start <target>` | Start stalker tracing |
| `trace stop` | Stop tracing |
| `trace events [limit]` | Show trace events |
| `trace clear` | Clear events |

### Store Commands
| Command | Description |
|---------|-------------|
| `field list [page]` | Show Field store |
| `field next [n]` | Next page |
| `field prev [n]` | Previous page |
| `field filter <expr>` | Filter data |
| `field clear` | Clear store |
| `lib list [page]` | Show Lib store |
| `lib save [sel]` | Save to lib |
| `lib remove <idx>` | Remove from lib |

---

## Implementation Order

### Sprint 1: Foundation
1. Rustyline integration in session.rs
2. Basic tab completion for commands
3. Command history persistence

### Sprint 2: Core Features (High Priority)
1. Function hooking (Interceptor)
2. Disassembly support
3. Hook message handling

### Sprint 3: Memory Operations
1. Memory pattern scanning
2. Value scanning with type support
3. Scan refinement (next scan)

### Sprint 4: Code Modification
1. Byte patching
2. NOP instructions
3. Memory protection changes

### Sprint 5: Thread Operations
1. Thread enumeration
2. Register inspection
3. Stack dumping
4. Backtrace

### Sprint 6: Advanced Features
1. Stalker code tracing
2. API Resolver integration
3. Import/Export analysis

### Sprint 7: Polish
1. Session save/restore
2. Export to file
3. Configuration support
4. Documentation

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Frida API changes | Pin frida version, test thoroughly |
| Architecture differences | Abstract arch-specific code |
| Memory access errors | Comprehensive protection checks |
| Performance with large data | Pagination, lazy loading |
| Complex hook states | State machine for hook lifecycle |

---

## Testing Strategy

1. **Unit Tests**: Test parsing, formatting, data structures
2. **Integration Tests**: Test against known binaries
3. **Platform Tests**: Test on Linux, macOS, Windows
4. **Architecture Tests**: Test on x64, ARM64

---

## Success Criteria

- [ ] Function hooking works reliably on all platforms
- [ ] Disassembly displays correctly for x64/ARM64
- [ ] Memory scanning finds values accurately
- [ ] Code patching persists and can be reverted
- [ ] Thread operations work across platforms
- [ ] REPL has history, completion, and smooth UX
- [ ] Performance is acceptable for large processes

