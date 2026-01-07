// src/gum/commands/mod.rs

pub mod memory_cmds;
pub mod nav_cmds;
pub mod store_cmds;
pub mod hook_cmds;
pub mod disasm_cmds;
pub mod scan_cmds;

use crate::gum::commander::{Command, CommandArg, SubCommand};
use crate::gum::commander::Commander;

pub fn build_all() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // Core commands: debug, help, exit, clear
    cmds.push(Command::new(
        "debug",
        "Debug functions",
        vec!["dbg"],
        vec![],
        vec![SubCommand::new("exports", "List exports", vec![], |c, a| {
            Commander::debug_exports(c, a)
        })
        .alias("e")],
        None,
    ));

    cmds.push(Command::new(
        "help",
        "Show this help message",
        vec!["h", "?"],
        vec![CommandArg::optional("command", "Command to show help for")],
        vec![],
        Some(|c, a| Commander::help(c, a)),
    ));

    cmds.push(Command::new(
        "exit",
        "Exit the session",
        vec!["quit", "q"],
        vec![],
        vec![],
        Some(|c, a| Commander::exit(c, a)),
    ));

    cmds.push(Command::new(
        "clear",
        "Clear the terminal screen",
        vec!["cls"],
        vec![],
        vec![],
        Some(|c, a| Commander::clear_screen(c, a)),
    ));

    // Grouped commands by category
    cmds.extend(nav_cmds::build());      // Navigation: select, deselect, add, sub, goto
    cmds.extend(store_cmds::build());    // Stores: field, lib
    cmds.extend(memory_cmds::build());   // Memory: list, view, read, write
    cmds.extend(hook_cmds::build());     // Hooking: hook add/remove/list/enable/disable
    cmds.extend(disasm_cmds::build());   // Disassembly: disas, patch, nop
    cmds.extend(scan_cmds::build());     // Scanning: scan, thread

    cmds
}
