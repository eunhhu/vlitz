// src/gum/commands/mod.rs

pub mod memory_cmds;
pub mod nav_cmds;
pub mod store_cmds;

use crate::gum::commander::{Command, CommandArg, SubCommand};
use crate::gum::commander::Commander;

pub fn build_all() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // Core commands: debug, help, exit
    cmds.push(Command::new(
        "debug",
        "Debug functions",
        vec!["d"],
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
        vec!["h"],
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

    // Grouped commands
    cmds.extend(nav_cmds::build());
    cmds.extend(store_cmds::build());
    cmds.extend(memory_cmds::build());

    cmds
}
