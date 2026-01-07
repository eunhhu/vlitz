// src/gum/commands/disasm_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander, SubCommand};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // Main disassemble command
    cmds.push(Command::new(
        "disas",
        "Disassemble instructions at address",
        vec!["dis", "u"],  // 'u' is common in debuggers for unassemble
        vec![
            CommandArg::optional("target", "Address, selector, or function name"),
            CommandArg::optional("count", "Number of instructions to disassemble (default 20)"),
        ],
        vec![
            SubCommand::new(
                "func",
                "Disassemble an entire function until return",
                vec![
                    CommandArg::optional("target", "Address or selector of function"),
                ],
                |c, a| Commander::disas_function(c, a),
            )
            .alias("f"),
        ],
        Some(|c, a| Commander::disas(c, a)),
    ));

    // Patch commands (grouped with disassembly as code modification)
    let mut patch_subs: Vec<SubCommand> = Vec::new();

    patch_subs.push(SubCommand::new(
        "bytes",
        "Patch bytes at address",
        vec![
            CommandArg::required("target", "Address or selector"),
            CommandArg::required("bytes", "Hex bytes to write (e.g., '90 90 90')"),
        ],
        |c, a| Commander::patch_bytes(c, a),
    ));

    patch_subs.push(SubCommand::new(
        "nop",
        "NOP out instructions at address",
        vec![
            CommandArg::required("target", "Address or selector"),
            CommandArg::optional("count", "Number of instructions to NOP (default 1)"),
        ],
        |c, a| Commander::patch_nop(c, a),
    ));

    patch_subs.push(SubCommand::new(
        "restore",
        "Restore original bytes at address",
        vec![
            CommandArg::required("target", "Address or selector"),
        ],
        |c, a| Commander::patch_restore(c, a),
    ));

    cmds.push(Command::new(
        "patch",
        "Code patching operations",
        vec!["p"],
        vec![],
        patch_subs,
        None,
    ));

    // NOP shortcut command
    cmds.push(Command::new(
        "nop",
        "NOP out instructions (shortcut for patch nop)",
        vec![],
        vec![
            CommandArg::required("target", "Address or selector"),
            CommandArg::optional("count", "Number of instructions to NOP (default 1)"),
        ],
        vec![],
        Some(|c, a| Commander::patch_nop(c, a)),
    ));

    cmds
}
