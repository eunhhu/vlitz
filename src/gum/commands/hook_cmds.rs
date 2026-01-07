// src/gum/commands/hook_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander, SubCommand};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    let mut hook_subs: Vec<SubCommand> = Vec::new();

    hook_subs.push(
        SubCommand::new(
            "add",
            "Add a hook to target address or function",
            vec![
                CommandArg::required("target", "Address, selector, or function name"),
                CommandArg::optional("options", "Hook options: -e (enter) -l (leave) -a (args) -r (retval) -b (backtrace)"),
            ],
            |c, a| Commander::hook_add(c, a),
        )
        .alias("a"),
    );

    hook_subs.push(
        SubCommand::new(
            "remove",
            "Remove a hook by ID",
            vec![CommandArg::required("id", "Hook ID to remove (e.g., hook_0)")],
            |c, a| Commander::hook_remove(c, a),
        )
        .alias("rm"),
    );

    hook_subs.push(
        SubCommand::new(
            "list",
            "List all active hooks",
            vec![],
            |c, a| Commander::hook_list(c, a),
        )
        .alias("ls"),
    );

    hook_subs.push(
        SubCommand::new(
            "enable",
            "Enable a disabled hook",
            vec![CommandArg::required("id", "Hook ID to enable")],
            |c, a| Commander::hook_enable(c, a),
        )
        .alias("en"),
    );

    hook_subs.push(
        SubCommand::new(
            "disable",
            "Disable an active hook (keeps configuration)",
            vec![CommandArg::required("id", "Hook ID to disable")],
            |c, a| Commander::hook_disable(c, a),
        )
        .alias("dis"),
    );

    hook_subs.push(SubCommand::new(
        "clear",
        "Remove all active hooks",
        vec![],
        |c, a| Commander::hook_clear(c, a),
    ));

    cmds.push(Command::new(
        "hook",
        "Function hooking operations",
        vec!["hk"],
        vec![],
        hook_subs,
        Some(|c, a| Commander::hook_list(c, a)), // Default to list
    ));

    cmds
}
