// src/gum/commands/memory_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander, SubCommand};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // list command group: modules, ranges, functions, variables
    let mut list_subs: Vec<SubCommand> = Vec::new();
    list_subs.push(SubCommand::new(
        "modules",
        "List process modules into Field store",
        vec![CommandArg::optional("filter", "Optional name filter (substring)")],
        |c, a| Commander::list_modules(c, a),
    ));
    list_subs.push(SubCommand::new(
        "ranges",
        "List memory ranges into Field store",
        vec![
            CommandArg::optional("protect", "Protection filter, e.g. r-x, rw-"),
            CommandArg::optional("filter", "Optional name filter (substring)")
        ],
        |c, a| Commander::list_ranges(c, a),
    ));
    list_subs.push(SubCommand::new(
        "functions",
        "List functions of a module into Field store",
        vec![
            CommandArg::optional(
                "module_selector",
                "Module selector or index; falls back to navigator module",
            ),
            CommandArg::optional("filter", "Optional name filter (substring)"),
        ],
        |c, a| Commander::list_functions(c, a),
    ));
    list_subs.push(SubCommand::new(
        "variables",
        "List variables of a module into Field store",
        vec![
            CommandArg::optional(
                "module_selector",
                "Module selector or index; falls back to navigator module",
            ),
            CommandArg::optional("filter", "Optional name filter (substring)"),
        ],
        |c, a| Commander::list_variables(c, a),
    ));

    cmds.push(Command::new(
        "list",
        "Enumerate target information into Field store",
        vec!["ls"],
        vec![],
        list_subs,
        None,
    ));

    // view
    cmds.push(Command::new(
        "view",
        "View memory at address/selection or at navigator address",
        vec!["v"],
        vec![
            CommandArg::optional(
                "target_or_size",
                "Selector/address or size if using navigator",
            ),
            CommandArg::optional("size", "Bytes to view (default 256)"),
            CommandArg::optional("type", "Value type (Byte, Word, DWord, QWord, etc.)"),
        ],
        vec![],
        Some(|c, a| Commander::view(c, a)),
    ));

    // read
    cmds.push(Command::new(
        "read",
        "Read memory at address/selection",
        vec!["r"],
        vec![
            CommandArg::required("target", "Selector or numeric address"),
            CommandArg::optional("type", "Value type (default Byte)"),
            CommandArg::optional("length", "Number of elements/bytes (default 16)"),
        ],
        vec![],
        Some(|c, a| Commander::read(c, a)),
    ));

    // write
    cmds.push(Command::new(
        "write",
        "Write value to address/selection",
        vec!["w"],
        vec![
            CommandArg::required("target", "Selector or numeric address"),
            CommandArg::required("value", "Value to write"),
            CommandArg::optional("type", "Value type (default Byte)"),
        ],
        vec![],
        Some(|c, a| Commander::write(c, a)),
    ));

    cmds
}
