// src/gum/commands/store_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander, SubCommand};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // field command with subcommands
    let mut field_subs: Vec<SubCommand> = Vec::new();
    field_subs.push(
        SubCommand::new(
            "list",
            "Show Field store page (optionally jump to page)",
            vec![CommandArg::optional("page", "1-based page number")],
            |c, a| Commander::field_list(c, a),
        )
        .alias("ls"),
    );
    field_subs.push(SubCommand::new(
        "next",
        "Go to next page in Field store (optionally by N pages)",
        vec![CommandArg::optional("pages", "Number of pages to advance")],
        |c, a| Commander::field_next(c, a),
    ));
    field_subs.push(SubCommand::new(
        "prev",
        "Go to previous page in Field store (optionally by N pages)",
        vec![CommandArg::optional("pages", "Number of pages to go back")],
        |c, a| Commander::field_prev(c, a),
    ));
    field_subs.push(SubCommand::new(
        "sort",
        "Sort Field store by a column",
        vec![CommandArg::optional("key", "Column key to sort by")],
        |c, a| Commander::field_sort(c, a),
    ));
    field_subs.push(SubCommand::new(
        "move",
        "Move an item from one index to another in Field store",
        vec![
            CommandArg::required("from", "1-based source index"),
            CommandArg::required("to", "1-based destination index"),
        ],
        |c, a| Commander::field_move(c, a),
    ));
    field_subs.push(
        SubCommand::new(
            "remove",
            "Remove one or more items from Field store",
            vec![
                CommandArg::required("index", "1-based start index"),
                CommandArg::optional("count", "Number of items to remove (default 1)"),
            ],
            |c, a| Commander::field_remove(c, a),
        )
        .alias("rm"),
    );
    field_subs.push(SubCommand::new(
        "clear",
        "Clear all items from Field store",
        vec![],
        |c, a| Commander::field_clear(c, a),
    ));
    field_subs.push(SubCommand::new(
        "filter",
        "Apply filter expression to Field store",
        vec![CommandArg::optional("expr", "Filter expression")],
        |c, a| Commander::field_filter(c, a),
    ));

    cmds.push(Command::new(
        "field",
        "Operations on the Field working set",
        vec!["f", "fld"],
        vec![],
        field_subs,
        None,
    ));

    // lib command with subcommands
    let mut lib_subs: Vec<SubCommand> = Vec::new();
    lib_subs.push(
        SubCommand::new(
            "list",
            "Show Lib store page (optionally jump to page)",
            vec![CommandArg::optional("page", "1-based page number")],
            |c, a| Commander::lib_list(c, a),
        )
        .alias("ls"),
    );
    lib_subs.push(SubCommand::new(
        "next",
        "Go to next page in Lib store (optionally by N pages)",
        vec![CommandArg::optional("pages", "Number of pages to advance")],
        |c, a| Commander::lib_next(c, a),
    ));
    lib_subs.push(SubCommand::new(
        "prev",
        "Go to previous page in Lib store (optionally by N pages)",
        vec![CommandArg::optional("pages", "Number of pages to go back")],
        |c, a| Commander::lib_prev(c, a),
    ));
    lib_subs.push(SubCommand::new(
        "sort",
        "Sort Lib store by a column",
        vec![CommandArg::optional("key", "Column key to sort by")],
        |c, a| Commander::lib_sort(c, a),
    ));
    lib_subs.push(SubCommand::new(
        "save",
        "Save selected Field item(s) or navigator item into Lib store",
        vec![CommandArg::optional(
            "selector",
            "Field selector; if omitted, uses navigator selection",
        )],
        |c, a| Commander::lib_save(c, a),
    ));
    lib_subs.push(SubCommand::new(
        "move",
        "Move an item from one index to another in Lib store",
        vec![
            CommandArg::required("from", "1-based source index"),
            CommandArg::required("to", "1-based destination index"),
        ],
        |c, a| Commander::lib_move(c, a),
    ));
    lib_subs.push(
        SubCommand::new(
            "remove",
            "Remove one or more items from Lib store",
            vec![
                CommandArg::required("index", "1-based start index"),
                CommandArg::optional("count", "Number of items to remove (default 1)"),
            ],
            |c, a| Commander::lib_remove(c, a),
        )
        .alias("rm"),
    );
    lib_subs.push(SubCommand::new(
        "clear",
        "Clear all items from Lib store",
        vec![],
        |c, a| Commander::lib_clear(c, a),
    ));
    lib_subs.push(SubCommand::new(
        "filter",
        "Apply filter expression to Lib store",
        vec![CommandArg::optional("expr", "Filter expression")],
        |c, a| Commander::lib_filter(c, a),
    ));

    cmds.push(Command::new(
        "lib",
        "Operations on the Lib saved set",
        vec!["l"],
        vec![],
        lib_subs,
        None,
    ));

    cmds
}
