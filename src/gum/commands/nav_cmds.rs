// src/gum/commands/nav_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    // select <selector>
    cmds.push(Command::new(
        "select",
        "Select a data item into the navigator by selector or index",
        vec![],
        vec![CommandArg::required(
            "selector",
            "Selector expression or index (optionally prefixed by store)",
        )],
        vec![],
        Some(|c, a| Commander::select(c, a)),
    ));

    // deselect
    cmds.push(Command::new(
        "deselect",
        "Clear the navigator selection",
        vec![],
        vec![],
        vec![],
        Some(|c, a| Commander::deselect(c, a)),
    ));

    // add <offset>
    cmds.push(Command::new(
        "add",
        "Add an offset to the current navigator address",
        vec![],
        vec![CommandArg::required("offset", "Offset to add (hex or dec)")],
        vec![],
        Some(|c, a| Commander::add(c, a)),
    ));

    // sub <offset>
    cmds.push(Command::new(
        "sub",
        "Subtract an offset from the current navigator address",
        vec![],
        vec![CommandArg::required("offset", "Offset to subtract (hex or dec)")],
        vec![],
        Some(|c, a| Commander::sub(c, a)),
    ));

    // goto <address>
    cmds.push(Command::new(
        "goto",
        "Jump navigator to an absolute address",
        vec![],
        vec![CommandArg::required("address", "Address to jump to (hex or dec)")],
        vec![],
        Some(|c, a| Commander::goto(c, a)),
    ));

    cmds
}
