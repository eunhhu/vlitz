// src/gum/commands/scan_cmds.rs

use crate::gum::commander::{Command, CommandArg, Commander, SubCommand};

pub(crate) fn build() -> Vec<Command> {
    let mut cmds: Vec<Command> = Vec::new();

    let mut scan_subs: Vec<SubCommand> = Vec::new();

    scan_subs.push(SubCommand::new(
        "bytes",
        "Scan for byte pattern (hex with ?? wildcards: 'AA BB ?? CC')",
        vec![
            CommandArg::required("pattern", "Byte pattern to search"),
            CommandArg::optional("protection", "Memory protection filter (e.g., 'r--', 'rw-')"),
        ],
        |c, a| Commander::scan_bytes(c, a),
    ));

    scan_subs.push(SubCommand::new(
        "string",
        "Scan for ASCII string",
        vec![
            CommandArg::required("text", "String to search"),
            CommandArg::optional("protection", "Memory protection filter"),
        ],
        |c, a| Commander::scan_string(c, a),
    ));

    scan_subs.push(
        SubCommand::new(
            "value",
            "Scan for typed value (int, float, etc.)",
            vec![
                CommandArg::required("type", "Value type: byte, short, int, long, float, double"),
                CommandArg::required("value", "Value to search"),
                CommandArg::optional("protection", "Memory protection filter"),
            ],
            |c, a| Commander::scan_value(c, a),
        )
        .alias("v"),
    );

    scan_subs.push(
        SubCommand::new(
            "next",
            "Refine scan results with new value",
            vec![
                CommandArg::required("value", "New value to filter by"),
                CommandArg::optional("comparison", "Comparison: eq, ne, gt, lt, ge, le (default: eq)"),
            ],
            |c, a| Commander::scan_next(c, a),
        )
        .alias("n"),
    );

    scan_subs.push(SubCommand::new(
        "changed",
        "Filter for addresses where value changed since snapshot",
        vec![],
        |c, a| Commander::scan_changed(c, a),
    ));

    scan_subs.push(SubCommand::new(
        "unchanged",
        "Filter for addresses where value is same as snapshot",
        vec![],
        |c, a| Commander::scan_unchanged(c, a),
    ));

    scan_subs.push(SubCommand::new(
        "snapshot",
        "Take a snapshot of current values for comparison",
        vec![],
        |c, a| Commander::scan_snapshot(c, a),
    ));

    scan_subs.push(
        SubCommand::new(
            "results",
            "Show current scan results",
            vec![
                CommandArg::optional("offset", "Result offset (default 0)"),
                CommandArg::optional("limit", "Number of results to show (default 50)"),
            ],
            |c, a| Commander::scan_results(c, a),
        )
        .alias("r"),
    );

    scan_subs.push(
        SubCommand::new(
            "list",
            "List scan results and load into Field store",
            vec![
                CommandArg::optional("limit", "Max results to load (default 100)"),
            ],
            |c, a| Commander::scan_list(c, a),
        )
        .alias("ls"),
    );

    scan_subs.push(SubCommand::new(
        "clear",
        "Clear all scan results",
        vec![],
        |c, a| Commander::scan_clear(c, a),
    ));

    cmds.push(Command::new(
        "scan",
        "Memory scanning operations",
        vec!["s"],
        vec![],
        scan_subs,
        Some(|c, a| Commander::scan_results(c, a)), // Default to showing results
    ));

    // Thread commands (related to memory inspection)
    let mut thread_subs: Vec<SubCommand> = Vec::new();

    thread_subs.push(
        SubCommand::new(
            "list",
            "List all threads in the process",
            vec![],
            |c, a| Commander::thread_list(c, a),
        )
        .alias("ls"),
    );

    thread_subs.push(
        SubCommand::new(
            "regs",
            "Show registers for a thread",
            vec![CommandArg::optional("thread_id", "Thread ID (default: current)")],
            |c, a| Commander::thread_regs(c, a),
        )
        .alias("r"),
    );

    thread_subs.push(
        SubCommand::new(
            "stack",
            "Dump stack for a thread",
            vec![
                CommandArg::optional("thread_id", "Thread ID (default: current)"),
                CommandArg::optional("depth", "Stack depth to show (default 32)"),
            ],
            |c, a| Commander::thread_stack(c, a),
        )
        .alias("s"),
    );

    thread_subs.push(
        SubCommand::new(
            "backtrace",
            "Show backtrace for a thread",
            vec![CommandArg::optional("thread_id", "Thread ID (default: current)")],
            |c, a| Commander::thread_backtrace(c, a),
        )
        .alias("bt"),
    );

    cmds.push(Command::new(
        "thread",
        "Thread inspection operations",
        vec!["t"],
        vec![],
        thread_subs,
        Some(|c, a| Commander::thread_list(c, a)), // Default to list
    ));

    cmds
}
