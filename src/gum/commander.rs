// src/gum/commander.rs
use crate::gum::{
    filter::parse_filter_string,
    list::{list_functions, list_ranges, list_variables},
    memory::{get_address_from_data, parse_value_type, read_memory_by_type, write_memory_by_type},
};
use crate::util::logger;
use crossterm::style::Stylize;

use super::{list::list_modules, navigator::Navigator, store::Store, vzdata::{VzData, VzValueType}};
use frida::Script;
use regex::Regex;
use std::{fmt, vec};

#[derive(Debug)]
struct CommandArg {
    name: String,
    description: String,
    required: bool,
}

impl CommandArg {
    fn new(name: &str, description: &str, required: bool) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            required,
        }
    }

    fn required(name: &str, description: &str) -> Self {
        Self::new(name, description, true)
    }

    fn optional(name: &str, description: &str) -> Self {
        Self::new(name, description, false)
    }
}

impl fmt::Display for CommandArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.required {
            write!(f, "<{}>", self.name)
        } else {
            write!(f, "[{}]", self.name)
        }
    }
}

type CommandHandler = fn(&mut Commander, &[&str]) -> bool;

struct SubCommand {
    name: String,
    aliases: Vec<String>,
    description: String,
    args: Vec<CommandArg>,
    execute: CommandHandler,
}

impl SubCommand {
    fn new(name: &str, description: &str, args: Vec<CommandArg>, execute: CommandHandler) -> Self {
        Self {
            name: name.to_string(),
            aliases: Vec::new(),
            description: description.to_string(),
            args,
            execute,
        }
    }

    fn alias(mut self, alias: &str) -> Self {
        self.aliases.push(alias.to_string());
        self
    }
}

struct Command {
    command: String,
    description: String,
    aliases: Vec<String>,
    args: Vec<CommandArg>,
    subcommands: Vec<SubCommand>,
    default_execute: Option<CommandHandler>,
}

impl Command {
    fn new(
        command: &str,
        description: &str,
        aliases: Vec<&str>,
        args: Vec<CommandArg>,
        subcommands: Vec<SubCommand>,
        default_execute: Option<CommandHandler>,
    ) -> Self {
        Self {
            command: command.to_string(),
            description: description.to_string(),
            aliases: aliases.into_iter().map(String::from).collect(),
            args,
            subcommands,
            default_execute,
        }
    }
}

pub struct Commander<'a, 'b> {
    script: &'a mut Script<'b>,
    pub env: String,
    field: Store,
    lib: Store,
    pub navigator: Navigator,
    commands: Vec<Command>,
}

impl<'a, 'b> Commander<'a, 'b> {
    pub fn new(script: &'a mut Script<'b>) -> Self {
        let env_value = script
            .exports
            .call("get_env", None)
            .expect("Failed to call get_env")
            .expect("Failed to get env value");
        let env_arr = env_value.as_array().cloned().unwrap_or_default();
        let os = env_arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let arch = env_arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
        Commander {
            script,
            env: format!("{} {}", os, arch),
            field: Store::new("Field".to_string()),
            lib: Store::new("Lib".to_string()),
            navigator: Navigator::new(),
            commands: vec![
                Command::new(
                    "debug",
                    "Debug functions",
                    vec!["d"],
                    vec![],
                    vec![SubCommand::new("exports", "List exports", vec![], |c, a| {
                        Commander::debug_exports(c, a)
                    })
                    .alias("e")],
                    None,
                ),
                Command::new(
                    "help",
                    "Show this help message",
                    vec!["h"],
                    vec![CommandArg::optional("command", "Command to show help for")],
                    vec![],
                    Some(|c, a| Commander::help(c, a)),
                ),
                Command::new(
                    "exit",
                    "Exit the session",
                    vec!["quit", "q"],
                    vec![],
                    vec![],
                    Some(|c, a| Commander::exit(c, a)),
                ),
                Command::new(
                    "select",
                    "Select data",
                    vec!["sel", "sl"],
                    vec![CommandArg::required("selector", "Selector")],
                    vec![],
                    Some(|c, a| Commander::select(c, a)),
                ),
                Command::new(
                    "deselect",
                    "Deselect data",
                    vec!["desel", "dsl"],
                    vec![],
                    vec![],
                    Some(|c, a| Commander::deselect(c, a)),
                ),
                Command::new(
                    "add",
                    "Add offset to selected data",
                    vec!["+"],
                    vec![CommandArg::required("offset", "Offset")],
                    vec![],
                    Some(|c, a| Commander::add(c, a)),
                ),
                Command::new(
                    "sub",
                    "Subtract offset from selected data",
                    vec!["-"],
                    vec![CommandArg::required("offset", "Offset")],
                    vec![],
                    Some(|c, a| Commander::sub(c, a)),
                ),
                Command::new(
                    "goto",
                    "Go to address",
                    vec!["go", ":"],
                    vec![CommandArg::required("address", "Address")],
                    vec![],
                    Some(|c, a| Commander::goto(c, a)),
                ),
                Command::new(
                    "field",
                    "Field manipulation commands.",
                    vec!["fld", "f"],
                    vec![CommandArg::optional("page", "Page number")],
                    vec![
                        SubCommand::new(
                            "list",
                            "List fields with optional page number",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_list(c, a),
                        )
                        .alias("ls")
                        .alias("l"),
                        SubCommand::new(
                            "next",
                            "Go to next page of fields",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_next(c, a),
                        )
                        .alias("n"),
                        SubCommand::new(
                            "prev",
                            "Go to previous page of fields",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_prev(c, a),
                        )
                        .alias("p"),
                        SubCommand::new(
                            "sort",
                            "Sort fields by name",
                            vec![CommandArg::optional("type", "Sort type [addr]")],
                            |c, a| Commander::field_sort(c, a),
                        )
                        .alias("s"),
                        SubCommand::new(
                            "move",
                            "Move fields",
                            vec![
                                CommandArg::required("from", "Index of data"),
                                CommandArg::required("to", "Index of data"),
                            ],
                            |c, a| Commander::field_move(c, a),
                        )
                        .alias("mv"),
                        SubCommand::new(
                            "remove",
                            "Remove data from field",
                            vec![
                                CommandArg::required("index", "Index of data"),
                                CommandArg::optional(
                                    "count",
                                    "Count of data to remove (default: 1)",
                                ),
                            ],
                            |c, a| Commander::field_remove(c, a),
                        )
                        .alias("rm")
                        .alias("del")
                        .alias("delete"),
                        SubCommand::new("clear", "Clear all fields", vec![], |c, a| {
                            Commander::field_clear(c, a)
                        })
                        .alias("cls")
                        .alias("clr")
                        .alias("cl")
                        .alias("c"),
                        SubCommand::new(
                            "filter",
                            "Filter fields",
                            vec![CommandArg::required(
                                "filter",
                                "Filter as filter expression",
                            )],
                            |c, a| Commander::field_filter(c, a),
                        )
                        .alias("f")
                        .alias("filter"),
                    ],
                    Some(|c, a| Commander::field_list(c, a)),
                ),
                Command::new(
                    "save",
                    "Save data from field",
                    vec!["sv"],
                    vec![CommandArg::required("selector", "Selector from field")],
                    vec![],
                    Some(|c, a| Commander::lib_save(c, a)),
                ),
                Command::new(
                    "lib",
                    "Library manipulation commands.",
                    vec!["lb", "l"],
                    vec![CommandArg::optional("page", "Page number")],
                    vec![
                        SubCommand::new(
                            "list",
                            "List libraries with optional page number",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_list(c, a),
                        )
                        .alias("ls")
                        .alias("l"),
                        SubCommand::new(
                            "next",
                            "Go to next page of libraries",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_next(c, a),
                        )
                        .alias("n"),
                        SubCommand::new(
                            "prev",
                            "Go to previous page of libraries",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_prev(c, a),
                        )
                        .alias("p"),
                        SubCommand::new(
                            "sort",
                            "Sort libraries by name",
                            vec![CommandArg::optional("type", "Sort type [addr]")],
                            |c, a| Commander::lib_sort(c, a),
                        )
                        .alias("s"),
                        SubCommand::new(
                            "move",
                            "Move data from one library to another",
                            vec![
                                CommandArg::required("from", "Index of data"),
                                CommandArg::required("to", "Index of data"),
                            ],
                            |c, a| Commander::lib_move(c, a),
                        )
                        .alias("mv"),
                        SubCommand::new(
                            "remove",
                            "Remove data from library",
                            vec![
                                CommandArg::required("index", "Index of data"),
                                CommandArg::optional(
                                    "count",
                                    "Count of data to remove (default: 1)",
                                ),
                            ],
                            |c, a| Commander::lib_remove(c, a),
                        )
                        .alias("rm")
                        .alias("del")
                        .alias("delete"),
                        SubCommand::new("clear", "Clear all data", vec![], |c, a| {
                            Commander::lib_clear(c, a)
                        })
                        .alias("cls")
                        .alias("clr")
                        .alias("cl")
                        .alias("c"),
                        SubCommand::new(
                            "filter",
                            "Filter libraries",
                            vec![CommandArg::required("filter", "Filter expression")],
                            |c, a| Commander::lib_filter(c, a),
                        )
                        .alias("f")
                        .alias("filter"),
                    ],
                    Some(|c, a| Commander::lib_list(c, a)),
                ),
                Command::new(
                    "list",
                    "List all data",
                    vec!["ls"],
                    vec![],
                    vec![
                        SubCommand::new(
                            "modules",
                            "List all modules",
                            vec![CommandArg::optional("filter", "Filter modules")],
                            |c, a| Commander::list_modules(c, a),
                        )
                        .alias("mods")
                        .alias("md")
                        .alias("m"),
                        SubCommand::new(
                            "ranges",
                            "List all ranges",
                            vec![CommandArg::optional("filter", "Filter ranges")],
                            |c, a| Commander::list_ranges(c, a),
                        )
                        .alias("ranges")
                        .alias("rngs")
                        .alias("rng")
                        .alias("r"),
                        SubCommand::new(
                            "functions",
                            "List all functions",
                            vec![CommandArg::optional("filter", "Filter functions")],
                            |c, a| Commander::list_functions(c, a),
                        )
                        .alias("funcs")
                        .alias("fns")
                        .alias("fn")
                        .alias("f"),
                        SubCommand::new(
                            "variables",
                            "List all variables",
                            vec![CommandArg::optional("filter", "Filter variables")],
                            |c, a| Commander::list_variables(c, a),
                        )
                        .alias("vars")
                        .alias("vrs")
                        .alias("vr")
                        .alias("v"),
                    ],
                    None,
                ),
                Command::new(
                    "read",
                    "Read data from memory",
                    vec!["r"],
                    vec![
                        CommandArg::optional("address", "Address (0x100), store selector (field:5, lib:3), or navigator data"),
                        CommandArg::optional("type", "Data type (byte, short, int, long, float, double, string, bytes, pointer)"),
                        CommandArg::optional("length", "Length for bytes/array types (default: 16)"),
                    ],
                    vec![],
                    Some(|c, a| Commander::read(c, a)),
                ),
                Command::new(
                    "write",
                    "Write data to memory",
                    vec!["w"],
                    vec![
                        CommandArg::optional("address", "Address (0x100), store selector (field:5, lib:3), or navigator data"),
                        CommandArg::required("value", "Value to write"),
                        CommandArg::optional("type", "Data type (byte, short, int, long, float, double, string, bytes, pointer)"),
                    ],
                    vec![],
                    Some(|c, a| Commander::write(c, a)),
                ),
            ],
        }
    }

    pub fn execute_command(&mut self, command: &str, args: &[&str]) -> bool {
        if let Some(cmd) = self
            .commands
            .iter()
            .find(|c| c.command == command || c.aliases.contains(&command.to_string()))
        {
            if !cmd.subcommands.is_empty() {
                if let Some((subcommand, sub_args)) = args.split_first() {
                    if let Some(sub_cmd) = cmd.subcommands.iter().find(|s| {
                        s.name == *subcommand || s.aliases.contains(&subcommand.to_string())
                    }) {
                        // Check required arguments for the subcommand
                        let required_args = sub_cmd.args.iter().filter(|a| a.required).count();
                        if sub_args.len() < required_args {
                            println!(
                                "{} Expected at least {} arguments, got {}",
                                "Error:".red(),
                                required_args,
                                sub_args.len()
                            );
                            return true;
                        }
                        return (sub_cmd.execute)(self, sub_args);
                    }
                }
                // If we reached here, no valid subcommand was found
                if let Some(default_exec) = &cmd.default_execute {
                    return default_exec(self, args);
                }
                println!(
                    "{} {}",
                    "No subcommand specified.".red(),
                    format!("Use 'help {}' for more information.", command).dark_grey()
                );
                return true;
            } else if let Some(exec) = &cmd.default_execute {
                return exec(self, args);
            }
        } else {
            println!("{} {}", "Unknown command:".red(), command);
        }
        true
    }

    fn help(&mut self, args: &[&str]) -> bool {
        if !args.is_empty() {
            let command = self
                .commands
                .iter()
                .find(|c| c.command == args[0] || c.aliases.contains(&args[0].to_string()));
            if let Some(cmd) = command {
                // Usage
                let args_usage = cmd
                    .args
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "\n{} {}{}",
                    "Usage:".green(),
                    cmd.command.clone().yellow(),
                    if args_usage.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", args_usage)
                    }
                );
                // Description
                println!("{} {}", "Description:".green(), cmd.description);
                // Arguments
                if !cmd.args.is_empty() {
                    println!("\n{}", "Arguments:".green());
                    for arg in &cmd.args {
                        let required = if arg.required { " (required)" } else { "" };
                        println!(
                            "  {:<15} {}{}",
                            format!("{}:", arg.name),
                            arg.description,
                            required.yellow()
                        );
                    }
                }

                // Aliases
                if !cmd.aliases.is_empty() {
                    println!(
                        "\n{} {}",
                        "Aliases:".green(),
                        cmd.aliases.join(", ").dark_grey()
                    );
                }

                // Subcommands
                if !cmd.subcommands.is_empty() {
                    println!("\n{}", "Subcommands:".green());
                    for sub in &cmd.subcommands {
                        let aliases = if !sub.aliases.is_empty() {
                            format!(" ({})", sub.aliases.join(", ").dark_grey())
                        } else {
                            String::new()
                        };
                        let sub_and_args = format!(
                            "{} {}",
                            sub.name,
                            sub.args
                                .iter()
                                .map(|arg| arg.to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                        if sub_and_args.len() > 15 {
                            println!("  {}", sub_and_args);
                            println!("  {} {}{}", " ".repeat(15), sub.description, aliases);
                        } else {
                            println!("  {:<15} {}{}", sub_and_args, sub.description, aliases);
                        }
                    }
                }

                return true;
            }

            println!("{} {}", "Unknown command:".red(), args[0]);
            true
        } else {
            // Show all commands
            println!(
                "  {}{} {}",
                "Command".green().bold(),
                " ".repeat(24 - "Command".len()),
                "Description".green().bold()
            );
            println!("  {:-<24} {:-<40}", "", "");

            for cmd in &self.commands {
                let aliases = if !cmd.aliases.is_empty() {
                    format!(" ({})", cmd.aliases.join(", ").dark_grey())
                } else {
                    String::new()
                };

                let args_usage = cmd
                    .args
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                let cmd_with_args: String = if args_usage.is_empty() {
                    cmd.command.clone().yellow().to_string()
                } else {
                    format!("{} {}", cmd.command.clone().yellow(), args_usage)
                };
                let mut cmd_len = cmd.command.len() + args_usage.len();
                if !args_usage.is_empty() {
                    cmd_len += 1;
                }

                if cmd_len < 24 {
                    println!(
                        "  {}{} {}{}",
                        cmd_with_args,
                        " ".repeat(24 - cmd_len),
                        cmd.description,
                        aliases
                    );
                } else {
                    println!(
                        "  {}\n  {}{}",
                        cmd_with_args,
                        " ".repeat(24),
                        format!("{}{}", cmd.description, aliases)
                    );
                }

                if !cmd.subcommands.is_empty() {
                    for subcmd in &cmd.subcommands {
                        let aliases = if !subcmd.aliases.is_empty() {
                            format!(" ({})", subcmd.aliases.join(", ").dark_grey())
                        } else {
                            String::new()
                        };
                        let args_usage = subcmd
                            .args
                            .iter()
                            .map(|arg| arg.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        let subcmd_with_args = if args_usage.is_empty() {
                            subcmd.name.clone().yellow().to_string()
                        } else {
                            format!("{} {}", subcmd.name.clone().yellow(), args_usage)
                        };
                        let mut subcmd_len = subcmd.name.len() + args_usage.len();
                        if !args_usage.is_empty() {
                            subcmd_len += 1;
                        }
                        if (subcmd_len + cmd.command.len() + 1) < 24 {
                            println!(
                                "  {}{}{} {}{}",
                                " ".repeat(cmd.command.len() + 1),
                                subcmd_with_args,
                                " ".repeat(24 - subcmd_len - cmd.command.len() - 1),
                                subcmd.description,
                                aliases
                            );
                        } else {
                            println!(
                                "  {}{}\n    {}{}{}",
                                " ".repeat(cmd.command.len() + 1),
                                subcmd_with_args,
                                " ".repeat(24 - 1),
                                subcmd.description,
                                aliases
                            );
                        }
                    }
                }
            }

            println!(
                "\nType \'{} {}\' for more information",
                "help".yellow().bold(),
                "[command]".bold()
            );

            true
        }
    }

    fn exit(&mut self, _args: &[&str]) -> bool {
        println!("{}", "Exiting...".yellow());
        false
    }

    fn selector(&mut self, s: &str) -> Result<Vec<&VzData>, String> {
        let re = Regex::new(r"^(?:(\w+):)?(.+)$").expect("Regex compilation failed");
        if let Some(caps) = re.captures(s) {
            let explicit_store_capture = caps.get(1);
            let selector_str = caps
                .get(2)
                .ok_or_else(|| "No selector provided".to_string())?
                .as_str();
            let selector_is_numeric = selector_str.chars().all(char::is_numeric);

            if let Some(store_match) = explicit_store_capture {
                // Store was EXPLICITLY specified
                let store_name = store_match.as_str();
                if store_name == "lib" || store_name == "l" {
                    // Explicit "lib:selector"
                    self.lib.get_data_by_selection(selector_str)
                        .map_err(|e| format!("Selector '{}': search in explicitly specified 'lib' store failed: {}", selector_str, e))
                        .and_then(|data| if data.is_empty() { Err(format!("Selector '{}': no items found in explicitly specified 'lib' store.", selector_str)) } else { Ok(data) })
                } else if store_name == "field" || store_name == "fld" || store_name == "f" {
                    // Explicit "field:selector"
                    self.field.get_data_by_selection(selector_str)
                        .map_err(|e| format!("Selector '{}': search in explicitly specified 'field' store failed: {}", selector_str, e))
                        .and_then(|data| if data.is_empty() { Err(format!("Selector '{}': no items found in explicitly specified 'field' store.", selector_str)) } else { Ok(data) })
                } else {
                    Err(format!(
                        "Unknown explicitly specified store: {}",
                        store_name
                    ))
                }
            } else {
                // NO store specified, default to "lib" with potential fallback for NUMERIC selectors
                match self.lib.get_data_by_selection(selector_str) {
                    Ok(lib_data) => {
                        if lib_data.is_empty() {
                            // Default "lib" search was empty
                            if selector_is_numeric {
                                // Selector is numeric, fallback to "field"
                                self.field.get_data_by_selection(selector_str).map_err(|field_e| {
                                    format!("Selector '{}': no items from 'lib' (default), and 'field' (fallback) search failed: {}", selector_str, field_e)
                                })
                            } else {
                                // Selector non-numeric, no fallback
                                Err(format!("Selector '{}': no items found in 'lib' (default). Non-numeric selectors do not fall back.", selector_str))
                            }
                        } else {
                            // Default "lib" search successful
                            Ok(lib_data)
                        }
                    }
                    Err(lib_e) => {
                        // Error from default "lib" store
                        if selector_is_numeric {
                            // Selector is numeric, fallback to "field"
                            self.field.get_data_by_selection(selector_str).map_err(|field_e| {
                                format!("Selector '{}': 'lib' (default) search failed (Error: {}), and 'field' (fallback) search also failed (Error: {})", selector_str, lib_e, field_e)
                            })
                        } else {
                            // Selector non-numeric, no fallback
                            Err(format!("Selector '{}': 'lib' (default) search failed (Error: {}). Non-numeric selectors do not fall back.", selector_str, lib_e))
                        }
                    }
                }
            }
        } else {
            Err(format!("Invalid selection format: {}", s))
        }
    }

    fn select(&mut self, args: &[&str]) -> bool {
        let selector = args.get(0).unwrap_or(&"");
        let result = self.selector(selector).map_err(|e| {
            println!("Failed to select data: {}", e);
            e
        });
        match result {
            Ok(data) => {
                if data.len() == 1 {
                    let item_to_select = data[0].clone();
                    self.navigator.select(&item_to_select);
                    true
                } else {
                    println!("Multiple data found for selector: {}", selector);
                    true
                }
            }
            Err(_) => true,
        }
    }

    fn deselect(&mut self, _args: &[&str]) -> bool {
        self.navigator.deselect();
        true
    }

    fn parse_number(s: &str) -> Result<u64, String> {
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex number: {}", s))
        } else {
            s.parse::<u64>()
                .map_err(|_| format!("Invalid number: {}", s))
        }
    }

    fn parse_usize(s: &str) -> Result<usize, String> {
        s.parse::<usize>()
            .map_err(|_| format!("Invalid number: {}", s))
    }

    fn add(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(offset)) => self.navigator.add(offset),
            Some(Err(e)) => logger::error(&format!("Invalid offset: {}", e)),
            None => logger::error("Offset argument required"),
        }
        true
    }

    fn sub(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(offset)) => self.navigator.sub(offset),
            Some(Err(e)) => logger::error(&format!("Invalid offset: {}", e)),
            None => logger::error("Offset argument required"),
        }
        true
    }

    fn goto(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(addr)) => self.navigator.goto(addr),
            Some(Err(e)) => logger::error(&format!("Invalid address: {}", e)),
            None => logger::error("Address argument required"),
        }
        true
    }

    fn field_list(&mut self, args: &[&str]) -> bool {
        match args.get(0) {
            Some(v) => match Self::parse_usize(v) {
                Ok(p) => println!("{}", self.field.to_string(Some(p.saturating_sub(1)))),
                Err(e) => logger::error(&e),
            },
            None => println!("{}", self.field.to_string(None)),
        }
        true
    }

    fn field_next(&mut self, args: &[&str]) -> bool {
        let (current_page, total_pages) = self.field.get_page_info();
        if current_page != total_pages {
            match args.get(0) {
                Some(v) => match Self::parse_usize(v) {
                    Ok(p) => self.field.next_page(p.max(1)),
                    Err(e) => logger::error(&e),
                },
                None => self.field.next_page(1),
            }
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_prev(&mut self, args: &[&str]) -> bool {
        let (current_page, _) = self.field.get_page_info();
        if current_page != 1 {
            match args.get(0) {
                Some(v) => match Self::parse_usize(v) {
                    Ok(p) => self.field.prev_page(p.max(1)),
                    Err(e) => logger::error(&e),
                },
                None => self.field.prev_page(1),
            }
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_sort(&mut self, args: &[&str]) -> bool {
        if let Some(sort_by) = args.get(0) {
            self.field.sort(Some(sort_by));
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_move(&mut self, args: &[&str]) -> bool {
        let from_res = args
            .get(0)
            .ok_or("Missing from index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid from index"));
        let to_res = args
            .get(1)
            .ok_or("Missing to index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid to index"));
        match (from_res, to_res) {
            (Ok(from), Ok(to)) => {
                if let Err(e) = self.field.move_data(from, to) {
                    logger::error(&format!("Field move error: {}", e));
                }
            }
            (Err(e), _) | (_, Err(e)) => logger::error(&format!("Field move error: {}", e)),
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_remove(&mut self, args: &[&str]) -> bool {
        let index_res = args
            .get(0)
            .ok_or("Missing index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid index"));
        let count_res = args
            .get(1)
            .unwrap_or(&"1")
            .parse::<usize>()
            .map_err(|_| "Invalid count");
        match (index_res, count_res) {
            (Ok(idx), Ok(count)) => {
                if let Err(e) = self.field.remove_data(idx, count) {
                    logger::error(&format!("Field remove error: {}", e));
                }
            }
            (Err(e), _) | (_, Err(e)) => logger::error(&format!("Field remove error: {}", e)),
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_clear(&mut self, _args: &[&str]) -> bool {
        self.field.clear_data();
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_filter(&mut self, args: &[&str]) -> bool {
        let filter_arg = args.get(0).map_or("", |v| v);
        let filter = parse_filter_string(filter_arg).unwrap_or_else(|_| {
            logger::error(&format!("Failed to parse filter string: {}", filter_arg));
            Vec::new()
        });
        self.field.filter(filter);
        println!("{}", self.field.to_string(None));
        true
    }

    fn lib_list(&mut self, args: &[&str]) -> bool {
        match args.get(0) {
            Some(v) => match Self::parse_usize(v) {
                Ok(p) => println!("{}", self.lib.to_string(Some(p.saturating_sub(1)))),
                Err(e) => logger::error(&e),
            },
            None => println!("{}", self.lib.to_string(None)),
        }
        true
    }

    fn lib_next(&mut self, args: &[&str]) -> bool {
        let (current_page, total_pages) = self.lib.get_page_info();
        if current_page != total_pages {
            match args.get(0) {
                Some(v) => match Self::parse_usize(v) {
                    Ok(p) => self.lib.next_page(p.max(1)),
                    Err(e) => logger::error(&e),
                },
                None => self.lib.next_page(1),
            }
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_prev(&mut self, args: &[&str]) -> bool {
        let (current_page, _) = self.lib.get_page_info();
        if current_page != 1 {
            match args.get(0) {
                Some(v) => match Self::parse_usize(v) {
                    Ok(p) => self.lib.prev_page(p.max(1)),
                    Err(e) => logger::error(&e),
                },
                None => self.lib.prev_page(1),
            }
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_sort(&mut self, args: &[&str]) -> bool {
        if let Some(sort_by) = args.get(0) {
            self.lib.sort(Some(sort_by));
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_save(&mut self, args: &[&str]) -> bool {
        let datas_res = if let Some(sel) = args.get(0) {
            self.field.get_data_by_selection(sel)
        } else {
            match self.navigator.get_data() {
                Some(d) => Ok(vec![d]),
                None => Err("No selector provided and navigator is empty".to_string()),
            }
        };
        match datas_res {
            Ok(datas) if !datas.is_empty() => {
                self.lib.add_datas(
                    datas
                        .into_iter()
                        .map(|d| {
                            let mut d = d.clone();
                            match &mut d {
                                VzData::Pointer(p) => {
                                    p.base.is_saved = true;
                                }
                                VzData::Module(m) => {
                                    m.base.is_saved = true;
                                }
                                VzData::Range(r) => {
                                    r.base.is_saved = true;
                                }
                                VzData::Function(f) => {
                                    f.base.is_saved = true;
                                }
                                VzData::Variable(v) => {
                                    v.base.is_saved = true;
                                }
                                VzData::JavaClass(c) => {
                                    c.base.is_saved = true;
                                }
                                VzData::JavaMethod(m) => {
                                    m.base.is_saved = true;
                                }
                                VzData::ObjCClass(c) => {
                                    c.base.is_saved = true;
                                }
                                VzData::ObjCMethod(m) => {
                                    m.base.is_saved = true;
                                }
                                VzData::Thread(t) => {
                                    t.base.is_saved = true;
                                }
                            }
                            d
                        })
                        .collect(),
                );
            }
            Ok(_) => logger::error("No data selected"),
            Err(e) => logger::error(&format!("Selection error: {}", e)),
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_move(&mut self, args: &[&str]) -> bool {
        let from_res = args
            .get(0)
            .ok_or("Missing from index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid from index"));
        let to_res = args
            .get(1)
            .ok_or("Missing to index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid to index"));
        match (from_res, to_res) {
            (Ok(from), Ok(to)) => {
                if let Err(e) = self.lib.move_data(from, to) {
                    logger::error(&format!("Lib move error: {}", e));
                }
            }
            (Err(e), _) | (_, Err(e)) => logger::error(&format!("Lib move error: {}", e)),
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_remove(&mut self, args: &[&str]) -> bool {
        let index_res = args
            .get(0)
            .ok_or("Missing index")
            .and_then(|v| v.parse::<usize>().map_err(|_| "Invalid index"));
        let count_res = args
            .get(1)
            .unwrap_or(&"1")
            .parse::<usize>()
            .map_err(|_| "Invalid count");
        match (index_res, count_res) {
            (Ok(idx), Ok(count)) => {
                if let Err(e) = self.lib.remove_data(idx, count) {
                    logger::error(&format!("Lib remove error: {}", e));
                }
            }
            (Err(e), _) | (_, Err(e)) => logger::error(&format!("Lib remove error: {}", e)),
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_clear(&mut self, _args: &[&str]) -> bool {
        self.lib.clear_data();
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_filter(&mut self, args: &[&str]) -> bool {
        let filter_arg = args.get(0).map_or("", |v| v);
        let filter = parse_filter_string(filter_arg).unwrap_or_else(|_| {
            logger::error(&format!("Failed to parse filter string: {}", filter_arg));
            Vec::new()
        });
        self.lib.filter(filter);
        println!("{}", self.lib.to_string(None));
        true
    }

    fn list_modules(&mut self, _args: &[&str]) -> bool {
        let filter = _args.get(0).map(|s| s.to_string());
        let modules = list_modules(&mut self.script, filter.as_deref())
            .unwrap_or(vec![])
            .into_iter()
            .map(|m| VzData::Module(m))
            .collect::<Vec<_>>();
        self.field.clear_data();
        self.field.add_datas(modules);
        println!("{}", self.field.to_string(None));
        true
    }

    fn list_ranges(&mut self, _args: &[&str]) -> bool {
        let protect = _args.get(0).map(|s| s.to_string());
        let filter = _args.get(1).map(|s| s.to_string());
        let ranges = list_ranges(&mut self.script, protect.as_deref(), filter.as_deref())
            .unwrap_or(vec![])
            .into_iter()
            .map(|r| VzData::Range(r))
            .collect::<Vec<_>>();
        self.field.clear_data();
        self.field.add_datas(ranges);
        println!("{}", self.field.to_string(None));
        true
    }

    fn list_functions(&mut self, _args: &[&str]) -> bool {
        let filter;
        let arg0 = _args.get(0).map(|s| s.to_string()).unwrap_or_default();
        let res = self.selector(arg0.as_str());
        let module = match res {
            Ok(data) => {
                if data.is_empty() {
                    logger::error("No data selected");
                    return true;
                } else if let Some(VzData::Module(m)) = data.first() {
                    filter = _args.get(1).map(|s| s.to_string());
                    m.clone()
                } else {
                    logger::error("Selected data is not a module");
                    return true;
                }
            }
            Err(e) => match self.navigator.get_data() {
                Some(vz_data_from_navigator) => {
                    if let VzData::Module(m) = vz_data_from_navigator {
                        filter = _args.get(0).map(|s| s.to_string());
                        m.clone()
                    } else {
                        logger::error(&format!(
                            "Selector error: {}. Navigator data is not a VzModule.",
                            e
                        ));
                        return true;
                    }
                }
                None => {
                    logger::error(&format!("Selector error: {}. Navigator has no data.", e));
                    return true;
                }
            },
        };
        let functions = list_functions(&mut self.script, module, filter.as_deref())
            .unwrap_or(vec![])
            .into_iter()
            .map(|f| VzData::Function(f))
            .collect::<Vec<_>>();
        self.field.clear_data();
        self.field.add_datas(functions);
        println!("{}", self.field.to_string(None));
        true
    }

    fn list_variables(&mut self, _args: &[&str]) -> bool {
        let filter;
        let arg0 = _args.get(0).map(|s| s.to_string()).unwrap_or_default();
        let res = self.selector(arg0.as_str());
        let module = match res {
            Ok(data) => {
                if data.is_empty() {
                    logger::error("No data selected");
                    return true;
                } else if let Some(VzData::Module(m)) = data.first() {
                    filter = _args.get(1).map(|s| s.to_string());
                    m.clone()
                } else {
                    logger::error("Selected data is not a module");
                    return true;
                }
            }
            Err(e) => match self.navigator.get_data() {
                Some(vz_data_from_navigator) => {
                    if let VzData::Module(m) = vz_data_from_navigator {
                        filter = _args.get(0).map(|s| s.to_string());
                        m.clone()
                    } else {
                        logger::error(&format!(
                            "Selector error: {}. Navigator data is not a VzModule.",
                            e
                        ));
                        return true;
                    }
                }
                None => {
                    logger::error(&format!("Selector error: {}. Navigator has no data.", e));
                    return true;
                }
            },
        };
        let variables = list_variables(&mut self.script, module, filter.as_deref())
            .unwrap_or(vec![])
            .into_iter()
            .map(|v| VzData::Variable(v))
            .collect::<Vec<_>>();
        self.field.clear_data();
        self.field.add_datas(variables);
        println!("{}", self.field.to_string(None));
        true
    }

    fn read(&mut self, args: &[&str]) -> bool {
        let arg0 = args.get(0).map(|s| s.to_string()).unwrap_or_default();
        let res = self.selector(arg0.as_str());
        let (address, value_type) = match res {
            Ok(data) => {
                if data.is_empty() {
                    logger::error("No data selected");
                    return true;
                }
                let addr = match get_address_from_data(data[0])
                    .ok_or_else(|| "No valid address found in selected data".to_string())
                    .and_then(|addr| {
                        if addr == 0 {
                            Err("Address cannot be zero".to_string())
                        } else {
                            Ok(addr)
                        }
                    }) {
                    Ok(addr) => addr,
                    Err(e) => {
                        logger::error(&e);
                        return true;
                    }
                };
                let vtype = args.get(1).map(|s| parse_value_type(s)).unwrap_or(VzValueType::Byte);
                (addr, vtype)
            }
            Err(_) => {
                match Self::parse_number(&arg0) {
                    Ok(addr) => {
                        let vtype = args.get(1).map(|s| parse_value_type(s)).unwrap_or(VzValueType::Byte);
                        (addr, vtype)
                    }
                    Err(e) => {
                        logger::error(&format!("Invalid address: {}", e));
                        return true;
                    }
                }
            }
        };

        let length = args.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(16);

        // Perform read operation
        match read_memory_by_type(&mut self.script, address, &value_type, Some(length)) {
            Ok(result) => {
                println!(
                    "{} {} {} = {}",
                    "[READ]".green(),
                    format!("{:#x}", address).yellow(),
                    format!("[{}]", value_type).blue(),
                    result
                );
            }
            Err(e) => {
                logger::error(&format!("Memory read error: {}", e));
            }
        }
        true
    }

    fn write(&mut self, args: &[&str]) -> bool {
        // Parse arguments: [address] <value> [type]
        if args.len() < 1 {
            logger::error("Write command requires at least value arguments");
            return true;
        }

        let arg0 = args.get(0).map(|s| s.to_string()).unwrap_or_default();
        let res = self.selector(arg0.as_str());
        let (address, value_str, value_type) = match res {
            Ok(data) => {
                if data.is_empty() {
                    logger::error("No data selected");
                    return true;
                }
                let addr = match get_address_from_data(data[0])
                    .ok_or_else(|| "No valid address found in selected data".to_string())
                    .and_then(|addr| {
                        if addr == 0 {
                            Err("Address cannot be zero".to_string())
                        } else {
                            Ok(addr)
                        }
                    }) {
                    Ok(addr) => addr,
                    Err(e) => {
                        logger::error(&e);
                        return true;
                    }
                };
                let vtype = args.get(2).map(|s| parse_value_type(s)).unwrap_or(VzValueType::Byte);
                (addr, args[1].to_string(), vtype)
            }
            Err(_) => {
                match Self::parse_number(&arg0) {
                    Ok(addr) => {
                        let vtype = args.get(2).map(|s| parse_value_type(s)).unwrap_or(VzValueType::Byte);
                        (addr, args[1].to_string(), vtype)
                    }
                    Err(e) => {
                        logger::error(&format!("Invalid address: {}", e));
                        return true;
                    }
                }
            }
        };

        // Perform write operation

        match write_memory_by_type(&mut self.script, address, &value_str, &value_type) {
            Ok(()) => {
                println!(
                    "{} {} {} = {}",
                    "[WRITE]".green(),
                    format!("{:#x}", address).yellow(),
                    format!("[{}]", value_type).blue(),
                    value_str
                );
            }
            Err(e) => {
                logger::error(&format!("Memory write error: {}", e));
            }
        }
        true
    }

    fn debug_exports(&mut self, _args: &[&str]) -> bool {
        match self.script.list_exports() {
            Ok(exports) => println!("{:?}", &exports),
            Err(e) => logger::error(&format!("Failed to list exports: {}", e)),
        }
        true
    }
}
