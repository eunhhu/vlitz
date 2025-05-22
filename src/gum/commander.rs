// src/gum/commander.rs
use crossterm::style::Stylize;
use crate::gum::{
    list::{list_functions, list_ranges, list_variables}
};

use super::{
    list::list_modules, navigator::Navigator, store::Store, vzdata::VzData
};
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
    fn new(
        name: &str,
        description: &str,
        args: Vec<CommandArg>,
        execute: CommandHandler,
    ) -> Self {
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
        let env_value = script.exports.call("get_env", None)
            .expect("Failed to call get_env")
            .expect("Failed to get env value");
        let env_arr = env_value.as_array().unwrap();
        Commander {
            script,
            env: format!(
                "{} {}",
                env_arr[0].as_str().unwrap_or(""),
                env_arr[1].as_str().unwrap_or("")
            ),
            field: Store::new("Field".to_string()),
            lib: Store::new("Lib".to_string()),
            navigator: Navigator::new(),
            commands: vec![
                Command::new(
                    "debug",
                    "Debug functions",
                    vec!["d"],
                    vec![],
                    vec![
                        SubCommand::new(
                            "exports",
                            "List exports",
                            vec![],
                            |c, a| Commander::debug_exports(c, a),
                        ).alias("e")
                    ],
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
                    vec![
                        CommandArg::required("selector", "Selector")
                    ],
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
                    vec![
                        CommandArg::required("offset", "Offset")
                    ],
                    vec![],
                    Some(|c, a| Commander::add(c, a)),
                ),
                Command::new(
                    "sub",
                    "Subtract offset from selected data",
                    vec!["-"],
                    vec![
                        CommandArg::required("offset", "Offset")
                    ],
                    vec![],
                    Some(|c, a| Commander::sub(c, a)),
                ),
                Command::new(
                    "field",
                    "Field manipulation commands.",
                    vec!["f", "fld"],
                    vec![
                        CommandArg::optional("page", "Page number")
                    ],
                    vec![
                        SubCommand::new(
                            "list",
                            "List fields with optional page number",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_list(c, a),
                        ).alias("ls").alias("l"),
                        SubCommand::new(
                            "next",
                            "Go to next page of fields",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_next(c, a),
                        ).alias("n"),
                        SubCommand::new(
                            "prev",
                            "Go to previous page of fields",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::field_prev(c, a),
                        ).alias("p"),
                        SubCommand::new(
                            "sort",
                            "Sort fields by name",
                            vec![CommandArg::optional("type", "Sort type [addr]")],
                            |c, a| Commander::field_sort(c, a),
                        ).alias("s"),
                        SubCommand::new(
                            "move",
                            "Move fields",
                            vec![
                                CommandArg::required("from", "Index of data"),
                                CommandArg::required("to", "Index of data")
                            ],
                            |c, a| Commander::field_move(c, a),
                        ).alias("mv"),
                        SubCommand::new(
                            "remove",
                            "Remove data from field",
                            vec![
                                CommandArg::required("index", "Index of data"),
                                CommandArg::optional("count", "Count of data to remove (default: 1)")
                            ],
                            |c, a| Commander::field_remove(c, a),
                        ).alias("rm").alias("del").alias("delete"),
                        SubCommand::new(
                            "clear",
                            "Clear all fields",
                            vec![],
                            |c, a| Commander::field_clear(c, a),
                        ).alias("cls").alias("clr").alias("cl").alias("c")
                    ],
                    Some(|c, a| Commander::field_list(c, a)),
                ),
                Command::new(
                    "lib",
                    "Library manipulation commands.",
                    vec!["l"],
                    vec![CommandArg::optional("page", "Page number")],
                    vec![
                        SubCommand::new(
                            "list",
                            "List libraries with optional page number",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_list(c, a),
                        ).alias("ls").alias("l"),
                        SubCommand::new(
                            "next",
                            "Go to next page of libraries",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_next(c, a),
                        ).alias("n"),
                        SubCommand::new(
                            "prev",
                            "Go to previous page of libraries",
                            vec![CommandArg::optional("page", "Page number")],
                            |c, a| Commander::lib_prev(c, a),
                        ).alias("p"),
                        SubCommand::new(
                            "sort",
                            "Sort libraries by name",
                            vec![CommandArg::optional("type", "Sort type [addr]")],
                            |c, a| Commander::lib_sort(c, a),
                        ).alias("s"),
                        SubCommand::new(
                            "save",
                            "Save data from field",
                            vec![CommandArg::required("selector", "Selector from field")],
                            |c, a| Commander::lib_save(c, a),
                        ).alias("sv"),
                        SubCommand::new(
                            "move",
                            "Move data from one library to another",
                            vec![
                                CommandArg::required("from", "Index of data"),
                                CommandArg::required("to", "Index of data")
                            ],
                            |c, a| Commander::lib_move(c, a),
                        ).alias("mv"),
                        SubCommand::new(
                            "remove",
                            "Remove data from library",
                            vec![
                                CommandArg::required("index", "Index of data"),
                                CommandArg::optional("count", "Count of data to remove (default: 1)")
                            ],
                            |c, a| Commander::lib_remove(c, a),
                        ).alias("rm").alias("del").alias("delete"),
                        SubCommand::new(
                            "clear",
                            "Clear all data",
                            vec![],
                            |c, a| Commander::lib_clear(c, a),
                        ).alias("cls").alias("clr").alias("cl").alias("c")
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
                        ).alias("mods").alias("md").alias("m"),
                        SubCommand::new(
                            "ranges",
                            "List all ranges",
                            vec![CommandArg::optional("filter", "Filter ranges")],
                            |c, a| Commander::list_ranges(c, a),
                        ).alias("ranges").alias("rngs").alias("rng").alias("r"),
                        SubCommand::new(
                            "functions",
                            "List all functions",
                            vec![CommandArg::optional("filter", "Filter functions")],
                            |c, a| Commander::list_functions(c, a),
                        ).alias("funcs").alias("fns").alias("fn").alias("f"),
                        SubCommand::new(
                            "variables",
                            "List all variables",
                            vec![CommandArg::optional("filter", "Filter variables")],
                            |c, a| Commander::list_variables(c, a),
                        ).alias("vars").alias("vrs").alias("vr").alias("v"),
                    ],
                    None,
                )
            ],
        }
    }

    pub fn execute_command(&mut self, command: &str, args: &[&str]) -> bool {
        if let Some(cmd) = self.commands.iter().find(|c| c.command == command || c.aliases.contains(&command.to_string())) {
            if !cmd.subcommands.is_empty() {
                if let Some((subcommand, sub_args)) = args.split_first() {
                    if let Some(sub_cmd) = cmd.subcommands.iter().find(|s| 
                        s.name == *subcommand || s.aliases.contains(&subcommand.to_string())
                    ) {
                        // Check required arguments for the subcommand
                        let required_args = sub_cmd.args.iter().filter(|a| a.required).count();
                        if sub_args.len() < required_args {
                            println!("{} Expected at least {} arguments, got {}",
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
                println!("{} {}", "No subcommand specified.".red(), format!("Use 'help {}' for more information.", command).dark_grey());
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
            let command = self.commands.iter().find(|c| c.command == args[0] || c.aliases.contains(&args[0].to_string()));
            if let Some(cmd) = command {
                // Usage
                let args_usage = cmd.args.iter()
                .map(|arg| arg.to_string())
                .collect::<Vec<_>>()
                .join(" ");
                println!("\n{} {}{}",
                    "Usage:".green(),
                    cmd.command.clone().yellow(),
                    if args_usage.is_empty() { "".to_string() } else { format!(" {}", args_usage) }
                );
                // Description
                println!("{} {}", "Description:".green(), cmd.description);
                // Arguments
                if !cmd.args.is_empty() {
                    println!("\n{}", "Arguments:".green());
                    for arg in &cmd.args {
                        let required = if arg.required { " (required)" } else { "" };
                        println!("  {:<15} {}{}",
                            format!("{}:", arg.name),
                            arg.description,
                            required.yellow()
                        );
                    }
                }

                // Aliases
                if !cmd.aliases.is_empty() {
                    println!("\n{} {}",
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
                        let sub_and_args = format!("{} {}", sub.name,
                            sub.args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>().join(" ")
                        );
                        if sub_and_args.len() > 15 {
                            println!("  {}",
                                sub_and_args
                            );
                            println!("  {} {}{}",
                                " ".repeat(15),
                                sub.description,
                                aliases
                            );
                        } else {
                            println!("  {:<15} {}{}",
                                sub_and_args,
                                sub.description,
                                aliases
                            );
                        }
                    }
                }
                
                return true;
            }
            
            println!("{} {}", "Unknown command:".red(), args[0]);
            true
        } else {
            // Show all commands
            println!("  {}{} {}", "Command".green().bold(), " ".repeat(24 - "Command".len()), "Description".green().bold());
            println!("  {:-<24} {:-<40}", "", "");
            
            for cmd in &self.commands {
                let aliases = if !cmd.aliases.is_empty() {
                    format!(" ({})", cmd.aliases.join(", ").dark_grey())
                } else {
                    String::new()
                };

                let args_usage = cmd.args.iter()
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
                    println!("  {}{} {}{}",
                        cmd_with_args,
                        " ".repeat(24 - cmd_len),
                        cmd.description,
                        aliases
                    );
                } else {
                    println!("  {}\n  {}{}",
                        cmd_with_args,
                        " ".repeat(24),
                        format!("{}{}", cmd.description, aliases)
                    );
                }

                if !cmd.subcommands.is_empty() {
                    for subcmd in &cmd.subcommands {
                        let aliases = if !subcmd.aliases.is_empty(){
                            format!(" ({})", subcmd.aliases.join(", ").dark_grey())
                        } else {
                            String::new()
                        };
                        let args_usage = subcmd.args.iter()
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
                            println!("  {}{}{} {}{}",
                                " ".repeat(cmd.command.len() + 1),
                                subcmd_with_args,
                                " ".repeat(24 - subcmd_len - cmd.command.len() - 1),
                                subcmd.description,
                                aliases
                            );
                        } else {
                            println!("  {}{}\n    {}{}{}",
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

            println!("\nType \'{} {}\' for more information", "help".yellow().bold(), "[command]".bold());
            
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
            let selector_str = caps.get(2).ok_or_else(|| "No selector provided".to_string())?.as_str();
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
                    Err(format!("Unknown explicitly specified store: {}", store_name))
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
            },
            Err(_) => {
                true
            }
        }
    }

    fn deselect(&mut self, _args: &[&str]) -> bool {
        self.navigator.deselect();
        true
    }

    fn parse_number(s: &str) -> u64 {
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).unwrap_or(0)
        } else {
            s.parse::<u64>().unwrap_or(0)
        }
    }

    fn add(&mut self, args: &[&str]) -> bool {
        let offset = args.get(0).map(|s| Self::parse_number(s)).unwrap_or(0);
        self.navigator.add(offset);
        true
    }

    fn sub(&mut self, args: &[&str]) -> bool {
        let offset = args.get(0).map(|s| Self::parse_number(s)).unwrap_or(0);
        self.navigator.sub(offset);
        true
    }

    fn field_list(&mut self, args: &[&str]) -> bool {
        let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        if let Some(page_num) = page.checked_sub(1) {
            println!("{}", self.field.to_string(Some(page_num as usize)));
        } else {
            println!("{}", self.field.to_string(None));
        }
        true
    }

    fn field_next(&mut self, args: &[&str]) -> bool {
        let (current_page, total_pages) = self.field.get_page_info();
        if current_page != total_pages {
            let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            self.field.next_page(page.try_into().unwrap());
        }
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_prev(&mut self, args: &[&str]) -> bool {
        let (current_page, _) = self.field.get_page_info();
        if current_page != 1 {
            let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            self.field.prev_page(page.try_into().unwrap());
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
        let from = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let to = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        self.field.move_data(from, to);
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_remove(&mut self, args: &[&str]) -> bool {
        let index = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let count = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1);
        self.field.remove_data(index, count);
        println!("{}", self.field.to_string(None));
        true
    }

    fn field_clear(&mut self, _args: &[&str]) -> bool {
        self.field.clear_data();
        println!("{}", self.field.to_string(None));
        true
    }

    fn lib_list(&mut self, args: &[&str]) -> bool {
        let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        if let Some(page_num) = page.checked_sub(1) {
            println!("{}", self.lib.to_string(Some(page_num as usize)));
        } else {
            println!("{}", self.lib.to_string(None));
        }
        true
    }

    fn lib_next(&mut self, args: &[&str]) -> bool {
        let (current_page, total_pages) = self.lib.get_page_info();
        if current_page != total_pages {
            let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            self.lib.next_page(page.try_into().unwrap());
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_prev(&mut self, args: &[&str]) -> bool {
        let (current_page, _) = self.lib.get_page_info();
        if current_page != 1 {
            let page = args.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            self.lib.prev_page(page.try_into().unwrap());
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
        let datas = self.field.get_data_by_selection(args.get(0).unwrap_or(&""));
        if let Ok(datas) = datas {
            self.lib.add_datas(datas.into_iter().map(|d| {
                let mut d = d.clone();
                match &mut d {
                    VzData::Pointer(p) => {p.base.is_saved = true;},
                    VzData::Module(m) => {m.base.is_saved = true;},
                    VzData::Range(r) => {r.base.is_saved = true;},
                    VzData::Function(f) => {f.base.is_saved = true;},
                    VzData::Variable(v) => {v.base.is_saved = true;},
                    VzData::JavaClass(c) => {c.base.is_saved = true;},
                    VzData::JavaMethod(m) => {m.base.is_saved = true;},
                    VzData::ObjCClass(c) => {c.base.is_saved = true;},
                    VzData::ObjCMethod(m) => {m.base.is_saved = true;},
                    VzData::Thread(t) => {t.base.is_saved = true;},
                }
                d
            }).collect());
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_move(&mut self, args: &[&str]) -> bool {
        let from = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let to = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        self.lib.move_data(from, to);
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_remove(&mut self, args: &[&str]) -> bool {
        let index = args.get(0).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        let count = args.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(1);
        self.lib.remove_data(index, count);
        println!("{}", self.lib.to_string(None));
        true
    }

    fn lib_clear(&mut self, _args: &[&str]) -> bool {
        self.lib.clear_data();
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
                    eprintln!("No data selected");
                    return true;
                } else if let Some(VzData::Module(m)) = data.first() {
                    filter = _args.get(1).map(|s| s.to_string());
                    m.clone()
                } else {
                    eprintln!("Selected data is not a module");
                    return true;
                }
            },
            Err(e) => { 
                match self.navigator.get_data() {
                    Some(vz_data_from_navigator) => {
                        if let VzData::Module(m) = vz_data_from_navigator {
                            filter = _args.get(0).map(|s| s.to_string());
                            m.clone()
                        } else {
                            eprintln!("Selector error: {}. Navigator data is not a VzModule.", e);
                            return true;
                        }
                    }
                    None => {
                        eprintln!("Selector error: {}. Navigator has no data.", e);
                        return true;
                    }
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
                    eprintln!("No data selected");
                    return true;
                } else if let Some(VzData::Module(m)) = data.first() {
                    filter = _args.get(1).map(|s| s.to_string());
                    m.clone()
                } else {
                    eprintln!("Selected data is not a module");
                    return true;
                }
            },
            Err(e) => { 
                match self.navigator.get_data() {
                    Some(vz_data_from_navigator) => {
                        if let VzData::Module(m) = vz_data_from_navigator {
                            filter = _args.get(0).map(|s| s.to_string());
                            m.clone()
                        } else {
                            eprintln!("Selector error: {}. Navigator data is not a VzModule.", e);
                            return true;
                        }
                    }
                    None => {
                        eprintln!("Selector error: {}. Navigator has no data.", e);
                        return true;
                    }
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

    fn debug_exports(&mut self, _args: &[&str]) -> bool {
        let exports = self.script.list_exports().unwrap();
        println!("{:?}", &exports);
        true
    }
}