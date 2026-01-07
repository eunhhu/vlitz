// src/gum/commander.rs
use crate::gum::{
    filter::parse_filter_string,
    list::{list_functions, list_ranges, list_variables},
    memory::{
        get_address_from_data, parse_value_type, read_memory_by_type, view_memory,
        write_memory_by_type,
    },
};
use crate::util::logger;
use crossterm::{style::Stylize, terminal, ExecutableCommand};

use super::{
    list::list_modules,
    navigator::Navigator,
    store::Store,
    vzdata::{
        new_base, VzBase, VzData, VzDataType, VzHook, VzInstruction, VzScanResult, VzThread,
        VzValueType,
    },
};
use frida::Script;
use regex::Regex;
use serde_json::json;
use std::{collections::HashMap, fmt, io::stdout, vec};

#[derive(Debug)]
pub(crate) struct CommandArg {
    name: String,
    description: String,
    required: bool,
}

impl CommandArg {
    pub(crate) fn new(name: &str, description: &str, required: bool) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            required,
        }
    }

    pub(crate) fn required(name: &str, description: &str) -> Self {
        Self::new(name, description, true)
    }

    pub(crate) fn optional(name: &str, description: &str) -> Self {
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

pub(crate) type CommandHandler = fn(&mut Commander, &[&str]) -> bool;

pub(crate) struct SubCommand {
    name: String,
    aliases: Vec<String>,
    description: String,
    args: Vec<CommandArg>,
    execute: CommandHandler,
}

impl SubCommand {
    pub(crate) fn new(
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

    pub(crate) fn alias(mut self, alias: &str) -> Self {
        self.aliases.push(alias.to_string());
        self
    }
}

pub(crate) struct Command {
    command: String,
    description: String,
    aliases: Vec<String>,
    args: Vec<CommandArg>,
    subcommands: Vec<SubCommand>,
    default_execute: Option<CommandHandler>,
}

impl Command {
    pub(crate) fn new(
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
            commands: crate::gum::commands::build_all(),
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

    pub(crate) fn help(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn exit(&mut self, _args: &[&str]) -> bool {
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

    pub(crate) fn select(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn deselect(&mut self, _args: &[&str]) -> bool {
        self.navigator.deselect();
        true
    }

    fn parse_number(s: &str) -> Result<u64, String> {
        crate::util::format::parse_hex_or_decimal(s)
    }

    fn parse_usize(s: &str) -> Result<usize, String> {
        crate::util::format::parse_hex_or_decimal_usize(s)
    }

    pub(crate) fn add(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(offset)) => self.navigator.add(offset),
            Some(Err(e)) => logger::error(&format!("Invalid offset: {}", e)),
            None => logger::error("Offset argument required"),
        }
        true
    }

    pub(crate) fn sub(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(offset)) => self.navigator.sub(offset),
            Some(Err(e)) => logger::error(&format!("Invalid offset: {}", e)),
            None => logger::error("Offset argument required"),
        }
        true
    }

    pub(crate) fn goto(&mut self, args: &[&str]) -> bool {
        match args.get(0).map(|s| Self::parse_number(s)) {
            Some(Ok(addr)) => self.navigator.goto(addr),
            Some(Err(e)) => logger::error(&format!("Invalid address: {}", e)),
            None => logger::error("Address argument required"),
        }
        true
    }

    pub(crate) fn field_list(&mut self, args: &[&str]) -> bool {
        match args.get(0) {
            Some(v) => match Self::parse_usize(v) {
                Ok(p) => println!("{}", self.field.to_string(Some(p.saturating_sub(1)))),
                Err(e) => logger::error(&e),
            },
            None => println!("{}", self.field.to_string(None)),
        }
        true
    }

    pub(crate) fn field_next(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn field_prev(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn field_sort(&mut self, args: &[&str]) -> bool {
        if let Some(sort_by) = args.get(0) {
            self.field.sort(Some(sort_by));
        }
        println!("{}", self.field.to_string(None));
        true
    }

    pub(crate) fn field_move(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn field_remove(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn field_clear(&mut self, _args: &[&str]) -> bool {
        self.field.clear_data();
        println!("{}", self.field.to_string(None));
        true
    }

    pub(crate) fn field_filter(&mut self, args: &[&str]) -> bool {
        let filter_arg = args.get(0).map_or("", |v| v);
        let filter = parse_filter_string(filter_arg).unwrap_or_else(|_| {
            logger::error(&format!("Failed to parse filter string: {}", filter_arg));
            Vec::new()
        });
        self.field.filter(filter);
        println!("{}", self.field.to_string(None));
        true
    }

    pub(crate) fn lib_list(&mut self, args: &[&str]) -> bool {
        match args.get(0) {
            Some(v) => match Self::parse_usize(v) {
                Ok(p) => println!("{}", self.lib.to_string(Some(p.saturating_sub(1)))),
                Err(e) => logger::error(&e),
            },
            None => println!("{}", self.lib.to_string(None)),
        }
        true
    }

    pub(crate) fn lib_next(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn lib_prev(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn lib_sort(&mut self, args: &[&str]) -> bool {
        if let Some(sort_by) = args.get(0) {
            self.lib.sort(Some(sort_by));
        }
        println!("{}", self.lib.to_string(None));
        true
    }

    pub(crate) fn lib_save(&mut self, args: &[&str]) -> bool {
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
                                VzData::Hook(h) => {
                                    h.base.is_saved = true;
                                }
                                VzData::Instruction(i) => {
                                    i.base.is_saved = true;
                                }
                                VzData::ScanResult(s) => {
                                    s.base.is_saved = true;
                                }
                                VzData::Import(i) => {
                                    i.base.is_saved = true;
                                }
                                VzData::Symbol(s) => {
                                    s.base.is_saved = true;
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

    pub(crate) fn lib_move(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn lib_remove(&mut self, args: &[&str]) -> bool {
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

    pub(crate) fn lib_clear(&mut self, _args: &[&str]) -> bool {
        self.lib.clear_data();
        println!("{}", self.lib.to_string(None));
        true
    }

    pub(crate) fn lib_filter(&mut self, args: &[&str]) -> bool {
        let filter_arg = args.get(0).map_or("", |v| v);
        let filter = parse_filter_string(filter_arg).unwrap_or_else(|_| {
            logger::error(&format!("Failed to parse filter string: {}", filter_arg));
            Vec::new()
        });
        self.lib.filter(filter);
        println!("{}", self.lib.to_string(None));
        true
    }

    pub(crate) fn list_modules(&mut self, _args: &[&str]) -> bool {
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

    pub(crate) fn list_ranges(&mut self, _args: &[&str]) -> bool {
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

    pub(crate) fn list_functions(&mut self, _args: &[&str]) -> bool {
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

    pub(crate) fn list_variables(&mut self, _args: &[&str]) -> bool {
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

    pub(crate) fn read(&mut self, args: &[&str]) -> bool {
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
                let vtype = args
                    .get(1)
                    .and_then(|s| parse_value_type(s).ok())
                    .unwrap_or(VzValueType::Byte);
                (addr, vtype)
            }
            Err(_) => match Self::parse_number(&arg0) {
                Ok(addr) => {
                    let vtype = args
                        .get(1)
                        .and_then(|s| parse_value_type(s).ok())
                        .unwrap_or(VzValueType::Byte);
                    (addr, vtype)
                }
                Err(e) => {
                    logger::error(&format!("Invalid address: {}", e));
                    return true;
                }
            },
        };

        let length = args
            .get(2)
            .and_then(|s| crate::util::format::parse_hex_or_decimal_usize(s).ok())
            .unwrap_or(16);

        // Perform read operation
        match read_memory_by_type(&mut self.script, address, &value_type, Some(length), true) {
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

    pub(crate) fn write(&mut self, args: &[&str]) -> bool {
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
                let vtype = args
                    .get(2)
                    .and_then(|s| parse_value_type(s).ok())
                    .unwrap_or(VzValueType::Byte);
                (addr, args[1].to_string(), vtype)
            }
            Err(_) => match Self::parse_number(&arg0) {
                Ok(addr) => {
                    let vtype = args
                        .get(2)
                        .and_then(|s| parse_value_type(s).ok())
                        .unwrap_or(VzValueType::Byte);
                    (addr, args[1].to_string(), vtype)
                }
                Err(e) => {
                    logger::error(&format!("Invalid address: {}", e));
                    return true;
                }
            },
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

    pub(crate) fn debug_exports(&mut self, _args: &[&str]) -> bool {
        match self.script.list_exports() {
            Ok(exports) => println!("{:?}", &exports),
            Err(e) => logger::error(&format!("Failed to list exports: {}", e)),
        }
        true
    }

    pub(crate) fn view(&mut self, args: &[&str]) -> bool {
        let arg0 = args.get(0).map(|s| s.to_string()).unwrap_or_default();
        let res = self.selector(arg0.as_str());
        let (address, size, value_type) = match res {
            Ok(data) => {
                if data.is_empty() {
                    match self.navigator.get_data() {
                        Some(nav_data) => {
                            let addr = match get_address_from_data(nav_data) {
                                Some(addr) if addr != 0 => addr,
                                _ => {
                                    logger::error("No valid address found in navigator data");
                                    return true;
                                }
                            };
                            let size = args
                                .get(0)
                                .and_then(|s| {
                                    crate::util::format::parse_hex_or_decimal_usize(s).ok()
                                })
                                .unwrap_or(256);
                            let vtype = args
                                .get(1)
                                .and_then(|s| parse_value_type(s).ok())
                                .unwrap_or(VzValueType::Byte);
                            (addr, size, vtype)
                        }
                        None => {
                            logger::error("No data selected and navigator is empty");
                            return true;
                        }
                    }
                } else {
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
                    let size = args
                        .get(1)
                        .and_then(|s| crate::util::format::parse_hex_or_decimal_usize(s).ok())
                        .unwrap_or(256);
                    let vtype = args
                        .get(2)
                        .and_then(|s| parse_value_type(s).ok())
                        .unwrap_or(VzValueType::Byte);
                    (addr, size, vtype)
                }
            }
            Err(_) => match Self::parse_number(&arg0) {
                Ok(addr) => {
                    let size = args
                        .get(1)
                        .and_then(|s| crate::util::format::parse_hex_or_decimal_usize(s).ok())
                        .unwrap_or(256);
                    let vtype = args
                        .get(2)
                        .and_then(|s| parse_value_type(s).ok())
                        .unwrap_or(VzValueType::Byte);
                    (addr, size, vtype)
                }
                Err(_) => match self.navigator.get_data() {
                    Some(nav_data) => {
                        let addr = match get_address_from_data(nav_data) {
                            Some(addr) if addr != 0 => addr,
                            _ => {
                                logger::error("No valid address found in navigator data");
                                return true;
                            }
                        };
                        let size = args
                            .get(0)
                            .and_then(|s| crate::util::format::parse_hex_or_decimal_usize(s).ok())
                            .unwrap_or(256);
                        let vtype = args
                            .get(1)
                            .and_then(|s| parse_value_type(s).ok())
                            .unwrap_or(VzValueType::Byte);
                        (addr, size, vtype)
                    }
                    None => {
                        logger::error("Invalid address and no navigator data available");
                        return true;
                    }
                },
            },
        };

        match view_memory(&mut self.script, address, &value_type, size) {
            Ok(result) => {
                println!("{}", result);
            }
            Err(e) => {
                logger::error(&format!("Memory view error: {}", e));
            }
        }
        true
    }

    // ========================================================================
    // Screen/Terminal Commands
    // ========================================================================

    pub(crate) fn clear_screen(&mut self, _args: &[&str]) -> bool {
        if let Err(e) = stdout().execute(terminal::Clear(terminal::ClearType::All)) {
            logger::error(&format!("Failed to clear screen: {}", e));
        }
        if let Err(e) = stdout().execute(crossterm::cursor::MoveTo(0, 0)) {
            logger::error(&format!("Failed to move cursor: {}", e));
        }
        true
    }

    // ========================================================================
    // Hook Commands
    // ========================================================================

    pub(crate) fn hook_add(&mut self, args: &[&str]) -> bool {
        if args.is_empty() {
            logger::error("Target address or selector required");
            return true;
        }

        let arg0 = args[0];

        // Try to resolve the target address
        let address = self.resolve_target_address(arg0);
        let address = match address {
            Ok(addr) => addr,
            Err(e) => {
                logger::error(&format!("Failed to resolve target: {}", e));
                return true;
            }
        };

        // Parse options from remaining args
        let mut config = serde_json::Map::new();
        config.insert("onEnter".to_string(), json!(true));
        config.insert("onLeave".to_string(), json!(false));
        config.insert("logArgs".to_string(), json!(false));
        config.insert("logRetval".to_string(), json!(false));
        config.insert("backtrace".to_string(), json!(false));
        config.insert("argCount".to_string(), json!(4));

        // Parse option flags
        for arg in args.iter().skip(1) {
            match *arg {
                "-e" | "--enter" => {
                    config.insert("onEnter".to_string(), json!(true));
                }
                "-l" | "--leave" => {
                    config.insert("onLeave".to_string(), json!(true));
                }
                "-a" | "--args" => {
                    config.insert("logArgs".to_string(), json!(true));
                }
                "-r" | "--retval" => {
                    config.insert("logRetval".to_string(), json!(true));
                }
                "-b" | "--backtrace" => {
                    config.insert("backtrace".to_string(), json!(true));
                }
                "-al" | "-la" | "--all" => {
                    config.insert("onEnter".to_string(), json!(true));
                    config.insert("onLeave".to_string(), json!(true));
                    config.insert("logArgs".to_string(), json!(true));
                    config.insert("logRetval".to_string(), json!(true));
                }
                _ => {}
            }
        }

        // Call the hook_attach RPC
        let result = self
            .script
            .exports
            .call("hook_attach", Some(json!([format!("{}", address), config])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        let id = value
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        println!(
                            "{} Hook added: {} @ {}",
                            "[HOOK]".green(),
                            id.cyan(),
                            format!("{:#x}", address).yellow()
                        );
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to add hook: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from hook_attach"),
            Err(e) => logger::error(&format!("Hook attach error: {}", e)),
        }
        true
    }

    pub(crate) fn hook_remove(&mut self, args: &[&str]) -> bool {
        let id = match args.get(0) {
            Some(id) => *id,
            None => {
                logger::error("Hook ID required");
                return true;
            }
        };

        let result = self.script.exports.call("hook_detach", Some(json!([id])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        println!("{} Hook removed: {}", "[HOOK]".green(), id.cyan());
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to remove hook: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from hook_detach"),
            Err(e) => logger::error(&format!("Hook detach error: {}", e)),
        }
        true
    }

    pub(crate) fn hook_list(&mut self, _args: &[&str]) -> bool {
        let result = self.script.exports.call("hook_list", None);

        match result {
            Ok(Some(value)) => {
                if let Some(hooks) = value.as_array() {
                    if hooks.is_empty() {
                        println!("{}", "No active hooks".dark_grey());
                    } else {
                        println!("{} Active hooks: {}", "[HOOKS]".green(), hooks.len());
                        for hook in hooks {
                            let id = hook.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                            let address =
                                hook.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let enabled = hook
                                .get("enabled")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let status = if enabled {
                                "enabled".green()
                            } else {
                                "disabled".dark_grey()
                            };

                            let config = hook.get("config");
                            let on_enter = config
                                .and_then(|c| c.get("onEnter"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let on_leave = config
                                .and_then(|c| c.get("onLeave"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let log_args = config
                                .and_then(|c| c.get("logArgs"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let log_retval = config
                                .and_then(|c| c.get("logRetval"))
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            let flags = format!(
                                "{}{}{}{}",
                                if on_enter { "E" } else { "-" },
                                if on_leave { "L" } else { "-" },
                                if log_args { "A" } else { "-" },
                                if log_retval { "R" } else { "-" }
                            );

                            println!(
                                "  {} @ {} [{}] ({})",
                                id.cyan(),
                                address.yellow(),
                                flags.dark_grey(),
                                status
                            );
                        }
                    }
                }
            }
            Ok(None) => println!("{}", "No active hooks".dark_grey()),
            Err(e) => logger::error(&format!("Hook list error: {}", e)),
        }
        true
    }

    pub(crate) fn hook_enable(&mut self, args: &[&str]) -> bool {
        let id = match args.get(0) {
            Some(id) => *id,
            None => {
                logger::error("Hook ID required");
                return true;
            }
        };

        let result = self.script.exports.call("hook_enable", Some(json!([id])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        println!("{} Hook enabled: {}", "[HOOK]".green(), id.cyan());
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to enable hook: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from hook_enable"),
            Err(e) => logger::error(&format!("Hook enable error: {}", e)),
        }
        true
    }

    pub(crate) fn hook_disable(&mut self, args: &[&str]) -> bool {
        let id = match args.get(0) {
            Some(id) => *id,
            None => {
                logger::error("Hook ID required");
                return true;
            }
        };

        let result = self.script.exports.call("hook_disable", Some(json!([id])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        println!("{} Hook disabled: {}", "[HOOK]".green(), id.cyan());
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to disable hook: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from hook_disable"),
            Err(e) => logger::error(&format!("Hook disable error: {}", e)),
        }
        true
    }

    pub(crate) fn hook_clear(&mut self, _args: &[&str]) -> bool {
        let result = self.script.exports.call("hook_clear_all", None);

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("{} Cleared {} hooks", "[HOOK]".green(), count);
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to clear hooks: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from hook_clear_all"),
            Err(e) => logger::error(&format!("Hook clear error: {}", e)),
        }
        true
    }

    // ========================================================================
    // Disassembly Commands
    // ========================================================================

    pub(crate) fn disas(&mut self, args: &[&str]) -> bool {
        let (address, count) = if args.is_empty() {
            // Use navigator address
            match self.navigator.get_data() {
                Some(data) => {
                    let addr = get_address_from_data(data).unwrap_or(0);
                    (addr, 20usize)
                }
                None => {
                    logger::error("No address specified and navigator is empty");
                    return true;
                }
            }
        } else {
            let addr = match self.resolve_target_address(args[0]) {
                Ok(a) => a,
                Err(e) => {
                    logger::error(&format!("Failed to resolve address: {}", e));
                    return true;
                }
            };
            let count = args
                .get(1)
                .and_then(|s| Self::parse_usize(s).ok())
                .unwrap_or(20);
            (addr, count)
        };

        if address == 0 {
            logger::error("Invalid address: 0x0");
            return true;
        }

        let result = self
            .script
            .exports
            .call("disassemble", Some(json!([format!("{}", address), count])));

        match result {
            Ok(Some(value)) => {
                if let Some(instructions) = value.as_array() {
                    if instructions.is_empty() {
                        println!("{}", "No instructions to display".dark_grey());
                    } else {
                        println!(
                            "{} Disassembly @ {}",
                            "[DISAS]".cyan(),
                            format!("{:#x}", address).yellow()
                        );
                        for insn in instructions {
                            let addr = insn.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let mnemonic =
                                insn.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("?");
                            let op_str = insn.get("opStr").and_then(|v| v.as_str()).unwrap_or("");
                            let bytes = insn
                                .get("bytes")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|b| b.as_u64())
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                })
                                .unwrap_or_default();

                            println!(
                                "  {} {} {} {}",
                                addr.yellow(),
                                format!("{:<24}", bytes).dark_grey(),
                                mnemonic.cyan(),
                                op_str
                            );
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from disassemble"),
            Err(e) => logger::error(&format!("Disassembly error: {}", e)),
        }
        true
    }

    pub(crate) fn disas_function(&mut self, args: &[&str]) -> bool {
        let address = if args.is_empty() {
            match self.navigator.get_data() {
                Some(data) => get_address_from_data(data).unwrap_or(0),
                None => {
                    logger::error("No address specified and navigator is empty");
                    return true;
                }
            }
        } else {
            match self.resolve_target_address(args[0]) {
                Ok(a) => a,
                Err(e) => {
                    logger::error(&format!("Failed to resolve address: {}", e));
                    return true;
                }
            }
        };

        if address == 0 {
            logger::error("Invalid address: 0x0");
            return true;
        }

        let result = self.script.exports.call(
            "disassemble_function",
            Some(json!([format!("{}", address)])),
        );

        match result {
            Ok(Some(value)) => {
                if let Some(instructions) = value.as_array() {
                    if instructions.is_empty() {
                        println!("{}", "No instructions to display".dark_grey());
                    } else {
                        println!(
                            "{} Function @ {} ({} instructions)",
                            "[DISAS]".cyan(),
                            format!("{:#x}", address).yellow(),
                            instructions.len()
                        );
                        for insn in instructions {
                            let addr = insn.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let mnemonic =
                                insn.get("mnemonic").and_then(|v| v.as_str()).unwrap_or("?");
                            let op_str = insn.get("opStr").and_then(|v| v.as_str()).unwrap_or("");
                            let bytes = insn
                                .get("bytes")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|b| b.as_u64())
                                        .map(|b| format!("{:02x}", b))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                })
                                .unwrap_or_default();

                            println!(
                                "  {} {} {} {}",
                                addr.yellow(),
                                format!("{:<24}", bytes).dark_grey(),
                                mnemonic.cyan(),
                                op_str
                            );
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from disassemble_function"),
            Err(e) => logger::error(&format!("Disassembly error: {}", e)),
        }
        true
    }

    // ========================================================================
    // Patch Commands
    // ========================================================================

    pub(crate) fn patch_bytes(&mut self, args: &[&str]) -> bool {
        if args.len() < 2 {
            logger::error("Usage: patch bytes <target> <hex_bytes>");
            return true;
        }

        let address = match self.resolve_target_address(args[0]) {
            Ok(a) => a,
            Err(e) => {
                logger::error(&format!("Failed to resolve address: {}", e));
                return true;
            }
        };

        // Parse hex bytes
        let bytes_str = args[1..].join(" ");
        let bytes: Vec<u8> = bytes_str
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .collect();

        if bytes.is_empty() {
            logger::error("Invalid hex bytes");
            return true;
        }

        let result = self
            .script
            .exports
            .call("patch_bytes", Some(json!([format!("{}", address), bytes])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        let original = value
                            .get("original")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|b| b.as_u64())
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        println!(
                            "{} Patched {} @ {}",
                            "[PATCH]".green(),
                            format!("{} bytes", bytes.len()).cyan(),
                            format!("{:#x}", address).yellow()
                        );
                        println!("  Original: {}", original.dark_grey());
                        println!("  Patched:  {}", bytes_str);
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to patch: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from patch_bytes"),
            Err(e) => logger::error(&format!("Patch error: {}", e)),
        }
        true
    }

    pub(crate) fn patch_nop(&mut self, args: &[&str]) -> bool {
        if args.is_empty() {
            logger::error("Usage: nop <target> [count]");
            return true;
        }

        let address = match self.resolve_target_address(args[0]) {
            Ok(a) => a,
            Err(e) => {
                logger::error(&format!("Failed to resolve address: {}", e));
                return true;
            }
        };

        let count = args
            .get(1)
            .and_then(|s| Self::parse_usize(s).ok())
            .unwrap_or(1);

        let result = self.script.exports.call(
            "nop_instructions",
            Some(json!([format!("{}", address), count])),
        );

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        let original = value
                            .get("original")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|b| b.as_u64())
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        println!(
                            "{} NOPed {} instruction(s) @ {}",
                            "[PATCH]".green(),
                            count,
                            format!("{:#x}", address).yellow()
                        );
                        println!("  Original: {}", original.dark_grey());
                    } else {
                        let error = value
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        logger::error(&format!("Failed to NOP: {}", error));
                    }
                }
            }
            Ok(None) => logger::error("No response from nop_instructions"),
            Err(e) => logger::error(&format!("NOP error: {}", e)),
        }
        true
    }

    pub(crate) fn patch_restore(&mut self, args: &[&str]) -> bool {
        // This would need to maintain a history of patches to restore
        // For now, just show a message
        logger::error("Patch restore not yet implemented. Save original bytes when patching.");
        true
    }

    // ========================================================================
    // Scan Commands
    // ========================================================================

    pub(crate) fn scan_bytes(&mut self, args: &[&str]) -> bool {
        if args.is_empty() {
            logger::error("Usage: scan bytes <pattern> [protection]");
            return true;
        }

        let pattern = args[0];
        let protection = args.get(1).map(|s| *s);

        println!("{} Scanning for pattern: {}", "[SCAN]".cyan(), pattern);

        let params = if let Some(prot) = protection {
            json!([pattern, prot])
        } else {
            json!([pattern])
        };

        let result = self.script.exports.call("scan_pattern", Some(params));

        match result {
            Ok(Some(value)) => {
                let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{} Found {} results",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );

                if count > 0 {
                    if let Some(results) = value.get("results").and_then(|v| v.as_array()) {
                        let show_count = results.len().min(10);
                        for result in results.iter().take(show_count) {
                            let addr = result
                                .get("address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            println!("  {}", addr.yellow());
                        }
                        if count > 10 {
                            println!(
                                "  ... and {} more (use 'scan results' to see all)",
                                count - 10
                            );
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from scan_pattern"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_string(&mut self, args: &[&str]) -> bool {
        if args.is_empty() {
            logger::error("Usage: scan string <text> [protection]");
            return true;
        }

        let text = args[0];
        let protection = args.get(1).map(|s| *s);

        println!("{} Scanning for string: \"{}\"", "[SCAN]".cyan(), text);

        let params = if let Some(prot) = protection {
            json!([text, prot])
        } else {
            json!([text])
        };

        let result = self.script.exports.call("scan_string", Some(params));

        match result {
            Ok(Some(value)) => {
                let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{} Found {} results",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );

                if count > 0 {
                    if let Some(results) = value.get("results").and_then(|v| v.as_array()) {
                        let show_count = results.len().min(10);
                        for result in results.iter().take(show_count) {
                            let addr = result
                                .get("address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            println!("  {}", addr.yellow());
                        }
                        if count > 10 {
                            println!("  ... and {} more", count - 10);
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from scan_string"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_value(&mut self, args: &[&str]) -> bool {
        if args.len() < 2 {
            logger::error("Usage: scan value <type> <value> [protection]");
            return true;
        }

        let value_type = args[0];
        let value = args[1];
        let protection = args.get(2).map(|s| *s);

        println!(
            "{} Scanning for {} value: {}",
            "[SCAN]".cyan(),
            value_type,
            value
        );

        let params = if let Some(prot) = protection {
            json!([value_type, value, prot])
        } else {
            json!([value_type, value])
        };

        let result = self.script.exports.call("scan_value", Some(params));

        match result {
            Ok(Some(value_result)) => {
                let count = value_result
                    .get("count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!(
                    "{} Found {} results",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );

                if count > 0 {
                    if let Some(results) = value_result.get("results").and_then(|v| v.as_array()) {
                        let show_count = results.len().min(10);
                        for result in results.iter().take(show_count) {
                            let addr = result
                                .get("address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            println!("  {}", addr.yellow());
                        }
                        if count > 10 {
                            println!("  ... and {} more", count - 10);
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from scan_value"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_next(&mut self, args: &[&str]) -> bool {
        if args.is_empty() {
            logger::error("Usage: scan next <value> [comparison]");
            return true;
        }

        let value = args[0];
        let comparison = args.get(1).unwrap_or(&"eq");

        println!(
            "{} Refining scan with value: {} ({})",
            "[SCAN]".cyan(),
            value,
            comparison
        );

        // We need to know the type from the previous scan
        // For now, assume int32 as default
        let result = self
            .script
            .exports
            .call("scan_next", Some(json!(["int32", value, comparison])));

        match result {
            Ok(Some(value_result)) => {
                let count = value_result
                    .get("count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!(
                    "{} {} results remaining",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );

                if count > 0 && count <= 20 {
                    if let Some(results) = value_result.get("results").and_then(|v| v.as_array()) {
                        for result in results {
                            let addr = result
                                .get("address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let current = result.get("currentValue");
                            if let Some(val) = current {
                                println!("  {} = {}", addr.yellow(), val);
                            } else {
                                println!("  {}", addr.yellow());
                            }
                        }
                    }
                }
            }
            Ok(None) => logger::error("No response from scan_next"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_changed(&mut self, _args: &[&str]) -> bool {
        let result = self
            .script
            .exports
            .call("scan_changed", Some(json!(["int32"])));

        match result {
            Ok(Some(value)) => {
                let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{} {} addresses changed",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );
            }
            Ok(None) => logger::error("No response from scan_changed"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_unchanged(&mut self, _args: &[&str]) -> bool {
        let result = self
            .script
            .exports
            .call("scan_unchanged", Some(json!(["int32"])));

        match result {
            Ok(Some(value)) => {
                let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{} {} addresses unchanged",
                    "[SCAN]".green(),
                    count.to_string().yellow()
                );
            }
            Ok(None) => logger::error("No response from scan_unchanged"),
            Err(e) => logger::error(&format!("Scan error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_snapshot(&mut self, _args: &[&str]) -> bool {
        let result = self
            .script
            .exports
            .call("scan_snapshot", Some(json!(["int32"])));

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("{} Snapshot taken of {} addresses", "[SCAN]".green(), count);
                    }
                }
            }
            Ok(None) => logger::error("No response from scan_snapshot"),
            Err(e) => logger::error(&format!("Snapshot error: {}", e)),
        }
        true
    }

    pub(crate) fn scan_results(&mut self, args: &[&str]) -> bool {
        let offset = args
            .get(0)
            .and_then(|s| Self::parse_usize(s).ok())
            .unwrap_or(0);
        let limit = args
            .get(1)
            .and_then(|s| Self::parse_usize(s).ok())
            .unwrap_or(50);

        let result = self.script.exports.call(
            "get_scan_result_values",
            Some(json!(["int32", offset, limit])),
        );

        match result {
            Ok(Some(value)) => {
                if let Some(results) = value.as_array() {
                    if results.is_empty() {
                        println!("{}", "No scan results".dark_grey());
                    } else {
                        println!(
                            "{} Scan results ({}-{}):",
                            "[SCAN]".cyan(),
                            offset,
                            offset + results.len()
                        );
                        for (i, result) in results.iter().enumerate() {
                            let addr = result
                                .get("address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let val = result.get("value");
                            let idx = offset + i;
                            if let Some(v) = val {
                                println!(
                                    "  [{}] {} = {}",
                                    idx.to_string().blue(),
                                    addr.yellow(),
                                    v
                                );
                            } else {
                                println!("  [{}] {}", idx.to_string().blue(), addr.yellow());
                            }
                        }
                    }
                }
            }
            Ok(None) => println!("{}", "No scan results".dark_grey()),
            Err(e) => logger::error(&format!("Error getting results: {}", e)),
        }
        true
    }

    pub(crate) fn scan_list(&mut self, args: &[&str]) -> bool {
        let limit = args
            .get(0)
            .and_then(|s| Self::parse_usize(s).ok())
            .unwrap_or(100);

        let result = self
            .script
            .exports
            .call("get_scan_result_values", Some(json!(["int32", 0, limit])));

        match result {
            Ok(Some(value)) => {
                if let Some(results) = value.as_array() {
                    let scan_results: Vec<VzData> = results
                        .iter()
                        .filter_map(|r| {
                            let addr_str = r.get("address").and_then(|v| v.as_str())?;
                            let address = crate::gum::vzdata::string_to_u64(addr_str);
                            let value = r.get("value").map(|v| v.to_string());

                            Some(VzData::ScanResult(VzScanResult {
                                base: new_base(VzDataType::ScanResult),
                                address,
                                size: 4,
                                value,
                                pattern: None,
                            }))
                        })
                        .collect();

                    self.field.clear_data();
                    self.field.add_datas(scan_results);
                    println!("{}", self.field.to_string(None));
                }
            }
            Ok(None) => println!("{}", "No scan results".dark_grey()),
            Err(e) => logger::error(&format!("Error loading results: {}", e)),
        }
        true
    }

    pub(crate) fn scan_clear(&mut self, _args: &[&str]) -> bool {
        let result = self.script.exports.call("clear_scan", None);

        match result {
            Ok(Some(value)) => {
                if let Some(success) = value.get("success").and_then(|v| v.as_bool()) {
                    if success {
                        println!("{} Scan results cleared", "[SCAN]".green());
                    }
                }
            }
            Ok(None) => logger::error("No response from clear_scan"),
            Err(e) => logger::error(&format!("Clear error: {}", e)),
        }
        true
    }

    // ========================================================================
    // Thread Commands
    // ========================================================================

    pub(crate) fn thread_list(&mut self, _args: &[&str]) -> bool {
        let result = self.script.exports.call("list_threads", None);

        match result {
            Ok(Some(value)) => {
                if let Some(threads) = value.as_array() {
                    if threads.is_empty() {
                        println!("{}", "No threads found".dark_grey());
                    } else {
                        println!("{} {} threads:", "[THREADS]".cyan(), threads.len());

                        let thread_datas: Vec<VzData> = threads
                            .iter()
                            .filter_map(|t| {
                                let id = t.get("id").and_then(|v| v.as_u64())?;
                                let state =
                                    t.get("state").and_then(|v| v.as_str()).unwrap_or("unknown");

                                println!(
                                    "  Thread {} ({})",
                                    id.to_string().yellow(),
                                    state.dark_grey()
                                );

                                Some(VzData::Thread(VzThread {
                                    base: new_base(VzDataType::Thread),
                                    id,
                                }))
                            })
                            .collect();

                        self.field.clear_data();
                        self.field.add_datas(thread_datas);
                    }
                }
            }
            Ok(None) => println!("{}", "No threads found".dark_grey()),
            Err(e) => logger::error(&format!("Thread list error: {}", e)),
        }
        true
    }

    pub(crate) fn thread_regs(&mut self, args: &[&str]) -> bool {
        let thread_id = args.get(0).and_then(|s| s.parse::<u64>().ok());

        let thread_id = match thread_id {
            Some(id) => id,
            None => {
                // Try to get first thread
                let result = self.script.exports.call("list_threads", None);
                match result {
                    Ok(Some(value)) => value
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|t| t.get("id"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    _ => 0,
                }
            }
        };

        if thread_id == 0 {
            logger::error("No valid thread ID");
            return true;
        }

        let result = self
            .script
            .exports
            .call("get_thread_context", Some(json!([thread_id])));

        match result {
            Ok(Some(value)) => {
                if value.is_null() {
                    println!("{}", "Thread context not available".dark_grey());
                } else if let Some(regs) = value.as_object() {
                    println!(
                        "{} Thread {} registers:",
                        "[REGS]".cyan(),
                        thread_id.to_string().yellow()
                    );
                    for (name, val) in regs {
                        if let Some(v) = val.as_str() {
                            println!("  {:<6} = {}", name.as_str().cyan(), v.yellow());
                        }
                    }
                }
            }
            Ok(None) => println!("{}", "Thread context not available".dark_grey()),
            Err(e) => logger::error(&format!("Register read error: {}", e)),
        }
        true
    }

    pub(crate) fn thread_stack(&mut self, args: &[&str]) -> bool {
        let thread_id = args.get(0).and_then(|s| s.parse::<u64>().ok());
        let depth = args
            .get(1)
            .and_then(|s| Self::parse_usize(s).ok())
            .unwrap_or(32);

        // First get thread context to find SP
        let thread_id = match thread_id {
            Some(id) => id,
            None => {
                let result = self.script.exports.call("list_threads", None);
                match result {
                    Ok(Some(value)) => value
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|t| t.get("id"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    _ => 0,
                }
            }
        };

        if thread_id == 0 {
            logger::error("No valid thread ID");
            return true;
        }

        // Get thread context to find SP
        let ctx_result = self
            .script
            .exports
            .call("get_thread_context", Some(json!([thread_id])));

        let sp = match ctx_result {
            Ok(Some(value)) => {
                // Try common SP register names
                value
                    .get("rsp")
                    .or_else(|| value.get("esp"))
                    .or_else(|| value.get("sp"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| crate::gum::vzdata::string_to_u64(s).into())
                    .unwrap_or(0)
            }
            _ => 0,
        };

        if sp == 0 {
            logger::error("Could not determine stack pointer");
            return true;
        }

        let result = self
            .script
            .exports
            .call("read_stack", Some(json!([format!("{}", sp), depth])));

        match result {
            Ok(Some(value)) => {
                if let Some(stack) = value.as_array() {
                    println!(
                        "{} Stack @ {} (thread {}):",
                        "[STACK]".cyan(),
                        format!("{:#x}", sp).yellow(),
                        thread_id
                    );
                    for entry in stack {
                        let offset = entry.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
                        let addr = entry.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                        let val = entry.get("value").and_then(|v| v.as_str()).unwrap_or("?");
                        let module = entry.get("module").and_then(|v| v.as_str());
                        let symbol = entry.get("symbol").and_then(|v| v.as_str());

                        let info = match (module, symbol) {
                            (Some(m), Some(s)) => format!(" ({}: {})", m, s),
                            (Some(m), None) => format!(" ({})", m),
                            _ => String::new(),
                        };

                        println!(
                            "  +{:<4} {} -> {}{}",
                            format!("{:#x}", offset),
                            addr.dark_grey(),
                            val.yellow(),
                            info.dark_grey()
                        );
                    }
                }
            }
            Ok(None) => println!("{}", "Could not read stack".dark_grey()),
            Err(e) => logger::error(&format!("Stack read error: {}", e)),
        }
        true
    }

    pub(crate) fn thread_backtrace(&mut self, args: &[&str]) -> bool {
        let result = self.script.exports.call("backtrace", None);

        match result {
            Ok(Some(value)) => {
                if let Some(frames) = value.as_array() {
                    if frames.is_empty() {
                        println!("{}", "No backtrace available".dark_grey());
                    } else {
                        println!("{} Backtrace ({} frames):", "[BT]".cyan(), frames.len());
                        for (i, frame) in frames.iter().enumerate() {
                            let addr = frame.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let module = frame.get("module").and_then(|v| v.as_str());
                            let symbol = frame.get("symbol").and_then(|v| v.as_str());
                            let offset = frame.get("offset").and_then(|v| v.as_i64());

                            let location = match (module, symbol, offset) {
                                (Some(m), Some(s), Some(o)) => format!("{}!{} +{:#x}", m, s, o),
                                (Some(m), Some(s), None) => format!("{}!{}", m, s),
                                (Some(m), None, Some(o)) => format!("{} +{:#x}", m, o),
                                (Some(m), None, None) => m.to_string(),
                                _ => "???".to_string(),
                            };

                            println!("  #{:<2} {} {}", i, addr.yellow(), location.dark_grey());
                        }
                    }
                }
            }
            Ok(None) => println!("{}", "No backtrace available".dark_grey()),
            Err(e) => logger::error(&format!("Backtrace error: {}", e)),
        }
        true
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Resolve a target string to an address
    /// Accepts: hex address, decimal address, or selector
    fn resolve_target_address(&mut self, target: &str) -> Result<u64, String> {
        // First try to parse as a number
        if let Ok(addr) = Self::parse_number(target) {
            return Ok(addr);
        }

        // Try selector
        match self.selector(target) {
            Ok(data) => {
                if data.is_empty() {
                    Err("No data found for selector".to_string())
                } else {
                    get_address_from_data(data[0])
                        .ok_or_else(|| "Selected data has no address".to_string())
                }
            }
            Err(e) => {
                // Try to resolve as symbol name
                let result = self
                    .script
                    .exports
                    .call("find_symbol", Some(json!([target])));

                match result {
                    Ok(Some(value)) => {
                        if value.is_null() {
                            Err(format!("Symbol not found: {}", target))
                        } else {
                            value
                                .get("address")
                                .and_then(|v| v.as_str())
                                .map(|s| crate::gum::vzdata::string_to_u64(s))
                                .ok_or_else(|| format!("Invalid symbol address for: {}", target))
                        }
                    }
                    Ok(None) => Err(format!("Symbol not found: {}", target)),
                    Err(_) => Err(e),
                }
            }
        }
    }
}
