// src/gum/commander.rs
use crossterm::style::Stylize;
use crate::util::fill;

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
                    "field",
                    "Field manipulation commands.",
                    vec!["f"],
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
                    ],
                    Some(|c, a| Commander::lib_list(c, a)),
                ),
                Command::new(
                    "list",
                    "List all data",
                    vec![],
                    vec![],
                    vec![SubCommand::new(
                        "modules",
                        "List all modules",
                        vec![],
                        |c, a| Commander::list_modules(c, a),
                    )],
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
                        if subcmd_len < 24 {
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
                                " ".repeat(24 - cmd.command.len() - 1),
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
            let store_name = caps.get(1).map_or("lib", |m| m.as_str());
            let selector = caps.get(2).ok_or("No selector provided")?;
            let selector = selector.as_str();
            let store = match store_name {
                "lib" => &self.lib,
                "field" => &self.field,
                _ => return Err(format!("Unknown store: {}", store_name)),
            };
            let data = store.get_data_by_selection(selector);
            match data {
                Ok(data) => Ok(data),
                Err(e) => {
                    if store.name == "lib" {
                        let store = &self.field;
                        let data = store.get_data_by_selection(selector);
                        match data {
                            Ok(data) => Ok(data),
                            Err(e) => Err(format!("Failed to get data: {}", e)),
                        }
                    } else {
                        Err(format!("Failed to get data: {}", e))
                    }
                },
            }
        } else {
            Err(format!("Invalid selection format: {}", s))
        }
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

    fn list_modules(&mut self, args: &[&str]) -> bool {
        let modules = list_modules(&mut self.script, None)
            .into_iter()
            .map(|m| VzData::Module(m))
            .collect::<Vec<_>>();
        self.field.add_datas(modules);
        println!("{}", self.field.to_string(None));
        true
    }
}