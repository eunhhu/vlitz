// src/gum/commander.rs
use crossterm::style::Stylize;
use crate::{util::lengthed};
use super::{
    navigator::Navigator, selector::{parse_selection_type, SelectorType}, store::Store, vzdata::VzData
};
use frida::Script;
use regex::Regex;

pub struct Commander<'a> {
    script: &'a Script<'a>,
    field: Store,
    lib: Store,
    pub navigator: Navigator,
}

impl<'a> Commander<'a> {
    pub fn new(script: &'a Script<'a>) -> Self {
        Commander { 
            script,
            field: Store::new(),
            lib: Store::new(),
            navigator: Navigator::new(),
        }
    }

    pub fn execute(&mut self, command: &str, args: Vec<&str>) {
        match command {
            "help" => self.help(),
            "ls" => self.ls(args),
            // add more commands here
            _ => {
                println!("{} {}",
                    "Unknown command:".red(),
                    command);
            }
        }
    }

    fn help(&self) {
        println!("{}", "Available commands:".green());
        println!("  {} - {}", lengthed("exit, quit, q", 24).yellow(), "Exit the session");
        println!("  {} - {}", lengthed("help", 24).yellow(), "Show this help message");
        println!("  {} - {}", lengthed("ls", 24).yellow(), "List the field data");
    }

    fn select(&mut self, s: &str) -> Result<Vec<&VzData>, String> {
        let re = Regex::new(r"^([a-zA-Z0-9]+)?:?(.+)$").unwrap();
        if let Some(caps) = re.captures(s) {
            let store_name = &caps[1];
            let selector = &caps[2];
            let store = match store_name {
                "field" => &self.field,
                "lib" => &self.lib,
                _ => return Err(format!("Unknown store: {}", store_name)),
            };
            let selector_type = parse_selection_type(selector);
            match selector_type {
                Ok(SelectorType::Indices(indices)) => {
                    store.get_multiple_data(&indices)
                }
                Ok(SelectorType::All) => {
                    store.get_all_data()
                }
                Err(e) => Err(e),
            }
        } else {
            Err(format!("Invalid selection format: {}", s))
        }
    }

    fn ls(&mut self, args: Vec<&str>) {
        if args.is_empty() {
            let cursor = if self.field.data.len() > 0 {
                self.field.get_cursor() + 1
            } else {
                0
            };
            let current_page = self.field.get_page_info().0;
            let total_pages = self.field.get_page_info().1;
            println!("{}", format!("Field {}-{} [{}] ({}/{})",
                cursor,
                self.field.get_cursor_end(),
                self.field.data.len(),
                current_page,
                total_pages
            ).green());

            let data = self.field.get_current_data();
            let max_idx_len = self.field.data.len().to_string().len();

            for (i, item) in data.iter().enumerate() {
                let global_idx = self.field.get_cursor() + i + 1;
                println!("[{}] {}",
                    lengthed(&global_idx.to_string(), max_idx_len).blue(),
                    item
                );
            }
        }
    }
}