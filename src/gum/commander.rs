use crossterm::style::Stylize;
use crate::{util::lengthed};
use super::field::Field;
use frida::Script;

pub struct Commander<'a> {
    script: &'a Script<'a>,
    field: Field,
}

impl<'a> Commander<'a> {
    pub fn new(script: &'a Script<'a>) -> Self {
        let field = Field::new();
        Commander { field, script }
    }

    pub fn execute(&mut self, command: &str, args: Vec<&str>) {
        match command {
            "ls" => self.ls(args),
            "help" => self.help(),
            // 여기에 다른 명령어들을 추가합니다.
            // "scan" => self.scan(args),
            // "modules" => self.list_modules(args),
            _ => {
                println!("{} {}",
                    "Unknown command:".red(),
                    command);
            }
        }
    }

    fn help(&self) {
        println!("{}", "Available commands:".green());
        println!("  {} - {}", lengthed("ls", 10).yellow(), "List the current data");
        println!("  {} - {}", lengthed("help", 10).yellow(), "Show this help message");
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