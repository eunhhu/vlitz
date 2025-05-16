use crossterm::style::Stylize;

use super::field::Field;

pub fn parser(field: &mut Field, command: &str, args: Vec<&str>) {
    match command {
        "ls" => {
            if args.is_empty() {
                // Header
                let current_page = field.get_page_info().0;
                let total_pages = field.get_page_info().1;
                println!("Field {}-{} [{}] ({}/{})",
                    field.get_cursor() + 1,
                    field.get_cursor_end(),
                    field.data.len(),
                    current_page,
                    total_pages);
                let data = field.get_current_data();
                for item in data {
                    println!("{} {}",
                        format!("[{}]", item.base.data_type).blue(),
                    );
                }
            } else {
                for arg in args {
                    println!("{} {}",
                        "Argument:".green(),
                        arg);
                }
            }
        }
        _ => {
            println!("{} {}",
                "Unknown command:".red(),
                command);
        }
    }
}
