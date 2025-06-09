use crossterm::style::Stylize;

pub fn error(message: &str) {
    eprintln!("{} {}", "[Error]".red(), message);
}
