use frida::{Script};
use std::{io::{stdin, stdout, Write}};
use crossterm::{
    ExecutableCommand,
    terminal, cursor, style::{Stylize}
};
use super::{command::parser, field::Field};

pub fn session_manager(script: &Script) {
    let mut stdout = stdout();
    stdout.execute(terminal::Clear(terminal::ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    let title = format!("vlitz v{}", version);
    stdout.execute(terminal::SetTitle(title)).unwrap();
    let mut field = Field::new();
    loop {
        let write_str = format!("{} > ", "vlitz".green());
        stdout.write(write_str.as_bytes()).unwrap();
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read line");
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        let mut args = input.split_whitespace();
        let command = args.next().unwrap_or("");
        match command {
            "exit" | "quit" | "q" => {
                break;
            }
            "help" => {
            }
            _ => {
                parser(&mut field, command, args.collect());
            }
        }
    }
}