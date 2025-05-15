use frida::{Script};
use std::{io::{stdin, stdout, Write}, process::exit};
use crossterm::{
    ExecutableCommand, QueueableCommand,
    terminal, cursor, style::{self, Stylize}
};

pub fn session_manager(script: &Script) {
    let mut stdout = stdout();
    stdout.execute(terminal::Clear(terminal::ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    let title = format!("vlitz v{}", version);
    stdout.execute(terminal::SetTitle(title)).unwrap();
    loop {
        stdout.write(b"vlitz>").unwrap();
        stdout.flush().unwrap();
        let mut input = String::new();
        stdin().read_line(&mut input).expect("Failed to read line");
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        if input == "exit" {
            break;
        }
    }
}