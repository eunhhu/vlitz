use frida::{Script};
use std::io::{self, stdout, Write};
use crossterm::{
    ExecutableCommand, QueueableCommand,
    terminal, cursor, style::{self, Stylize}
};

pub fn session_manager(script: &Script) {
    let mut stdout = stdout();
    stdout.execute(terminal::Clear(terminal::ClearType::All)).unwrap();
    stdout.flush().unwrap();
}