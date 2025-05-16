// src/gum/session.rs
use frida::{Script};
use std::{
    io::{stdin, stdout, Write},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};
use crossterm::{
    ExecutableCommand,
    terminal, cursor, style::{Stylize}
};
use super::{commander::Commander};

pub fn session_manager(script: &Script) {
    let mut stdout = stdout();
    let version = env!("CARGO_PKG_VERSION");
    let title = format!("vlitz v{}", version);
    stdout.execute(terminal::SetTitle(title)).unwrap();
    stdout.execute(terminal::Clear(terminal::ClearType::All)).unwrap();
    stdout.execute(cursor::MoveTo(0, 0)).unwrap();
    println!("{}", "Welcome to vlitz!".green());
    println!("{}", "Type 'help' for a list of commands.".yellow());
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).unwrap_or_else(|e| {
        eprintln!("Error setting Ctrl-C handler: {}", e);
        std::process::exit(1);
    });
    let mut commander = Commander::new(&script);
    loop {
        if !running.load(Ordering::SeqCst) {
            println!("\n{}", "Ctrl + C detected. Exiting...".yellow());
            break;
        }
        let write_str = format!("{}>", commander.navigator);
        stdout.write(write_str.as_bytes()).unwrap();
        stdout.flush().unwrap();
        let mut input = String::new();
        let bytes_read = stdin().read_line(&mut input);
        match bytes_read {
            Ok(0) => {
                println!("\n{}", "Ctrl + D detected. Exiting...".yellow());
                break;
            },
            Ok(_) => (), // Successfully read some bytes
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        };
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        let mut args = input.split_whitespace();
        let command = args.next().unwrap_or("");
        match command {
            "exit" | "quit" | "q" => {
                println!("{}", "Exiting...".yellow());
                break;
            }
            _ => {
                commander.execute(command, args.collect());
            }
        }
    }
}