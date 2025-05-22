// src/gum/session.rs
use frida::{Script, Session};
use regex::Regex;
use std::{
    io::{stdin, stdout, Write},
    sync::{Arc, atomic::{AtomicBool, Ordering}},
};
use crossterm::{
    ExecutableCommand,
    terminal, cursor, style::{Stylize}
};
use super::{commander::Commander};

fn parse_command(input: &str) -> Vec<String> {
    let re = Regex::new(r#"("[^"]*")|('[^']*')|(\S+)"#).unwrap();
    
    re.find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn session_manager(session: &Session, script: &mut Script<'_>, pid: u32) {
    let mut commander = Commander::new(script);
    let version = env!("CARGO_PKG_VERSION");
    let title = format!("vlitz v{}", version);
    stdout().execute(terminal::SetTitle(title)).unwrap();
    stdout().execute(terminal::Clear(terminal::ClearType::All)).unwrap();
    stdout().execute(cursor::MoveTo(0, 0)).unwrap();
    println!("{}", format!("Welcome to Vlitz v{} - A Strong Dynamic Debugger", version).green());
    println!("Attached on: [{}] {}", pid.to_string().blue(), commander.env.clone().cyan());
    println!("{}", "Type 'help' for more information about available commands.".yellow());
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).unwrap_or_else(|e| {
        eprintln!("Error setting Ctrl-C handler: {}", e);
        std::process::exit(1);
    });
    loop {
        if !running.load(Ordering::SeqCst) {
            println!("\n{}", "Ctrl + C detected. Exiting...".yellow());
            break;
        }
        let write_str = format!("{}>", commander.navigator);
        stdout().write(write_str.as_bytes()).unwrap();
        stdout().flush().unwrap();
        let mut input = String::new();
        let bytes_read = stdin().read_line(&mut input);
        match bytes_read {
            Ok(0) => {
                println!("\n{}", "Ctrl + D detected. Exiting...".yellow());
                break;
            },
            Ok(_) => (), // Successfully read some bytes
            Err(e) => {
                println!("Error reading input: {}", e);
                break;
            }
        };
        if session.is_detached() {
            println!("{}", "Session detached. Exiting...".red());
            break;
        }
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        let mut args = parse_command(input);
        let command = args.remove(0);
        match command.as_str() {
            _ => {
                if !commander.execute_command(command.as_str(), args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice()) {
                    break;
                }
            }
        }
    }
}