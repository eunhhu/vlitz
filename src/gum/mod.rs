// src/gum/mod.rs
mod handler;
mod session;

pub mod vzdata;
pub mod store;
pub mod commander;
pub mod navigator;
pub mod list;
pub mod filter;

use std::process::exit;

use crate::core::cli::TargetArgs;
use crossterm::style::Stylize;
use frida::{Device, ScriptOption};
use handler::Handler;
use session::session_manager;

pub fn attach(device: &mut Device, args: &TargetArgs) {
    let (session, pid) = if let Some(_pid) = args.attach_pid {
        let pid: u32 = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_pid() == _pid)
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                println!("{} {}", "Process not found:".red(), _pid.to_string().yellow());
                exit(0);
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref file) = args.file {
        let pid = device
            .spawn(file, &frida::SpawnOptions::new())
            .unwrap_or_else(|e| {
                println!("{} {} ({})", "Failed to spawn process:".red(), file.to_string().yellow(), e);
                exit(0);
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_name {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                println!("{} {}", "Process not found:".red(), name.to_string().yellow());
                exit(0);
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_identifier {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                println!("{} {}", "Process not found:".red(), name.to_string().yellow());
                exit(0);
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.target {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                println!("{} {}", "Process not found:".red(), name.to_string().yellow());
                exit(0);
            });
        (device.attach(pid).unwrap(), pid)
    } else {
        println!("{}", "No target specified".red());
        exit(0);
    };
    if session.is_detached() {
        println!("{}", "Session detached...".yellow().bold());
        return;
    }
    let script_content = include_str!("../agent.js").to_string();
    let mut script = session
        .create_script(&script_content, &mut ScriptOption::default())
        .unwrap_or_else(|e| {
            println!("{} {}", "Failed to create script:".red(), e);
            exit(0);
        });

    let handler = script.handle_message(Handler);
    if let Err(e) = handler {
        println!("{} {}", "Failed to set message handler:".red(), e);
        exit(0);
    }

    script.load().unwrap_or_else(|e| {
        println!("{} {}", "Failed to load script:".red(), e);
        exit(0);
    });

    if args.file.is_some() {
        device.resume(pid).unwrap_or_else(|e| {
            println!("{} {}", "Failed to resume process:".red(), e);
            exit(0);
        });
    }

    session_manager(&session, &mut script, pid);

    if !session.is_detached() {
        script.unload().unwrap();
        session.detach().unwrap();
        println!("{}", "Session detached.".yellow().bold());
    }
}
