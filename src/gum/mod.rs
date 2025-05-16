// src/gum/mod.rs
mod handler;
mod session;

pub mod vzdata;
pub mod store;
pub mod commander;
pub mod navigator;
pub mod selector;

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
            .expect("Process not found");
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref file) = args.file {
        let pid = device
            .spawn(file, &frida::SpawnOptions::new())
            .unwrap_or_else(|e| {
                panic!("{} {} ({})", "Failed to spawn process:".red(), file.to_string().yellow(), e);
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_name {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                panic!("{} {}", "Process not found:".red(), name.to_string().yellow());
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_identifier {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                panic!("{} {}", "Process not found:".red(), name.to_string().yellow());
            });
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.target {
        let pid = device
            .enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .unwrap_or_else(|| {
                panic!("{} {}", "Process not found:".red(), name.to_string().yellow());
            });
        (device.attach(pid).unwrap(), pid)
    } else {
        panic!("{}", "No target specified".red());
    };
    if session.is_detached() {
        println!("{}", "Session detached...".yellow().bold());
        return;
    }
    let script_content = include_str!("../agent.js").to_string();
    let mut script = session
        .create_script(&script_content, &mut ScriptOption::default())
        .unwrap_or_else(|e| {
            panic!("{} {}", "Failed to create script:".red(), e);
        });

    let handler = script.handle_message(Handler);
    if let Err(e) = handler {
        panic!("{} {}", "Failed to set message handler:".red(), e);
    }

    script.load().unwrap_or_else(|e| {
        panic!("{} {}", "Failed to load script:".red(), e);
    });

    if args.file.is_some() {
        device.resume(pid).unwrap_or_else(|e| {
            panic!("{} {}", "Failed to resume process:".red(), e);
        });
    }

    session_manager(&script);

    script.unload().unwrap();
    session.detach().unwrap();
    println!("{}", "Session detached.".yellow().bold());
}
