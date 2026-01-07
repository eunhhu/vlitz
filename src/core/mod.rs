mod actions;
pub mod cli;
pub mod error;
mod kill;
mod manager;
pub mod process;
mod ps;

use crate::{
    gum::attach,
    util::{format::lengthed, highlight},
};
use actions::get_device;
use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use crossterm::style::Stylize;
use error::VlitzError;
use manager::Manager;
use std::process::exit;

fn handle_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    let bin_name = "vlitz".to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    exit(0);
}

fn handle_attach(manager: &Manager, args: &cli::AttachArgs) {
    let device_opt = get_device(manager, &args.connection);
    if let Some(mut device) = device_opt {
        attach(&mut device, &args.target);
        exit(0);
    } else {
        println!("{}", VlitzError::DeviceNotFound);
        exit(1);
    }
}

fn handle_ps(manager: &Manager, args: &cli::PsArgs) {
    let device = get_device(manager, &args.connection);
    if let Some(device) = device {
        println!(
            "{} {}",
            "Device:".green(),
            device.get_id().replace("\"", "").green()
        );
        let processes = ps::ps(&device, args);
        println!(
            "{} {:<12} ({})",
            lengthed("PID", 5).cyan().bold(),
            "Process Name".yellow().bold(),
            processes.len(),
        );
        for process in processes {
            let process_name = if let Some(ref f) = args.filter {
                highlight(process.get_name(), f)
            } else {
                process.get_name().to_string()
            };
            println!(
                "{} {}",
                lengthed(&process.get_pid().to_string(), 5).blue(),
                process_name
            );
        }
        exit(0);
    } else {
        println!("{}", VlitzError::DeviceNotFound);
        exit(1);
    }
}

fn handle_kill(manager: &Manager, args: &cli::KillArgs) {
    let device = get_device(manager, &args.connection);
    if let Some(mut device) = device {
        let killed_processes = kill::kill(&mut device, &args.process);
        if killed_processes.is_empty() {
            println!("No processes killed");
        } else {
            for prc in killed_processes {
                println!(
                    "Killed process {} {}",
                    format!("\"{}\"", prc.0).yellow(),
                    format!("[{}]", prc.1.to_string()).blue()
                );
            }
            exit(0);
        }
    } else {
        println!("{}", VlitzError::DeviceNotFound);
        exit(1);
    }
}

fn handle_devices(manager: &Manager) {
    let devices = manager.device_manager.enumerate_all_devices();
    println!(
        "{} {} {}",
        lengthed("Type", 6).cyan().bold(),
        lengthed("ID", 12).yellow().bold(),
        "Device Name".yellow().bold()
    );
    for device in devices {
        println!(
            "{} {} {}",
            lengthed(&device.get_type().to_string(), 6).blue(),
            lengthed(device.get_id(), 12).white(),
            device.get_name().grey()
        );
    }
    exit(0);
}

pub fn execute_cli() {
    let cliparser = Cli::parse();

    if let Some(_shell) = cliparser.generate_completion {
        if let Err(e) = cliparser.generate_completion() {
            crate::util::logger::error(&format!("Failed to generate completion: {}", e));
            exit(1);
        }
        exit(0);
    }

    let manager = Manager::new();

    match &cliparser.command {
        Commands::Completions { shell } => handle_completions(*shell),
        Commands::Attach(args) => handle_attach(&manager, args),
        Commands::Ps(args) => handle_ps(&manager, args),
        Commands::Kill(args) => handle_kill(&manager, args),
        Commands::Devices => handle_devices(&manager),
    }
}
